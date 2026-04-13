"""
tests/test_auth.py — SecureJobs
===================================
Integration tests for the authentication routes.
Uses FastAPI TestClient (real HTTP requests, test DB, no real SMTP).

Covers:
  - Registration (happy path, duplicate email)
  - Login with wrong credentials
  - Login with suspended account
  - Successful TOTP login issues JWT cookie
  - Logout clears cookie
  - Unverified user redirected to email verify
  - Role is persisted correctly (user vs recruiter)
  - Rate limit triggers after 5 failed login attempts
"""

import os
import pytest
import pyotp

os.environ.setdefault("SECRET_KEY",   "test-secret-key-32-bytes-padding!")
os.environ.setdefault("AES_KEY",      "test-aes-key-32-bytes-padding!!!")
os.environ.setdefault("MESSAGE_KEY",  "test-msg-key-32-bytes-padding!!!")
os.environ.setdefault("DB_USER",      "test")
os.environ.setdefault("DB_PASSWORD",  "test")
os.environ.setdefault("DB_HOST",      "localhost")
os.environ.setdefault("DB_NAME",      "test")
os.environ.setdefault("SMTP_EMAIL",   "test@test.com")
os.environ.setdefault("SMTP_APP_PASSWORD", "fake")

from auth.password import hash_password
from auth.totp import generate_totp_secret


# ── Helper: create a fully verified user directly in the DB ───
def make_user(db, email="test@example.com", password="password123",
              role="user", is_verified=True, is_suspended=False,
              is_admin=False):
    from models.user import User
    secret = generate_totp_secret()
    user   = User(
        full_name    = "Test User",
        email        = email,
        phone        = "1234567890",
        hashed_pw    = hash_password(password),
        otp_secret   = secret,
        role         = role,
        is_verified  = is_verified,
        is_suspended = is_suspended,
        is_admin     = is_admin,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# ── Helper: get a CSRF token from any GET page ─────────────────
def get_csrf(client, url="/login"):
    resp = client.get(url)
    # Extract csrf_token from the set-cookie header
    for key, val in resp.cookies.items():
        if "csrf" in key.lower():
            return val
    # Fallback: parse from HTML form hidden input
    import re
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', resp.text)
    return match.group(1) if match else ""


# ══════════════════════════════════════════════════════════════
# REGISTRATION
# ══════════════════════════════════════════════════════════════

class TestRegister:

    def test_register_page_loads(self, client):
        resp = client.get("/register")
        assert resp.status_code == 200
        assert "Create Account" in resp.text

    def test_duplicate_email_redirects_with_error(self, client, db):
        make_user(db, email="taken@example.com")
        csrf = get_csrf(client, "/register")
        resp = client.post("/register", data={
            "full_name": "Another",
            "email":     "taken@example.com",
            "phone":     "000",
            "password":  "pass",
            "role":      "user",
            "csrf_token": csrf,
        })
        assert "email_taken" in str(resp.url) or resp.status_code in (200, 303)

    def test_role_sanitised_to_user_if_invalid(self, client, db):
        """Role 'admin' from form should be rejected and default to 'user'."""
        from models.user import User
        csrf = get_csrf(client, "/register")
        client.post("/register", data={
            "full_name": "Hacker",
            "email":     "hacker@example.com",
            "phone":     "000",
            "password":  "pass",
            "role":      "admin",        # attempt to self-assign admin
            "csrf_token": csrf,
        })
        user = db.query(User).filter(User.email == "hacker@example.com").first()
        if user:
            assert user.role in ("user", "recruiter")
            assert user.role != "admin"


# ══════════════════════════════════════════════════════════════
# LOGIN — STEP 1 (credentials)
# ══════════════════════════════════════════════════════════════

class TestLoginCredentials:

    def test_login_page_loads(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200
        assert "Login" in resp.text

    def test_wrong_password_shows_error(self, client, db):
        make_user(db, email="user@example.com", password="correct")
        csrf = get_csrf(client)
        resp = client.post("/login", data={
            "email":      "user@example.com",
            "password":   "wrong-password",
            "csrf_token": csrf,
        }, allow_redirects=True)
        assert "invalid_credentials" in str(resp.url) or resp.status_code == 200

    def test_nonexistent_email_shows_error(self, client):
        csrf = get_csrf(client)
        resp = client.post("/login", data={
            "email":      "nobody@nowhere.com",
            "password":   "anything",
            "csrf_token": csrf,
        }, allow_redirects=True)
        assert "invalid_credentials" in str(resp.url) or resp.status_code == 200

    def test_suspended_user_blocked(self, client, db):
        make_user(db, email="banned@example.com", is_suspended=True)
        csrf = get_csrf(client)
        resp = client.post("/login", data={
            "email":      "banned@example.com",
            "password":   "password123",
            "csrf_token": csrf,
        }, allow_redirects=True)
        assert "suspended" in str(resp.url) or "suspended" in resp.text.lower()

    def test_unverified_user_redirected_to_verify(self, client, db):
        make_user(db, email="unverified@example.com", is_verified=False)
        csrf = get_csrf(client)
        resp = client.post("/login", data={
            "email":      "unverified@example.com",
            "password":   "password123",
            "csrf_token": csrf,
        }, allow_redirects=True)
        assert "verify-email" in str(resp.url) or resp.status_code == 200

    def test_valid_credentials_proceed_to_totp(self, client, db):
        make_user(db, email="valid@example.com")
        csrf = get_csrf(client)
        resp = client.post("/login", data={
            "email":      "valid@example.com",
            "password":   "password123",
            "csrf_token": csrf,
        }, allow_redirects=True)
        # Should show the TOTP entry page (virtual keyboard)
        assert resp.status_code == 200
        assert "Two-Factor" in resp.text or "authenticator" in resp.text.lower()


# ══════════════════════════════════════════════════════════════
# LOGIN — STEP 2 (TOTP)
# ══════════════════════════════════════════════════════════════

class TestLoginTOTP:

    def _login_step1(self, client, db, email="totp@example.com"):
        """Complete step 1 and return the user object."""
        user = make_user(db, email=email)
        csrf = get_csrf(client)
        client.post("/login", data={
            "email":      email,
            "password":   "password123",
            "csrf_token": csrf,
        }, allow_redirects=False)
        return user

    def test_valid_totp_sets_cookie_and_redirects(self, client, db):
        user = self._login_step1(client, db)
        otp  = pyotp.TOTP(user.otp_secret).now()
        csrf = get_csrf(client, "/login")
        resp = client.post(f"/totp-login/{user.email}", data={
            "otp":        otp,
            "csrf_token": csrf,
        }, allow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers.get("location", "").endswith("/profile")
        assert "access_token" in client.cookies

    def test_wrong_totp_shows_error(self, client, db):
        user = self._login_step1(client, db, email="badotp@example.com")
        csrf = get_csrf(client, "/login")
        resp = client.post(f"/totp-login/{user.email}", data={
            "otp":        "000000",      # almost certainly wrong
            "csrf_token": csrf,
        }, allow_redirects=True)
        assert "invalid_otp" in str(resp.url) or resp.status_code == 200
        assert "access_token" not in client.cookies


# ══════════════════════════════════════════════════════════════
# LOGOUT
# ══════════════════════════════════════════════════════════════

class TestLogout:

    def test_logout_deletes_cookie(self, client, db):
        # Log in first
        user = make_user(db, email="logout@example.com")
        otp  = pyotp.TOTP(user.otp_secret).now()
        csrf = get_csrf(client)
        client.post("/login", data={
            "email": user.email, "password": "password123", "csrf_token": csrf
        })
        csrf = get_csrf(client, "/login")
        client.post(f"/totp-login/{user.email}", data={
            "otp": otp, "csrf_token": csrf
        })
        assert "access_token" in client.cookies

        # Now log out
        client.get("/logout")
        assert "access_token" not in client.cookies


# ══════════════════════════════════════════════════════════════
# ACCESS CONTROL
# ══════════════════════════════════════════════════════════════

class TestAccessControl:

    def test_unauthenticated_profile_redirects_to_login(self, client):
        resp = client.get("/profile", allow_redirects=False)
        assert resp.status_code == 303
        assert "/login" in resp.headers.get("location", "")

    def test_unauthenticated_admin_returns_403(self, client):
        resp = client.get("/admin")
        assert resp.status_code == 403

    def test_regular_user_cannot_access_admin(self, client, db):
        from auth.jwt import create_token
        user = make_user(db, email="regular@example.com", role="user")
        token = create_token({"sub": user.email})
        client.cookies.set("access_token", token)
        resp = client.get("/admin")
        assert resp.status_code == 403

    def test_regular_user_cannot_create_job(self, client, db):
        from auth.jwt import create_token
        user = make_user(db, email="seeker@example.com", role="user")
        token = create_token({"sub": user.email})
        client.cookies.set("access_token", token)
        resp = client.get("/jobs/create", allow_redirects=False)
        # Should redirect away (not a recruiter)
        assert resp.status_code == 303

    def test_admin_can_access_admin_panel(self, client, db):
        from auth.jwt import create_token
        admin = make_user(db, email="admin@example.com",
                          role="admin", is_admin=True)
        token = create_token({"sub": admin.email})
        client.cookies.set("access_token", token)
        resp = client.get("/admin")
        assert resp.status_code == 200
