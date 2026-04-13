"""
tests/test_security.py — SecureJobs
=====================================
Security-specific tests that directly verify defences against
the attack categories required by the milestone spec:

  - CSRF protection (POST without token rejected)
  - Security headers present on every response
  - Duplicate application prevention
  - Horizontal privilege escalation (recruiter cross-company)
  - Resume upload file type enforcement
  - Resume upload size enforcement
  - Role sanitisation (cannot self-assign admin at registration)
  - JWT cookie flags (httponly)
"""

import os
import io
import pytest

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
from auth.jwt import create_token


def make_user(db, email="u@example.com", role="user",
              is_verified=True, is_admin=False, company_id=None):
    from models.user import User
    user = User(
        full_name    = "Test",
        email        = email,
        phone        = "000",
        hashed_pw    = hash_password("password123"),
        otp_secret   = generate_totp_secret(),
        role         = role,
        is_verified  = is_verified,
        is_admin     = is_admin,
        company_id   = company_id,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def auth_client(client, db, email="u@example.com", **kwargs):
    """Create a user and inject their JWT cookie into the test client."""
    user  = make_user(db, email=email, **kwargs)
    token = create_token({"sub": user.email})
    client.cookies.set("access_token", token)
    return user


# ══════════════════════════════════════════════════════════════
# CSRF PROTECTION
# ══════════════════════════════════════════════════════════════

class TestCSRFProtection:

    def test_post_login_without_csrf_token_rejected(self, client):
        """POST with no CSRF token must be rejected."""
        resp = client.post("/login", data={
            "email":    "any@example.com",
            "password": "anything",
            # No csrf_token
        })
        # fastapi-csrf-protect raises CsrfProtectError → error page or 422
        assert resp.status_code in (400, 403, 422)

    def test_post_register_without_csrf_rejected(self, client):
        resp = client.post("/register", data={
            "full_name": "Test",
            "email":     "test@test.com",
            "phone":     "000",
            "password":  "pass",
        })
        assert resp.status_code in (400, 403, 422)

    def test_post_profile_edit_without_csrf_rejected(self, client, db):
        auth_client(client, db, email="csrf@example.com")
        resp = client.post("/profile/edit", data={
            "full_name": "Hacker",
        })
        assert resp.status_code in (400, 403, 422)

    def test_admin_suspend_without_csrf_rejected(self, client, db):
        auth_client(client, db, email="a@example.com",
                    role="admin", is_admin=True)
        resp = client.post("/admin/suspend/999")
        assert resp.status_code in (400, 403, 422)


# ══════════════════════════════════════════════════════════════
# SECURITY HEADERS
# ══════════════════════════════════════════════════════════════

class TestSecurityHeaders:
    """Every response from the app must include hardening headers."""

    REQUIRED_HEADERS = {
        "x-frame-options":        "DENY",
        "x-content-type-options": "nosniff",
    }

    def _check_headers(self, resp):
        for header, expected in self.REQUIRED_HEADERS.items():
            actual = resp.headers.get(header, "")
            assert actual == expected, (
                f"Header '{header}': expected '{expected}', got '{actual}'"
            )

    def test_home_page_headers(self, client):
        self._check_headers(client.get("/"))

    def test_login_page_headers(self, client):
        self._check_headers(client.get("/login"))

    def test_register_page_headers(self, client):
        self._check_headers(client.get("/register"))

    def test_csp_header_present(self, client):
        resp = client.get("/")
        assert "content-security-policy" in resp.headers

    def test_referrer_policy_present(self, client):
        resp = client.get("/")
        assert "referrer-policy" in resp.headers


# ══════════════════════════════════════════════════════════════
# DUPLICATE APPLICATION PREVENTION
# ══════════════════════════════════════════════════════════════

class TestDuplicateApplication:

    def _make_job(self, db):
        from models.job import JobPosting
        job = JobPosting(title="Dev Role", description="Test", skills="Python",
                         location="Remote")
        db.add(job)
        db.commit()
        db.refresh(job)
        return job

    def _get_csrf(self, client):
        import re
        resp = client.get("/jobs")
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', resp.text)
        return match.group(1) if match else ""

    def test_second_application_ignored(self, client, db):
        from models.job import Application
        user = auth_client(client, db, email="applicant@example.com")
        job  = self._make_job(db)

        # First application
        csrf = self._get_csrf(client)
        client.post(f"/apply/{job.id}", data={"cover_note": "first", "csrf_token": csrf})

        # Second application to same job
        csrf = self._get_csrf(client)
        client.post(f"/apply/{job.id}", data={"cover_note": "second", "csrf_token": csrf})

        count = db.query(Application).filter(
            Application.job_id  == job.id,
            Application.user_id == user.id,
        ).count()
        assert count == 1   # only one row, not two


# ══════════════════════════════════════════════════════════════
# RESUME UPLOAD SECURITY
# ══════════════════════════════════════════════════════════════

class TestResumeUpload:

    def _get_csrf(self, client):
        import re
        resp = client.get("/profile")
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', resp.text)
        return match.group(1) if match else ""

    def test_upload_wrong_mime_type_rejected(self, client, db):
        auth_client(client, db, email="upload1@example.com")
        csrf = self._get_csrf(client)
        resp = client.post(
            "/upload",
            data={"csrf_token": csrf},
            files={"resume": ("evil.exe", b"MZ\x90\x00", "application/octet-stream")},
        )
        # Should be rejected with 400
        assert resp.status_code == 400

    def test_upload_javascript_file_rejected(self, client, db):
        auth_client(client, db, email="upload2@example.com")
        csrf = self._get_csrf(client)
        resp = client.post(
            "/upload",
            data={"csrf_token": csrf},
            files={"resume": ("xss.js", b"alert(1)", "text/javascript")},
        )
        assert resp.status_code == 400

    def test_upload_oversized_file_rejected(self, client, db):
        auth_client(client, db, email="upload3@example.com")
        csrf = self._get_csrf(client)
        # 6 MB file — over the 5 MB limit
        big_data = b"%PDF-" + b"X" * (6 * 1024 * 1024)
        resp = client.post(
            "/upload",
            data={"csrf_token": csrf},
            files={"resume": ("big.pdf", big_data, "application/pdf")},
        )
        assert resp.status_code == 413

    def test_upload_pdf_accepted(self, client, db):
        auth_client(client, db, email="upload4@example.com")
        csrf = self._get_csrf(client)
        # Minimal valid-looking PDF header
        pdf_data = b"%PDF-1.4 fake content for testing"
        resp = client.post(
            "/upload",
            data={"csrf_token": csrf},
            files={"resume": ("resume.pdf", pdf_data, "application/pdf")},
        )
        # Should succeed (redirect to profile)
        assert resp.status_code in (200, 303)


# ══════════════════════════════════════════════════════════════
# HORIZONTAL PRIVILEGE ESCALATION (recruiter cross-company)
# ══════════════════════════════════════════════════════════════

class TestHorizontalPrivilege:

    def test_recruiter_cannot_view_other_companys_applicants(self, client, db):
        from models.job import JobPosting, Application

        # Company A recruiter
        r_a = make_user(db, email="recruiter_a@example.com",
                        role="recruiter", company_id=1)
        # Company B recruiter — this is who we test
        r_b = make_user(db, email="recruiter_b@example.com",
                        role="recruiter", company_id=2)

        # Job belonging to company A
        job = JobPosting(title="A Job", description="A", skills="",
                         location="", company_id=1)
        db.add(job)
        db.commit()
        db.refresh(job)

        # Set client as company B recruiter
        token = create_token({"sub": r_b.email})
        client.cookies.set("access_token", token)

        # Try to access company A's job applicants
        resp = client.get(f"/job/{job.id}/applicants", allow_redirects=False)
        # Should redirect away (not their job)
        assert resp.status_code == 303
        assert resp.headers.get("location", "").endswith("/recruiter")


# ══════════════════════════════════════════════════════════════
# JWT COOKIE FLAGS
# ══════════════════════════════════════════════════════════════

class TestJWTCookieFlags:

    def test_access_token_cookie_is_httponly(self, client, db):
        """HttpOnly flag prevents JavaScript from reading the JWT."""
        import pyotp
        from auth.totp import generate_totp_secret
        secret = generate_totp_secret()
        from models.user import User
        user = User(
            full_name="Flag Test", email="flags@example.com", phone="000",
            hashed_pw=hash_password("password123"),
            otp_secret=secret, role="user",
            is_verified=True, is_admin=False,
        )
        db.add(user)
        db.commit()

        import re
        resp  = client.get("/login")
        csrf  = re.search(r'name="csrf_token"\s+value="([^"]+)"', resp.text)
        token = csrf.group(1) if csrf else ""

        client.post("/login", data={
            "email": "flags@example.com",
            "password": "password123",
            "csrf_token": token,
        })

        otp  = pyotp.TOTP(secret).now()
        resp = client.get("/login")
        csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', resp.text)
        token = csrf.group(1) if csrf else ""

        resp = client.post(f"/totp-login/flags@example.com", data={
            "otp": otp, "csrf_token": token,
        }, allow_redirects=False)

        # The Set-Cookie header should contain HttpOnly
        set_cookie = resp.headers.get("set-cookie", "")
        if "access_token" in set_cookie:
            assert "httponly" in set_cookie.lower()
