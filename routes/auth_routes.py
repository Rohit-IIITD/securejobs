"""
routes/auth_routes.py — SecureJobs
=====================================
Handles the full authentication lifecycle:
  GET/POST  /register
  GET/POST  /verify-email/{email}
  GET/POST  /setup-totp/{email}
  GET/POST  /login
  POST      /totp-login/{email}
  GET       /logout

AUDIT LOGGING added to:
  - Successful registration
  - Successful login (after TOTP)
  - Failed login attempts (wrong password, suspended, invalid OTP)
  - Logout
"""

import base64
import logging
from io import BytesIO

import qrcode
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi_csrf_protect import CsrfProtect
from sqlalchemy.orm import Session

from auth.jwt import create_token, get_current_user
from auth.password import hash_password, verify_password
from auth.totp import generate_totp_secret, get_totp_uri, verify_totp
from database import get_db
from models.user import User
from services.audit_service import log_action
from services.email_service import send_email_otp, store_email_otp, verify_email_otp
from utils.limiter import limiter
from utils.template_helpers import csrf_response

logger    = logging.getLogger(__name__)
router    = APIRouter()
templates = Jinja2Templates(directory="templates")


# ── Register ──────────────────────────────────────────────────

@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, csrf_protect: CsrfProtect = Depends()):
    return csrf_response(request, templates, "register.html", {}, csrf_protect)


@router.post("/register")
async def register(
    request:   Request,
    full_name: str = Form(...),
    email:     str = Form(...),
    phone:     str = Form(...),
    password:  str = Form(...),
    role:      str = Form("user"),
    db:        Session = Depends(get_db),
    csrf_protect: CsrfProtect = Depends(),
):
    await csrf_protect.validate_csrf(request)

    if db.query(User).filter(User.email == email).first():
        return RedirectResponse("/register?error=email_taken", status_code=303)

    if role not in ("user", "recruiter"):
        role = "user"

    secret = generate_totp_secret()
    user   = User(
        full_name  = full_name,
        email      = email,
        phone      = phone,
        hashed_pw  = hash_password(password),
        otp_secret = secret,
        role       = role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # ── AUDIT: new account created ────────────────────────────
    log_action(
        db,
        actor_id = user.id,
        action   = "REGISTER",
        target   = f"user:{user.id}",
        detail   = f"New {role} account registered with email {email}",
    )

    code = store_email_otp(db, email, "registration")
    try:
        send_email_otp(email, code, "registration")
    except Exception as exc:
        logger.error("SMTP error: %s", exc)
        logger.info("DEV — OTP for %s: %s", email, code)

    return RedirectResponse(f"/verify-email/{email}", status_code=303)


# ── Email OTP verification ────────────────────────────────────

@router.get("/verify-email/{email}", response_class=HTMLResponse)
async def verify_email_page(
    request: Request,
    email:   str,
    csrf_protect: CsrfProtect = Depends(),
):
    return csrf_response(
        request, templates, "verify_email.html", {"email": email}, csrf_protect
    )


@router.post("/verify-email/{email}")
async def verify_email(
    request: Request,
    email:   str,
    code:    str = Form(...),
    db:      Session = Depends(get_db),
    csrf_protect: CsrfProtect = Depends(),
):
    await csrf_protect.validate_csrf(request)

    if not verify_email_otp(db, email, code, "registration"):
        # ── AUDIT: failed email verification ─────────────────
        user = db.query(User).filter(User.email == email).first()
        if user:
            log_action(
                db,
                actor_id = user.id,
                action   = "EMAIL_VERIFY_FAIL",
                target   = f"user:{user.id}",
                detail   = f"Invalid or expired email OTP for {email}",
            )
        return RedirectResponse(f"/verify-email/{email}?error=invalid", status_code=303)

    user = db.query(User).filter(User.email == email).first()
    if user:
        user.is_verified = True
        db.commit()

        # ── AUDIT: email verified ─────────────────────────────
        log_action(
            db,
            actor_id = user.id,
            action   = "EMAIL_VERIFIED",
            target   = f"user:{user.id}",
            detail   = f"Email address verified for {email}",
        )

    return RedirectResponse(f"/setup-totp/{email}", status_code=303)


# ── TOTP setup (QR code scan) ─────────────────────────────────

@router.get("/setup-totp/{email}", response_class=HTMLResponse)
async def setup_totp_page(
    request: Request,
    email:   str,
    db:      Session = Depends(get_db),
    csrf_protect: CsrfProtect = Depends(),
):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return RedirectResponse("/register", status_code=303)

    totp_uri  = get_totp_uri(user.otp_secret, user.email)
    qr        = qrcode.make(totp_uri)
    buf       = BytesIO()
    qr.save(buf, format="PNG")
    qr_base64 = base64.b64encode(buf.getvalue()).decode()

    return csrf_response(
        request, templates, "verify.html",
        {"email": email, "qr": qr_base64},
        csrf_protect,
    )


@router.post("/setup-totp/{email}")
async def setup_totp(
    request: Request,
    email:   str,
    otp:     str = Form(...),
    db:      Session = Depends(get_db),
    csrf_protect: CsrfProtect = Depends(),
):
    await csrf_protect.validate_csrf(request)

    user = db.query(User).filter(User.email == email).first()
    if not user:
        return RedirectResponse("/register", status_code=303)

    if verify_totp(user.otp_secret, otp):
        # ── AUDIT: TOTP setup completed ───────────────────────
        log_action(
            db,
            actor_id = user.id,
            action   = "TOTP_SETUP_COMPLETE",
            target   = f"user:{user.id}",
            detail   = f"TOTP authenticator successfully configured for {email}",
        )
        return RedirectResponse("/login", status_code=303)

    # ── AUDIT: TOTP setup failed ──────────────────────────────
    log_action(
        db,
        actor_id = user.id,
        action   = "TOTP_SETUP_FAIL",
        target   = f"user:{user.id}",
        detail   = f"Invalid TOTP code during setup for {email}",
    )
    return RedirectResponse(f"/setup-totp/{email}?error=invalid_otp", status_code=303)


# ── Login (step 1 — credentials) ─────────────────────────────

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, csrf_protect: CsrfProtect = Depends()):
    return csrf_response(request, templates, "login.html", {}, csrf_protect)


@router.post("/login")
@limiter.limit("5/minute")          # max 5 login attempts per IP per minute
async def login(
    request:  Request,
    email:    str = Form(...),
    password: str = Form(...),
    db:       Session = Depends(get_db),
    csrf_protect: CsrfProtect = Depends(),
):
    await csrf_protect.validate_csrf(request)

    user = db.query(User).filter(User.email == email).first()

    if not user or not verify_password(password, user.hashed_pw):
        # ── AUDIT: wrong credentials ──────────────────────────
        # Use actor_id=0 (sentinel for "unknown user") so we
        # don't leak whether the email exists.
        log_action(
            db,
            actor_id = user.id if user else 0,
            action   = "LOGIN_FAIL_CREDENTIALS",
            target   = f"email:{email}",
            detail   = "Invalid email or password",
        )
        return RedirectResponse("/login?error=invalid_credentials", status_code=303)

    if user.is_suspended:
        # ── AUDIT: suspended user attempted login ─────────────
        log_action(
            db,
            actor_id = user.id,
            action   = "LOGIN_FAIL_SUSPENDED",
            target   = f"user:{user.id}",
            detail   = f"Login attempt by suspended account {email}",
        )
        return RedirectResponse("/login?error=suspended", status_code=303)

    if not user.is_verified:
        return RedirectResponse(f"/verify-email/{email}", status_code=303)

    # Credentials OK — proceed to TOTP step (no audit yet, not fully logged in)
    return csrf_response(
        request, templates, "totp_login.html", {"email": email}, csrf_protect
    )


# ── Login (step 2 — TOTP) ─────────────────────────────────────

@router.post("/totp-login/{email}")
@limiter.limit("5/minute")          # max 5 TOTP attempts per IP per minute
async def totp_login(
    request: Request,
    email:   str,
    otp:     str = Form(...),
    db:      Session = Depends(get_db),
    csrf_protect: CsrfProtect = Depends(),
):
    await csrf_protect.validate_csrf(request)

    user = db.query(User).filter(User.email == email).first()
    if not user:
        return RedirectResponse("/login", status_code=303)

    if verify_totp(user.otp_secret, otp):
        # ── AUDIT: successful login ───────────────────────────
        log_action(
            db,
            actor_id = user.id,
            action   = "LOGIN_SUCCESS",
            target   = f"user:{user.id}",
            detail   = f"Successful login for {email} (role={user.role})",
        )
        token = create_token({"sub": user.email})
        resp  = RedirectResponse("/profile", status_code=303)
        resp.set_cookie(
            "access_token",
            token,
            httponly = True,
            samesite = "strict",   # upgraded from "lax"
            secure   = True,       # SECURITY FIX: only send over HTTPS
        )
        return resp

    # ── AUDIT: wrong TOTP code ────────────────────────────────
    log_action(
        db,
        actor_id = user.id,
        action   = "LOGIN_FAIL_TOTP",
        target   = f"user:{user.id}",
        detail   = f"Invalid TOTP code at login for {email}",
    )
    return RedirectResponse("/login?error=invalid_otp", status_code=303)


# ── Logout ────────────────────────────────────────────────────

@router.get("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    # Best-effort audit — user may not be logged in
    user = get_current_user(request, db)
    if user:
        log_action(
            db,
            actor_id = user.id,
            action   = "LOGOUT",
            target   = f"user:{user.id}",
            detail   = f"User {user.email} logged out",
        )
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("access_token")
    return response
