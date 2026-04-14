"""
services/email_service.py — SecureJobs
========================================
All email-OTP business logic:
  - store_email_otp    — generate, persist, return code
  - send_email_otp     — SMTP delivery via Gmail
  - verify_email_otp   — validate code and mark used
"""

import logging
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText

from sqlalchemy.orm import Session

from config import SMTP_APP_PASSWORD, SMTP_EMAIL
from models.user import EmailOTP
from utils.otp_generator import generate_otp_code

logger = logging.getLogger(__name__)


def store_email_otp(db: Session, email: str, purpose: str) -> str:
    """
    Invalidate any previous unused codes for (email, purpose),
    persist a new 6-digit code, and return it.
    """
    # Invalidate old codes
    db.query(EmailOTP).filter(
        EmailOTP.email   == email,
        EmailOTP.purpose == purpose,
        EmailOTP.used    == False,   # noqa: E712
    ).delete()

    code = generate_otp_code()
    otp  = EmailOTP(
        email      = email,
        code       = code,
        purpose    = purpose,
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    db.add(otp)
    db.commit()
    return code


def send_email_otp(to_email: str, code: str, purpose: str) -> None:
    """Send *code* to *to_email* via Gmail SMTP (TLS on port 587)."""
    subject = "Your SecureJobs verification code"
    body    = (
        f"Your {purpose} verification code is:\n\n"
        f"  {code}\n\n"
        f"This code expires in 10 minutes. Do not share it with anyone."
    )
    msg            = MIMEText(body)
    msg["Subject"] = subject
    msg["From"]    = SMTP_EMAIL
    msg["To"]      = to_email

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.ehlo()
        server.starttls()
        server.login(SMTP_EMAIL, SMTP_APP_PASSWORD)
        server.sendmail(SMTP_EMAIL, to_email, msg.as_string())


def verify_email_otp(db: Session, email: str, code: str, purpose: str) -> bool:
    """
    Return True and mark the OTP used if the code is valid and
    unexpired; return False otherwise.
    """
    otp = db.query(EmailOTP).filter(
        EmailOTP.email   == email,
        EmailOTP.code    == code,
        EmailOTP.purpose == purpose,
        EmailOTP.used    == False,   # noqa: E712
    ).first()

    if not otp:
        return False
    if datetime.now(timezone.utc) > otp.expires_at.replace(tzinfo=timezone.utc):
        return False

    otp.used = True
    db.commit()
    return True
