"""
services/seed.py — SecureJobs
================================
One-time admin user seeding.  Called once from main.py at startup.
Extracted here so main.py contains zero business logic.
"""

import logging

from database import SessionLocal
from models.user import User
from auth.password import hash_password
from auth.totp import generate_totp_secret
from config import ADMIN_EMAIL, ADMIN_PASSWORD

logger = logging.getLogger(__name__)


def seed_admin() -> None:
    """
    If no user with ADMIN_EMAIL exists, create the admin account and
    log its TOTP secret so it can be added to an authenticator app.
    Safe to call on every startup — idempotent.
    """
    db    = SessionLocal()
    try:
        admin = db.query(User).filter(User.email == ADMIN_EMAIL).first()
        if not admin:
            secret = generate_totp_secret()
            logger.info("🔐 ADMIN TOTP SECRET: %s", secret)
            logger.info("👉 Add this to Google Authenticator manually")
            admin = User(
                full_name    = "Admin",
                email        = ADMIN_EMAIL,
                phone        = "0000000000",
                hashed_pw    = hash_password(ADMIN_PASSWORD),
                otp_secret   = secret,
                is_verified  = True,
                is_admin     = True,
                role         = "admin",
            )
            db.add(admin)
            db.commit()
    finally:
        db.close()
