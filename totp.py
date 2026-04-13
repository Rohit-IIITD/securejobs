"""
auth/totp.py — SecureJobs
==========================
Thin wrappers around pyotp so TOTP logic is isolated in one place.
"""

import pyotp


def generate_totp_secret() -> str:
    """Generate a fresh base-32 TOTP secret."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, email: str, issuer: str = "SecureJobs") -> str:
    """Return the otpauth:// URI for QR-code generation."""
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)


def verify_totp(secret: str, otp: str, valid_window: int = 1) -> bool:
    """Return True if *otp* is valid for the current time window."""
    return pyotp.TOTP(secret).verify(otp, valid_window=valid_window)
