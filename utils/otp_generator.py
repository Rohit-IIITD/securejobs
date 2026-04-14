"""
utils/otp_generator.py — SecureJobs
======================================
Generate a secure 6-digit OTP code.
"""
 
import secrets
 
 
def generate_otp_code(length: int = 6) -> str:
    """Return a cryptographically secure numeric OTP string."""
    return "".join([str(secrets.randbelow(10)) for _ in range(length)])
 