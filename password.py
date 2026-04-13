"""
auth/password.py — SecureJobs
==============================
Thin wrappers around bcrypt so the rest of the codebase never
imports bcrypt directly. Swap the hashing library here only.
"""

import bcrypt


def hash_password(plain: str) -> str:
    """Return a bcrypt hash of *plain* as a UTF-8 string."""
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if *plain* matches *hashed*."""
    return bcrypt.checkpw(plain.encode(), hashed.encode())
