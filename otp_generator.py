"""
utils/otp_generator.py — SecureJobs
=====================================
Pure utility: generate a numeric OTP code.
No DB, no network, no side effects — trivially unit-testable.

SECURITY FIX: Replaced `random` (pseudo-random, NOT cryptographically secure)
with `secrets` (cryptographically secure, uses OS entropy source /dev/urandom).

Why this matters:
  - `random.choices()` uses a Mersenne Twister PRNG seeded from system time.
    An attacker who observes enough OTP outputs could reconstruct the seed
    and predict future codes.
  - `secrets.choice()` pulls from /dev/urandom (Linux) which is cryptographically
    unpredictable and cannot be reverse-engineered from observed outputs.
"""

import secrets
import string


def generate_otp_code(length: int = 6) -> str:
    """
    Return a cryptographically secure random string of *length* decimal digits.
    Uses secrets.choice() which draws from the OS CSPRNG (/dev/urandom).
    """
    return "".join(secrets.choice(string.digits) for _ in range(length))
