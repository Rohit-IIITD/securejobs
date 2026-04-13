"""
auth/jwt.py — SecureJobs
=========================
JWT token creation and decoding.
get_current_user() reads the cookie set at login and returns the
User ORM object, or None if the token is missing/invalid/expired.
"""

from datetime import datetime, timedelta, timezone

from fastapi import Request
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from config import ALGORITHM, SECRET_KEY
from models.user import User


def create_token(data: dict) -> str:
    """Create a signed JWT that expires in 60 minutes."""
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(minutes=60)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(request: Request, db: Session) -> User | None:
    """
    Extract the JWT from the 'access_token' cookie and return the
    corresponding User, or None if absent / invalid / expired.
    """
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            return None
        return db.query(User).filter(User.email == email).first()
    except (JWTError, Exception):
        return None
