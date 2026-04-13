"""
auth/guards.py — SecureJobs
============================
FastAPI-compatible guard functions.

require_authenticated_user  — injects the current User or redirects to /login
require_user                — raises 401 if not logged in
require_role                — raises 403 if wrong role
require_admin               — raises 403 if not admin
"""

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from auth.jwt import get_current_user
from database import get_db
from models.user import User


# ── FastAPI Depends-compatible dependency ─────────────────────

def require_authenticated_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    """
    Inject as a FastAPI dependency to protect routes that need a
    logged-in user.  Raises HTTP 401 if no valid session exists.

    For redirect-on-failure (HTML routes) call get_current_user()
    manually and redirect — this guard is for API-style 401s.
    """
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


# ── Imperative guards (called inside route handlers) ──────────

def require_user(user: User | None) -> None:
    """Raise 401 if user is None."""
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")


def require_role(user: User | None, role: str) -> None:
    """Raise 403 if user is None or has the wrong role."""
    if not user or user.role != role:
        raise HTTPException(status_code=403, detail="Forbidden")


def require_admin(user: User | None) -> None:
    """Raise 403 if user is None or is not an admin."""
    if not user or user.role != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
