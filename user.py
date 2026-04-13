"""
models/user.py — SecureJobs
============================
Auth-domain models: User and EmailOTP.
Only imports Base from database — no circular dependencies.
"""

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text

from database import Base


class User(Base):
    __tablename__ = "users"

    id        = Column(Integer, primary_key=True)
    full_name = Column(String(120), nullable=False)
    email     = Column(String(254), unique=True, nullable=False)
    phone     = Column(String(20))
    role      = Column(String(20), default="user")   # user | recruiter | admin
    is_admin  = Column(Boolean, default=False)
    hashed_pw = Column(Text, nullable=False)
    otp_secret = Column(String(64))

    # editable profile fields
    headline  = Column(String(160), default="")
    bio       = Column(Text, default="")
    location  = Column(String(120), default="")

    # flags
    is_verified  = Column(Boolean, default=False)
    is_suspended = Column(Boolean, default=False)

    # ownership — set when a recruiter belongs to a company
    company_id = Column(Integer)

    resume_path = Column(String(255), default="")
    created_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class EmailOTP(Base):
    __tablename__ = "email_otps"

    id         = Column(Integer, primary_key=True)
    email      = Column(String(254), nullable=False, index=True)
    code       = Column(String(10),  nullable=False)
    purpose    = Column(String(40),  nullable=False)   # e.g. 'registration'
    expires_at = Column(DateTime,    nullable=False)
    used       = Column(Boolean,     default=False)
    created_at = Column(DateTime,    default=lambda: datetime.now(timezone.utc))
