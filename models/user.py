"""
models/user.py — SecureJobs
============================
User and EmailOTP SQLAlchemy models.
"""
 
from datetime import datetime
 
from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text
from database import Base
 
 
class User(Base):
    __tablename__ = "users"
 
    id               = Column(Integer, primary_key=True, index=True)
    full_name        = Column(String(120), nullable=False)
    email            = Column(String(255), unique=True, index=True, nullable=False)
    phone            = Column(String(30), nullable=True)
    hashed_pw        = Column(String(255), nullable=False)
    otp_secret       = Column(String(64), nullable=True)
    role             = Column(String(20), default="user")
    is_verified      = Column(Boolean, default=False)
    is_admin         = Column(Boolean, default=False)
    is_suspended     = Column(Boolean, default=False)
    company_id       = Column(Integer, nullable=True)
    headline         = Column(String(160), nullable=True)
    bio              = Column(Text, nullable=True)
    location         = Column(String(120), nullable=True)
    resume_path      = Column(String(255), nullable=True)
    resume_signature = Column(Text, nullable=True)
    created_at       = Column(DateTime, default=datetime.utcnow)
 
 
class EmailOTP(Base):
    __tablename__ = "email_otps"
 
    id         = Column(Integer, primary_key=True, index=True)
    email      = Column(String(255), index=True, nullable=False)
    code       = Column(String(10), nullable=False)
    purpose    = Column(String(50), nullable=False)
    used       = Column(Boolean, default=False)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)