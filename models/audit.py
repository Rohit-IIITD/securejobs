"""
models/audit.py — SecureJobs
==============================
AuditLog SQLAlchemy model.
"""
 
from datetime import datetime
 
from sqlalchemy import Column, DateTime, Integer, String, Text
from database import Base
 
 
class AuditLog(Base):
    __tablename__ = "audit_logs"
 
    id            = Column(Integer, primary_key=True, index=True)
    actor_id      = Column(Integer, nullable=False)
    action        = Column(String(80), nullable=False)
    target        = Column(String(120), nullable=True)
    detail        = Column(Text, nullable=True)
    prev_hash     = Column(String(64), nullable=True)
    row_hash      = Column(String(64), nullable=True)
    row_signature = Column(Text, nullable=True)
    logged_at     = Column(DateTime, default=datetime.utcnow)