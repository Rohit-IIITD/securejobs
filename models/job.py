"""
models/job.py — SecureJobs
============================
JobPosting and Application SQLAlchemy models.
"""
 
from datetime import datetime
 
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from database import Base
 
 
class JobPosting(Base):
    __tablename__ = "job_postings"
 
    id          = Column(Integer, primary_key=True, index=True)
    title       = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    skills      = Column(Text, nullable=True)
    location    = Column(String(120), nullable=True)
    company_id  = Column(Integer, nullable=True)
    created_at  = Column(DateTime, default=datetime.utcnow)
 
 
class Application(Base):
    __tablename__ = "applications"
 
    id         = Column(Integer, primary_key=True, index=True)
    job_id     = Column(Integer, ForeignKey("job_postings.id"), nullable=False)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=False)
    cover_note = Column(Text, nullable=True)
    status     = Column(String(30), default="Applied")
    created_at = Column(DateTime, default=datetime.utcnow)