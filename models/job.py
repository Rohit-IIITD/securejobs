"""
models/job.py — SecureJobs
============================
All SQLAlchemy models: Company, JobPosting, Application,
Conversation, ConversationParticipant, Message, AuditLog.
"""
 
from datetime import datetime
 
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from database import Base
 
 
class Company(Base):
    __tablename__ = "companies"
 
    id         = Column(Integer, primary_key=True, index=True)
    name       = Column(String(200), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
 
 
class JobPosting(Base):
    __tablename__ = "job_postings"
 
    id          = Column(Integer, primary_key=True, index=True)
    title       = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    skills      = Column(Text, nullable=True)
    location    = Column(String(120), nullable=True)
    company_id  = Column(Integer, ForeignKey("companies.id"), nullable=True)
    created_at  = Column(DateTime, default=datetime.utcnow)
 
 
class Application(Base):
    __tablename__ = "applications"
 
    id         = Column(Integer, primary_key=True, index=True)
    job_id     = Column(Integer, ForeignKey("job_postings.id"), nullable=False)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=False)
    cover_note = Column(Text, nullable=True)
    status     = Column(String(30), default="Applied")
    created_at = Column(DateTime, default=datetime.utcnow)
 
 
class Conversation(Base):
    __tablename__ = "conversations"
 
    id         = Column(Integer, primary_key=True, index=True)
    is_group   = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
 
 
class ConversationParticipant(Base):
    __tablename__ = "conversation_participants"
 
    id              = Column(Integer, primary_key=True, index=True)
    conversation_id = Column(Integer, ForeignKey("conversations.id"), nullable=False)
    user_id         = Column(Integer, ForeignKey("users.id"), nullable=False)
 
 
class Message(Base):
    __tablename__ = "messages"
 
    id              = Column(Integer, primary_key=True, index=True)
    conversation_id = Column(Integer, ForeignKey("conversations.id"), nullable=False)
    sender_id       = Column(Integer, ForeignKey("users.id"), nullable=False)
    ciphertext      = Column(Text, nullable=False)
    sent_at         = Column(DateTime, default=datetime.utcnow)
 
 
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
 