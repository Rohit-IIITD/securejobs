"""
models/job.py — SecureJobs
===========================
Job-domain models: Company, JobPosting, Application,
Conversation, ConversationParticipant, Message, AuditLog.
Only imports Base from database — no circular dependencies.

Fixes applied:
  - Company: added description, location, website columns
  - JobPosting: deadline changed from DateTime → Date
  - Message: added conversation_id, sender_id columns
  - Conversation: new model (was missing entirely)
  - ConversationParticipant: new model (was missing entirely)
"""

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, Date, DateTime, Integer, String, Text

from database import Base


class Company(Base):
    __tablename__ = "companies"

    id          = Column(Integer, primary_key=True)
    name        = Column(String(120))
    description = Column(Text,        default="")      # FIX: was missing
    location    = Column(String(120), default="")      # FIX: was missing
    website     = Column(String(255), default="")      # FIX: was missing
    owner_id    = Column(Integer)
    created_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class JobPosting(Base):
    __tablename__ = "job_postings"

    id          = Column(Integer, primary_key=True)
    company_id  = Column(Integer)
    title       = Column(String(160))
    description = Column(Text)
    skills      = Column(Text)
    location    = Column(String(120))
    is_remote   = Column(Boolean, default=False)
    salary_min  = Column(Integer)
    salary_max  = Column(Integer)
    job_type    = Column(String(30))
    deadline    = Column(Date)                         # FIX: was DateTime, schema says DATE
    created_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Application(Base):
    __tablename__ = "applications"

    id              = Column(Integer, primary_key=True)
    job_id          = Column(Integer)
    user_id         = Column(Integer)
    cover_note      = Column(Text)
    status          = Column(String(20), default="Applied")
    recruiter_notes = Column(Text)
    applied_at      = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Conversation(Base):                              # FIX: was missing entirely
    __tablename__ = "conversations"

    id         = Column(Integer, primary_key=True)
    is_group   = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ConversationParticipant(Base):                   # FIX: was missing entirely
    __tablename__ = "conversation_participants"

    id              = Column(Integer, primary_key=True)
    conversation_id = Column(Integer)
    user_id         = Column(Integer)


class Message(Base):
    __tablename__ = "messages"

    id              = Column(Integer, primary_key=True)
    conversation_id = Column(Integer)                  # FIX: was missing
    sender_id       = Column(Integer)                  # FIX: was missing
    ciphertext      = Column(Text)
    sent_at         = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id        = Column(Integer, primary_key=True)
    actor_id  = Column(Integer)
    action    = Column(String(80))
    target    = Column(String(120))
    detail    = Column(Text)
    prev_hash = Column(String(64))
    row_hash  = Column(String(64))
    logged_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
