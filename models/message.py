"""
models/message.py — SecureJobs
================================
Conversation and Message SQLAlchemy models.
"""
 
from datetime import datetime
 
from sqlalchemy import Column, DateTime, Integer, Text
from database import Base
 
 
class Conversation(Base):
    __tablename__ = "conversations"
 
    id         = Column(Integer, primary_key=True, index=True)
    user1_id   = Column(Integer, nullable=False)
    user2_id   = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
 
 
class Message(Base):
    __tablename__ = "messages"
 
    id              = Column(Integer, primary_key=True, index=True)
    conversation_id = Column(Integer, nullable=False)
    sender_id       = Column(Integer, nullable=False)
    ciphertext      = Column(Text, nullable=False)
    sent_at         = Column(DateTime, default=datetime.utcnow)
 