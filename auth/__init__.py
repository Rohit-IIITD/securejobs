"""
models/__init__.py — SecureJobs
================================
Re-exports every model so Base.metadata.create_all() sees all tables.
"""

from models.user import User, EmailOTP                          # noqa: F401
from models.job  import (                                       # noqa: F401
    Company, JobPosting, Application,
    Conversation, ConversationParticipant,                      # FIX: added
    Message, AuditLog,
)
