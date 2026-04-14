"""
services/message_service.py — SecureJobs
==========================================
Conversation management: find or create a 1-to-1 conversation
between two users and return its ID.
"""

from sqlalchemy import text
from sqlalchemy.orm import Session


def get_or_create_conversation(db: Session, user1_id: int, user2_id: int) -> int:
    """
    Return the conversation ID for the 1-to-1 chat between
    *user1_id* and *user2_id*, creating one if it doesn't exist.
    Uses raw SQL via sqlalchemy.text() for SQLAlchemy 2.x compatibility.
    """
    row = db.execute(text("""
        SELECT c.id FROM conversations c
        JOIN conversation_participants p1 ON p1.conversation_id = c.id
        JOIN conversation_participants p2 ON p2.conversation_id = c.id
        WHERE p1.user_id = :u1 AND p2.user_id = :u2 AND c.is_group = FALSE
        LIMIT 1
    """), {"u1": user1_id, "u2": user2_id}).fetchone()

    if row:
        return row[0]

    result   = db.execute(
        text("INSERT INTO conversations (is_group) VALUES (FALSE) RETURNING id")
    )
    convo_id = result.fetchone()[0]

    db.execute(
        text("INSERT INTO conversation_participants (conversation_id, user_id) VALUES (:c, :u)"),
        {"c": convo_id, "u": user1_id},
    )
    db.execute(
        text("INSERT INTO conversation_participants (conversation_id, user_id) VALUES (:c, :u)"),
        {"c": convo_id, "u": user2_id},
    )
    db.commit()
    return convo_id
