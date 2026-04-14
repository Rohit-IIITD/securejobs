"""
services/audit_service.py — SecureJobs
========================================
Append an entry to the audit_logs table using a SHA-256 hash chain
so log tampering is detectable.
"""

import hashlib

from sqlalchemy import text
from sqlalchemy.orm import Session


def log_action(
    db:       Session,
    actor_id: int,
    action:   str,
    target:   str = "",
    detail:   str = "",
) -> None:
    """
    Append one audit-log row that chains off the previous row's hash.
    Call after any sensitive state change (suspend, delete, status update…).
    """
    last = db.execute(
        text("SELECT row_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
    ).fetchone()

    prev_hash = last[0] if last else ""

    raw      = f"{actor_id}|{action}|{target}|{detail}|{prev_hash}"
    row_hash = hashlib.sha256(raw.encode()).hexdigest()

    db.execute(text("""
        INSERT INTO audit_logs (actor_id, action, target, detail, prev_hash, row_hash)
        VALUES (:a, :act, :t, :d, :p, :r)
    """), {
        "a":   actor_id,
        "act": action,
        "t":   target,
        "d":   detail,
        "p":   prev_hash,
        "r":   row_hash,
    })
    db.commit()
