"""
tests/test_audit.py — SecureJobs
===================================
Tests for the tamper-evident audit log system.

Covers:
  - log_action() writes rows correctly
  - Hash chain is maintained across multiple rows
  - verify_chain() passes on a clean chain
  - verify_chain() detects a modified row (hash tamper)
  - verify_chain() detects a PKI signature violation
  - verify_chain() counts unsigned (pre-PKI) rows correctly
"""

import hashlib
import os
import pytest

os.environ.setdefault("SECRET_KEY",   "test-secret-key-32-bytes-padding!")
os.environ.setdefault("AES_KEY",      "test-aes-key-32-bytes-padding!!!")
os.environ.setdefault("MESSAGE_KEY",  "test-msg-key-32-bytes-padding!!!")
os.environ.setdefault("DB_USER",      "test")
os.environ.setdefault("DB_PASSWORD",  "test")
os.environ.setdefault("DB_HOST",      "localhost")
os.environ.setdefault("DB_NAME",      "test")
os.environ.setdefault("SMTP_EMAIL",   "test@test.com")
os.environ.setdefault("SMTP_APP_PASSWORD", "fake")

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from database import Base

# Use a separate in-memory DB for audit tests so they don't
# interfere with the conftest.py session DB.
_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
_Session = sessionmaker(bind=_engine)


@pytest.fixture(autouse=True)
def fresh_db():
    """Create tables, yield a session, drop everything after each test."""
    Base.metadata.create_all(bind=_engine)
    session = _Session()
    yield session
    session.close()
    Base.metadata.drop_all(bind=_engine)


# ══════════════════════════════════════════════════════════════
# log_action() basic behaviour
# ══════════════════════════════════════════════════════════════

class TestLogAction:

    def test_row_is_inserted(self, fresh_db):
        from services.audit_service import log_action
        log_action(fresh_db, actor_id=1, action="TEST", target="x", detail="y")
        count = fresh_db.execute(text("SELECT COUNT(*) FROM audit_logs")).scalar()
        assert count == 1

    def test_row_fields_correct(self, fresh_db):
        from services.audit_service import log_action
        log_action(fresh_db, actor_id=42, action="LOGIN_SUCCESS",
                   target="user:42", detail="ok")
        row = fresh_db.execute(text(
            "SELECT actor_id, action, target, detail FROM audit_logs LIMIT 1"
        )).fetchone()
        assert row[0] == 42
        assert row[1] == "LOGIN_SUCCESS"
        assert row[2] == "user:42"
        assert row[3] == "ok"

    def test_first_row_prev_hash_is_empty(self, fresh_db):
        from services.audit_service import log_action
        log_action(fresh_db, actor_id=1, action="FIRST", target="", detail="")
        row = fresh_db.execute(text(
            "SELECT prev_hash FROM audit_logs LIMIT 1"
        )).fetchone()
        assert row[0] == ""

    def test_second_row_prev_hash_matches_first_row_hash(self, fresh_db):
        from services.audit_service import log_action
        log_action(fresh_db, actor_id=1, action="FIRST",  target="", detail="")
        log_action(fresh_db, actor_id=1, action="SECOND", target="", detail="")
        rows = fresh_db.execute(text(
            "SELECT row_hash, prev_hash FROM audit_logs ORDER BY id ASC"
        )).fetchall()
        first_hash  = rows[0][0]
        second_prev = rows[1][1]
        assert first_hash == second_prev

    def test_row_hash_is_sha256(self, fresh_db):
        from services.audit_service import log_action
        log_action(fresh_db, actor_id=1, action="ACT", target="t", detail="d")
        row = fresh_db.execute(text(
            "SELECT row_hash FROM audit_logs LIMIT 1"
        )).fetchone()
        # SHA-256 hex digest is exactly 64 characters
        assert len(row[0]) == 64

    def test_row_signature_stored(self, fresh_db):
        from services.audit_service import log_action
        log_action(fresh_db, actor_id=1, action="SIGNED", target="", detail="")
        row = fresh_db.execute(text(
            "SELECT row_signature FROM audit_logs LIMIT 1"
        )).fetchone()
        # Signature should be a non-empty hex string
        assert row[0] != ""
        int(row[0], 16)   # valid hex


# ══════════════════════════════════════════════════════════════
# verify_chain() on a clean chain
# ══════════════════════════════════════════════════════════════

class TestVerifyChainClean:

    def test_empty_db_passes(self, fresh_db):
        from services.audit_service import verify_chain
        result = verify_chain(fresh_db)
        assert result["total"]         == 0
        assert result["hash_ok"]       is True
        assert result["signatures_ok"] is True

    def test_single_row_passes(self, fresh_db):
        from services.audit_service import log_action, verify_chain
        log_action(fresh_db, actor_id=1, action="A", target="", detail="")
        result = verify_chain(fresh_db)
        assert result["total"]         == 1
        assert result["hash_ok"]       is True
        assert result["signatures_ok"] is True
        assert result["first_bad_hash"] is None
        assert result["first_bad_sig"]  is None

    def test_five_rows_all_pass(self, fresh_db):
        from services.audit_service import log_action, verify_chain
        for i in range(5):
            log_action(fresh_db, actor_id=i, action=f"ACTION_{i}",
                       target=f"t{i}", detail=f"d{i}")
        result = verify_chain(fresh_db)
        assert result["total"]         == 5
        assert result["hash_ok"]       is True
        assert result["signatures_ok"] is True


# ══════════════════════════════════════════════════════════════
# verify_chain() tamper detection
# ══════════════════════════════════════════════════════════════

class TestVerifyChainTampered:

    def test_modified_detail_breaks_hash_chain(self, fresh_db):
        from services.audit_service import log_action, verify_chain
        log_action(fresh_db, actor_id=1, action="A", target="t", detail="original")
        log_action(fresh_db, actor_id=1, action="B", target="t", detail="ok")

        # Directly tamper with the first row's detail in the DB
        first_id = fresh_db.execute(text(
            "SELECT id FROM audit_logs ORDER BY id ASC LIMIT 1"
        )).scalar()
        fresh_db.execute(text(
            "UPDATE audit_logs SET detail='TAMPERED' WHERE id=:id"
        ), {"id": first_id})
        fresh_db.commit()

        result = verify_chain(fresh_db)
        assert result["hash_ok"]       is False
        assert result["first_bad_hash"] == first_id

    def test_modified_detail_breaks_pki_signature(self, fresh_db):
        from services.audit_service import log_action, verify_chain
        log_action(fresh_db, actor_id=1, action="A", target="t", detail="original")

        first_id = fresh_db.execute(text(
            "SELECT id FROM audit_logs ORDER BY id ASC LIMIT 1"
        )).scalar()
        # Tamper with detail but leave row_hash and row_signature unchanged
        fresh_db.execute(text(
            "UPDATE audit_logs SET detail='TAMPERED' WHERE id=:id"
        ), {"id": first_id})
        fresh_db.commit()

        result = verify_chain(fresh_db)
        # PKI signature should also fail (signed the original detail)
        assert result["signatures_ok"] is False
        assert result["first_bad_sig"] == first_id

    def test_forged_row_hash_detected(self, fresh_db):
        from services.audit_service import log_action, verify_chain
        log_action(fresh_db, actor_id=1, action="A", target="t", detail="d")

        first_id = fresh_db.execute(text(
            "SELECT id FROM audit_logs ORDER BY id ASC LIMIT 1"
        )).scalar()
        # Replace row_hash with a plausible-looking but wrong hash
        fake_hash = hashlib.sha256(b"fake").hexdigest()
        fresh_db.execute(text(
            "UPDATE audit_logs SET row_hash=:h WHERE id=:id"
        ), {"h": fake_hash, "id": first_id})
        fresh_db.commit()

        result = verify_chain(fresh_db)
        assert result["hash_ok"]       is False

    def test_unsigned_rows_counted_not_flagged(self, fresh_db):
        """Pre-PKI rows with empty row_signature should be counted but not fail."""
        from services.audit_service import log_action, verify_chain
        log_action(fresh_db, actor_id=1, action="A", target="", detail="")

        # Simulate a pre-PKI row by clearing the signature
        fresh_db.execute(text(
            "UPDATE audit_logs SET row_signature='' WHERE 1=1"
        ))
        fresh_db.commit()

        result = verify_chain(fresh_db)
        assert result["unsigned_rows"]  == 1
        assert result["signatures_ok"]  is True   # unsigned ≠ invalid
