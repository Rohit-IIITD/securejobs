"""
database.py — SecureJobs
========================
Database engine, session factory, declarative base, and the
FastAPI-compatible get_db() dependency.

Import order that avoids circular imports:
    config  ←  database  ←  models  ←  services  ←  routes  ←  main
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from config import DB_URL

# ── Engine ────────────────────────────────────────────────────
engine = create_engine(DB_URL, pool_pre_ping=True)

# ── Session factory ───────────────────────────────────────────
SessionLocal = sessionmaker(bind=engine)

# ── Declarative base ──────────────────────────────────────────
# All SQLAlchemy model classes inherit from this Base.
Base = declarative_base()


# ── FastAPI dependency ────────────────────────────────────────
def get_db():
    """
    Yield a DB session for the duration of one request, then close it.
    Always inject via Depends(get_db) — never call SessionLocal() directly.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
