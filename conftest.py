"""
tests/conftest.py — SecureJobs
================================
Shared pytest fixtures available to every test file.

HOW TO RUN ALL TESTS:
    pip install pytest pytest-asyncio httpx
    pytest tests/ -v

FIXTURE HIERARCHY:
    engine (session-scoped) — in-memory SQLite DB created once per session
    db     (function-scoped) — fresh transaction rolled back after each test
    client (function-scoped) — FastAPI TestClient with the test DB injected

WHY SQLite FOR TESTS:
    - No PostgreSQL server needed to run tests
    - In-memory → tests are fast and isolated
    - SQLAlchemy ORM works identically on both
    - The only difference: SQLite doesn't support TIMESTAMPTZ;
      we use DateTime which works fine for unit tests
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# ── Override DB before importing app ──────────────────────────
# We patch get_db() to use our test DB instead of PostgreSQL.
TEST_DB_URL = "sqlite:///./test_securejobs.db"

from database import Base, get_db
from main import app

test_engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},  # required for SQLite
)
TestSessionLocal = sessionmaker(bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def create_tables():
    """Create all tables once before any test runs."""
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture()
def db():
    """
    Provide a DB session that is rolled back after each test.
    This keeps tests independent — no test pollutes another's data.
    """
    connection = test_engine.connect()
    transaction = connection.begin()
    session = TestSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture()
def client(db):
    """
    FastAPI TestClient with get_db() overridden to use the test DB.
    Cookies persist across requests within one test (like a real browser).
    """
    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()
