"""
config.py — SecureJobs
======================
Single source of truth for every environment variable and constant.
All other modules import from here. Nothing is hard-coded.
"""

import os
from dotenv import load_dotenv

load_dotenv()   # reads .env from the working directory

# ── JWT ───────────────────────────────────────────────────────
SECRET_KEY = os.environ["SECRET_KEY"]
ALGORITHM  = "HS256"

# ── AES-256-GCM (resume encryption) ──────────────────────────
AES_KEY = os.environ["AES_KEY"].encode()[:32]   # exactly 32 bytes

# ── AES-256-GCM (message encryption) ─────────────────────────
MESSAGE_KEY = os.environ["MESSAGE_KEY"].encode()

# ── PostgreSQL ────────────────────────────────────────────────
# ── PostgreSQL ────────────────────────────────────────────────
DB_URL = os.environ["postgresql://securejobs_db_user:fjP03twMMMZ3e2LAJSOytVUC13ltn2xf@dpg-d7eicilckfvc73a7qmhg-a/securejobs_db"]
# ── Gmail SMTP ────────────────────────────────────────────────
SMTP_EMAIL        = os.environ["SMTP_EMAIL"]
SMTP_APP_PASSWORD = os.environ["SMTP_APP_PASSWORD"]

# ── Admin seed ────────────────────────────────────────────────
ADMIN_EMAIL    = os.environ.get("ADMIN_EMAIL",    "admin@portal.com")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

# ── File storage ──────────────────────────────────────────────
RESUME_DIR = "encrypted_resumes"
