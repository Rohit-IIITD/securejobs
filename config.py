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
DB_URL = os.environ["DATABASE_URL"]
# ── Gmail SMTP ────────────────────────────────────────────────
SMTP_EMAIL        = os.environ["SMTP_EMAIL"]
SMTP_APP_PASSWORD = os.environ["SMTP_APP_PASSWORD"]

# ── Admin seed ────────────────────────────────────────────────
ADMIN_EMAIL    = os.environ.get("ADMIN_EMAIL",    "admin@portal.com")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

# ── File storage ──────────────────────────────────────────────
RESUME_DIR = "encrypted_resumes"


from fastapi_csrf_protect import CsrfProtect
from pydantic import BaseModel

class CsrfSettings(BaseModel):
    secret_key: str = SECRET_KEY
    token_location: str = "body"
    token_key: str = "csrf_token"

@CsrfProtect.load_config
def get_csrf_config():
    return CsrfSettings()