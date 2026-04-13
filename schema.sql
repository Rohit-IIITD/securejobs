-- ─────────────────────────────────────────────
--  SecureJobs — FULL SCHEMA (M2 + M3 COMPLETE)
-- ─────────────────────────────────────────────

-- ══════════════════════════════════════════
-- USERS (with ROLE system)
-- ══════════════════════════════════════════

CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    full_name     VARCHAR(120) NOT NULL,
    email         VARCHAR(254) NOT NULL UNIQUE,
    phone         VARCHAR(20),
    hashed_pw     TEXT NOT NULL,
    otp_secret    VARCHAR(64),

    -- profile
    headline      VARCHAR(160) DEFAULT '',
    bio           TEXT DEFAULT '',
    location      VARCHAR(120) DEFAULT '',

    -- role system
    role          VARCHAR(20) DEFAULT 'user',  -- user | recruiter | admin

    -- flags
    is_verified   BOOLEAN DEFAULT FALSE,
    is_admin      BOOLEAN DEFAULT FALSE,
    is_suspended  BOOLEAN DEFAULT FALSE,

    -- resume
    resume_path   VARCHAR(255) DEFAULT '',

    created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- ══════════════════════════════════════════
-- EMAIL OTP
-- ══════════════════════════════════════════

CREATE TABLE IF NOT EXISTS email_otps (
    id          SERIAL PRIMARY KEY,
    email       VARCHAR(254) NOT NULL,
    code        VARCHAR(10)  NOT NULL,
    purpose     VARCHAR(40)  NOT NULL,
    expires_at  TIMESTAMPTZ  NOT NULL,
    used        BOOLEAN      DEFAULT FALSE,
    created_at  TIMESTAMPTZ  DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_email_otps_email ON email_otps(email);

-- ══════════════════════════════════════════
-- COMPANIES (RECRUITER OWNED)
-- ══════════════════════════════════════════

CREATE TABLE IF NOT EXISTS companies (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(120) NOT NULL,
    description TEXT DEFAULT '',
    location    VARCHAR(120) DEFAULT '',
    website     VARCHAR(255) DEFAULT '',

    owner_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,

    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ══════════════════════════════════════════
-- JOB POSTINGS (SEARCH-READY)
-- ══════════════════════════════════════════

CREATE TABLE IF NOT EXISTS job_postings (
    id            SERIAL PRIMARY KEY,

    company_id    INTEGER REFERENCES companies(id) ON DELETE CASCADE,

    title         VARCHAR(160) NOT NULL,
    description   TEXT DEFAULT '',

    -- search fields
    skills        TEXT,                    -- NEW (comma-separated or JSON later)
    location      VARCHAR(120) DEFAULT '',
    is_remote     BOOLEAN DEFAULT FALSE,

    salary_min    INTEGER,
    salary_max    INTEGER,

    job_type      VARCHAR(30) DEFAULT 'full-time',  -- full-time | internship

    deadline      DATE,

    created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- Index for search performance
CREATE INDEX IF NOT EXISTS idx_jobs_title ON job_postings(title);
CREATE INDEX IF NOT EXISTS idx_jobs_location ON job_postings(location);

-- ══════════════════════════════════════════
-- APPLICATIONS (TRACKING ENABLED)
-- ══════════════════════════════════════════

CREATE TABLE IF NOT EXISTS applications (
    id          SERIAL PRIMARY KEY,

    job_id      INTEGER REFERENCES job_postings(id) ON DELETE CASCADE,
    user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,

    cover_note  TEXT DEFAULT '',

    status      VARCHAR(20) DEFAULT 'Applied',
    -- Applied | Reviewed | Interviewed | Rejected | Offer

    recruiter_notes TEXT DEFAULT '',

    applied_at  TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE (job_id, user_id)
);

-- ══════════════════════════════════════════
-- MESSAGING SYSTEM (GROUP READY)
-- ══════════════════════════════════════════

-- Conversations (group or 1–1)
CREATE TABLE IF NOT EXISTS conversations (
    id          SERIAL PRIMARY KEY,
    is_group    BOOLEAN DEFAULT FALSE,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Participants
CREATE TABLE IF NOT EXISTS conversation_participants (
    id              SERIAL PRIMARY KEY,
    conversation_id INTEGER REFERENCES conversations(id) ON DELETE CASCADE,
    user_id         INTEGER REFERENCES users(id) ON DELETE CASCADE
);

-- Messages
CREATE TABLE IF NOT EXISTS messages (
    id              SERIAL PRIMARY KEY,
    conversation_id INTEGER REFERENCES conversations(id) ON DELETE CASCADE,
    sender_id       INTEGER REFERENCES users(id) ON DELETE SET NULL,

    ciphertext      TEXT NOT NULL,  -- encrypted message

    sent_at         TIMESTAMPTZ DEFAULT NOW()
);

-- ══════════════════════════════════════════
-- AUDIT LOGS (HASH CHAIN)
-- ══════════════════════════════════════════

CREATE TABLE IF NOT EXISTS audit_logs (
    id          SERIAL PRIMARY KEY,

    actor_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,

    action      VARCHAR(80) NOT NULL,
    target      VARCHAR(120),
    detail      TEXT,

    prev_hash   VARCHAR(64) DEFAULT '',
    row_hash    VARCHAR(64) NOT NULL,

    logged_at   TIMESTAMPTZ DEFAULT NOW()
);

-- ══════════════════════════════════════════
-- SECURITY INDEXES
-- ══════════════════════════════════════════

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_applications_user ON applications(user_id);
CREATE INDEX IF NOT EXISTS idx_applications_job ON applications(job_id);