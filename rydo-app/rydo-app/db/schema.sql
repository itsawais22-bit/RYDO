-- RYDO authentication database (SQLite)
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT    NOT NULL CHECK (length(name) BETWEEN 2 AND 80),
    phone          TEXT    NOT NULL UNIQUE CHECK (phone GLOB '03[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]'),
    password_hash  TEXT    NOT NULL,                       -- scrypt, never plain text
    role           TEXT    NOT NULL DEFAULT 'rider' CHECK (role IN ('rider','driver','admin')),
    is_verified    INTEGER NOT NULL DEFAULT 0 CHECK (is_verified IN (0,1)),  -- phone verified via OTP
    avatar_url     TEXT,
    rating         REAL    NOT NULL DEFAULT 5.0,
    failed_logins  INTEGER NOT NULL DEFAULT 0,
    locked_until   TEXT,                                   -- ISO time; set after too many bad passwords
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_login_at  TEXT
);

CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- One-time codes for phone verification and password reset
CREATE TABLE IF NOT EXISTS otp_codes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    phone       TEXT    NOT NULL,
    purpose     TEXT    NOT NULL CHECK (purpose IN ('signup','reset')),
    code_hash   TEXT    NOT NULL,                          -- HMAC of the code, never the code itself
    attempts    INTEGER NOT NULL DEFAULT 0,
    used        INTEGER NOT NULL DEFAULT 0 CHECK (used IN (0,1)),
    expires_at  TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_otp_lookup ON otp_codes(phone, purpose, used);
