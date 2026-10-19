-- +goose Up

-- SQLite has no schemas, so the auth_ prefix does what pgstore's auth schema
-- does: keeps these tables from colliding with an app's own users or accounts
-- table in the same file.
--
-- Columns follow pgstore's migrations one for one. What changes is storage:
-- ids are TEXT holding a canonical lower-case uuid, instants are TEXT in a
-- fixed-width UTC layout so they compare as they sort, booleans are INTEGER,
-- and a list is TEXT holding a JSON array. No column defaults an id or a
-- timestamp; the store fills both before it writes.

CREATE TABLE auth_users (
    id                TEXT    PRIMARY KEY,
    email             TEXT    NOT NULL UNIQUE,
    password_hash     TEXT    NOT NULL,
    email_verified    INTEGER NOT NULL DEFAULT 0,
    email_verified_at TEXT,
    created_at        TEXT    NOT NULL,
    updated_at        TEXT    NOT NULL
);

CREATE TABLE auth_refresh_tokens (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    user_agent TEXT NOT NULL DEFAULT '',
    ip_address TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX auth_refresh_tokens_user_id_idx ON auth_refresh_tokens (user_id);

CREATE TABLE auth_password_reset_tokens (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used_at    TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX auth_password_reset_tokens_user_id_idx ON auth_password_reset_tokens (user_id);

CREATE TABLE auth_email_verification_tokens (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used_at    TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX auth_email_verification_tokens_user_id_idx ON auth_email_verification_tokens (user_id);

CREATE TABLE auth_totp_settings (
    id                   TEXT    PRIMARY KEY,
    user_id              TEXT    NOT NULL UNIQUE REFERENCES auth_users(id) ON DELETE CASCADE,
    secret_encrypted     BLOB    NOT NULL,
    enabled              INTEGER NOT NULL DEFAULT 0,
    verified_at          TEXT,
    recovery_code_hashes TEXT    NOT NULL DEFAULT '[]',
    recovery_codes_used  INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT    NOT NULL,
    updated_at           TEXT    NOT NULL
);

CREATE TABLE auth_pending_two_factor_sessions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Keyed by email, not user, so the lockout check cannot reveal whether an
-- account exists. Counted on every login attempt, hence the index.
CREATE TABLE auth_failed_login_attempts (
    id         TEXT PRIMARY KEY,
    email      TEXT NOT NULL,
    ip_address TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX auth_failed_login_attempts_email_created_at_idx
    ON auth_failed_login_attempts (email, created_at DESC);

-- Operator locks only; the primary key makes locking twice idempotent.
CREATE TABLE auth_account_locks (
    user_id   TEXT PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE,
    locked_at TEXT NOT NULL
);

-- (provider, provider_account_id) decides whose sign-in this is, so it is
-- unique; email is not, because providers assert addresses they do not own.
CREATE TABLE auth_accounts (
    id                      TEXT    PRIMARY KEY,
    user_id                 TEXT    NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    provider                TEXT    NOT NULL,
    provider_account_id     TEXT    NOT NULL,
    email                   TEXT    NOT NULL DEFAULT '',
    email_verified          INTEGER NOT NULL DEFAULT 0,
    access_token_encrypted  BLOB,
    refresh_token_encrypted BLOB,
    token_expires_at        TEXT,
    scopes                  TEXT    NOT NULL DEFAULT '[]',
    created_at              TEXT    NOT NULL,
    updated_at              TEXT    NOT NULL,
    UNIQUE (provider, provider_account_id)
);
CREATE INDEX auth_accounts_user_id_idx ON auth_accounts (user_id);

-- credential_id decides whose credential signed, so it is unique; data is
-- the authoritative binary record and must be a BLOB.
CREATE TABLE auth_webauthn_credentials (
    id              TEXT    PRIMARY KEY,
    user_id         TEXT    NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    credential_id   BLOB    NOT NULL UNIQUE,
    data            BLOB    NOT NULL,
    name            TEXT    NOT NULL DEFAULT '',
    transports      TEXT    NOT NULL DEFAULT '[]',
    backup_eligible INTEGER NOT NULL DEFAULT 0,
    backup_state    INTEGER NOT NULL DEFAULT 0,
    clone_warning   INTEGER NOT NULL DEFAULT 0,
    last_used_at    TEXT,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
);
CREATE INDEX auth_webauthn_credentials_user_id_idx ON auth_webauthn_credentials (user_id);

-- Consumed by one DELETE ... RETURNING so a challenge can be redeemed once.
-- user_id is NULL for a discoverable login.
CREATE TABLE auth_webauthn_challenges (
    id         TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    user_id    TEXT REFERENCES auth_users(id) ON DELETE CASCADE,
    data       BLOB NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX auth_webauthn_challenges_expires_at_idx ON auth_webauthn_challenges (expires_at);

-- No foreign key: a passwordless flow creates the account on redemption.
CREATE TABLE auth_email_login_tokens (
    id         TEXT    PRIMARY KEY,
    email      TEXT    NOT NULL,
    kind       TEXT    NOT NULL,
    token_hash TEXT    NOT NULL UNIQUE,
    attempts   INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT    NOT NULL,
    used_at    TEXT,
    created_at TEXT    NOT NULL
);
CREATE INDEX auth_email_login_tokens_email_kind_idx ON auth_email_login_tokens (email, kind);

-- +goose Down
DROP TABLE auth_email_login_tokens;
DROP TABLE auth_webauthn_challenges;
DROP TABLE auth_webauthn_credentials;
DROP TABLE auth_accounts;
DROP TABLE auth_account_locks;
DROP TABLE auth_failed_login_attempts;
DROP TABLE auth_pending_two_factor_sessions;
DROP TABLE auth_totp_settings;
DROP TABLE auth_email_verification_tokens;
DROP TABLE auth_password_reset_tokens;
DROP TABLE auth_refresh_tokens;
DROP TABLE auth_users;
