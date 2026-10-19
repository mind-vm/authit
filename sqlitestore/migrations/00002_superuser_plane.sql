-- +goose Up

-- The operator plane, in its own tables for the reasons pgstore's migration
-- gives: an operator has no team and no role, and a dump of the user-session
-- table must not be replayable as an admin session.
CREATE TABLE auth_superusers (
    id            TEXT    PRIMARY KEY,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    display_name  TEXT    NOT NULL DEFAULT '',
    is_active     INTEGER NOT NULL DEFAULT 1,
    created_by    TEXT    REFERENCES auth_superusers(id),  -- NULL for the bootstrap operator
    last_login_at TEXT,
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL
);

CREATE TABLE auth_superuser_refresh_tokens (
    id           TEXT PRIMARY KEY,
    superuser_id TEXT NOT NULL REFERENCES auth_superusers(id) ON DELETE CASCADE,
    token_hash   TEXT NOT NULL UNIQUE,
    expires_at   TEXT NOT NULL,
    revoked_at   TEXT,
    user_agent   TEXT NOT NULL DEFAULT '',
    ip_address   TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL
);
CREATE INDEX auth_superuser_refresh_tokens_superuser_id_idx
    ON auth_superuser_refresh_tokens (superuser_id);

-- +goose Down
DROP TABLE auth_superuser_refresh_tokens;
DROP TABLE auth_superusers;
