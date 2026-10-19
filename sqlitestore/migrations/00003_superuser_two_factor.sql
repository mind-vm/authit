-- +goose Up

-- An operator's second factor, apart from auth_totp_settings for the reason
-- auth_superuser_refresh_tokens is apart from auth_refresh_tokens.
CREATE TABLE auth_superuser_totp_settings (
    id                   TEXT    PRIMARY KEY,
    superuser_id         TEXT    NOT NULL UNIQUE REFERENCES auth_superusers(id) ON DELETE CASCADE,
    secret_encrypted     BLOB    NOT NULL,
    enabled              INTEGER NOT NULL DEFAULT 0,
    verified_at          TEXT,
    recovery_code_hashes TEXT    NOT NULL DEFAULT '[]',
    recovery_codes_used  INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT    NOT NULL,
    updated_at           TEXT    NOT NULL
);

CREATE TABLE auth_superuser_pending_two_factor_sessions (
    id           TEXT PRIMARY KEY,
    superuser_id TEXT NOT NULL REFERENCES auth_superusers(id) ON DELETE CASCADE,
    token_hash   TEXT NOT NULL UNIQUE,
    expires_at   TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

-- +goose Down
DROP TABLE auth_superuser_pending_two_factor_sessions;
DROP TABLE auth_superuser_totp_settings;
