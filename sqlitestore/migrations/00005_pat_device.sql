-- +goose Up

-- Personal access tokens and RFC 8628 device authorizations. Columns follow
-- pgstore's 00005_pat_device.sql one for one.

-- The raw token is the bearer credential, so only its hash is stored.
-- Revoked and expired rows stay: the service reads both columns itself.
CREATE TABLE auth_personal_access_tokens (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL DEFAULT '',
    token_hash   TEXT NOT NULL UNIQUE,
    scopes       TEXT NOT NULL DEFAULT '[]',
    expires_at   TEXT,
    last_used_at TEXT,
    revoked_at   TEXT,
    created_at   TEXT NOT NULL
);
CREATE INDEX auth_personal_access_tokens_user_id_idx ON auth_personal_access_tokens (user_id);

-- device_code is the CLI's poll secret, so only its hash is stored;
-- user_code is short, typed by a person and stored in the clear, its safety
-- coming from the rate limit on guesses. user_id is set on approval.
CREATE TABLE auth_device_authorizations (
    id               TEXT    PRIMARY KEY,
    device_code_hash TEXT    NOT NULL UNIQUE,
    user_code        TEXT    NOT NULL UNIQUE,
    client_id        TEXT    NOT NULL DEFAULT '',
    scope            TEXT    NOT NULL DEFAULT '',
    status           TEXT    NOT NULL DEFAULT 'pending',
    user_id          TEXT    REFERENCES auth_users(id) ON DELETE CASCADE,
    expires_at       TEXT    NOT NULL,
    interval_seconds INTEGER NOT NULL DEFAULT 5,
    last_polled_at   TEXT,
    created_at       TEXT    NOT NULL
);

-- +goose Down
DROP TABLE auth_device_authorizations;
DROP TABLE auth_personal_access_tokens;
