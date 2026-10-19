-- +goose Up

-- PIN sign-in on bound devices (package pin). Columns follow pgstore's
-- 00007_pin.sql one for one.

-- One PIN per user. The lock after repeated wrong PINs lives in
-- auth_failed_login_attempts under a key of the pin package's own, so it
-- has no column here.
CREATE TABLE auth_pin_credentials (
    user_id    TEXT PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE,
    pin_hash   TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- token_hash is hex(SHA-256(token)), so device tokens issued by an app's own
-- implementation in that format import unchanged. expires_at is NULL for a
-- device signed in until revoked.
CREATE TABLE auth_bound_devices (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL DEFAULT '',
    token_hash   TEXT NOT NULL UNIQUE,
    user_agent   TEXT NOT NULL DEFAULT '',
    ip_address   TEXT NOT NULL DEFAULT '',
    expires_at   TEXT,
    last_used_at TEXT,
    revoked_at   TEXT,
    created_at   TEXT NOT NULL
);
CREATE INDEX auth_bound_devices_user_id_idx ON auth_bound_devices (user_id);

-- +goose Down
DROP TABLE auth_bound_devices;
DROP TABLE auth_pin_credentials;
