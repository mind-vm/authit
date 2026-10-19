-- +goose Up

-- PIN sign-in on bound devices (package pin).

-- One PIN per user. The lock after repeated wrong PINs lives in
-- auth.failed_login_attempts under a key of the pin package's own, so it
-- has no column here.
CREATE TABLE auth.pin_credentials (
    user_id    uuid        PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    pin_hash   text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- token_hash is hex(SHA-256(token)), so device tokens issued by an app's own
-- implementation in that format import unchanged. expires_at is NULL for a
-- device signed in until revoked.
CREATE TABLE auth.bound_devices (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    name         text        NOT NULL DEFAULT '',
    token_hash   text        NOT NULL UNIQUE,
    user_agent   text        NOT NULL DEFAULT '',
    ip_address   text        NOT NULL DEFAULT '',
    expires_at   timestamptz,
    last_used_at timestamptz,
    revoked_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX bound_devices_user_id_idx ON auth.bound_devices (user_id);

-- +goose Down
DROP TABLE auth.bound_devices, auth.pin_credentials;
