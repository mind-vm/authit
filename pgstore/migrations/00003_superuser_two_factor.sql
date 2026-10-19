-- +goose Up

-- An operator's second factor. Its own tables rather than rows in
-- auth.totp_settings, for the reason auth.superuser_refresh_tokens is its own:
-- the user-plane tables are reachable from product code, these are not.
CREATE TABLE auth.superuser_totp_settings (
    id                   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    superuser_id         uuid        NOT NULL UNIQUE REFERENCES auth.superusers(id) ON DELETE CASCADE,
    secret_encrypted     bytea       NOT NULL,
    enabled              boolean     NOT NULL DEFAULT false,
    verified_at          timestamptz,
    recovery_code_hashes text[]      NOT NULL DEFAULT '{}',
    recovery_codes_used  integer     NOT NULL DEFAULT 0,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE auth.superuser_pending_two_factor_sessions (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    superuser_id uuid        NOT NULL REFERENCES auth.superusers(id) ON DELETE CASCADE,
    token_hash   text        NOT NULL UNIQUE,
    expires_at   timestamptz NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE auth.superuser_pending_two_factor_sessions, auth.superuser_totp_settings;
