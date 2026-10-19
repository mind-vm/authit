-- +goose Up

-- Personal access tokens and RFC 8628 device authorizations.

-- The raw token is the bearer credential, so only its hash is stored.
-- Revoked and expired rows stay: the service reads both columns itself.
CREATE TABLE auth.personal_access_tokens (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    name         text        NOT NULL DEFAULT '',
    token_hash   text        NOT NULL UNIQUE,
    scopes       text[]      NOT NULL DEFAULT '{}',
    expires_at   timestamptz,
    last_used_at timestamptz,
    revoked_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX personal_access_tokens_user_id_idx ON auth.personal_access_tokens (user_id);

-- device_code is the CLI's poll secret, so only its hash is stored;
-- user_code is short, typed by a person and stored in the clear, its safety
-- coming from the rate limit on guesses. user_id is set on approval.
CREATE TABLE auth.device_authorizations (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    device_code_hash text        NOT NULL UNIQUE,
    user_code        text        NOT NULL UNIQUE,
    client_id        text        NOT NULL DEFAULT '',
    scope            text        NOT NULL DEFAULT '',
    status           text        NOT NULL DEFAULT 'pending',
    user_id          uuid        REFERENCES auth.users(id) ON DELETE CASCADE,
    expires_at       timestamptz NOT NULL,
    interval_seconds integer     NOT NULL DEFAULT 5,
    last_polled_at   timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE auth.device_authorizations, auth.personal_access_tokens;
