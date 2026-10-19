-- +goose Up

-- The auth tables live in their own schema so they cannot collide with an
-- app's own users or accounts table, and so the tenancy rule, which reads the
-- app's migrations, never sees them.
CREATE SCHEMA IF NOT EXISTS auth;

CREATE TABLE auth.users (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    email             text        NOT NULL UNIQUE,
    -- Self-describing hash format (PHC argon2id or $2 bcrypt); size for both.
    password_hash     text        NOT NULL,
    email_verified    boolean     NOT NULL DEFAULT false,
    email_verified_at timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

-- Doubles as the session list, and as the session itself in opaque mode.
CREATE TABLE auth.refresh_tokens (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    token_hash text        NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    user_agent text        NOT NULL DEFAULT '',
    ip_address text        NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX refresh_tokens_user_id_idx ON auth.refresh_tokens (user_id);

CREATE TABLE auth.password_reset_tokens (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    token_hash text        NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX password_reset_tokens_user_id_idx ON auth.password_reset_tokens (user_id);

CREATE TABLE auth.email_verification_tokens (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    token_hash text        NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX email_verification_tokens_user_id_idx ON auth.email_verification_tokens (user_id);

CREATE TABLE auth.totp_settings (
    id                   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id              uuid        NOT NULL UNIQUE REFERENCES auth.users(id) ON DELETE CASCADE,
    secret_encrypted     bytea       NOT NULL,
    enabled              boolean     NOT NULL DEFAULT false,
    verified_at          timestamptz,
    recovery_code_hashes text[]      NOT NULL DEFAULT '{}',
    recovery_codes_used  integer     NOT NULL DEFAULT 0,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE auth.pending_two_factor_sessions (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    token_hash text        NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Keyed by email, not user, so the lockout check cannot reveal whether an
-- account exists. Counted on every login attempt, hence the index.
CREATE TABLE auth.failed_login_attempts (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    email      text        NOT NULL,
    ip_address text        NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX failed_login_attempts_email_created_at_idx
    ON auth.failed_login_attempts (email, created_at DESC);

-- Operator locks only; the primary key makes locking twice idempotent.
CREATE TABLE auth.account_locks (
    user_id   uuid        PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    locked_at timestamptz NOT NULL DEFAULT now()
);

-- (provider, provider_account_id) decides whose sign-in this is, so it is
-- unique; email is not, because providers assert addresses they do not own.
CREATE TABLE auth.accounts (
    id                      uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                 uuid        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    provider                text        NOT NULL,
    provider_account_id     text        NOT NULL,
    email                   text        NOT NULL DEFAULT '',
    email_verified          boolean     NOT NULL DEFAULT false,
    access_token_encrypted  bytea,
    refresh_token_encrypted bytea,
    token_expires_at        timestamptz,
    scopes                  text[]      NOT NULL DEFAULT '{}',
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider, provider_account_id)
);
CREATE INDEX accounts_user_id_idx ON auth.accounts (user_id);

-- credential_id decides whose credential signed, so it is unique; data is
-- the authoritative binary record and must be bytea.
CREATE TABLE auth.webauthn_credentials (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         uuid        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    credential_id   bytea       NOT NULL UNIQUE,
    data            bytea       NOT NULL,
    name            text        NOT NULL DEFAULT '',
    transports      text[]      NOT NULL DEFAULT '{}',
    backup_eligible boolean     NOT NULL DEFAULT false,
    backup_state    boolean     NOT NULL DEFAULT false,
    clone_warning   boolean     NOT NULL DEFAULT false,
    last_used_at    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX webauthn_credentials_user_id_idx ON auth.webauthn_credentials (user_id);

-- Consumed by one DELETE ... RETURNING so a challenge can be redeemed once.
-- user_id is NULL for a discoverable login.
CREATE TABLE auth.webauthn_challenges (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash text        NOT NULL UNIQUE,
    user_id    uuid        REFERENCES auth.users(id) ON DELETE CASCADE,
    data       bytea       NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX webauthn_challenges_expires_at_idx ON auth.webauthn_challenges (expires_at);

-- No foreign key: a passwordless flow creates the account on redemption.
CREATE TABLE auth.email_login_tokens (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    email      text        NOT NULL,
    kind       text        NOT NULL,
    token_hash text        NOT NULL UNIQUE,
    attempts   integer     NOT NULL DEFAULT 0,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX email_login_tokens_email_kind_idx ON auth.email_login_tokens (email, kind);

-- +goose Down
-- The schema stays: goose's version table lives in it.
DROP TABLE auth.email_login_tokens, auth.webauthn_challenges, auth.webauthn_credentials,
    auth.accounts, auth.account_locks, auth.failed_login_attempts,
    auth.pending_two_factor_sessions, auth.totp_settings, auth.email_verification_tokens,
    auth.password_reset_tokens, auth.refresh_tokens, auth.users;
