-- +goose Up

-- The operator plane. A separate table from auth.users, not a flag on it: an
-- operator identity has no team and no role, and the only way to create one is
-- through the superuser package's API, so a compromised user-facing
-- registration flow can never mint one.
CREATE TABLE auth.superusers (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    email         text        NOT NULL UNIQUE,
    password_hash text        NOT NULL,
    display_name  text        NOT NULL DEFAULT '',
    is_active     boolean     NOT NULL DEFAULT true,
    created_by    uuid        REFERENCES auth.superusers(id),  -- NULL for the bootstrap operator
    last_login_at timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Its own table rather than a column on auth.refresh_tokens, so a leaked dump
-- of the user-session table cannot be replayed as an admin session.
CREATE TABLE auth.superuser_refresh_tokens (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    superuser_id uuid        NOT NULL REFERENCES auth.superusers(id) ON DELETE CASCADE,
    token_hash   text        NOT NULL UNIQUE,
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz,
    user_agent   text        NOT NULL DEFAULT '',
    ip_address   text        NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX superuser_refresh_tokens_superuser_id_idx
    ON auth.superuser_refresh_tokens (superuser_id);

-- +goose Down
DROP TABLE auth.superuser_refresh_tokens, auth.superusers;
