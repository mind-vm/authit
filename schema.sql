-- authit reference schema (PostgreSQL)
--
-- THIS IS DOCUMENTATION, NOT A MIGRATION. authit ships no DDL on purpose:
-- the store interfaces are the contract, and a host application owns its own
-- schema, naming, and migration tooling. Nothing here is versioned, and
-- authit will never read it.
--
-- What it is for: one correct, complete table set, so the column set behind
-- each store.* type doesn't have to be reverse-engineered from the struct
-- definitions one at a time. Rename the tables, rename the columns, split
-- them, merge them into tables you already have, drop the ones whose flows
-- you don't use — the adapter you write (or configure, via sqlbstore) is
-- what maps your names onto authit's fields. sqlbstore/example_test.go is
-- this same schema wired up through sqlbstore, end to end.
--
-- Three things here that reading store/*.go will NOT tell you:
--
--  1. account_locks (below) has no canonical authit type at all. LockoutStore's
--     LockAccount/IsAccountLocked/UnlockAccount are existence operations over a
--     table whose shape is entirely yours, so nothing in store/user.go hints
--     that a second lockout table exists. Miss it and the failure is at
--     runtime, not compile time.
--  2. store.TOTPSettings does not use the column names you would guess:
--     the fields are Enabled, VerifiedAt, RecoveryCodeHashes and
--     RecoveryCodesUsed -- not `confirmed` and `backup_codes`.
--  3. store.TOTPSettings.RecoveryCodeHashes is a []string with no obvious
--     storage. text[] is used below; a join table or a JSON column are equally
--     valid and change only your adapter.
--
-- Conventions used here, none of them required:
--
--  * IDs are uuid. authit's service packages generate their own IDs with
--    crypto.NewID (a UUIDv4 string) before handing a record to a store, so
--    `DEFAULT gen_random_uuid()` is belt-and-braces for a hand-written store.
--    It IS load-bearing under sqlbstore, whose Table.Create deliberately
--    blanks the ID so the database default assigns one.
--  * Token columns hold a hex SHA-256 digest (crypto.HashToken), 64 chars.
--    Raw tokens are never persisted -- authit hands the raw value to the
--    caller exactly once and stores only the hash.
--  * Struct fields that are plain strings (UserAgent, IPAddress, DisplayName)
--    are NOT NULL DEFAULT '' rather than nullable, so a round-trip through the
--    database can't turn "" into NULL and back into a pointer your adapter
--    then has to dereference.
--  * Foreign keys to users(id) are ON DELETE CASCADE, so deleting a user
--    takes their sessions and tokens with them. failed_login_attempts is
--    keyed by email, not user_id, on purpose: the temporary lockout is
--    derived from it and is evaluated before a matching user is confirmed to
--    exist, so it cannot leak account existence.

-- ---------------------------------------------------------------------------
-- user plane -- the seven stores in user.Stores, plus the eighth table
-- ---------------------------------------------------------------------------

-- store.UserStore / store.User
CREATE TABLE users (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    email             text        NOT NULL UNIQUE,
    password_hash     text        NOT NULL,      -- bcrypt, from crypto.HashPassword
    email_verified    boolean     NOT NULL DEFAULT false,
    email_verified_at timestamptz,               -- *time.Time: NULL until verified
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

-- store.RefreshTokenStore / store.RefreshToken.
-- Doubles as the session list behind user.Service.ListSessions, which is why
-- user_agent and ip_address are here at all.
CREATE TABLE refresh_tokens (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash text        NOT NULL UNIQUE,      -- looked up on every refresh
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,                      -- *time.Time: NULL while live
    user_agent text        NOT NULL DEFAULT '',
    ip_address text        NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX refresh_tokens_user_id_idx ON refresh_tokens (user_id);

-- store.PasswordResetStore / store.PasswordResetToken
CREATE TABLE password_reset_tokens (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash text        NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,                      -- single use: NULL until redeemed
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX password_reset_tokens_user_id_idx ON password_reset_tokens (user_id);

-- store.EmailVerificationStore / store.EmailVerificationToken
CREATE TABLE email_verification_tokens (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash text        NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX email_verification_tokens_user_id_idx ON email_verification_tokens (user_id);

-- store.TOTPStore / store.TOTPSettings.
-- Note the field names: Enabled (not `confirmed`), VerifiedAt,
-- RecoveryCodeHashes (not `backup_codes`), RecoveryCodesUsed. Guessing the
-- obvious names here is the single most common way to end up writing
-- translation code around credential storage.
CREATE TABLE totp_settings (
    id                   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id              uuid        NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    secret_encrypted     bytea       NOT NULL,   -- []byte, AES-256-GCM (crypto.EncryptSecret)
    enabled              boolean     NOT NULL DEFAULT false,
    verified_at          timestamptz,            -- when enrollment was confirmed
    recovery_code_hashes text[]      NOT NULL DEFAULT '{}',  -- []string of hashed backup codes
    recovery_codes_used  integer     NOT NULL DEFAULT 0,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);

-- store.PendingTwoFactorStore / store.PendingTwoFactorSession.
-- Short-lived (Config.PendingTwoFactorTTL, 5 minutes by default): issued
-- after a correct password when TOTP is on, exchanged for a real session.
CREATE TABLE pending_two_factor_sessions (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash text        NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- store.LockoutStore, table 1 of 2 / store.FailedLoginAttempt.
-- Keyed by email rather than user_id so a lockout check can happen before
-- the user is known to exist.
CREATE TABLE failed_login_attempts (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    email      text        NOT NULL,
    ip_address text        NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
-- CountRecentFailedLoginAttempts filters on both columns together, and runs
-- on EVERY login attempt rather than only on failures -- the temporary
-- lockout is derived from this count. Do not drop this index.
CREATE INDEX failed_login_attempts_email_created_at_idx
    ON failed_login_attempts (email, created_at DESC);

-- store.LockoutStore, table 2 of 2 -- THE ONE WITH NO authit TYPE.
-- LockAccount/IsAccountLocked/UnlockAccount are insert/exists/delete over a
-- set of locked user ids; the row shape is entirely yours. The UNIQUE
-- constraint on user_id is required, not decorative: LockAccount relies on it
-- to make locking an already-locked account idempotent rather than an error.
--
-- These are operator-driven ("administrative") locks only. Nothing inside
-- authit writes here -- the automatic brute-force lockout is temporary and
-- derived from failed_login_attempts, so it needs no storage and lifts on its
-- own. A row here holds until your own admin surface deletes it.
CREATE TABLE account_locks (
    user_id   uuid        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    locked_at timestamptz NOT NULL DEFAULT now()
);

-- store.AccountStore / store.Account -- external identities (oidc package).
-- Absent from the user plane above because a password-only deployment needs
-- none of it.
--
-- The UNIQUE constraint on (provider, provider_account_id) is the important
-- line in this table. That pair is the only thing deciding which user a
-- social sign-in belongs to; without the constraint a duplicate row makes
-- the lookup a coin flip between two accounts, which is an account takeover.
--
-- email is deliberately NOT unique: two providers can assert the same
-- address, and one can assert an address belonging to somebody else's
-- account. Treating it as an identifier is the classic social-login
-- vulnerability -- see oidc.LinkingPolicy.
--
-- The token columns are bytea, not text: they hold AES-256-GCM ciphertext,
-- which contains zero bytes that a text column will mangle. They are NULL
-- unless oidc.Config.ProviderTokenKey is set, which it is not by default.
CREATE TABLE accounts (
    id                      uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                 uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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
CREATE INDEX accounts_user_id_idx ON accounts (user_id);

-- store.WebAuthnCredentialStore / store.WebAuthnCredential -- passkeys and
-- security keys (passkey package). Absent from the user plane above because
-- a password-only deployment needs none of it.
--
-- credential_id is UNIQUE and it matters: it is what an assertion is looked
-- up by, and therefore the only thing deciding whose credential just signed
-- the challenge.
--
-- credential_id and data are bytea, NOT text. data is the authoritative
-- credential record -- it holds the public key a signature is checked
-- against -- and it is neither UTF-8 nor free of zero bytes. A text column
-- will mangle it, and the symptom is every login for that authenticator
-- failing after it was stored successfully.
--
-- The remaining columns are denormalised out of data and rewritten on every
-- update, so a settings page can list credentials without decoding a blob
-- and an operator can query for clone_warning. When they disagree with
-- data, data wins.
CREATE TABLE webauthn_credentials (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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
CREATE INDEX webauthn_credentials_user_id_idx ON webauthn_credentials (user_id);

-- store.WebAuthnChallengeStore / store.WebAuthnChallenge -- in-flight
-- ceremonies (passkey package).
--
-- A WebAuthn ceremony spans two requests: the browser is handed options and
-- comes back with a signature over the challenge inside them. The challenge
-- lives here in between, rather than in the browser's hands, because it is
-- what the signature is verified against -- and a caller who can substitute
-- it can present an assertion captured earlier and have it checked against
-- expectations of its own.
--
-- Rows are short-lived (the passkey Config.Timeout, 60s by default) and
-- consumed on first use. That single statement is the point of the table:
--
--   DELETE FROM webauthn_challenges WHERE token_hash = $1 RETURNING ...
--
-- A SELECT followed by a DELETE is not the same thing and must not be
-- substituted. Two connections can interleave between the two statements,
-- both read the row, and both finish the same ceremony -- which is a
-- captured assertion accepted twice. The signature counter does not catch
-- it: synced passkeys report a counter of zero forever.
--
-- token_hash is UNIQUE because it is the only thing a ceremony is found by.
-- user_id is set for a registration and NULL for a discoverable login,
-- which names no account by design; authit never queries by it, and it is
-- here so in-flight ceremonies cascade away with the account.
--
-- data is bytea, not text. It is the serialised ceremony state and must
-- round-trip byte for byte.
CREATE TABLE webauthn_challenges (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash text        NOT NULL UNIQUE,
    user_id    uuid        REFERENCES users(id) ON DELETE CASCADE,
    data       bytea       NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
-- Expired rows are refused by authit but nothing removes them. As with
-- password_reset_tokens and the other short-lived tables, sweeping is
-- yours:  DELETE FROM webauthn_challenges WHERE expires_at < now();
CREATE INDEX webauthn_challenges_expires_at_idx ON webauthn_challenges (expires_at);

-- store.EmailLoginStore / store.EmailLoginToken -- magic links and sign-in
-- codes (emaillogin package). Absent from the user plane above because a
-- password-only deployment needs none of it.
--
-- Keyed by email, not user_id, and with no foreign key: the account may not
-- exist yet. A passwordless flow can create one, and it does so when the
-- token is redeemed rather than when it is requested, so that nobody can
-- fill the user table with addresses they do not control.
--
-- attempts is what makes a six-digit code survivable. The index on
-- (email, kind) is the one a code redemption uses to find the record it must
-- count a failed guess against -- a lookup by token hash cannot work for a
-- guess that did not match.
CREATE TABLE email_login_tokens (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    email      text        NOT NULL,
    kind       text        NOT NULL,
    token_hash text        NOT NULL UNIQUE,
    attempts   integer     NOT NULL DEFAULT 0,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX email_login_tokens_email_kind_idx ON email_login_tokens (email, kind);
-- used_at and attempts are both written by compare-and-set, never by
-- reading the row and writing it back. Redeeming is
--   UPDATE ... SET used_at = $2 WHERE id = $1 AND used_at IS NULL
-- and no rows affected means another request redeemed it first; counting a
-- wrong guess is
--   UPDATE ... SET attempts = attempts + 1 WHERE id = $1 RETURNING attempts
-- with the returned value decisive. Read-then-write lets one magic link
-- sign two people in, and lets parallel guesses share a single charge
-- against the budget that is the only thing making six digits safe.

-- ---------------------------------------------------------------------------
-- team plane -- team.Stores
-- ---------------------------------------------------------------------------

-- store.TeamStore / store.Team
CREATE TABLE teams (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text        NOT NULL,
    slug       text        NOT NULL UNIQUE,
    owner_id   uuid        NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- store.MemberStore / store.Member.
-- role is a plain string: store.RoleOwner/Admin/Member are a starting point,
-- not a closed set, and only RoleOwner has meaning to authit (last-owner
-- protection). Roles are per-team by design -- see store/team.go on why an
-- identity that spans teams belongs in your own model, not here.
--
-- user_id is nullable so a team can track a member before a login exists
-- (an invited-but-not-yet-registered contact).
--
-- is_active is the column the sqlbstore docs warn about: a DEFAULT true
-- column that an update must be able to write an explicit false to. If you
-- are hand-writing an upsert-style Update, make sure it does.
CREATE TABLE team_members (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id      uuid        NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id      uuid        REFERENCES users(id) ON DELETE CASCADE,
    role         text        NOT NULL,
    display_name text        NOT NULL DEFAULT '',
    email        text        NOT NULL DEFAULT '',
    is_active    boolean     NOT NULL DEFAULT true,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
-- GetMemberByUserAndTeam is a compound lookup; one membership per pair.
CREATE UNIQUE INDEX team_members_team_id_user_id_idx
    ON team_members (team_id, user_id) WHERE user_id IS NOT NULL;
-- ListMembershipsByUser drives a multi-team login/team-selection step.
CREATE INDEX team_members_user_id_idx ON team_members (user_id);

-- store.InvitationStore / store.Invitation.
-- status is 'pending' | 'accepted' | 'revoked'. There is deliberately no
-- 'expired' state: expiry is derived from expires_at at read time and never
-- written back, so no sweeper job is needed to keep the column honest.
CREATE TABLE team_invitations (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id       uuid        NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    email         text        NOT NULL,
    token_hash    text        NOT NULL UNIQUE,
    role          text        NOT NULL,
    status        text        NOT NULL DEFAULT 'pending',
    invited_by_id uuid        NOT NULL REFERENCES users(id),
    expires_at    timestamptz NOT NULL,
    accepted_at   timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX team_invitations_team_id_idx ON team_invitations (team_id);

-- ---------------------------------------------------------------------------
-- superuser plane -- superuser.Stores
-- ---------------------------------------------------------------------------

-- store.SuperuserStore / store.Superuser.
-- A separate table from users, not a flag on it: an operator identity has no
-- team and no role, and the only way to create one is through the superuser
-- package's API, so a compromised user-facing registration flow can never
-- mint one.
CREATE TABLE superusers (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    email         text        NOT NULL UNIQUE,
    password_hash text        NOT NULL,
    display_name  text        NOT NULL DEFAULT '',
    is_active     boolean     NOT NULL DEFAULT true,
    created_by    uuid        REFERENCES superusers(id),  -- NULL for the bootstrap operator
    last_login_at timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- store.SuperuserRefreshTokenStore / store.SuperuserRefreshToken.
-- Its own table rather than a column on refresh_tokens, so a leaked dump of
-- the user-session table cannot be replayed as an admin session.
CREATE TABLE superuser_refresh_tokens (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    superuser_id uuid        NOT NULL REFERENCES superusers(id) ON DELETE CASCADE,
    token_hash   text        NOT NULL UNIQUE,
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz,
    user_agent   text        NOT NULL DEFAULT '',
    ip_address   text        NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX superuser_refresh_tokens_superuser_id_idx
    ON superuser_refresh_tokens (superuser_id);

-- ---------------------------------------------------------------------------
-- CLI / non-interactive auth -- pat.Stores and device.Stores
-- ---------------------------------------------------------------------------

-- store.PersonalAccessTokenStore / store.PersonalAccessToken.
-- Unlike refresh_tokens there is no paired short-lived access token: the raw
-- value IS the credential, checked by hash on every request.
CREATE TABLE personal_access_tokens (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         text        NOT NULL DEFAULT '',   -- user-chosen label, e.g. "laptop"
    token_hash   text        NOT NULL UNIQUE,
    scopes       text[]      NOT NULL DEFAULT '{}', -- []string, meaning is yours
    expires_at   timestamptz,                       -- NULL means it never expires
    last_used_at timestamptz,
    revoked_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX personal_access_tokens_user_id_idx ON personal_access_tokens (user_id);

-- store.DeviceAuthorizationStore / store.DeviceAuthorization (RFC 8628).
-- Note the asymmetry: device_code is a secret and only its hash is stored,
-- while user_code is stored in the clear -- it is short and low-entropy by
-- design, and its security comes from you rate-limiting guesses at the
-- verification endpoint.
CREATE TABLE device_authorizations (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    device_code_hash text        NOT NULL UNIQUE,
    user_code        text        NOT NULL UNIQUE,   -- plaintext, e.g. "WDJB-MJHT"
    client_id        text        NOT NULL DEFAULT '',
    scope            text        NOT NULL DEFAULT '',
    status           text        NOT NULL DEFAULT 'pending',  -- pending|approved|denied
    user_id          uuid        REFERENCES users(id) ON DELETE CASCADE,  -- set on approval
    expires_at       timestamptz NOT NULL,
    interval_seconds integer     NOT NULL DEFAULT 5,
    last_polled_at   timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now()
);
