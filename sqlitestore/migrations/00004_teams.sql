-- +goose Up

-- The team plane: teams, their members and the invitations to join them.
-- Columns follow pgstore's 00004_teams.sql one for one.

-- owner_id is the user who created the team, not its ownership, which lives
-- in the owner members. It carries no cascade: deleting that user must not
-- take a whole tenant with it, so it is refused until the team is handed on
-- or deleted.
CREATE TABLE auth_teams (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    slug       TEXT NOT NULL UNIQUE,
    owner_id   TEXT NOT NULL REFERENCES auth_users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- user_id is nullable so a team can track a member before a login exists.
-- One membership per (team, user); SQLite treats NULLs as distinct, so
-- members without a user do not collide.
CREATE TABLE auth_team_members (
    id           TEXT    PRIMARY KEY,
    team_id      TEXT    NOT NULL REFERENCES auth_teams(id) ON DELETE CASCADE,
    user_id      TEXT    REFERENCES auth_users(id) ON DELETE CASCADE,
    role         TEXT    NOT NULL,
    display_name TEXT    NOT NULL DEFAULT '',
    email        TEXT    NOT NULL DEFAULT '',
    is_active    INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT    NOT NULL,
    updated_at   TEXT    NOT NULL,
    UNIQUE (team_id, user_id)
);
CREATE INDEX auth_team_members_user_id_idx ON auth_team_members (user_id);

-- invited_by_id names the inviting member, not a user: team.CreateInvitation
-- takes a member id. It is nullable because the inviter is optional (an
-- empty InvitedByID is NULL here), and a member leaving the team clears it
-- rather than withdrawing the invitations they sent.
CREATE TABLE auth_team_invitations (
    id            TEXT PRIMARY KEY,
    team_id       TEXT NOT NULL REFERENCES auth_teams(id) ON DELETE CASCADE,
    email         TEXT NOT NULL,
    token_hash    TEXT NOT NULL UNIQUE,
    role          TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    invited_by_id TEXT REFERENCES auth_team_members(id) ON DELETE SET NULL,
    expires_at    TEXT NOT NULL,
    accepted_at   TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
CREATE INDEX auth_team_invitations_team_id_idx ON auth_team_invitations (team_id);

-- +goose Down
DROP TABLE auth_team_invitations;
DROP TABLE auth_team_members;
DROP TABLE auth_teams;
