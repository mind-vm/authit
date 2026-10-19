-- +goose Up

-- The team plane: teams, their members and the invitations to join them.

-- owner_id is the user who created the team, not its ownership, which lives
-- in the owner members. It carries no cascade: deleting that user must not
-- take a whole tenant with it, so it is refused until the team is handed on
-- or deleted.
CREATE TABLE auth.teams (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text        NOT NULL,
    slug       text        NOT NULL UNIQUE,
    owner_id   uuid        NOT NULL REFERENCES auth.users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- user_id is nullable so a team can track a member before a login exists.
-- One membership per (team, user); NULLs are distinct, so members without a
-- user do not collide.
CREATE TABLE auth.team_members (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id      uuid        NOT NULL REFERENCES auth.teams(id) ON DELETE CASCADE,
    user_id      uuid        REFERENCES auth.users(id) ON DELETE CASCADE,
    role         text        NOT NULL,
    display_name text        NOT NULL DEFAULT '',
    email        text        NOT NULL DEFAULT '',
    is_active    boolean     NOT NULL DEFAULT true,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (team_id, user_id)
);
CREATE INDEX team_members_user_id_idx ON auth.team_members (user_id);

-- invited_by_id names the inviting member, not a user: team.CreateInvitation
-- takes a member id. It is nullable because the inviter is optional (an
-- empty InvitedByID is NULL here), and a member leaving the team clears it
-- rather than withdrawing the invitations they sent.
CREATE TABLE auth.team_invitations (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id       uuid        NOT NULL REFERENCES auth.teams(id) ON DELETE CASCADE,
    email         text        NOT NULL,
    token_hash    text        NOT NULL UNIQUE,
    role          text        NOT NULL,
    status        text        NOT NULL DEFAULT 'pending',
    invited_by_id uuid        REFERENCES auth.team_members(id) ON DELETE SET NULL,
    expires_at    timestamptz NOT NULL,
    accepted_at   timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX team_invitations_team_id_idx ON auth.team_invitations (team_id);

-- +goose Down
DROP TABLE auth.team_invitations, auth.team_members, auth.teams;
