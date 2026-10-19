-- +goose Up

-- The team a session acts in (user.Service.SwitchTeam), NULL for none.
-- Deleting the team ends the sessions acting in it.
ALTER TABLE auth_refresh_tokens ADD COLUMN team_id TEXT REFERENCES auth_teams(id) ON DELETE CASCADE;

-- +goose Down
ALTER TABLE auth_refresh_tokens DROP COLUMN team_id;
