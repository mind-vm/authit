-- +goose Up

-- The team a session acts in (user.Service.SwitchTeam), NULL for none.
-- Deleting the team ends the sessions acting in it.
ALTER TABLE auth.refresh_tokens ADD COLUMN team_id uuid REFERENCES auth.teams(id) ON DELETE CASCADE;

-- +goose Down
ALTER TABLE auth.refresh_tokens DROP COLUMN team_id;
