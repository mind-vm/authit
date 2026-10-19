-- name: CreateMember :exec
INSERT INTO auth.team_members (id, team_id, user_id, role, display_name, email, is_active, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: GetMember :one
SELECT * FROM auth.team_members WHERE id = $1;

-- name: GetMemberByUserAndTeam :one
SELECT * FROM auth.team_members WHERE user_id = $1 AND team_id = $2;

-- name: ListMembersByTeam :many
SELECT * FROM auth.team_members WHERE team_id = $1 ORDER BY created_at, id;

-- The same list, locking the rows it returns. Run inside a transaction it
-- makes team.Service's last-owner check and the write it guards one step:
-- two owners demoting each other at once queue on these locks, and the
-- second sees the first's write, where READ COMMITTED would let both pass.
-- name: ListMembersByTeamForUpdate :many
SELECT * FROM auth.team_members WHERE team_id = $1 ORDER BY created_at, id FOR UPDATE;

-- name: ListMembershipsByUser :many
SELECT * FROM auth.team_members WHERE user_id = $1 ORDER BY created_at, id;

-- name: UpdateMember :execrows
UPDATE auth.team_members
SET user_id = $2, role = $3, display_name = $4, email = $5, is_active = $6, updated_at = $7
WHERE id = $1;

-- name: DeleteMember :execrows
DELETE FROM auth.team_members WHERE id = $1;
