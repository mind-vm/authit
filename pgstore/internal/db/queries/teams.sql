-- name: CreateTeam :exec
INSERT INTO auth.teams (id, name, slug, owner_id, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetTeam :one
SELECT * FROM auth.teams WHERE id = $1;

-- name: GetTeamBySlug :one
SELECT * FROM auth.teams WHERE slug = $1;

-- name: UpdateTeam :execrows
UPDATE auth.teams SET name = $2, slug = $3, owner_id = $4, updated_at = $5 WHERE id = $1;

-- name: DeleteTeam :execrows
DELETE FROM auth.teams WHERE id = $1;
