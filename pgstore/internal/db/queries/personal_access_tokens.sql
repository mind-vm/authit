-- name: CreatePersonalAccessToken :exec
INSERT INTO auth.personal_access_tokens (id, user_id, name, token_hash, scopes, expires_at,
    last_used_at, revoked_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: GetPersonalAccessToken :one
SELECT * FROM auth.personal_access_tokens WHERE id = $1;

-- Revoked and expired rows too: the service reads both columns itself.
-- name: GetPersonalAccessTokenByHash :one
SELECT * FROM auth.personal_access_tokens WHERE token_hash = $1;

-- name: ListPersonalAccessTokensByUser :many
SELECT * FROM auth.personal_access_tokens WHERE user_id = $1 ORDER BY created_at, id;

-- name: UpdatePersonalAccessToken :execrows
UPDATE auth.personal_access_tokens
SET user_id = $2, name = $3, token_hash = $4, scopes = $5, expires_at = $6,
    last_used_at = $7, revoked_at = $8
WHERE id = $1;
