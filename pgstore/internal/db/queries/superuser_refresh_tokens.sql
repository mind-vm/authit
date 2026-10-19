-- name: CreateSuperuserRefreshToken :exec
INSERT INTO auth.superuser_refresh_tokens (id, superuser_id, token_hash, expires_at, revoked_at, user_agent, ip_address, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetSuperuserRefreshTokenByHash :one
SELECT * FROM auth.superuser_refresh_tokens WHERE token_hash = $1;

-- name: RevokeSuperuserRefreshToken :execrows
UPDATE auth.superuser_refresh_tokens SET revoked_at = COALESCE(revoked_at, now()) WHERE id = $1;

-- name: ConsumeSuperuserRefreshToken :execrows
UPDATE auth.superuser_refresh_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL;

-- name: RevokeAllSuperuserRefreshTokens :exec
UPDATE auth.superuser_refresh_tokens SET revoked_at = now() WHERE superuser_id = $1 AND revoked_at IS NULL;

-- name: ListActiveSuperuserRefreshTokens :many
SELECT * FROM auth.superuser_refresh_tokens
WHERE superuser_id = $1 AND revoked_at IS NULL AND expires_at > now()
ORDER BY created_at, id;
