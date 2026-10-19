-- name: CreateRefreshToken :exec
INSERT INTO auth.refresh_tokens (id, user_id, token_hash, expires_at, revoked_at, user_agent, ip_address, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetRefreshTokenByHash :one
SELECT * FROM auth.refresh_tokens WHERE token_hash = $1;

-- name: RevokeRefreshToken :execrows
UPDATE auth.refresh_tokens SET revoked_at = COALESCE(revoked_at, now()) WHERE id = $1;

-- Revokes only a live token, so of concurrent refreshes exactly one matches.
-- name: ConsumeRefreshToken :execrows
UPDATE auth.refresh_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL;

-- A revoked session must not be extended back to life.
-- name: TouchRefreshToken :execrows
UPDATE auth.refresh_tokens SET expires_at = $2 WHERE id = $1 AND revoked_at IS NULL;

-- name: RevokeAllUserRefreshTokens :exec
UPDATE auth.refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL;

-- name: ListActiveRefreshTokens :many
SELECT * FROM auth.refresh_tokens
WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
ORDER BY created_at, id;
