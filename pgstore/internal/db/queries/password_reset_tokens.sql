-- name: CreatePasswordResetToken :exec
INSERT INTO auth.password_reset_tokens (id, user_id, token_hash, expires_at, used_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetPasswordResetTokenByHash :one
SELECT * FROM auth.password_reset_tokens WHERE token_hash = $1;

-- name: MarkPasswordResetTokenUsed :execrows
UPDATE auth.password_reset_tokens SET used_at = now() WHERE id = $1;

-- name: DeleteUserPasswordResetTokens :exec
DELETE FROM auth.password_reset_tokens WHERE user_id = $1;
