-- name: CreatePendingTwoFactorSession :exec
INSERT INTO auth.pending_two_factor_sessions (id, user_id, token_hash, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5);

-- name: GetPendingTwoFactorSessionByHash :one
SELECT * FROM auth.pending_two_factor_sessions WHERE token_hash = $1;

-- name: DeletePendingTwoFactorSession :exec
DELETE FROM auth.pending_two_factor_sessions WHERE id = $1;
