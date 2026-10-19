-- name: CreateEmailVerificationToken :exec
INSERT INTO auth.email_verification_tokens (id, user_id, token_hash, expires_at, used_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetEmailVerificationTokenByHash :one
SELECT * FROM auth.email_verification_tokens WHERE token_hash = $1;

-- name: MarkEmailVerificationTokenUsed :execrows
UPDATE auth.email_verification_tokens SET used_at = now() WHERE id = $1;

-- name: DeleteUserEmailVerificationTokens :exec
DELETE FROM auth.email_verification_tokens WHERE user_id = $1;
