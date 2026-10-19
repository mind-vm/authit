-- name: CreateEmailLoginToken :exec
INSERT INTO auth.email_login_tokens (id, email, kind, token_hash, attempts, expires_at, used_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetEmailLoginTokenByHash :one
SELECT * FROM auth.email_login_tokens WHERE token_hash = $1;

-- name: GetEmailLoginTokenByEmail :one
SELECT * FROM auth.email_login_tokens
WHERE email = $1 AND kind = $2
ORDER BY created_at DESC, id DESC
LIMIT 1;

-- Compare-and-set: no rows means another redemption won.
-- name: MarkEmailLoginTokenUsed :execrows
UPDATE auth.email_login_tokens SET used_at = $2 WHERE id = $1 AND used_at IS NULL;

-- The database computes the count so parallel guesses each cost one.
-- name: IncrementEmailLoginTokenAttempts :one
UPDATE auth.email_login_tokens SET attempts = attempts + 1 WHERE id = $1 RETURNING attempts;

-- name: DeleteEmailLoginTokens :exec
DELETE FROM auth.email_login_tokens WHERE email = $1 AND kind = $2;
