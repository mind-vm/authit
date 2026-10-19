-- name: CreateAccount :exec
INSERT INTO auth.accounts (id, user_id, provider, provider_account_id, email, email_verified,
    access_token_encrypted, refresh_token_encrypted, token_expires_at, scopes, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: GetAccount :one
SELECT * FROM auth.accounts WHERE id = $1;

-- name: GetAccountByProvider :one
SELECT * FROM auth.accounts WHERE provider = $1 AND provider_account_id = $2;

-- name: ListAccountsByUser :many
SELECT * FROM auth.accounts WHERE user_id = $1 ORDER BY created_at, id;

-- name: UpdateAccount :execrows
UPDATE auth.accounts
SET user_id = $2, provider = $3, provider_account_id = $4, email = $5, email_verified = $6,
    access_token_encrypted = $7, refresh_token_encrypted = $8, token_expires_at = $9,
    scopes = $10, updated_at = $11
WHERE id = $1;

-- name: DeleteAccount :execrows
DELETE FROM auth.accounts WHERE id = $1;
