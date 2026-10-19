-- name: CreateUser :exec
INSERT INTO auth.users (id, email, password_hash, email_verified, email_verified_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: GetUserByID :one
SELECT * FROM auth.users WHERE id = $1;

-- name: GetUserByEmail :one
SELECT * FROM auth.users WHERE email = $1;

-- name: UpdateUser :execrows
UPDATE auth.users
SET email = $2, password_hash = $3, email_verified = $4, email_verified_at = $5, updated_at = $6
WHERE id = $1;
