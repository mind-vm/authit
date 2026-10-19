-- name: CreateSuperuser :exec
INSERT INTO auth.superusers (id, email, password_hash, display_name, is_active, created_by, last_login_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: GetSuperuserByID :one
SELECT * FROM auth.superusers WHERE id = $1;

-- name: GetSuperuserByEmail :one
SELECT * FROM auth.superusers WHERE email = $1;

-- name: ListSuperusers :many
SELECT * FROM auth.superusers ORDER BY created_at, id;

-- name: UpdateSuperuser :execrows
UPDATE auth.superusers
SET email = $2, password_hash = $3, display_name = $4, is_active = $5,
    last_login_at = $6, updated_at = $7
WHERE id = $1;

-- name: CountSuperusers :one
SELECT count(*) FROM auth.superusers;
