-- A replaced PIN keeps the row's created_at.
-- name: SetPINCredential :exec
INSERT INTO auth.pin_credentials (user_id, pin_hash, created_at, updated_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (user_id) DO UPDATE SET pin_hash = EXCLUDED.pin_hash, updated_at = EXCLUDED.updated_at;

-- name: GetPINCredential :one
SELECT * FROM auth.pin_credentials WHERE user_id = $1;

-- name: DeletePINCredential :exec
DELETE FROM auth.pin_credentials WHERE user_id = $1;

-- name: CreateBoundDevice :exec
INSERT INTO auth.bound_devices (id, user_id, name, token_hash, user_agent, ip_address,
    expires_at, last_used_at, revoked_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: GetBoundDevice :one
SELECT * FROM auth.bound_devices WHERE id = $1;

-- Revoked and expired devices too: the service reads both columns itself.
-- name: GetBoundDeviceByTokenHash :one
SELECT * FROM auth.bound_devices WHERE token_hash = $1;

-- name: ListBoundDevicesByUser :many
SELECT * FROM auth.bound_devices WHERE user_id = $1 ORDER BY created_at, id;

-- A revoked device is not touched, so a use racing a revocation cannot
-- write over it.
-- name: TouchBoundDevice :execrows
UPDATE auth.bound_devices SET last_used_at = $2 WHERE id = $1 AND revoked_at IS NULL;

-- name: RevokeBoundDevice :execrows
UPDATE auth.bound_devices SET revoked_at = COALESCE(revoked_at, $2) WHERE id = $1;

-- name: RevokeAllBoundDevices :execrows
UPDATE auth.bound_devices SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL;
