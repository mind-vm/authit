-- name: CreateDeviceAuthorization :exec
INSERT INTO auth.device_authorizations (id, device_code_hash, user_code, client_id, scope, status,
    user_id, expires_at, interval_seconds, last_polled_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- name: GetDeviceAuthorizationByDeviceCodeHash :one
SELECT * FROM auth.device_authorizations WHERE device_code_hash = $1;

-- name: GetDeviceAuthorizationByUserCode :one
SELECT * FROM auth.device_authorizations WHERE user_code = $1;

-- name: UpdateDeviceAuthorization :execrows
UPDATE auth.device_authorizations
SET device_code_hash = $2, user_code = $3, client_id = $4, scope = $5, status = $6,
    user_id = $7, expires_at = $8, interval_seconds = $9, last_polled_at = $10
WHERE id = $1;

-- name: DeleteDeviceAuthorization :exec
DELETE FROM auth.device_authorizations WHERE id = $1;
