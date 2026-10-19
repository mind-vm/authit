-- name: CreateSuperuserTOTPSettings :exec
INSERT INTO auth.superuser_totp_settings (id, superuser_id, secret_encrypted, enabled, verified_at, recovery_code_hashes, recovery_codes_used, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: GetSuperuserTOTPSettings :one
SELECT * FROM auth.superuser_totp_settings WHERE superuser_id = $1;

-- name: UpdateSuperuserTOTPSettings :execrows
UPDATE auth.superuser_totp_settings
SET secret_encrypted = $2, enabled = $3, verified_at = $4, recovery_code_hashes = $5,
    recovery_codes_used = $6, updated_at = $7
WHERE superuser_id = $1;

-- name: DeleteSuperuserTOTPSettings :exec
DELETE FROM auth.superuser_totp_settings WHERE superuser_id = $1;

-- name: CreateSuperuserPendingTwoFactorSession :exec
INSERT INTO auth.superuser_pending_two_factor_sessions (id, superuser_id, token_hash, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5);

-- name: GetSuperuserPendingTwoFactorSessionByHash :one
SELECT * FROM auth.superuser_pending_two_factor_sessions WHERE token_hash = $1;

-- name: DeleteSuperuserPendingTwoFactorSession :exec
DELETE FROM auth.superuser_pending_two_factor_sessions WHERE id = $1;
