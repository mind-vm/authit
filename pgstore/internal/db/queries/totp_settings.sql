-- name: CreateTOTPSettings :exec
INSERT INTO auth.totp_settings (id, user_id, secret_encrypted, enabled, verified_at, recovery_code_hashes, recovery_codes_used, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: GetTOTPSettingsByUserID :one
SELECT * FROM auth.totp_settings WHERE user_id = $1;

-- name: UpdateTOTPSettings :execrows
UPDATE auth.totp_settings
SET secret_encrypted = $2, enabled = $3, verified_at = $4, recovery_code_hashes = $5,
    recovery_codes_used = $6, updated_at = $7
WHERE user_id = $1;

-- name: DeleteTOTPSettings :exec
DELETE FROM auth.totp_settings WHERE user_id = $1;
