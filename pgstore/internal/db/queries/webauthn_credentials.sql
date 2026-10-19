-- name: CreateWebAuthnCredential :exec
INSERT INTO auth.webauthn_credentials (id, user_id, credential_id, data, name, transports,
    backup_eligible, backup_state, clone_warning, last_used_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: GetWebAuthnCredential :one
SELECT * FROM auth.webauthn_credentials WHERE id = $1;

-- name: GetWebAuthnCredentialByCredentialID :one
SELECT * FROM auth.webauthn_credentials WHERE credential_id = $1;

-- name: ListWebAuthnCredentialsByUser :many
SELECT * FROM auth.webauthn_credentials WHERE user_id = $1 ORDER BY created_at, id;

-- name: UpdateWebAuthnCredential :execrows
UPDATE auth.webauthn_credentials
SET credential_id = $2, data = $3, name = $4, transports = $5, backup_eligible = $6,
    backup_state = $7, clone_warning = $8, last_used_at = $9, updated_at = $10
WHERE id = $1;

-- name: DeleteWebAuthnCredential :execrows
DELETE FROM auth.webauthn_credentials WHERE id = $1;
