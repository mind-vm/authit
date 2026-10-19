-- name: CreateWebAuthnChallenge :exec
INSERT INTO auth.webauthn_challenges (id, token_hash, user_id, data, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- The DELETE decides, so two concurrent redemptions cannot both get the row.
-- name: ConsumeWebAuthnChallenge :one
DELETE FROM auth.webauthn_challenges WHERE token_hash = $1 RETURNING *;
