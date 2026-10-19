-- name: CreateInvitation :exec
INSERT INTO auth.team_invitations (id, team_id, email, token_hash, role, status, invited_by_id,
    expires_at, accepted_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- name: GetInvitation :one
SELECT * FROM auth.team_invitations WHERE id = $1;

-- Every status, not only pending: the service reads Status to refuse a
-- revoked or accepted invitation.
-- name: GetInvitationByTokenHash :one
SELECT * FROM auth.team_invitations WHERE token_hash = $1;

-- name: ListInvitationsByTeam :many
SELECT * FROM auth.team_invitations WHERE team_id = $1 ORDER BY created_at, id;

-- name: UpdateInvitation :execrows
UPDATE auth.team_invitations
SET email = $2, token_hash = $3, role = $4, status = $5, invited_by_id = $6,
    expires_at = $7, accepted_at = $8, updated_at = $9
WHERE id = $1;
