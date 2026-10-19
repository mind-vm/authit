-- name: LockAccount :exec
INSERT INTO auth.account_locks (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING;

-- name: IsAccountLocked :one
SELECT EXISTS (SELECT 1 FROM auth.account_locks WHERE user_id = $1);

-- name: UnlockAccount :exec
DELETE FROM auth.account_locks WHERE user_id = $1;
