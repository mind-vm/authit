-- name: RecordFailedLoginAttempt :exec
INSERT INTO auth.failed_login_attempts (id, email, ip_address, created_at)
VALUES ($1, $2, $3, $4);

-- name: CountRecentFailedLoginAttempts :one
SELECT count(*) FROM auth.failed_login_attempts WHERE email = $1 AND created_at > $2;

-- name: ClearFailedLoginAttempts :exec
DELETE FROM auth.failed_login_attempts WHERE email = $1;
