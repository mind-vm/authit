package sqlbstore

import (
	"context"
	"time"

	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/sqlb"
)

// LockoutAdapter implements store.LockoutStore over two app tables: A for
// failed-login attempts (fits Table[A, store.FailedLoginAttempt] like
// every other adapter) and L for the set of currently-locked accounts.
//
// L has no canonical authit type — LockAccount/IsAccountLocked/
// UnlockAccount are pure existence operations ("is this user_id present in
// the locks table"), not a CRUD-over-a-struct concern — so unlike every
// other adapter in this package, L's shape is entirely the host app's own
// (NewLockRow constructs whatever row it needs, e.g. just a user_id column
// and a locked_at default), and Lock/IsLocked/Unlock talk to it with raw
// sqlb calls rather than through Table.
type LockoutAdapter[A, L any] struct {
	Attempts               Table[A, store.FailedLoginAttempt]
	AttemptsDB             sqlb.Executor
	AttemptEmailColumn     string
	AttemptCreatedAtColumn string

	LocksDB          sqlb.Executor
	NewLockRow       func(userID string) L
	LockUserIDColumn string
}

func (a LockoutAdapter[A, L]) RecordFailedLoginAttempt(ctx context.Context, at *store.FailedLoginAttempt) error {
	v, err := a.Attempts.Create(ctx, a.AttemptsDB, *at)
	if err != nil {
		return err
	}
	*at = v
	return nil
}

func (a LockoutAdapter[A, L]) CountRecentFailedLoginAttempts(ctx context.Context, email string, since time.Time) (int, error) {
	n, err := a.Attempts.CountWhere(ctx, a.AttemptsDB,
		sqlb.F(a.AttemptEmailColumn).Eq(email), sqlb.F(a.AttemptCreatedAtColumn).Gt(since))
	return int(n), err
}

func (a LockoutAdapter[A, L]) ClearFailedLoginAttempts(ctx context.Context, email string) error {
	_, err := a.Attempts.DeleteWhere(ctx, a.AttemptsDB, sqlb.F(a.AttemptEmailColumn).Eq(email))
	return err
}

func (a LockoutAdapter[A, L]) LockAccount(ctx context.Context, userID string) error {
	row := a.NewLockRow(userID)
	// OnConflictDoNothing rather than a check-then-insert: locking an
	// already-locked account is idempotent, not an error, and the unique
	// constraint on LockUserIDColumn is what actually decides.
	_, err := sqlb.InsertRows(&row).OnConflictDoNothing(a.LockUserIDColumn).Exec(ctx, a.LocksDB)
	return err
}

func (a LockoutAdapter[A, L]) IsAccountLocked(ctx context.Context, userID string) (bool, error) {
	return sqlb.Query[L]().Where(sqlb.F(a.LockUserIDColumn).Eq(userID)).Exists(ctx, a.LocksDB)
}

func (a LockoutAdapter[A, L]) UnlockAccount(ctx context.Context, userID string) error {
	_, err := sqlb.DeleteRows[L]().Where(sqlb.F(a.LockUserIDColumn).Eq(userID)).Exec(ctx, a.LocksDB)
	return err
}
