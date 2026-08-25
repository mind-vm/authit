package sqlbstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/mind-vm/authit/sqlbstore"
	"github.com/mind-vm/authit/store"
)

type testFailedAttempt struct {
	ID        string    `db:"id" sqlb:"type:uuid,pk,default"`
	Email     string    `db:"email" sqlb:"type:text"`
	CreatedAt time.Time `db:"created_at" sqlb:"type:timestamptz,default"`
}

func (testFailedAttempt) TableName() string { return "sqlbstore_test_failed_attempts" }

type testLock struct {
	UserID   string    `db:"user_id" sqlb:"type:uuid,pk"`
	LockedAt time.Time `db:"locked_at" sqlb:"type:timestamptz,default"`
}

func (testLock) TableName() string { return "sqlbstore_test_account_locks" }

func TestLockoutAdapter(t *testing.T) {
	pool := testPool(t)
	db := applyDDL(t, pool, `
		CREATE TABLE IF NOT EXISTS sqlbstore_test_failed_attempts (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			email text NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now()
		);
		CREATE TABLE IF NOT EXISTS sqlbstore_test_account_locks (
			user_id uuid PRIMARY KEY,
			locked_at timestamptz NOT NULL DEFAULT now()
		)`, "sqlbstore_test_failed_attempts", "sqlbstore_test_account_locks")

	a := sqlbstore.LockoutAdapter[testFailedAttempt, testLock]{
		Attempts: sqlbstore.Table[testFailedAttempt, store.FailedLoginAttempt]{
			ToRow: func(f store.FailedLoginAttempt) testFailedAttempt {
				return testFailedAttempt{Email: f.Email}
			},
			FromRow: func(r testFailedAttempt) store.FailedLoginAttempt {
				return store.FailedLoginAttempt{ID: r.ID, Email: r.Email, CreatedAt: r.CreatedAt}
			},
			GetID:    func(f store.FailedLoginAttempt) string { return f.ID },
			SetID:    func(r testFailedAttempt, id string) testFailedAttempt { r.ID = id; return r },
			IDColumn: "id",
		},
		AttemptsDB:             db,
		AttemptEmailColumn:     "email",
		AttemptCreatedAtColumn: "created_at",

		LocksDB:          db,
		NewLockRow:       func(userID string) testLock { return testLock{UserID: userID} },
		LockUserIDColumn: "user_id",
	}
	ctx := context.Background()

	email := "locked-out@example.com"
	since := time.Now().Add(-time.Minute)

	for range 3 {
		if err := a.RecordFailedLoginAttempt(ctx, &store.FailedLoginAttempt{Email: email}); err != nil {
			t.Fatalf("RecordFailedLoginAttempt: %v", err)
		}
	}
	if err := a.RecordFailedLoginAttempt(ctx, &store.FailedLoginAttempt{Email: "someone-else@example.com"}); err != nil {
		t.Fatalf("RecordFailedLoginAttempt (other email): %v", err)
	}

	count, err := a.CountRecentFailedLoginAttempts(ctx, email, since)
	if err != nil {
		t.Fatalf("CountRecentFailedLoginAttempts: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 recent attempts, got %d", count)
	}

	userID := "33333333-3333-3333-3333-333333333333"
	locked, err := a.IsAccountLocked(ctx, userID)
	if err != nil {
		t.Fatalf("IsAccountLocked: %v", err)
	}
	if locked {
		t.Fatal("expected account not locked yet")
	}

	if err := a.LockAccount(ctx, userID); err != nil {
		t.Fatalf("LockAccount: %v", err)
	}
	// Locking twice must be idempotent (OnConflictDoNothing), not an error.
	if err := a.LockAccount(ctx, userID); err != nil {
		t.Fatalf("LockAccount (second call): %v", err)
	}

	locked, err = a.IsAccountLocked(ctx, userID)
	if err != nil {
		t.Fatalf("IsAccountLocked (after lock): %v", err)
	}
	if !locked {
		t.Fatal("expected account to be locked")
	}

	if err := a.ClearFailedLoginAttempts(ctx, email); err != nil {
		t.Fatalf("ClearFailedLoginAttempts: %v", err)
	}
	count, err = a.CountRecentFailedLoginAttempts(ctx, email, since)
	if err != nil {
		t.Fatalf("CountRecentFailedLoginAttempts (after clear): %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 attempts after clear, got %d", count)
	}

	if err := a.UnlockAccount(ctx, userID); err != nil {
		t.Fatalf("UnlockAccount: %v", err)
	}
	locked, err = a.IsAccountLocked(ctx, userID)
	if err != nil {
		t.Fatalf("IsAccountLocked (after unlock): %v", err)
	}
	if locked {
		t.Fatal("expected account unlocked")
	}
}
