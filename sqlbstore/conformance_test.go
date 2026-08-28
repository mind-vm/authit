package sqlbstore_test

import (
	"context"
	"testing"

	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/authit/storetest"
)

// userPlaneTables is every table the user plane touches, in an order safe
// to truncate together.
var userPlaneTables = []string{
	"users", "refresh_tokens", "password_reset_tokens", "email_verification_tokens",
	"totp_settings", "pending_two_factor_sessions", "failed_login_attempts", "account_locks",
}

// TestReferenceSchemaConformance runs the shared store conformance suite
// against the example adapters over ../schema.sql.
//
// TestExampleUserStoresAgainstReferenceSchema already drives the real user
// flows over the same wiring, but a flow test only exercises the paths the
// service happens to take. The conformance suite asserts the contract
// directly -- that a missing row is store.ErrNotFound and not pgx.ErrNoRows,
// that a revoked refresh token is still returned by hash, that `since`
// actually filters -- which is where an adapter goes wrong in ways a happy
// path never notices.
//
// Skips without MYBRAIN_DATABASE_URL, like every other test in this file.
func TestReferenceSchemaConformance(t *testing.T) {
	db, pool := referenceSchemaPool(t)
	stores := exampleUserStores(db)

	// The suite wants an empty store per subtest. Recreating the schema
	// each time would be correct and slow; truncating is neither
	// observably different nor slow.
	fresh := func(t *testing.T) {
		t.Helper()
		for _, table := range userPlaneTables {
			if _, err := pool.Exec(context.Background(), "TRUNCATE "+table+" CASCADE"); err != nil {
				t.Fatalf("truncating %s: %v", table, err)
			}
		}
	}

	// schema.sql declares real foreign keys, so a refresh token for a user
	// that does not exist is rejected by the database rather than accepted
	// as the in-memory stores accept it. This is exactly what
	// storetest.Fixtures is for.
	ensureUser := func(t *testing.T, userID string) {
		t.Helper()
		_, err := pool.Exec(context.Background(),
			`INSERT INTO users (id, email, password_hash) VALUES ($1, $2, 'x')
			 ON CONFLICT (id) DO NOTHING`,
			userID, userID+"@example.com")
		if err != nil {
			t.Fatalf("creating fixture user %s: %v", userID, err)
		}
	}

	storetest.RunAll(t, storetest.Stores{
		Fixtures: storetest.Fixtures{EnsureUser: ensureUser},
		Users: func(t *testing.T) store.UserStore {
			fresh(t)
			return stores.Users
		},
		RefreshTokens: func(t *testing.T) store.RefreshTokenStore {
			fresh(t)
			return stores.RefreshTokens
		},
		PasswordResets: func(t *testing.T) store.PasswordResetStore {
			fresh(t)
			return stores.PasswordResets
		},
		EmailVerifications: func(t *testing.T) store.EmailVerificationStore {
			fresh(t)
			return stores.EmailVerifications
		},
		TOTP: func(t *testing.T) store.TOTPStore {
			fresh(t)
			return stores.TOTP
		},
		PendingTwoFactor: func(t *testing.T) store.PendingTwoFactorStore {
			fresh(t)
			return stores.PendingTwoFactor
		},
		Lockouts: func(t *testing.T) store.LockoutStore {
			fresh(t)
			return stores.Lockouts
		},
	})
}
