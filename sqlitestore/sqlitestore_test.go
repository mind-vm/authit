package sqlitestore_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mind-vm/authit/sqlitestore"
	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/authit/storetest"
)

// fresh returns an empty, migrated Store in its own file under the test's
// temporary directory. Unlike pgstore's suite there is nothing to truncate:
// a new file is the empty store.
func fresh(t *testing.T) *sqlitestore.Store {
	t.Helper()
	s, err := sqlitestore.Open(context.Background(), filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestConformance runs auth's port contract against SQLite, with the same
// ports and fixtures pgstore's suite uses.
func TestConformance(t *testing.T) {
	// The suite calls a factory per subtest and the fixtures separately, so
	// the fixtures follow whichever store the factory handed out last.
	var cur *sqlitestore.Store
	empty := func(t *testing.T) *sqlitestore.Store {
		cur = fresh(t)
		return cur
	}
	ensure := func(table string) func(t *testing.T, id string) {
		return func(t *testing.T, id string) {
			t.Helper()
			now := time.Now().UTC().Format(time.RFC3339Nano)
			_, err := cur.DB().Exec(`INSERT INTO `+table+` (id, email, password_hash, created_at, updated_at)
				VALUES (?, ?, '', ?, ?) ON CONFLICT (id) DO NOTHING`, id, id+"@fixture.test", now, now)
			if err != nil {
				t.Fatal(err)
			}
		}
	}

	ensureUser := ensure("auth_users")
	// A fixture team is owned by a fixture user, and a fixture member
	// belongs to a team, so each creates what it hangs off first.
	ensureTeam := func(t *testing.T, id string) {
		t.Helper()
		ensureUser(t, fixtureOwner)
		now := time.Now().UTC().Format(time.RFC3339Nano)
		_, err := cur.DB().Exec(`INSERT INTO auth_teams (id, name, slug, owner_id, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING`, id, id, "fixture-"+id, fixtureOwner, now, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	ensureMember := func(t *testing.T, id, teamID string) {
		t.Helper()
		ensureTeam(t, teamID)
		now := time.Now().UTC().Format(time.RFC3339Nano)
		_, err := cur.DB().Exec(`INSERT INTO auth_team_members (id, team_id, role, created_at, updated_at)
			VALUES (?, ?, 'member', ?, ?) ON CONFLICT (id) DO NOTHING`, id, teamID, now, now)
		if err != nil {
			t.Fatal(err)
		}
	}

	storetest.RunAll(t, storetest.Stores{
		Fixtures: storetest.Fixtures{
			EnsureUser: ensureUser, EnsureTeam: ensureTeam, EnsureMember: ensureMember,
			EnsureSuperuser: ensure("auth_superusers"),
		},
		Users:              func(t *testing.T) store.UserStore { return empty(t) },
		RefreshTokens:      func(t *testing.T) store.RefreshTokenStore { return empty(t) },
		PasswordResets:     func(t *testing.T) store.PasswordResetStore { return empty(t) },
		EmailVerifications: func(t *testing.T) store.EmailVerificationStore { return empty(t) },
		TOTP:               func(t *testing.T) store.TOTPStore { return empty(t) },
		PendingTwoFactor:   func(t *testing.T) store.PendingTwoFactorStore { return empty(t) },
		Lockouts:           func(t *testing.T) store.LockoutStore { return empty(t) },
		Accounts:           func(t *testing.T) store.AccountStore { return empty(t) },
		WebAuthn:           func(t *testing.T) store.WebAuthnCredentialStore { return empty(t) },
		WebAuthnChallenges: func(t *testing.T) store.WebAuthnChallengeStore { return empty(t) },
		EmailLogins:        func(t *testing.T) store.EmailLoginStore { return empty(t) },
		Superusers:         func(t *testing.T) store.SuperuserStore { return empty(t) },
		SuperuserTokens:    func(t *testing.T) store.SuperuserRefreshTokenStore { return empty(t) },
		SuperuserTwoFactor: func(t *testing.T) store.SuperuserTwoFactorStore { return empty(t) },
		Teams:              func(t *testing.T) store.TeamStore { return empty(t) },
		Members:            func(t *testing.T) store.MemberStore { return empty(t) },
		Invitations:        func(t *testing.T) store.InvitationStore { return empty(t) },
		PATs:               func(t *testing.T) store.PersonalAccessTokenStore { return empty(t) },
		Devices:            func(t *testing.T) store.DeviceAuthorizationStore { return empty(t) },
	})
}

// fixtureOwner owns the teams the conformance fixtures create; the suite's
// own ids stop well short of it.
const fixtureOwner = "00000000-0000-4000-8000-0000000000fe"

// TestRunInTxRollsBack holds the TxRunner contract: a write made with fn's
// context is undone when fn fails, and the error comes back unchanged.
func TestRunInTxRollsBack(t *testing.T) {
	ctx := context.Background()
	s := fresh(t)
	boom := errors.New("boom")
	now := time.Now()
	u := &store.User{ID: "00000000-0000-4000-8000-000000000001", Email: "tx@example.com", CreatedAt: now, UpdatedAt: now}

	err := s.RunInTx(ctx, func(ctx context.Context) error {
		if err := s.CreateUser(ctx, u); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("RunInTx returned %v, want %v", err, boom)
	}
	if _, err := s.GetUserByID(ctx, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("user survived the rollback: %v", err)
	}
}

// TestRunInTxRollsBackOnPanic: a panic in fn must roll back before it
// propagates, and leave the database usable.
func TestRunInTxRollsBackOnPanic(t *testing.T) {
	ctx := context.Background()
	s := fresh(t)
	now := time.Now()
	u := &store.User{Email: "panic@example.com", CreatedAt: now, UpdatedAt: now}

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("the panic did not propagate")
			}
		}()
		_ = s.RunInTx(ctx, func(ctx context.Context) error {
			if err := s.CreateUser(ctx, u); err != nil {
				t.Fatal(err)
			}
			panic("boom")
		})
	}()
	if _, err := s.GetUserByEmail(ctx, u.Email); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("user survived the panic: %v", err)
	}
	if err := s.CreateUser(ctx, &store.User{Email: "after@example.com", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("store unusable after the panic: %v", err)
	}
}

// TestIDsAreCanonical: a uuid column in Postgres finds a row whatever the
// case of the id it is asked for. A TEXT column would not, so the store
// stores and looks up the canonical form.
func TestIDsAreCanonical(t *testing.T) {
	ctx := context.Background()
	s := fresh(t)
	now := time.Now()
	upper := "ABCDEF00-0000-4000-8000-000000000001"
	u := &store.User{ID: upper, Email: "case@example.com", CreatedAt: now, UpdatedAt: now}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if u.ID != strings.ToLower(upper) {
		t.Fatalf("Create left id %q, want the canonical %q", u.ID, strings.ToLower(upper))
	}
	for _, id := range []string{upper, strings.ToLower(upper)} {
		if _, err := s.GetUserByID(ctx, id); err != nil {
			t.Fatalf("GetUserByID(%q): %v", id, err)
		}
	}
}

// TestForeignKeysAreEnforced: SQLite ignores REFERENCES unless the
// connection turns them on, and the cascades are part of the schema.
func TestForeignKeysAreEnforced(t *testing.T) {
	ctx := context.Background()
	s := fresh(t)
	err := s.CreateRefreshToken(ctx, &store.RefreshToken{
		UserID: "00000000-0000-4000-8000-0000000000ff", TokenHash: "h",
		ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
	})
	if err == nil {
		t.Fatal("a refresh token for a missing user was accepted")
	}
}

// TestOpenRefusesMemory: database/sql opens a fresh in-memory database per
// connection, so writes would land in databases nobody reads.
func TestOpenRefusesMemory(t *testing.T) {
	if _, err := sqlitestore.Open(context.Background(), ":memory:"); err == nil {
		t.Fatal("Open accepted :memory:")
	}
}

// TestReopen: migrating an up-to-date file is a no-op, and its rows are
// still there.
func TestReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "auth.db")
	s, err := sqlitestore.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := s.CreateUser(ctx, &store.User{Email: "kept@example.com", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s, err = sqlitestore.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.GetUserByEmail(ctx, "kept@example.com"); err != nil {
		t.Fatalf("user lost across reopen: %v", err)
	}
}
