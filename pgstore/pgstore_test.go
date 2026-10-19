package pgstore_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mind-vm/authit/internal/pgtest"
	"github.com/mind-vm/authit/pgstore"
	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/authit/storetest"
)

// TestConformance runs auth's port contract against Postgres. One database
// serves the whole suite; each factory call truncates it, which is what
// "return an empty store" means here.
func TestConformance(t *testing.T) {
	pool := pgtest.Pool(t, pgstore.Migrate)
	s := pgstore.New(pool)
	empty := func(t *testing.T) *pgstore.Store {
		t.Helper()
		_, err := pool.Exec(context.Background(), `TRUNCATE auth.users, auth.failed_login_attempts,
			auth.email_login_tokens, auth.webauthn_challenges, auth.superusers CASCADE`)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	storetest.RunAll(t, storetest.Stores{
		Fixtures: storetest.Fixtures{
			EnsureUser: ensureUser(pool), EnsureTeam: ensureTeam(pool), EnsureMember: ensureMember(pool),
			EnsureSuperuser: ensureSuperuser(pool),
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
	})
}

// fixtureOwner owns the teams the conformance fixtures create; the suite's
// own ids stop well short of it.
const fixtureOwner = "00000000-0000-4000-8000-0000000000fe"

// ensureTeam satisfies the foreign keys to auth.teams, owned by a fixture
// user.
func ensureTeam(pool *pgxpool.Pool) func(t *testing.T, teamID string) {
	return func(t *testing.T, teamID string) {
		t.Helper()
		ensureUser(pool)(t, fixtureOwner)
		_, err := pool.Exec(context.Background(), `INSERT INTO auth.teams (id, name, slug, owner_id)
			VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING`, teamID, teamID, "fixture-"+teamID, fixtureOwner)
		if err != nil {
			t.Fatal(err)
		}
	}
}

// ensureMember satisfies the foreign key from an invitation to the member
// who sent it.
func ensureMember(pool *pgxpool.Pool) func(t *testing.T, memberID, teamID string) {
	return func(t *testing.T, memberID, teamID string) {
		t.Helper()
		ensureTeam(pool)(t, teamID)
		_, err := pool.Exec(context.Background(), `INSERT INTO auth.team_members (id, team_id, role)
			VALUES ($1, $2, 'member') ON CONFLICT (id) DO NOTHING`, memberID, teamID)
		if err != nil {
			t.Fatal(err)
		}
	}
}

// ensureSuperuser satisfies the foreign key from auth.superuser_refresh_tokens
// that the ports do not mention.
func ensureSuperuser(pool *pgxpool.Pool) func(t *testing.T, superuserID string) {
	return func(t *testing.T, superuserID string) {
		t.Helper()
		_, err := pool.Exec(context.Background(), `INSERT INTO auth.superusers (id, email, password_hash)
			VALUES ($1, $2, '') ON CONFLICT (id) DO NOTHING`, superuserID, superuserID+"@fixture.test")
		if err != nil {
			t.Fatal(err)
		}
	}
}

// ensureUser satisfies the foreign keys to auth.users that the ports do not
// mention.
func ensureUser(pool *pgxpool.Pool) func(t *testing.T, userID string) {
	return func(t *testing.T, userID string) {
		t.Helper()
		_, err := pool.Exec(context.Background(), `INSERT INTO auth.users (id, email, password_hash)
			VALUES ($1, $2, '') ON CONFLICT (id) DO NOTHING`, userID, userID+"@fixture.test")
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestRunInTxRollsBack holds the TxRunner contract: a write made with fn's
// context is undone when fn fails, and the error comes back unchanged.
func TestRunInTxRollsBack(t *testing.T) {
	ctx := context.Background()
	s := pgstore.New(pgtest.Pool(t, pgstore.Migrate))
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
