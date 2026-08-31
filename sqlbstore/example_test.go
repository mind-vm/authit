package sqlbstore_test

// This file drives the reference binding through authit's real user flows.
//
// The wiring itself used to live here, which meant the worked example was
// something you copied out of a test file and the tests exercised a private
// copy of it. Both halves of that were bad, and the second one hid a bug:
// see refschema's package doc. It is now an ordinary importable package,
// and this file is only its test.
//
// What remains here is the part that cannot move: applying ../schema.sql
// verbatim to a real database and running the flows over it, so the
// reference schema is checked rather than merely believed. It skips when no
// Postgres DSN is configured -- and a skipped run is not a passing one, as
// this package's own history shows.

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/sqlbstore/refschema"
	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/authit/user"
	"github.com/mind-vm/sqlb"
)

// These two indirections keep the tests below reading as they did. Read
// refschema for the worked example: a Table[R, T] carrying the two-way
// conversion, plus the handful of column names each adapter needs beyond
// the primary key in order to filter.

func exampleUserStores(db sqlb.Executor) user.Stores {
	return refschema.UserStores(db)
}

func exampleWebAuthnChallenges(db sqlb.Executor) store.WebAuthnChallengeStore {
	return refschema.WebAuthnChallenges(db)
}

func exampleSigner(t *testing.T) authitjwt.Signer {
	t.Helper()
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	signer, err := authitjwt.NewHMACSigner(secret, authitjwt.Defaults{Issuer: "authit-example", TTL: time.Minute})
	if err != nil {
		t.Fatalf("NewHMACSigner: %v", err)
	}
	return signer
}

// TestExampleUserStoresSatisfyUserService needs no database: it checks that
// the wiring above is a complete, correctly-typed set of ports, which is the
// part a reader is most likely to get wrong by omission.
func TestExampleUserStoresSatisfyUserService(t *testing.T) {
	if _, err := user.NewService(exampleUserStores(nil), exampleSigner(t), nil, user.Config{}); err != nil {
		t.Fatalf("the example wiring should satisfy user.NewService: %v", err)
	}
}

// referenceSchemaPool applies ../schema.sql into a throwaway Postgres schema
// and returns an executor scoped to it, so the reference schema is exercised
// under its real table names without colliding with anything in the target
// database.
func referenceSchemaPool(t *testing.T) (sqlb.Executor, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("MYBRAIN_DATABASE_URL")
	if dsn == "" {
		t.Skip("MYBRAIN_DATABASE_URL not set; skipping reference-schema integration test")
		return nil, nil
	}
	ddl, err := os.ReadFile("../schema.sql")
	if err != nil {
		t.Fatalf("reading ../schema.sql: %v", err)
	}

	const schema = "authit_reference_schema_test"
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("pgxpool.ParseConfig: %v", err)
	}
	// Every table in schema.sql is created and resolved inside this schema.
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	if _, err := pool.Exec(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`); err != nil {
		t.Fatalf("dropping stale schema: %v", err)
	}
	if _, err := pool.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("creating schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	})
	if _, err := pool.Exec(ctx, string(ddl)); err != nil {
		t.Fatalf("applying ../schema.sql: %v", err)
	}
	// The raw pool comes back too, so a caller can truncate between
	// subtests and insert fixture rows that foreign keys require.
	return sqlb.New(pool), pool
}

// TestExampleUserStoresAgainstReferenceSchema drives the real user flows
// through the example wiring against ../schema.sql, so a drift between the
// two -- a renamed column, a missing table, a type that won't round-trip --
// fails here rather than in a consumer's port.
func TestExampleUserStoresAgainstReferenceSchema(t *testing.T) {
	db, _ := referenceSchemaPool(t)
	svc, err := user.NewService(exampleUserStores(db), exampleSigner(t), nil, user.Config{
		MaxFailedLoginAttempts: 3,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	ctx := context.Background()

	// users: insert, read back by email, and a DB-assigned id.
	u, err := svc.Register(ctx, "example@example.com", "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if u.ID == "" || u.CreatedAt.IsZero() {
		t.Fatalf("expected DB-defaulted id/created_at, got %+v", u)
	}

	// The strict default is in force, so login is refused until verified.
	if _, err := svc.Authenticate(ctx, "example@example.com", "correct-horse-battery-staple", "ua", "127.0.0.1"); !errors.Is(err, user.ErrEmailNotVerified) {
		t.Fatalf("expected ErrEmailNotVerified, got %v", err)
	}

	// users UPDATE: the boolean must actually reach the column.
	if err := svc.MarkEmailVerified(ctx, u.ID); err != nil {
		t.Fatalf("MarkEmailVerified: %v", err)
	}

	// refresh_tokens INSERT + failed_login_attempts DELETE on success.
	result, err := svc.Authenticate(ctx, "example@example.com", "correct-horse-battery-staple", "ua", "127.0.0.1")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if result.Tokens == nil {
		t.Fatal("expected a token pair")
	}

	// refresh_tokens SELECT by hash, UPDATE revoked_at, INSERT replacement.
	rotated, err := svc.Refresh(ctx, result.Tokens.RefreshToken, "ua", "127.0.0.1")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// refresh_tokens SELECT by user_id, filtered on revoked_at/expires_at.
	// This runs BEFORE the reuse below, deliberately: replaying a rotated
	// token is treated as a compromise and revokes the whole family, so
	// afterwards there is correctly nothing left to list.
	sessions, err := svc.ListSessions(ctx, u.ID, rotated.RefreshToken)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 || !sessions[0].IsCurrent {
		t.Fatalf("expected exactly one current session, got %+v", sessions)
	}

	// Replaying the token that was already rotated away: refused, and the
	// refusal is indistinguishable from a garbage token.
	if _, err := svc.Refresh(ctx, result.Tokens.RefreshToken, "ua", "127.0.0.1"); !errors.Is(err, user.ErrInvalidToken) {
		t.Fatal("expected the rotated-away refresh token to be revoked")
	}

	// refresh_tokens UPDATE revoked_at across every row for the user --
	// the family revocation that reuse triggers. A replayed token means
	// either the old or the new one is in someone else's hands and there
	// is no way to tell which, so both go. Asserting it here is what
	// proves the bulk UPDATE reaches real rows and not just the one.
	sessions, err = svc.ListSessions(ctx, u.ID, rotated.RefreshToken)
	if err != nil {
		t.Fatalf("ListSessions after reuse: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("reuse must revoke the whole family, still have %+v", sessions)
	}

	// failed_login_attempts INSERT + COUNT, then account_locks INSERT --
	// the table with no authit type, and the one a port is most likely to
	// have missed entirely.
	for range 3 {
		if _, err := svc.Authenticate(ctx, "example@example.com", "wrong-password", "ua", "127.0.0.1"); !errors.Is(err, user.ErrInvalidCredentials) {
			t.Fatalf("expected ErrInvalidCredentials, got %v", err)
		}
	}
	if _, err := svc.Authenticate(ctx, "example@example.com", "correct-horse-battery-staple", "ua", "127.0.0.1"); !errors.Is(err, user.ErrAccountLocked) {
		t.Fatalf("expected ErrAccountLocked after 3 failures, got %v", err)
	}
}
