package user_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jryannel/authit/internal/authittest"
	authitjwt "github.com/jryannel/authit/jwt"
	"github.com/jryannel/authit/store"
	"github.com/jryannel/authit/user"
	"github.com/jryannel/sqlb"
)

// serviceWithConfig builds a Service over fresh memstores with cfg as
// given, so a test can exercise one Config knob without the defaults
// newTestService bakes in.
func serviceWithConfig(t *testing.T, cfg user.Config) (*user.Service, *sqlb.DB, *capturingEmailer) {
	t.Helper()
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	signer, err := authitjwt.NewHMACSigner(secret, authitjwt.Defaults{Issuer: "authit-test", TTL: time.Minute})
	if err != nil {
		t.Fatalf("NewHMACSigner: %v", err)
	}
	emailer := &capturingEmailer{}
	db := authittest.FreshDB(t)
	svc, err := user.NewService(db, signer, emailer, cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, db, emailer
}

// storedUser reads a user back from the database, for the assertions that are
// about what was persisted rather than about what a call returned.
func storedUser(t *testing.T, db *sqlb.DB, id string) store.User {
	t.Helper()
	u, err := sqlb.Query[store.User]().Where(store.UserCols.ID.Eq(id)).One(context.Background(), db)
	if err != nil {
		t.Fatalf("reading back user %s: %v", id, err)
	}
	return u
}

// A zero-value Config must keep the strict behaviour: an unverified
// address cannot log in, and nobody is surprised by an upgrade.
func TestEmailVerificationRequiredIsTheDefault(t *testing.T) {
	svc, _, _ := serviceWithConfig(t, user.Config{})
	ctx := context.Background()

	if _, err := svc.Register(ctx, "unverified@example.com", "correct-horse"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.Authenticate(ctx, "unverified@example.com", "correct-horse", "ua", "1.2.3.4"); !errors.Is(err, user.ErrEmailNotVerified) {
		t.Fatalf("expected ErrEmailNotVerified under the default policy, got %v", err)
	}
}

// With the policy relaxed, an unverified address logs in normally — the
// invite-only/SSO/seeded-account case.
func TestEmailVerificationOptionalAllowsLogin(t *testing.T) {
	svc, db, _ := serviceWithConfig(t, user.Config{EmailVerification: user.EmailVerificationOptional})
	ctx := context.Background()

	u, err := svc.Register(ctx, "invited@example.com", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	result, err := svc.Authenticate(ctx, "invited@example.com", "correct-horse", "ua", "1.2.3.4")
	if err != nil {
		t.Fatalf("Authenticate under EmailVerificationOptional: %v", err)
	}
	if result.Tokens == nil || result.Tokens.AccessToken == "" {
		t.Fatal("expected a token pair")
	}

	// Relaxing the login gate must not quietly mark the address verified:
	// the host may still be gating its own features on the flag.
	stored := storedUser(t, db, u.ID)
	if stored.EmailVerified {
		t.Fatal("EmailVerificationOptional must not mark the address verified")
	}
}

// MarkEmailVerified is the seeder/invite path: verified without ever
// minting a token.
func TestMarkEmailVerified(t *testing.T) {
	svc, db, _ := serviceWithConfig(t, user.Config{})
	ctx := context.Background()

	u, err := svc.Register(ctx, "seeded@example.com", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := svc.MarkEmailVerified(ctx, u.ID); err != nil {
		t.Fatalf("MarkEmailVerified: %v", err)
	}

	stored := storedUser(t, db, u.ID)
	if !stored.EmailVerified || stored.EmailVerifiedAt == nil {
		t.Fatalf("expected a verified user with a timestamp, got %+v", stored)
	}

	// ...and login now works under the strict default policy.
	if _, err := svc.Authenticate(ctx, "seeded@example.com", "correct-horse", "ua", "1.2.3.4"); err != nil {
		t.Fatalf("Authenticate after MarkEmailVerified: %v", err)
	}

	// Idempotent, and it does not move EmailVerifiedAt.
	first := *stored.EmailVerifiedAt
	if err := svc.MarkEmailVerified(ctx, u.ID); err != nil {
		t.Fatalf("MarkEmailVerified (second call): %v", err)
	}
	stored = storedUser(t, db, u.ID)
	if !stored.EmailVerifiedAt.Equal(first) {
		t.Fatalf("EmailVerifiedAt moved on a repeat call: %v -> %v", first, *stored.EmailVerifiedAt)
	}
}

// A verification link already sitting in an inbox must not stay redeemable
// after the address has been verified out of band.
func TestMarkEmailVerifiedInvalidatesOutstandingTokens(t *testing.T) {
	svc, _, emailer := serviceWithConfig(t, user.Config{})
	ctx := context.Background()

	u, err := svc.Register(ctx, "raced@example.com", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := svc.RequestEmailVerification(ctx, u.ID); err != nil {
		t.Fatalf("RequestEmailVerification: %v", err)
	}
	outstanding := emailer.lastVerificationToken
	if outstanding == "" {
		t.Fatal("expected a verification token to have been sent")
	}

	if err := svc.MarkEmailVerified(ctx, u.ID); err != nil {
		t.Fatalf("MarkEmailVerified: %v", err)
	}
	if err := svc.VerifyEmail(ctx, outstanding); !errors.Is(err, user.ErrInvalidToken) {
		t.Fatalf("expected the outstanding token to be dead, got %v", err)
	}
}

func TestMarkEmailVerifiedUnknownUser(t *testing.T) {
	svc, _, _ := serviceWithConfig(t, user.Config{})
	// A syntactically valid but absent id: the column is a uuid, so a made-up
	// string would be refused by the type rather than by the lookup.
	if err := svc.MarkEmailVerified(context.Background(), "00000000-0000-0000-0000-000000000000"); !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("expected user.ErrNotFound, got %v", err)
	}
}
