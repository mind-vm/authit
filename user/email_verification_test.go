package user_test

import (
	"context"
	"errors"
	"testing"
	"time"

	authitjwt "github.com/jryannel/authit/jwt"
	"github.com/jryannel/authit/memstore"
	"github.com/jryannel/authit/store"
	"github.com/jryannel/authit/user"
)

// serviceWithConfig builds a Service over fresh memstores with cfg as
// given, so a test can exercise one Config knob without the defaults
// newTestService bakes in.
func serviceWithConfig(t *testing.T, cfg user.Config) (*user.Service, user.Stores, *capturingEmailer) {
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
	stores := user.Stores{
		Users:              memstore.NewUserStore(),
		RefreshTokens:      memstore.NewRefreshTokenStore(),
		PasswordResets:     memstore.NewPasswordResetStore(),
		EmailVerifications: memstore.NewEmailVerificationStore(),
		TOTP:               memstore.NewTOTPStore(),
		PendingTwoFactor:   memstore.NewPendingTwoFactorStore(),
		Lockouts:           memstore.NewLockoutStore(),
	}
	svc, err := user.NewService(stores, signer, emailer, cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, stores, emailer
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
	svc, stores, _ := serviceWithConfig(t, user.Config{EmailVerification: user.EmailVerificationOptional})
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
	stored, err := stores.Users.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if stored.EmailVerified {
		t.Fatal("EmailVerificationOptional must not mark the address verified")
	}
}

// MarkEmailVerified is the seeder/invite path: verified without ever
// minting a token.
func TestMarkEmailVerified(t *testing.T) {
	svc, stores, _ := serviceWithConfig(t, user.Config{})
	ctx := context.Background()

	u, err := svc.Register(ctx, "seeded@example.com", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := svc.MarkEmailVerified(ctx, u.ID); err != nil {
		t.Fatalf("MarkEmailVerified: %v", err)
	}

	stored, err := stores.Users.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
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
	stored, err = stores.Users.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUserByID (after second call): %v", err)
	}
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
	if err := svc.MarkEmailVerified(context.Background(), "no-such-user"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected store.ErrNotFound, got %v", err)
	}
}
