package user_test

import (
	"context"
	"errors"
	"testing"
	"time"

	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/memstore"
	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/authit/user"
	"github.com/pquerna/otp/totp"
)

// lockoutFixture builds a service whose lockout store the test can inspect
// directly, so assertions can distinguish "temporarily throttled" (derived
// from the attempts table) from "administratively locked" (a row in the
// locks table).
type lockoutFixture struct {
	svc      *user.Service
	emailer  *capturingEmailer
	lockouts *memstore.LockoutStore
}

func newLockoutFixture(t *testing.T, cfg user.Config) lockoutFixture {
	t.Helper()
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	signer, err := authitjwt.NewHMACSigner(secret, authitjwt.Defaults{Issuer: "authit-test", TTL: time.Minute})
	if err != nil {
		t.Fatalf("NewHMACSigner: %v", err)
	}
	totpKey := make([]byte, 32)
	for i := range totpKey {
		totpKey[i] = byte(i)
	}
	cfg.TOTPEncryptionKey = totpKey

	emailer := &capturingEmailer{}
	lockouts := memstore.NewLockoutStore()
	svc, err := user.NewService(user.Stores{
		Users:              memstore.NewUserStore(),
		RefreshTokens:      memstore.NewRefreshTokenStore(),
		PasswordResets:     memstore.NewPasswordResetStore(),
		EmailVerifications: memstore.NewEmailVerificationStore(),
		TOTP:               memstore.NewTOTPStore(),
		PendingTwoFactor:   memstore.NewPendingTwoFactorStore(),
		Lockouts:           lockouts,
	}, signer, emailer, cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return lockoutFixture{svc: svc, emailer: emailer, lockouts: lockouts}
}

// enrollTOTP registers a verified user with 2FA enabled and returns their
// id and TOTP secret.
func enrollTOTP(t *testing.T, f lockoutFixture, email, password string) (uid, secret string) {
	t.Helper()
	ctx := context.Background()
	uid = registerCaptured(t, f.svc, f.emailer, email, password)
	setup, err := f.svc.BeginTwoFactorSetup(ctx, uid, email)
	if err != nil {
		t.Fatalf("BeginTwoFactorSetup: %v", err)
	}
	code, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if _, err := f.svc.ConfirmTwoFactorSetup(ctx, uid, code); err != nil {
		t.Fatalf("ConfirmTwoFactorSetup: %v", err)
	}
	return uid, setup.Secret
}

// TestTwoFactorGuessesAreRateLimited is the regression test for the
// central defect: the second factor used to be entirely unmetered. A
// correct password cleared the failed-attempt counter before the 2FA step,
// and VerifyTwoFactorLogin never recorded a failure -- so an attacker
// holding the password had unlimited guesses at a six-digit code.
func TestTwoFactorGuessesAreRateLimited(t *testing.T) {
	f := newLockoutFixture(t, user.Config{MaxFailedLoginAttempts: 3, FailedLoginWindow: time.Minute})
	ctx := context.Background()
	_, _ = enrollTOTP(t, f, "erin@example.com", "correct-horse-battery")

	result, err := f.svc.Authenticate(ctx, "erin@example.com", "correct-horse-battery", "ua", "ip")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !result.RequiresTwoFactor {
		t.Fatal("expected 2FA to be required")
	}

	// Burn the budget on wrong codes.
	for i := 0; i < 3; i++ {
		_, err := f.svc.VerifyTwoFactorLogin(ctx, result.PendingTwoFactorToken, "000000", "ua", "ip")
		if !errors.Is(err, user.ErrInvalidTwoFactor) {
			t.Fatalf("attempt %d: expected ErrInvalidTwoFactor, got %v", i+1, err)
		}
	}

	// The next guess against the same pending session must be refused.
	if _, err := f.svc.VerifyTwoFactorLogin(ctx, result.PendingTwoFactorToken, "000000", "ua", "ip"); !errors.Is(err, user.ErrAccountLocked) {
		t.Fatalf("expected ErrAccountLocked on the 4th 2FA guess, got %v", err)
	}
}

// TestTwoFactorThrottleSurvivesReauthentication closes the obvious escape
// hatch: if a fresh pending session could be minted with the (known-good)
// password, a per-session cap would buy nothing. Authenticate consults the
// same counter, so it cannot.
func TestTwoFactorThrottleSurvivesReauthentication(t *testing.T) {
	f := newLockoutFixture(t, user.Config{MaxFailedLoginAttempts: 3, FailedLoginWindow: time.Minute})
	ctx := context.Background()
	enrollTOTP(t, f, "frank@example.com", "correct-horse-battery")

	for i := 0; i < 3; i++ {
		result, err := f.svc.Authenticate(ctx, "frank@example.com", "correct-horse-battery", "ua", "ip")
		if err != nil {
			t.Fatalf("Authenticate %d: %v", i+1, err)
		}
		if _, err := f.svc.VerifyTwoFactorLogin(ctx, result.PendingTwoFactorToken, "000000", "ua", "ip"); !errors.Is(err, user.ErrInvalidTwoFactor) {
			t.Fatalf("attempt %d: expected ErrInvalidTwoFactor, got %v", i+1, err)
		}
	}

	// A correct password must no longer even yield a pending session.
	if _, err := f.svc.Authenticate(ctx, "frank@example.com", "correct-horse-battery", "ua", "ip"); !errors.Is(err, user.ErrAccountLocked) {
		t.Fatalf("expected ErrAccountLocked, got %v", err)
	}

}

// TestSuccessfulTwoFactorLoginResetsCounter checks the other half of moving
// the reset: it must still happen, just later. Failures before a fully
// successful login must not accumulate across sessions.
func TestSuccessfulTwoFactorLoginResetsCounter(t *testing.T) {
	f := newLockoutFixture(t, user.Config{MaxFailedLoginAttempts: 3, FailedLoginWindow: time.Minute})
	ctx := context.Background()
	_, secret := enrollTOTP(t, f, "heidi@example.com", "correct-horse-battery")

	result, err := f.svc.Authenticate(ctx, "heidi@example.com", "correct-horse-battery", "ua", "ip")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	// Two bad guesses, then a good one.
	for i := 0; i < 2; i++ {
		if _, err := f.svc.VerifyTwoFactorLogin(ctx, result.PendingTwoFactorToken, "000000", "ua", "ip"); !errors.Is(err, user.ErrInvalidTwoFactor) {
			t.Fatalf("expected ErrInvalidTwoFactor, got %v", err)
		}
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if _, err := f.svc.VerifyTwoFactorLogin(ctx, result.PendingTwoFactorToken, code, "ua", "ip"); err != nil {
		t.Fatalf("VerifyTwoFactorLogin: %v", err)
	}

	// The counter is now clear: three fresh failures should be needed to
	// throttle again, so two must not be enough.
	next, err := f.svc.Authenticate(ctx, "heidi@example.com", "correct-horse-battery", "ua", "ip")
	if err != nil {
		t.Fatalf("Authenticate after success: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := f.svc.VerifyTwoFactorLogin(ctx, next.PendingTwoFactorToken, "000000", "ua", "ip"); !errors.Is(err, user.ErrInvalidTwoFactor) {
			t.Fatalf("expected ErrInvalidTwoFactor, got %v", err)
		}
	}
}

// TestFailedLoginsDoNotWriteAdministrativeLock is the regression test for
// the permanent-lockout DoS: failed logins used to call LockAccount, which
// had no expiry and which nothing in the library ever cleared.
func TestFailedLoginsDoNotWriteAdministrativeLock(t *testing.T) {
	f := newLockoutFixture(t, user.Config{MaxFailedLoginAttempts: 3, FailedLoginWindow: time.Minute})
	ctx := context.Background()
	uid := registerCaptured(t, f.svc, f.emailer, "ivan@example.com", "correct-horse-battery")

	for i := 0; i < 5; i++ {
		if _, err := f.svc.Authenticate(ctx, "ivan@example.com", "wrong-horse-battery", "ua", "attacker-ip"); err == nil {
			t.Fatal("expected failure")
		}
	}
	locked, err := f.lockouts.IsAccountLocked(ctx, uid)
	if err != nil {
		t.Fatalf("IsAccountLocked: %v", err)
	}
	if locked {
		t.Fatal("failed logins must not write an administrative lock: that is what made the DoS permanent")
	}
	// Throttled, but only via the derived path.
	if _, err := f.svc.Authenticate(ctx, "ivan@example.com", "correct-horse-battery", "ua", "ip"); !errors.Is(err, user.ErrAccountLocked) {
		t.Fatalf("expected ErrAccountLocked while throttled, got %v", err)
	}
}

// TestThrottleLiftsWithoutOperatorAction is the other half of the same
// regression: the temporary lockout is derived from the attempts table, so
// it must expire on its own. Unknown addresses are used deliberately --
// they short-circuit the bcrypt comparison, which keeps the attempts inside
// a window short enough to test without a slow sleep.
func TestThrottleLiftsWithoutOperatorAction(t *testing.T) {
	f := newLockoutFixture(t, user.Config{MaxFailedLoginAttempts: 3, FailedLoginWindow: 100 * time.Millisecond})
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := f.svc.Authenticate(ctx, "ghost@example.com", "guess", "ua", "ip"); !errors.Is(err, user.ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	if _, err := f.svc.Authenticate(ctx, "ghost@example.com", "guess", "ua", "ip"); !errors.Is(err, user.ErrAccountLocked) {
		t.Fatalf("expected ErrAccountLocked while throttled, got %v", err)
	}
	time.Sleep(250 * time.Millisecond)
	if _, err := f.svc.Authenticate(ctx, "ghost@example.com", "guess", "ua", "ip"); !errors.Is(err, user.ErrInvalidCredentials) {
		t.Fatalf("expected the throttle to lift on its own, got %v", err)
	}
}

// TestAdministrativeLockStillBlocksLogin keeps the operator-driven path
// working: LockAccount is now only reachable by the host, and must still
// deny logins until UnlockAccount is called.
func TestAdministrativeLockStillBlocksLogin(t *testing.T) {
	f := newLockoutFixture(t, user.Config{MaxFailedLoginAttempts: 3, FailedLoginWindow: time.Minute})
	ctx := context.Background()
	uid := registerCaptured(t, f.svc, f.emailer, "judy@example.com", "correct-horse-battery")

	if err := f.lockouts.LockAccount(ctx, uid); err != nil {
		t.Fatalf("LockAccount: %v", err)
	}
	if _, err := f.svc.Authenticate(ctx, "judy@example.com", "correct-horse-battery", "ua", "ip"); !errors.Is(err, user.ErrAccountLocked) {
		t.Fatalf("expected ErrAccountLocked, got %v", err)
	}
	if err := f.lockouts.UnlockAccount(ctx, uid); err != nil {
		t.Fatalf("UnlockAccount: %v", err)
	}
	if _, err := f.svc.Authenticate(ctx, "judy@example.com", "correct-horse-battery", "ua", "ip"); err != nil {
		t.Fatalf("expected login to succeed after unlock, got %v", err)
	}
}

// TestThrottleAppliesToUnknownAddresses pins the behaviour the doc comment
// on checkLockoutAndFetchUser claims: the lockout is evaluated by email,
// before the account is known to exist, so an unknown address and a
// throttled one take the same path.
func TestThrottleAppliesToUnknownAddresses(t *testing.T) {
	f := newLockoutFixture(t, user.Config{MaxFailedLoginAttempts: 3, FailedLoginWindow: time.Minute})
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := f.svc.Authenticate(ctx, "nobody@example.com", "guess", "ua", "ip"); !errors.Is(err, user.ErrInvalidCredentials) {
			t.Fatalf("attempt %d: expected ErrInvalidCredentials, got %v", i+1, err)
		}
	}
	if _, err := f.svc.Authenticate(ctx, "nobody@example.com", "guess", "ua", "ip"); !errors.Is(err, user.ErrAccountLocked) {
		t.Fatalf("expected an unknown address to throttle like a real one, got %v", err)
	}
}

var _ store.LockoutStore = (*memstore.LockoutStore)(nil)
