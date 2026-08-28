package user_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	authitcrypto "github.com/mind-vm/authit/crypto"
	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/memstore"
	"github.com/mind-vm/authit/user"
)

// serviceOver builds a Service over stores the caller already holds, so a
// test can point two differently-configured services at the same data.
func serviceOver(t *testing.T, stores user.Stores, emailer user.EmailSender, cfg user.Config) *user.Service {
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
	svc, err := user.NewService(stores, signer, emailer, cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func freshStores() (user.Stores, *memstore.UserStore) {
	users := memstore.NewUserStore()
	return user.Stores{
		Users:              users,
		RefreshTokens:      memstore.NewRefreshTokenStore(),
		PasswordResets:     memstore.NewPasswordResetStore(),
		EmailVerifications: memstore.NewEmailVerificationStore(),
		TOTP:               memstore.NewTOTPStore(),
		PendingTwoFactor:   memstore.NewPendingTwoFactorStore(),
		Lockouts:           memstore.NewLockoutStore(),
	}, users
}

// TestPasswordHashUpgradesOnLogin is the migration path that makes the
// hasher swappable: an application whose corpus was written by the old
// hardcoded bcrypt must move to argon2id by doing nothing but letting users
// log in.
func TestPasswordHashUpgradesOnLogin(t *testing.T) {
	ctx := context.Background()
	stores, users := freshStores()
	emailer := &capturingEmailer{}
	const email, password = "alice@example.com", "correct-horse-battery"

	// An application still on bcrypt.
	old := serviceOver(t, stores, emailer, user.Config{PasswordHasher: authitcrypto.BcryptHasher{Cost: 4}})
	registerCaptured(t, old, emailer, email, password)

	stored, err := users.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if !strings.HasPrefix(stored.PasswordHash, "$2") {
		t.Fatalf("expected a bcrypt hash to start with, got %q", stored.PasswordHash)
	}

	// The same data, now served by a service configured with the default
	// (argon2id) hasher. The old password must still work...
	upgraded := serviceOver(t, stores, emailer, user.Config{})
	if _, err := upgraded.Authenticate(ctx, email, password, "ua", "ip"); err != nil {
		t.Fatalf("a bcrypt-hashed password must still authenticate: %v", err)
	}
	// ...and the stored hash must have been rewritten.
	stored, err = users.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if !strings.HasPrefix(stored.PasswordHash, "$argon2id$") {
		t.Fatalf("expected the hash to be upgraded to argon2id, got %q", stored.PasswordHash)
	}
	// Still the same password, and still not any other one.
	if _, err := upgraded.Authenticate(ctx, email, password, "ua", "ip"); err != nil {
		t.Fatalf("Authenticate after upgrade: %v", err)
	}
	if _, err := upgraded.Authenticate(ctx, email, "wrong-horse-battery", "ua", "ip"); !errors.Is(err, user.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

// TestUpgradeDoesNotHappenForCurrentHashes guards against rewriting every
// user's row on every login, which would be a write amplification bug.
func TestUpgradeDoesNotHappenForCurrentHashes(t *testing.T) {
	ctx := context.Background()
	stores, users := freshStores()
	emailer := &capturingEmailer{}
	const email, password = "bob@example.com", "correct-horse-battery"

	svc := serviceOver(t, stores, emailer, user.Config{})
	registerCaptured(t, svc, emailer, email, password)
	before, err := users.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if _, err := svc.Authenticate(ctx, email, password, "ua", "ip"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	after, err := users.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if before.PasswordHash != after.PasswordHash {
		t.Fatal("a hash already at current parameters must not be rewritten on login")
	}
}

// TestPasswordPolicyIsEnforcedOnEveryWritePath: registration is the obvious
// one, but a weak password reached through reset or change is just as weak.
func TestPasswordPolicyIsEnforcedOnEveryWritePath(t *testing.T) {
	ctx := context.Background()
	stores, _ := freshStores()
	emailer := &capturingEmailer{}
	svc := serviceOver(t, stores, emailer, user.Config{})
	const email, password = "carol@example.com", "correct-horse-battery"

	if _, err := svc.Register(ctx, email, "short"); !errors.Is(err, user.ErrWeakPassword) {
		t.Fatalf("Register: expected ErrWeakPassword, got %v", err)
	}
	uid := registerCaptured(t, svc, emailer, email, password)

	if err := svc.ChangePassword(ctx, uid, password, "short"); !errors.Is(err, user.ErrWeakPassword) {
		t.Fatalf("ChangePassword: expected ErrWeakPassword, got %v", err)
	}
	// A wrong current password must still lose to ErrInvalidCredentials
	// rather than leaking that the new one was acceptable.
	if err := svc.ChangePassword(ctx, uid, "wrong-horse-battery", "another-valid-passphrase"); !errors.Is(err, user.ErrInvalidCredentials) {
		t.Fatalf("ChangePassword: expected ErrInvalidCredentials, got %v", err)
	}
	if err := svc.ChangePassword(ctx, uid, password, "another-valid-passphrase"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	if err := svc.RequestPasswordReset(ctx, email); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if err := svc.ResetPassword(ctx, emailer.lastResetToken, "short"); !errors.Is(err, user.ErrWeakPassword) {
		t.Fatalf("ResetPassword: expected ErrWeakPassword, got %v", err)
	}
	// The token must survive a rejected password, or a typo burns the link.
	if err := svc.ResetPassword(ctx, emailer.lastResetToken, "a-third-valid-passphrase"); err != nil {
		t.Fatalf("ResetPassword after a rejected attempt: %v", err)
	}
	if _, err := svc.Authenticate(ctx, email, "a-third-valid-passphrase", "ua", "ip"); err != nil {
		t.Fatalf("Authenticate with the reset password: %v", err)
	}
}

// TestPasswordPolicyIsNotAppliedOnLogin: tightening the policy must not
// lock out the users it was raised to protect.
func TestPasswordPolicyIsNotAppliedOnLogin(t *testing.T) {
	ctx := context.Background()
	stores, _ := freshStores()
	emailer := &capturingEmailer{}
	const email, password = "dave@example.com", "correct-horse-battery"

	lax := serviceOver(t, stores, emailer, user.Config{
		PasswordValidator: func(context.Context, string, string) error { return nil },
	})
	registerCaptured(t, lax, emailer, email, password)

	// Same data, far stricter policy than the existing password satisfies.
	strict := serviceOver(t, stores, emailer, user.Config{
		PasswordValidator: authitcrypto.LengthPolicy(200, 0),
	})
	if _, err := strict.Authenticate(ctx, email, password, "ua", "ip"); err != nil {
		t.Fatalf("an existing password must still authenticate under a tightened policy: %v", err)
	}
	// But it does apply the moment the password is being set again.
	if _, err := strict.Register(ctx, "erin@example.com", password); !errors.Is(err, user.ErrWeakPassword) {
		t.Fatalf("expected the tightened policy to apply on Register, got %v", err)
	}
}
