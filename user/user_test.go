package user_test

import (
	"context"
	"errors"
	"testing"
	"time"

	authitjwt "github.com/jryannel/authit/jwt"
	"github.com/jryannel/authit/memstore"
	"github.com/jryannel/authit/user"
	"github.com/pquerna/otp/totp"
)

func newTestService(t *testing.T) *user.Service {
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

	stores := user.Stores{
		Users:              memstore.NewUserStore(),
		RefreshTokens:      memstore.NewRefreshTokenStore(),
		PasswordResets:     memstore.NewPasswordResetStore(),
		EmailVerifications: memstore.NewEmailVerificationStore(),
		TOTP:               memstore.NewTOTPStore(),
		PendingTwoFactor:   memstore.NewPendingTwoFactorStore(),
		Lockouts:           memstore.NewLockoutStore(),
	}
	svc, err := user.NewService(stores, signer, nil, user.Config{
		MaxFailedLoginAttempts: 3,
		TOTPEncryptionKey:      totpKey,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

// capturingEmailer records the last token sent for each flow, standing in
// for a real mail provider so tests can complete the token-based flows.
type capturingEmailer struct {
	lastVerificationToken string
	lastResetToken        string
}

func (c *capturingEmailer) SendPasswordReset(_ context.Context, _, token string) error {
	c.lastResetToken = token
	return nil
}

func (c *capturingEmailer) SendEmailVerification(_ context.Context, _, token string) error {
	c.lastVerificationToken = token
	return nil
}

func serviceWithCapturingEmailer(t *testing.T) (*user.Service, *capturingEmailer) {
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
	svc, err := user.NewService(stores, signer, emailer, user.Config{
		MaxFailedLoginAttempts: 3,
		TOTPEncryptionKey:      totpKey,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, emailer
}

// registerCaptured registers a user and verifies their email via the
// capturingEmailer, returning the new user's ID.
func registerCaptured(t *testing.T, svc *user.Service, emailer *capturingEmailer, email, password string) string {
	t.Helper()
	ctx := context.Background()
	u, err := svc.Register(ctx, email, password)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := svc.RequestEmailVerification(ctx, u.ID); err != nil {
		t.Fatalf("RequestEmailVerification: %v", err)
	}
	if emailer.lastVerificationToken == "" {
		t.Fatal("expected a verification token to have been sent")
	}
	if err := svc.VerifyEmail(ctx, emailer.lastVerificationToken); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	return u.ID
}

func TestRegisterLoginRefreshLogout(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if _, err := svc.Register(ctx, "alice@example.com", "correct-horse"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.Register(ctx, "alice@example.com", "other"); !errors.Is(err, user.ErrEmailTaken) {
		t.Fatalf("expected ErrEmailTaken, got %v", err)
	}

	// Login before verification should fail.
	if _, err := svc.Authenticate(ctx, "alice@example.com", "correct-horse", "ua", "1.2.3.4"); !errors.Is(err, user.ErrEmailNotVerified) {
		t.Fatalf("expected ErrEmailNotVerified, got %v", err)
	}

	svc2, emailer := serviceWithCapturingEmailer(t)
	uid := registerCaptured(t, svc2, emailer, "bob@example.com", "hunter2xx")

	result, err := svc2.Authenticate(context.Background(), "bob@example.com", "hunter2xx", "ua", "1.2.3.4")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if result.RequiresTwoFactor {
		t.Fatal("did not expect 2FA to be required")
	}
	if result.Tokens == nil || result.Tokens.AccessToken == "" || result.Tokens.RefreshToken == "" {
		t.Fatal("expected a token pair")
	}
	if result.User.ID != uid {
		t.Fatal("returned user should match registered user")
	}

	refreshed, err := svc2.Refresh(context.Background(), result.Tokens.RefreshToken, "ua", "1.2.3.4")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if refreshed.RefreshToken == result.Tokens.RefreshToken {
		t.Fatal("expected refresh to rotate the token")
	}

	// Old refresh token should now be invalid.
	if _, err := svc2.Refresh(context.Background(), result.Tokens.RefreshToken, "ua", "1.2.3.4"); !errors.Is(err, user.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for rotated-out token, got %v", err)
	}

	if err := svc2.Logout(context.Background(), refreshed.RefreshToken); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := svc2.Refresh(context.Background(), refreshed.RefreshToken, "ua", "1.2.3.4"); !errors.Is(err, user.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken after logout, got %v", err)
	}
}

func TestAccountLockout(t *testing.T) {
	svc, emailer := serviceWithCapturingEmailer(t)
	registerCaptured(t, svc, emailer, "carol@example.com", "correct-pw")
	ctx := context.Background()

	for range 3 {
		if _, err := svc.Authenticate(ctx, "carol@example.com", "wrong-pw", "ua", "ip"); !errors.Is(err, user.ErrInvalidCredentials) {
			t.Fatalf("expected ErrInvalidCredentials, got %v", err)
		}
	}
	if _, err := svc.Authenticate(ctx, "carol@example.com", "correct-pw", "ua", "ip"); !errors.Is(err, user.ErrAccountLocked) {
		t.Fatalf("expected ErrAccountLocked after threshold, got %v", err)
	}
}

func TestPasswordResetFlow(t *testing.T) {
	svc, emailer := serviceWithCapturingEmailer(t)
	registerCaptured(t, svc, emailer, "dave@example.com", "old-password")
	ctx := context.Background()

	// Unknown email should not error (anti-enumeration) and should send no mail.
	if err := svc.RequestPasswordReset(ctx, "nobody@example.com"); err != nil {
		t.Fatalf("RequestPasswordReset(unknown): %v", err)
	}

	if err := svc.RequestPasswordReset(ctx, "dave@example.com"); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	rawToken := emailer.lastResetToken
	if rawToken == "" {
		t.Fatal("expected a reset token to have been sent")
	}

	if err := svc.ValidatePasswordResetToken(ctx, rawToken); err != nil {
		t.Fatalf("ValidatePasswordResetToken: %v", err)
	}

	// Log in once to have a session that reset should revoke.
	auth, err := svc.Authenticate(ctx, "dave@example.com", "old-password", "ua", "ip")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if err := svc.ResetPassword(ctx, rawToken, "new-password"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	// Reusing the token should fail.
	if err := svc.ResetPassword(ctx, rawToken, "another"); !errors.Is(err, user.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken on reuse, got %v", err)
	}

	// Old password no longer works; new one does.
	if _, err := svc.Authenticate(ctx, "dave@example.com", "old-password", "ua", "ip"); !errors.Is(err, user.ErrInvalidCredentials) {
		t.Fatalf("expected old password to be rejected, got %v", err)
	}
	if _, err := svc.Authenticate(ctx, "dave@example.com", "new-password", "ua", "ip"); err != nil {
		t.Fatalf("expected new password to work, got %v", err)
	}

	// The session from before the reset should have been revoked.
	if _, err := svc.Refresh(ctx, auth.Tokens.RefreshToken, "ua", "ip"); !errors.Is(err, user.ErrInvalidToken) {
		t.Fatalf("expected pre-reset session to be revoked, got %v", err)
	}
}

func TestTwoFactorLoginFlow(t *testing.T) {
	svc, emailer := serviceWithCapturingEmailer(t)
	uid := registerCaptured(t, svc, emailer, "erin@example.com", "correct-pw")
	ctx := context.Background()

	setup, err := svc.BeginTwoFactorSetup(ctx, uid, "erin@example.com")
	if err != nil {
		t.Fatalf("BeginTwoFactorSetup: %v", err)
	}
	code, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	enrollment, err := svc.ConfirmTwoFactorSetup(ctx, uid, code)
	if err != nil {
		t.Fatalf("ConfirmTwoFactorSetup: %v", err)
	}
	if len(enrollment.BackupCodes) == 0 {
		t.Fatal("expected backup codes")
	}

	result, err := svc.Authenticate(ctx, "erin@example.com", "correct-pw", "ua", "ip")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !result.RequiresTwoFactor || result.PendingTwoFactorToken == "" {
		t.Fatal("expected 2FA to be required")
	}
	if result.Tokens != nil {
		t.Fatal("did not expect tokens before 2FA verification")
	}

	loginCode, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	final, err := svc.VerifyTwoFactorLogin(ctx, result.PendingTwoFactorToken, loginCode, "ua", "ip")
	if err != nil {
		t.Fatalf("VerifyTwoFactorLogin: %v", err)
	}
	if final.Tokens == nil {
		t.Fatal("expected tokens after successful 2FA verification")
	}

	status, err := svc.TwoFactorStatus(ctx, uid)
	if err != nil {
		t.Fatalf("TwoFactorStatus: %v", err)
	}
	if !status.Enabled || status.RemainingBackupCodes != len(enrollment.BackupCodes) {
		t.Fatalf("unexpected status: %+v", status)
	}

	// Backup code should also work and should be single-use.
	result2, err := svc.Authenticate(ctx, "erin@example.com", "correct-pw", "ua", "ip")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	backup := enrollment.BackupCodes[0]
	if _, err := svc.VerifyTwoFactorLogin(ctx, result2.PendingTwoFactorToken, backup, "ua", "ip"); err != nil {
		t.Fatalf("VerifyTwoFactorLogin(backup): %v", err)
	}
	statusAfter, err := svc.TwoFactorStatus(ctx, uid)
	if err != nil {
		t.Fatalf("TwoFactorStatus: %v", err)
	}
	if statusAfter.RemainingBackupCodes != len(enrollment.BackupCodes)-1 {
		t.Fatalf("expected one fewer backup code, got %d", statusAfter.RemainingBackupCodes)
	}
}

func TestSessions(t *testing.T) {
	svc, emailer := serviceWithCapturingEmailer(t)
	registerCaptured(t, svc, emailer, "frank@example.com", "correct-pw")
	ctx := context.Background()

	a, err := svc.Authenticate(ctx, "frank@example.com", "correct-pw", "device-a", "ip-a")
	if err != nil {
		t.Fatalf("Authenticate a: %v", err)
	}
	_, err = svc.Authenticate(ctx, "frank@example.com", "correct-pw", "device-b", "ip-b")
	if err != nil {
		t.Fatalf("Authenticate b: %v", err)
	}

	sessions, err := svc.ListSessions(ctx, a.User.ID, a.Tokens.RefreshToken)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}
	var current bool
	for _, s := range sessions {
		if s.IsCurrent {
			current = true
		}
	}
	if !current {
		t.Fatal("expected one session to be flagged current")
	}

	if err := svc.RevokeOtherSessions(ctx, a.User.ID, a.Tokens.RefreshToken); err != nil {
		t.Fatalf("RevokeOtherSessions: %v", err)
	}
	sessions, err = svc.ListSessions(ctx, a.User.ID, a.Tokens.RefreshToken)
	if err != nil {
		t.Fatalf("ListSessions after revoke: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session after RevokeOtherSessions, got %d", len(sessions))
	}
}
