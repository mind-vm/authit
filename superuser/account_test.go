package superuser_test

import (
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/mind-vm/authit/memstore"
	"github.com/mind-vm/authit/superuser"
)

func newTwoFactorService(t *testing.T) *superuser.Service {
	t.Helper()
	svc, err := superuser.NewService(superuser.Stores{
		Superusers:    memstore.NewSuperuserStore(),
		RefreshTokens: memstore.NewSuperuserRefreshTokenStore(),
		Lockouts:      memstore.NewLockoutStore(),
		TwoFactor:     memstore.NewSuperuserTwoFactorStore(),
	}, newSigner(t), superuser.Config{TOTPEncryptionKey: make([]byte, 32)})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

const opsEmail, opsPassword = "ops@example.com", "correct-horse-battery"

func signIn(t *testing.T, svc *superuser.Service) (id string, tokens superuser.TokenPair) {
	t.Helper()
	res, err := svc.Authenticate(t.Context(), opsEmail, opsPassword, "ua", "ip")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.Tokens == nil {
		t.Fatal("Authenticate asked for a second factor")
	}
	claims, err := svc.Verify(res.Tokens.AccessToken)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return claims.Subject, *res.Tokens
}

func code(t *testing.T, secret string) string {
	t.Helper()
	c, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	return c
}

func TestEnrolledSecondFactorIsAskedForAtSignIn(t *testing.T) {
	svc := newTwoFactorService(t)
	ctx := t.Context()
	if _, err := svc.Bootstrap(ctx, opsEmail, opsPassword, "Ops"); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	id, _ := signIn(t, svc)

	setup, err := svc.BeginTwoFactorSetup(ctx, id, opsEmail)
	if err != nil {
		t.Fatalf("BeginTwoFactorSetup: %v", err)
	}
	// Begun but not confirmed changes nothing at sign-in.
	signIn(t, svc)

	backup, err := svc.ConfirmTwoFactorSetup(ctx, id, code(t, setup.Secret))
	if err != nil {
		t.Fatalf("ConfirmTwoFactorSetup: %v", err)
	}

	res, err := svc.Authenticate(ctx, opsEmail, opsPassword, "ua", "ip")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.Tokens != nil || res.TwoFactorToken == "" {
		t.Fatal("a password alone signed in an operator with a second factor")
	}
	if _, err := svc.VerifyTwoFactorLogin(ctx, res.TwoFactorToken, "000000", "ua", "ip"); !errors.Is(err, superuser.ErrInvalidTwoFactor) {
		t.Fatalf("wrong code: got %v, want ErrInvalidTwoFactor", err)
	}
	pair, err := svc.VerifyTwoFactorLogin(ctx, res.TwoFactorToken, code(t, setup.Secret), "ua", "ip")
	if err != nil {
		t.Fatalf("VerifyTwoFactorLogin: %v", err)
	}
	if _, err := svc.Verify(pair.AccessToken); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if _, err := svc.VerifyTwoFactorLogin(ctx, res.TwoFactorToken, code(t, setup.Secret), "ua", "ip"); !errors.Is(err, superuser.ErrInvalidToken) {
		t.Fatalf("a spent pending token was accepted again: %v", err)
	}

	// A backup code works once.
	res, _ = svc.Authenticate(ctx, opsEmail, opsPassword, "ua", "ip")
	if _, err := svc.VerifyTwoFactorLogin(ctx, res.TwoFactorToken, backup[0], "ua", "ip"); err != nil {
		t.Fatalf("backup code: %v", err)
	}
	res, _ = svc.Authenticate(ctx, opsEmail, opsPassword, "ua", "ip")
	if _, err := svc.VerifyTwoFactorLogin(ctx, res.TwoFactorToken, backup[0], "ua", "ip"); !errors.Is(err, superuser.ErrInvalidTwoFactor) {
		t.Fatalf("a spent backup code was accepted again: %v", err)
	}

	if err := svc.DisableTwoFactor(ctx, id, code(t, setup.Secret)); err != nil {
		t.Fatalf("DisableTwoFactor: %v", err)
	}
	signIn(t, svc)
}

func TestChangePasswordEndsOtherSessions(t *testing.T) {
	svc := newTwoFactorService(t)
	ctx := t.Context()
	if _, err := svc.Bootstrap(ctx, opsEmail, opsPassword, "Ops"); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	id, here := signIn(t, svc)
	signIn(t, svc)
	claims, _ := svc.Verify(here.AccessToken)

	if _, err := svc.ChangePassword(ctx, id, claims.ID, "wrong-horse-battery", "a-new-passphrase!!"); !errors.Is(err, superuser.ErrInvalidCredentials) {
		t.Fatalf("wrong current password: got %v", err)
	}
	if n, err := svc.ChangePassword(ctx, id, claims.ID, opsPassword, "a-new-passphrase!!"); err != nil || n != 1 {
		t.Fatalf("ChangePassword = %d, %v; want 1 other session ended", n, err)
	}
	// Listed rather than refreshed: refreshing a revoked token is reuse,
	// which rightly ends every session.
	sessions, err := svc.ListSessions(ctx, id, claims.ID)
	if err != nil || len(sessions) != 1 || !sessions[0].IsCurrent {
		t.Fatalf("after a password change: %+v, %v; want only the current session", sessions, err)
	}
	if _, err := svc.Authenticate(ctx, opsEmail, "a-new-passphrase!!", "ua", "ip"); err != nil {
		t.Fatalf("the new password does not sign in: %v", err)
	}
}

func TestSessionsAreTheOperatorsOwn(t *testing.T) {
	svc := newTwoFactorService(t)
	ctx := t.Context()
	if _, err := svc.Bootstrap(ctx, opsEmail, opsPassword, "Ops"); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if _, err := svc.CreateFromShell(ctx, "other@example.com", "other-horse-battery", "Other"); err != nil {
		t.Fatalf("CreateFromShell: %v", err)
	}
	id, here := signIn(t, svc)
	signIn(t, svc)
	claims, _ := svc.Verify(here.AccessToken)

	sessions, err := svc.ListSessions(ctx, id, claims.ID)
	if err != nil || len(sessions) != 2 {
		t.Fatalf("ListSessions = %d, %v; want 2", len(sessions), err)
	}
	current := 0
	for _, s := range sessions {
		if s.IsCurrent {
			current++
		}
	}
	if current != 1 {
		t.Fatalf("%d sessions marked current, want 1", current)
	}

	res, _ := svc.Authenticate(ctx, "other@example.com", "other-horse-battery", "ua", "ip")
	otherClaims, _ := svc.Verify(res.Tokens.AccessToken)
	if err := svc.RevokeSession(ctx, id, otherClaims.ID); !errors.Is(err, superuser.ErrSessionNotFound) {
		t.Fatalf("revoked another operator's session: %v", err)
	}

	n, err := svc.RevokeOtherSessions(ctx, id, claims.ID)
	if err != nil || n != 1 {
		t.Fatalf("RevokeOtherSessions = %d, %v; want 1", n, err)
	}
	sessions, _ = svc.ListSessions(ctx, id, claims.ID)
	if len(sessions) != 1 || !sessions[0].IsCurrent {
		t.Fatalf("after revoking the others: %+v", sessions)
	}
}
