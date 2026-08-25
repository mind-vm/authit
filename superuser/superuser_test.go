package superuser_test

import (
	"errors"
	"testing"
	"time"

	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/memstore"
	"github.com/mind-vm/authit/superuser"
)

func newSigner(t *testing.T) authitjwt.Signer {
	t.Helper()
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	s, err := authitjwt.NewHMACSigner(secret, authitjwt.Defaults{Issuer: "authit-test", TTL: time.Minute})
	if err != nil {
		t.Fatalf("NewHMACSigner: %v", err)
	}
	return s
}

func newTestService(t *testing.T) *superuser.Service {
	t.Helper()
	stores := superuser.Stores{
		Superusers:    memstore.NewSuperuserStore(),
		RefreshTokens: memstore.NewSuperuserRefreshTokenStore(),
		Lockouts:      memstore.NewLockoutStore(),
	}
	svc, err := superuser.NewService(stores, newSigner(t), superuser.Config{MaxFailedLoginAttempts: 3})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func TestBootstrapOnlyOnce(t *testing.T) {
	svc := newTestService(t)
	ctx := t.Context()

	if _, err := svc.Bootstrap(ctx, "root@example.com", "s3cret!!", "Root"); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if _, err := svc.Bootstrap(ctx, "someone-else@example.com", "s3cret!!", "Someone"); !errors.Is(err, superuser.ErrAlreadyBootstrapped) {
		t.Fatalf("expected ErrAlreadyBootstrapped, got %v", err)
	}
}

func TestAuthenticateAndRefresh(t *testing.T) {
	svc := newTestService(t)
	ctx := t.Context()
	if _, err := svc.Bootstrap(ctx, "root@example.com", "s3cret!!", "Root"); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	tokens, err := svc.Authenticate(ctx, "root@example.com", "s3cret!!", "ua", "ip")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	claims, err := svc.Verify(tokens.AccessToken)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !claims.HasAudience(superuser.DefaultAudience) {
		t.Fatal("expected superuser audience on issued token")
	}

	refreshed, err := svc.Refresh(ctx, tokens.RefreshToken, "ua", "ip")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if refreshed.RefreshToken == tokens.RefreshToken {
		t.Fatal("expected refresh to rotate the token")
	}
	if _, err := svc.Refresh(ctx, tokens.RefreshToken, "ua", "ip"); !errors.Is(err, superuser.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for rotated-out token, got %v", err)
	}

	if _, err := svc.Authenticate(ctx, "root@example.com", "wrong", "ua", "ip"); !errors.Is(err, superuser.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestAudienceSeparationFromUserPlane(t *testing.T) {
	signer := newSigner(t)

	suStores := superuser.Stores{
		Superusers:    memstore.NewSuperuserStore(),
		RefreshTokens: memstore.NewSuperuserRefreshTokenStore(),
	}
	suSvc, err := superuser.NewService(suStores, signer, superuser.Config{})
	if err != nil {
		t.Fatalf("superuser.NewService: %v", err)
	}
	ctx := t.Context()
	if _, err := suSvc.Bootstrap(ctx, "root@example.com", "s3cret!!", "Root"); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	// A normal user access token, even though it verifies fine against the
	// same signer, must be rejected by superuser.Verify because it lacks
	// the superuser audience.
	userToken, err := signer.Generate(authitjwt.Claims{Email: "user@example.com"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := suSvc.Verify(userToken); !errors.Is(err, superuser.ErrInvalidToken) {
		t.Fatalf("expected a plain user token to be rejected by superuser plane, got %v", err)
	}
}

func TestDeactivateCannotTargetSelf(t *testing.T) {
	svc := newTestService(t)
	ctx := t.Context()
	su, err := svc.Bootstrap(ctx, "root@example.com", "s3cret!!", "Root")
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if err := svc.Deactivate(ctx, su.ID, su.ID); !errors.Is(err, superuser.ErrCannotDeactivateSelf) {
		t.Fatalf("expected ErrCannotDeactivateSelf, got %v", err)
	}
}

func TestImpersonateProducesUserPlaneToken(t *testing.T) {
	signer := newSigner(t)
	suStores := superuser.Stores{
		Superusers:    memstore.NewSuperuserStore(),
		RefreshTokens: memstore.NewSuperuserRefreshTokenStore(),
	}
	suSvc, err := superuser.NewService(suStores, signer, superuser.Config{})
	if err != nil {
		t.Fatalf("superuser.NewService: %v", err)
	}
	ctx := t.Context()
	su, err := suSvc.Bootstrap(ctx, "root@example.com", "s3cret!!", "Root")
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	token, err := suSvc.Impersonate(ctx, su.ID, "target-user-1", "target@example.com")
	if err != nil {
		t.Fatalf("Impersonate: %v", err)
	}

	var claims authitjwt.Claims
	if err := signer.Verify(token, &claims); err != nil {
		t.Fatalf("expected impersonation token to verify as a plain user token: %v", err)
	}
	if claims.Subject != "target-user-1" {
		t.Fatalf("expected Subject=target-user-1, got %q", claims.Subject)
	}
	if !claims.IsImpersonation() || claims.ActorID != su.ID {
		t.Fatalf("expected ActorID=%q, got claims=%+v", su.ID, claims)
	}

	// And it must NOT be accepted by the superuser plane (no audience).
	if _, err := suSvc.Verify(token); !errors.Is(err, superuser.ErrInvalidToken) {
		t.Fatalf("expected impersonation token to be rejected by superuser plane, got %v", err)
	}
}
