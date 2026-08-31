package user_test

import (
	"context"
	"errors"
	"testing"
	"time"

	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/memstore"
	"github.com/mind-vm/authit/user"
)

// opaqueFixture is a service in SessionModeOpaque, plus the stores so a
// test can revoke behind the service's back.
type opaqueFixture struct {
	svc    *user.Service
	tokens *memstore.RefreshTokenStore
}

func newOpaqueService(t *testing.T, cfg user.Config) opaqueFixture {
	t.Helper()
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	signer, err := authitjwt.NewHMACSigner(secret, authitjwt.Defaults{Issuer: "authit-test", TTL: time.Minute})
	if err != nil {
		t.Fatalf("NewHMACSigner: %v", err)
	}
	tokens := memstore.NewRefreshTokenStore()
	stores := user.Stores{
		Users:              memstore.NewUserStore(),
		RefreshTokens:      tokens,
		PasswordResets:     memstore.NewPasswordResetStore(),
		EmailVerifications: memstore.NewEmailVerificationStore(),
		TOTP:               memstore.NewTOTPStore(),
		PendingTwoFactor:   memstore.NewPendingTwoFactorStore(),
		Lockouts:           memstore.NewLockoutStore(),
	}
	cfg.SessionMode = user.SessionModeOpaque
	cfg.EmailVerification = user.EmailVerificationOptional
	svc, err := user.NewService(stores, signer, nil, cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return opaqueFixture{svc: svc, tokens: tokens}
}

// register creates an account and signs in, returning the sign-in result --
// Register itself mints nothing.
func (f opaqueFixture) register(t *testing.T) user.AuthResult {
	t.Helper()
	ctx := context.Background()
	if _, err := f.svc.Register(ctx, "alice@example.com", "correct-horse-battery-staple"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	res, err := f.svc.Authenticate(ctx, "alice@example.com", "correct-horse-battery-staple", "ua", "127.0.0.1")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.Tokens == nil {
		t.Fatal("expected a token pair")
	}
	return res
}

// TestOpaqueSessionRevocationIsImmediate is the entire reason
// SessionModeOpaque exists.
//
// In the JWT mode a revoked session stops being refreshable at once and
// stays *usable* until the access token expires, because checking it looks
// nothing up. Here the check is the lookup, so revoking ends the session on
// the next request rather than up to AccessTokenTTL later.
func TestOpaqueSessionRevocationIsImmediate(t *testing.T) {
	ctx := context.Background()
	f := newOpaqueService(t, user.Config{})
	res := f.register(t)

	claims, err := f.svc.ValidateSession(ctx, res.Tokens.AccessToken)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if claims.Subject != res.User.ID {
		t.Fatalf("Subject = %q, want %q", claims.Subject, res.User.ID)
	}

	sessions, err := f.svc.ListSessions(ctx, res.User.ID, res.Tokens.AccessToken)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 || !sessions[0].IsCurrent {
		t.Fatalf("expected the session token to name the current session, got %+v", sessions)
	}
	if err := f.svc.RevokeSession(ctx, res.User.ID, sessions[0].ID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}

	// No waiting for anything to expire.
	if _, err := f.svc.ValidateSession(ctx, res.Tokens.AccessToken); !errors.Is(err, user.ErrInvalidToken) {
		t.Fatalf("a revoked session must be refused at once, got %v", err)
	}
}

// TestOpaqueSessionIssuesOneCredential. The pair exists so the common path
// avoids a lookup; once every request performs one, a second credential for
// avoiding lookups is ceremony. Refresh says so rather than rotating.
func TestOpaqueSessionIssuesOneCredential(t *testing.T) {
	ctx := context.Background()
	f := newOpaqueService(t, user.Config{})
	res := f.register(t)

	if res.Tokens.RefreshToken != "" {
		t.Fatalf("expected no refresh token in opaque mode, got %q", res.Tokens.RefreshToken)
	}
	if res.Tokens.AccessToken == "" {
		t.Fatal("expected a session token")
	}
	if _, err := f.svc.Refresh(ctx, res.Tokens.AccessToken, "ua", "127.0.0.1"); !errors.Is(err, user.ErrWrongSessionMode) {
		t.Fatalf("Refresh in opaque mode = %v, want ErrWrongSessionMode", err)
	}
}

// TestOpaqueSessionTokenIsNotAJWT. The token must not be parseable as one:
// a host that swapped modes and kept verifying signatures would accept
// nothing, but a host that kept *minting* JWTs while validating by lookup
// would accept everything the signer ever produced. The shapes are
// deliberately not interchangeable.
func TestOpaqueSessionTokenIsNotAJWT(t *testing.T) {
	f := newOpaqueService(t, user.Config{})
	res := f.register(t)
	for _, c := range res.Tokens.AccessToken {
		if c == '.' {
			t.Fatalf("session token %q looks like a JWT; it must be opaque", res.Tokens.AccessToken)
		}
	}
}

// TestValidateSessionRefusesInJWTMode. A signed token is a string like any
// other and would be looked up and not found, which reads to a caller as
// "your session expired" rather than "this server is not configured the way
// you think".
func TestValidateSessionRefusesInJWTMode(t *testing.T) {
	svc := newTestService(t)
	// No session is needed: the mode decides, not the token. That is the
	// point -- looking the token up first and reporting "not found" would
	// tell a caller their session expired when the truth is that this
	// server never had one.
	if _, err := svc.ValidateSession(context.Background(), "anything-at-all"); !errors.Is(err, user.ErrWrongSessionMode) {
		t.Fatalf("ValidateSession in JWT mode = %v, want ErrWrongSessionMode", err)
	}
}

// TestOpaqueSessionSlidingExpiry: using a session past the threshold
// extends it, and using one before the threshold does not write at all --
// which is the difference between a database write per request and a rare
// one.
func TestOpaqueSessionSlidingExpiry(t *testing.T) {
	ctx := context.Background()

	t.Run("extends once past the threshold", func(t *testing.T) {
		// Threshold of zero: every use is past it.
		f := newOpaqueService(t, user.Config{RefreshTokenTTL: time.Hour, SessionSlidingWindow: time.Nanosecond})
		res := f.register(t)
		before, err := f.svc.ListSessions(ctx, res.User.ID, res.Tokens.AccessToken)
		if err != nil {
			t.Fatalf("ListSessions: %v", err)
		}
		time.Sleep(2 * time.Millisecond)
		if _, err := f.svc.ValidateSession(ctx, res.Tokens.AccessToken); err != nil {
			t.Fatalf("ValidateSession: %v", err)
		}
		after, err := f.svc.ListSessions(ctx, res.User.ID, res.Tokens.AccessToken)
		if err != nil {
			t.Fatalf("ListSessions: %v", err)
		}
		if !after[0].ExpiresAt.After(before[0].ExpiresAt) {
			t.Fatalf("expiry did not move: %v -> %v", before[0].ExpiresAt, after[0].ExpiresAt)
		}
	})

	t.Run("does not extend before the threshold", func(t *testing.T) {
		f := newOpaqueService(t, user.Config{RefreshTokenTTL: time.Hour, SessionSlidingWindow: time.Hour})
		res := f.register(t)
		before, err := f.svc.ListSessions(ctx, res.User.ID, res.Tokens.AccessToken)
		if err != nil {
			t.Fatalf("ListSessions: %v", err)
		}
		time.Sleep(2 * time.Millisecond)
		if _, err := f.svc.ValidateSession(ctx, res.Tokens.AccessToken); err != nil {
			t.Fatalf("ValidateSession: %v", err)
		}
		after, err := f.svc.ListSessions(ctx, res.User.ID, res.Tokens.AccessToken)
		if err != nil {
			t.Fatalf("ListSessions: %v", err)
		}
		if !after[0].ExpiresAt.Equal(before[0].ExpiresAt) {
			t.Fatalf("expiry moved before the threshold: %v -> %v", before[0].ExpiresAt, after[0].ExpiresAt)
		}
	})

	t.Run("a negative window disables extension entirely", func(t *testing.T) {
		f := newOpaqueService(t, user.Config{RefreshTokenTTL: time.Hour, SessionSlidingWindow: -time.Second})
		res := f.register(t)
		before, _ := f.svc.ListSessions(ctx, res.User.ID, res.Tokens.AccessToken)
		time.Sleep(2 * time.Millisecond)
		if _, err := f.svc.ValidateSession(ctx, res.Tokens.AccessToken); err != nil {
			t.Fatalf("ValidateSession: %v", err)
		}
		after, _ := f.svc.ListSessions(ctx, res.User.ID, res.Tokens.AccessToken)
		if !after[0].ExpiresAt.Equal(before[0].ExpiresAt) {
			t.Fatal("a negative SessionSlidingWindow must not extend")
		}
	})
}
