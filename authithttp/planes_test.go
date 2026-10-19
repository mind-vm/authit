package authithttp_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mind-vm/authit/authithttp"
	"github.com/mind-vm/authit/emaillogin"
	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/memstore"
	"github.com/mind-vm/authit/pat"
	"github.com/mind-vm/authit/superuser"
	"github.com/mind-vm/authit/user"
)

// planeSentinels are every plane's own ErrInvalidToken, with the message it
// had before it joined authithttp's class. The message is pinned because a
// host may log it or match on it, and joining the class must not change it.
var planeSentinels = []struct {
	name string
	err  error
	msg  string
}{
	{"user", user.ErrInvalidToken, "authit/user: invalid or expired token"},
	{"superuser", superuser.ErrInvalidToken, "authit/superuser: invalid or expired token"},
	{"pat", pat.ErrInvalidToken, "authit/pat: invalid, revoked, or expired token"},
	{"emaillogin", emaillogin.ErrInvalidToken, "authit/emaillogin: invalid or expired sign-in credential"},
}

// TestPlaneInvalidTokensAre401 is the bug: an expired opaque session came
// back from user.ValidateSession as user.ErrInvalidToken, which StatusFor
// did not recognise, so a host answered 500 to a caller whose session had
// simply ended.
func TestPlaneInvalidTokensAre401(t *testing.T) {
	for _, tc := range planeSentinels {
		t.Run(tc.name, func(t *testing.T) {
			wrapped := fmt.Errorf("handler: %w", tc.err)
			for _, err := range []error{tc.err, wrapped} {
				if !errors.Is(err, authithttp.ErrInvalidToken) {
					t.Fatalf("errors.Is(%v, authithttp.ErrInvalidToken) = false", err)
				}
				if !errors.Is(err, tc.err) {
					t.Fatalf("errors.Is(%v, its own sentinel) = false", err)
				}
				if got := authithttp.StatusFor(err); got != http.StatusUnauthorized {
					t.Fatalf("StatusFor(%v) = %d, want 401", err, got)
				}
			}
			if tc.err.Error() != tc.msg {
				t.Fatalf("message changed: %q, want %q", tc.err.Error(), tc.msg)
			}
		})
	}
}

// The class is one way. A plane's sentinel is still only itself: a
// superuser token failure must not satisfy a check for a user one, and a
// bearer failure from Validate is not a plane's.
func TestPlaneSentinelsStayDistinct(t *testing.T) {
	for _, a := range planeSentinels {
		if errors.Is(authithttp.ErrInvalidToken, a.err) {
			t.Fatalf("authithttp.ErrInvalidToken matches %s.ErrInvalidToken", a.name)
		}
		for _, b := range planeSentinels {
			if a.name != b.name && errors.Is(a.err, b.err) {
				t.Fatalf("%s.ErrInvalidToken matches %s.ErrInvalidToken", a.name, b.name)
			}
		}
	}
}

func hmacSigner(t *testing.T) authitjwt.Signer {
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

// What follows drives each plane through its real failure path rather than
// handing StatusFor the sentinel directly, so a plane that one day returns
// a fresh errors.New from somewhere is caught here.

func TestOpaqueSessionAuthIs401ForAnUnknownSession(t *testing.T) {
	svc, err := user.NewService(user.Stores{
		Users:              memstore.NewUserStore(),
		RefreshTokens:      memstore.NewRefreshTokenStore(),
		PasswordResets:     memstore.NewPasswordResetStore(),
		EmailVerifications: memstore.NewEmailVerificationStore(),
		TOTP:               memstore.NewTOTPStore(),
		PendingTwoFactor:   memstore.NewPendingTwoFactorStore(),
		Lockouts:           memstore.NewLockoutStore(),
	}, hmacSigner(t), nil, user.Config{SessionMode: user.SessionModeOpaque})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer no-such-session")
	_, err = authithttp.SessionAuth(svc).Authenticate(r.Context(), r)
	if !errors.Is(err, user.ErrInvalidToken) {
		t.Fatalf("expected user.ErrInvalidToken, got %v", err)
	}
	if got := authithttp.StatusFor(err); got != http.StatusUnauthorized {
		t.Fatalf("StatusFor = %d, want 401", got)
	}
}

func TestSuperuserVerifyIs401ForAForgery(t *testing.T) {
	svc, err := superuser.NewService(superuser.Stores{
		Superusers:    memstore.NewSuperuserStore(),
		RefreshTokens: memstore.NewSuperuserRefreshTokenStore(),
		Lockouts:      memstore.NewLockoutStore(),
	}, hmacSigner(t), superuser.Config{})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	_, err = svc.Verify("not-a-jwt")
	if got := authithttp.StatusFor(err); got != http.StatusUnauthorized {
		t.Fatalf("StatusFor(%v) = %d, want 401", err, got)
	}
}

func TestPATResolveIs401ForAnUnknownToken(t *testing.T) {
	svc, err := pat.NewService(pat.Stores{Tokens: memstore.NewPersonalAccessTokenStore()}, pat.Config{})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	_, err = svc.Resolve(context.Background(), "pat_not-a-real-token")
	if got := authithttp.StatusFor(err); got != http.StatusUnauthorized {
		t.Fatalf("StatusFor(%v) = %d, want 401", err, got)
	}
}

type discardSender struct{}

func (discardSender) SendMagicLink(context.Context, string, string) error  { return nil }
func (discardSender) SendSignInCode(context.Context, string, string) error { return nil }

func TestEmailLoginRedeemIs401ForAnUnknownLink(t *testing.T) {
	svc, err := emaillogin.NewService(emaillogin.Stores{
		Users:  memstore.NewUserStore(),
		Tokens: memstore.NewEmailLoginStore(),
	}, discardSender{}, emaillogin.Config{})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	_, err = svc.RedeemMagicLink(context.Background(), "no-such-link")
	if got := authithttp.StatusFor(err); got != http.StatusUnauthorized {
		t.Fatalf("StatusFor(%v) = %d, want 401", err, got)
	}
}
