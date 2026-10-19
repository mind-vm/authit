package user_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mind-vm/authit/audit"
	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/authit/storetest"
	"github.com/mind-vm/authit/user"
	"github.com/pquerna/otp/totp"
)

var sessionModes = []struct {
	name string
	mode user.SessionMode
}{
	{"jwt", user.SessionModeJWT},
	{"opaque", user.SessionModeOpaque},
}

type issueFixture struct {
	svc     *user.Service
	stores  user.Stores
	emailer *capturingEmailer
	audit   *recordingAudit
}

func newIssueFixture(t *testing.T, mode user.SessionMode, cfg user.Config) issueFixture {
	t.Helper()
	stores, _ := freshStores()
	f := issueFixture{stores: stores, emailer: &capturingEmailer{}, audit: &recordingAudit{}}
	cfg.SessionMode = mode
	cfg.AuditLogger = f.audit
	f.svc = serviceOver(t, stores, f.emailer, cfg)
	return f
}

// lastEvent returns the most recent event of type typ, failing if there is
// none.
func (f issueFixture) lastEvent(t *testing.T, typ audit.EventType) audit.Event {
	t.Helper()
	for i := len(f.audit.events) - 1; i >= 0; i-- {
		if f.audit.events[i].Type == typ {
			return f.audit.events[i]
		}
	}
	t.Fatalf("no %s event among %d", typ, len(f.audit.events))
	return audit.Event{}
}

func (f issueFixture) sessions(t *testing.T, uid string) []user.Session {
	t.Helper()
	got, err := f.svc.ListSessions(context.Background(), uid, "")
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	return got
}

// TestIssueSessionFollowsTheSessionMode is the point of the method: a
// passkey or OIDC sign-in gets the same kind of session a password login
// does, in either mode -- listed, revocable, and validated the mode's way.
func TestIssueSessionFollowsTheSessionMode(t *testing.T) {
	for _, m := range sessionModes {
		t.Run(m.name, func(t *testing.T) {
			ctx := context.Background()
			f := newIssueFixture(t, m.mode, user.Config{})
			uid := registerCaptured(t, f.svc, f.emailer, "alice@example.com", "correct-horse-battery")

			res, err := f.svc.IssueSession(ctx, uid, user.LoginMethodPasskey, "ua", "203.0.113.7")
			if err != nil {
				t.Fatalf("IssueSession: %v", err)
			}
			if res.Tokens == nil || res.Tokens.AccessToken == "" || res.RequiresTwoFactor || res.User.ID != uid {
				t.Fatalf("unexpected result: %+v", res)
			}

			switch m.mode {
			case user.SessionModeJWT:
				if res.Tokens.RefreshToken == "" {
					t.Fatal("JWT mode issues a refresh token")
				}
				if _, err := f.svc.ValidateSession(ctx, res.Tokens.AccessToken); !errors.Is(err, user.ErrWrongSessionMode) {
					t.Fatalf("ValidateSession in JWT mode: %v", err)
				}
				if _, err := f.svc.Refresh(ctx, res.Tokens.RefreshToken, "ua", "203.0.113.7"); err != nil {
					t.Fatalf("the refresh token must work: %v", err)
				}
			case user.SessionModeOpaque:
				if res.Tokens.RefreshToken != "" {
					t.Fatal("opaque mode issues one token")
				}
				claims, err := f.svc.ValidateSession(ctx, res.Tokens.AccessToken)
				if err != nil || claims.Subject != uid || claims.Email != "alice@example.com" {
					t.Fatalf("ValidateSession: %+v, %v", claims, err)
				}
			}

			sessions := f.sessions(t, uid)
			if len(sessions) != 1 || sessions[0].UserAgent != "ua" || sessions[0].IPAddress != "203.0.113.7" {
				t.Fatalf("expected one listed session, got %+v", sessions)
			}
			if err := f.svc.RevokeSession(ctx, uid, sessions[0].ID); err != nil {
				t.Fatalf("RevokeSession: %v", err)
			}
			if m.mode == user.SessionModeOpaque {
				if _, err := f.svc.ValidateSession(ctx, res.Tokens.AccessToken); !errors.Is(err, user.ErrInvalidToken) {
					t.Fatalf("a revoked session must stop validating: %v", err)
				}
			}

			e := f.lastEvent(t, audit.EventUserLoginSucceeded)
			if e.ActorID != uid || e.Metadata["method"] != "passkey" || e.IPAddress != "203.0.113.7" {
				t.Fatalf("audit event: %+v", e)
			}
		})
	}
}

func TestIssueSessionRefusesALockedAccount(t *testing.T) {
	for _, m := range sessionModes {
		t.Run(m.name, func(t *testing.T) {
			ctx := context.Background()
			f := newIssueFixture(t, m.mode, user.Config{})
			uid := registerCaptured(t, f.svc, f.emailer, "alice@example.com", "correct-horse-battery")
			if err := f.stores.Lockouts.LockAccount(ctx, uid); err != nil {
				t.Fatal(err)
			}

			if _, err := f.svc.IssueSession(ctx, uid, user.LoginMethodOIDC, "ua", "ip"); !errors.Is(err, user.ErrAccountLocked) {
				t.Fatalf("got %v, want ErrAccountLocked", err)
			}
			if got := f.sessions(t, uid); len(got) != 0 {
				t.Fatalf("a refused sign-in must leave no session, got %d", len(got))
			}
			if e := f.lastEvent(t, audit.EventUserLoginLocked); e.Result != audit.ResultDenied || e.Metadata["method"] != "oidc" {
				t.Fatalf("audit event: %+v", e)
			}
		})
	}
}

// Failed passwords throttle password guessing. They must not be a way for
// a stranger to keep the owner from signing in with a passkey.
func TestIssueSessionIgnoresThePasswordThrottle(t *testing.T) {
	ctx := context.Background()
	f := newIssueFixture(t, user.SessionModeOpaque, user.Config{MaxFailedLoginAttempts: 2, FailedLoginWindow: time.Hour})
	uid := registerCaptured(t, f.svc, f.emailer, "alice@example.com", "correct-horse-battery")
	for range 3 {
		_, _ = f.svc.Authenticate(ctx, "alice@example.com", "wrong", "ua", "ip")
	}
	if _, err := f.svc.Authenticate(ctx, "alice@example.com", "correct-horse-battery", "ua", "ip"); !errors.Is(err, user.ErrAccountLocked) {
		t.Fatalf("precondition: the password path should be throttled, got %v", err)
	}
	if _, err := f.svc.IssueSession(ctx, uid, user.LoginMethodPasskey, "ua", "ip"); err != nil {
		t.Fatalf("IssueSession while throttled: %v", err)
	}
}

func TestIssueSessionEmailVerification(t *testing.T) {
	ctx := context.Background()
	f := newIssueFixture(t, user.SessionModeOpaque, user.Config{})
	u, err := f.svc.Register(ctx, "unverified@example.com", "correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}

	for _, method := range []user.LoginMethod{user.LoginMethodPasskey, user.LoginMethodOIDC, "saml"} {
		if _, err := f.svc.IssueSession(ctx, u.ID, method, "ua", "ip"); !errors.Is(err, user.ErrEmailNotVerified) {
			t.Fatalf("%s for an unverified account: got %v, want ErrEmailNotVerified", method, err)
		}
	}
	if e := f.lastEvent(t, audit.EventUserLoginFailed); e.Metadata["reason"] != "email_not_verified" || e.Metadata["method"] != "saml" {
		t.Fatalf("audit event: %+v", e)
	}
	// A magic link or a code was delivered to the address: the sign-in
	// itself is the proof.
	for _, method := range []user.LoginMethod{user.LoginMethodMagicLink, user.LoginMethodSignInCode} {
		if _, err := f.svc.IssueSession(ctx, u.ID, method, "ua", "ip"); err != nil {
			t.Fatalf("%s for an unverified account: %v", method, err)
		}
	}

	relaxed := newIssueFixture(t, user.SessionModeOpaque, user.Config{EmailVerification: user.EmailVerificationOptional})
	u, err = relaxed.svc.Register(ctx, "unverified@example.com", "correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relaxed.svc.IssueSession(ctx, u.ID, user.LoginMethodPasskey, "ua", "ip"); err != nil {
		t.Fatalf("under EmailVerificationOptional: %v", err)
	}
}

func TestIssueSessionRunsTheHooks(t *testing.T) {
	for _, m := range sessionModes {
		t.Run(m.name, func(t *testing.T) {
			ctx := context.Background()
			blocked := errors.New("blocked by the host")
			probe := &storetest.TxProbe{}
			var gate, after []string
			afterInTx := false
			stores, _ := freshStores()
			stores.Tx = probe
			emailer := &capturingEmailer{}
			svc := serviceOver(t, stores, emailer, user.Config{
				SessionMode: m.mode,
				Hooks: user.Hooks{
					BeforeAuthenticate: func(_ context.Context, email string) error {
						gate = append(gate, email)
						if email == "blocked@example.com" {
							return blocked
						}
						return nil
					},
					AfterAuthenticate: func(ctx context.Context, u store.User) error {
						after = append(after, u.Email)
						afterInTx = storetest.InTx(ctx)
						return nil
					},
				},
			})
			ok := registerCaptured(t, svc, emailer, "alice@example.com", "correct-horse-battery")
			bad := registerCaptured(t, svc, emailer, "blocked@example.com", "correct-horse-battery")

			if _, err := svc.IssueSession(ctx, bad, user.LoginMethodMagicLink, "ua", "ip"); !errors.Is(err, blocked) {
				t.Fatalf("the gate's own error must come back, got %v", err)
			}
			if len(after) != 0 {
				t.Fatal("AfterAuthenticate must not run for a refused sign-in")
			}
			if _, err := svc.IssueSession(ctx, ok, user.LoginMethodMagicLink, "ua", "ip"); err != nil {
				t.Fatalf("IssueSession: %v", err)
			}
			if len(gate) != 2 || len(after) != 1 || after[0] != "alice@example.com" {
				t.Fatalf("hooks saw gate=%v after=%v", gate, after)
			}
			if !afterInTx || probe.CallCount() != 1 {
				t.Fatalf("AfterAuthenticate should share the session's transaction (inTx=%v, calls=%d)", afterInTx, probe.CallCount())
			}
		})
	}
}

// An AfterAuthenticate error reaches the caller as from Authenticate.
func TestIssueSessionAfterHookErrorIsReturned(t *testing.T) {
	ctx := context.Background()
	failed := errors.New("provisioning failed")
	f := newIssueFixture(t, user.SessionModeOpaque, user.Config{Hooks: user.Hooks{
		AfterAuthenticate: func(context.Context, store.User) error { return failed },
	}})
	uid := registerCaptured(t, f.svc, f.emailer, "alice@example.com", "correct-horse-battery")
	if _, err := f.svc.IssueSession(ctx, uid, user.LoginMethodOIDC, "ua", "ip"); !errors.Is(err, failed) {
		t.Fatalf("got %v, want the hook's error", err)
	}
	if f.audit.has(audit.EventUserLoginSucceeded) {
		t.Fatal("a sign-in the hook refused must not be audited as a success")
	}
}

// A second factor the user turned on is not waived because the first was
// not a password.
func TestIssueSessionHonoursTwoFactor(t *testing.T) {
	for _, m := range sessionModes {
		t.Run(m.name, func(t *testing.T) {
			ctx := context.Background()
			f := newIssueFixture(t, m.mode, user.Config{})
			uid := registerCaptured(t, f.svc, f.emailer, "erin@example.com", "correct-horse-battery")
			setup, err := f.svc.BeginTwoFactorSetup(ctx, uid, "erin@example.com")
			if err != nil {
				t.Fatal(err)
			}
			code, _ := totp.GenerateCode(setup.Secret, time.Now())
			if _, err := f.svc.ConfirmTwoFactorSetup(ctx, uid, code); err != nil {
				t.Fatal(err)
			}

			res, err := f.svc.IssueSession(ctx, uid, user.LoginMethodMagicLink, "ua", "ip")
			if err != nil {
				t.Fatalf("IssueSession: %v", err)
			}
			if !res.RequiresTwoFactor || res.PendingTwoFactorToken == "" || res.Tokens != nil {
				t.Fatalf("expected a pending second factor, got %+v", res)
			}
			if got := f.sessions(t, uid); len(got) != 0 {
				t.Fatalf("no session before the second factor, got %d", len(got))
			}
			code, _ = totp.GenerateCode(setup.Secret, time.Now())
			final, err := f.svc.VerifyTwoFactorLogin(ctx, res.PendingTwoFactorToken, code, "ua", "ip")
			if err != nil || final.Tokens == nil {
				t.Fatalf("VerifyTwoFactorLogin: %+v, %v", final, err)
			}
		})
	}
}

func TestIssueSessionRefusesBadInput(t *testing.T) {
	ctx := context.Background()
	f := newIssueFixture(t, user.SessionModeOpaque, user.Config{})
	uid := registerCaptured(t, f.svc, f.emailer, "alice@example.com", "correct-horse-battery")

	if _, err := f.svc.IssueSession(ctx, uid, "", "ua", "ip"); err == nil {
		t.Fatal("an empty LoginMethod must be refused")
	}
	if got := f.sessions(t, uid); len(got) != 0 {
		t.Fatal("nothing may be issued without a method")
	}
	const gone = "00000000-0000-4000-8000-000000000000"
	if _, err := f.svc.IssueSession(ctx, gone, user.LoginMethodPasskey, "ua", "ip"); !errors.Is(err, user.ErrInvalidCredentials) {
		t.Fatalf("an unknown user: got %v, want ErrInvalidCredentials", err)
	}
	if e := f.lastEvent(t, audit.EventUserLoginFailed); e.Metadata["reason"] != "unknown_user" {
		t.Fatalf("audit event: %+v", e)
	}
}
