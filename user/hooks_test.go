package user_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/authit/storetest"
	"github.com/mind-vm/authit/user"
	"github.com/pquerna/otp/totp"
)

// TestBeforeRegisterGatesRegistration is the headline use: invite-only
// signup, a domain allow-list, a blocklist.
func TestBeforeRegisterGatesRegistration(t *testing.T) {
	ctx := context.Background()
	stores, users := freshStores()
	notInvited := errors.New("not invited")

	var seen string
	svc := serviceOver(t, stores, &capturingEmailer{}, user.Config{
		Hooks: user.Hooks{
			BeforeRegister: func(_ context.Context, email string) error {
				seen = email
				if email != "invited@example.com" {
					return notInvited
				}
				return nil
			},
		},
	})

	if _, err := svc.Register(ctx, "  Stranger@Example.COM ", "correct-horse-battery"); !errors.Is(err, notInvited) {
		t.Fatalf("the hook's own error must reach the caller unchanged, got %v", err)
	}
	// The hook sees the normalised address, not what was typed — otherwise
	// every allow-list would need to re-implement normalisation, and get
	// it subtly different.
	if seen != "stranger@example.com" {
		t.Fatalf("hook saw %q, want the normalised address", seen)
	}
	if _, err := users.GetUserByEmail(ctx, "stranger@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a refused registration must leave no account behind")
	}

	if _, err := svc.Register(ctx, "invited@example.com", "correct-horse-battery"); err != nil {
		t.Fatalf("an allowed registration: %v", err)
	}
}

// TestAfterRegisterRollsBackWithATxRunner is the guarantee that makes After
// hooks worth having: "create the account only if provisioning succeeds".
func TestAfterRegisterRollsBackWithATxRunner(t *testing.T) {
	ctx := context.Background()
	provisioningFailed := errors.New("workspace provisioning failed")

	stores, _ := freshStores()
	probe := &storetest.TxProbe{}
	stores.Tx = probe
	witness := storetest.NewTxWitness()
	stores.Users = witnessedUsers{stores.Users, witness}

	svc := serviceOver(t, stores, &capturingEmailer{}, user.Config{
		Hooks: user.Hooks{
			AfterRegister: func(ctx context.Context, u store.User) error {
				witness.Record(ctx, "AfterRegister")
				if u.Email == "" || u.ID == "" {
					t.Errorf("AfterRegister received an incomplete user: %+v", u)
				}
				return provisioningFailed
			},
		},
	})

	if _, err := svc.Register(ctx, "alice@example.com", "correct-horse-battery"); !errors.Is(err, provisioningFailed) {
		t.Fatalf("expected the hook's error, got %v", err)
	}
	if probe.CallCount() != 1 {
		t.Fatalf("Register opened %d transactions, want 1 once an AfterRegister hook exists", probe.CallCount())
	}
	// The hook must be inside, or its error could not undo anything.
	witness.AssertInTx(t, "AfterRegister")
}

// TestNoTransactionWithoutAnAfterHook: a single insert plus a nil hook has
// nothing to make atomic, and a transaction per registration would be a
// round trip spent guarding a no-op.
func TestNoTransactionWithoutAnAfterHook(t *testing.T) {
	ctx := context.Background()
	stores, _ := freshStores()
	probe := &storetest.TxProbe{}
	stores.Tx = probe
	svc := serviceOver(t, stores, &capturingEmailer{}, user.Config{
		EmailVerification: user.EmailVerificationOptional,
	})

	if _, err := svc.Register(ctx, "alice@example.com", "correct-horse-battery"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.Authenticate(ctx, "alice@example.com", "correct-horse-battery", "ua", "ip"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if probe.CallCount() != 0 {
		t.Fatalf("opened %d transactions with no After hooks configured, want 0", probe.CallCount())
	}
}

// TestBeforeAuthenticateRunsAfterTheLockout: a hook must not be reachable
// in a way that bypasses the brute-force controls in front of it.
func TestBeforeAuthenticateRunsAfterTheLockout(t *testing.T) {
	ctx := context.Background()
	stores, _ := freshStores()
	calls := 0
	svc := serviceOver(t, stores, &capturingEmailer{}, user.Config{
		MaxFailedLoginAttempts: 2,
		FailedLoginWindow:      time.Minute,
		Hooks: user.Hooks{
			BeforeAuthenticate: func(context.Context, string) error {
				calls++
				return nil
			},
		},
	})
	const email, password = "alice@example.com", "correct-horse-battery"
	if _, err := svc.Register(ctx, email, password); err != nil {
		t.Fatalf("Register: %v", err)
	}

	for i := 0; i < 2; i++ {
		if _, err := svc.Authenticate(ctx, email, "wrong-horse-battery", "ua", "ip"); !errors.Is(err, user.ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	before := calls
	if _, err := svc.Authenticate(ctx, email, password, "ua", "ip"); !errors.Is(err, user.ErrAccountLocked) {
		t.Fatalf("expected ErrAccountLocked, got %v", err)
	}
	if calls != before {
		t.Fatal("BeforeAuthenticate ran on a throttled login; it must sit behind the lockout, not in front of it")
	}
}

// TestAfterAuthenticateOnlyFiresOnACompletedLogin: an account with 2FA
// enabled has not logged in when the password is accepted. A hook stamping
// last-seen, or writing an audit trail, must not fire there.
func TestAfterAuthenticateOnlyFiresOnACompletedLogin(t *testing.T) {
	ctx := context.Background()
	stores, _ := freshStores()
	fired := 0
	emailer := &capturingEmailer{}
	svc := serviceOver(t, stores, emailer, user.Config{
		Hooks: user.Hooks{
			AfterAuthenticate: func(context.Context, store.User) error {
				fired++
				return nil
			},
		},
	})
	const email, password = "alice@example.com", "correct-horse-battery"
	uid := registerCaptured(t, svc, emailer, email, password)

	setup, err := svc.BeginTwoFactorSetup(ctx, uid, email)
	if err != nil {
		t.Fatalf("BeginTwoFactorSetup: %v", err)
	}
	code, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if _, err := svc.ConfirmTwoFactorSetup(ctx, uid, code); err != nil {
		t.Fatalf("ConfirmTwoFactorSetup: %v", err)
	}
	fired = 0

	res, err := svc.Authenticate(ctx, email, password, "ua", "ip")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !res.RequiresTwoFactor {
		t.Fatal("expected 2FA to be required")
	}
	if fired != 0 {
		t.Fatal("AfterAuthenticate fired on a login still owing a second factor")
	}

	loginCode, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if _, err := svc.VerifyTwoFactorLogin(ctx, res.PendingTwoFactorToken, loginCode, "ua", "ip"); err != nil {
		t.Fatalf("VerifyTwoFactorLogin: %v", err)
	}
	if fired != 1 {
		t.Fatalf("AfterAuthenticate fired %d times after a completed login, want 1", fired)
	}
}

// TestAfterPasswordChangeCoversBothPaths: a password can change by two
// routes, and a hook that only saw one would miss exactly the case that
// matters — a reset driven by somebody who lost control of the account.
func TestAfterPasswordChangeCoversBothPaths(t *testing.T) {
	ctx := context.Background()
	stores, _ := freshStores()
	fired := 0
	emailer := &capturingEmailer{}
	svc := serviceOver(t, stores, emailer, user.Config{
		Hooks: user.Hooks{
			AfterPasswordChange: func(_ context.Context, u store.User) error {
				fired++
				if u.PasswordHash == "" {
					t.Error("the hook should see the user as they now are")
				}
				return nil
			},
		},
	})
	const email = "alice@example.com"
	uid := registerCaptured(t, svc, emailer, email, "correct-horse-battery")

	if err := svc.ChangePassword(ctx, uid, "correct-horse-battery", "a-second-passphrase"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if fired != 1 {
		t.Fatalf("after ChangePassword, hook fired %d times, want 1", fired)
	}

	if err := svc.RequestPasswordReset(ctx, email); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if err := svc.ResetPassword(ctx, emailer.lastResetToken, "a-third-passphrase"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	if fired != 2 {
		t.Fatalf("after ResetPassword, hook fired %d times, want 2", fired)
	}
}

// TestZeroHooksChangeNothing: the whole struct is optional.
func TestZeroHooksChangeNothing(t *testing.T) {
	ctx := context.Background()
	stores, _ := freshStores()
	emailer := &capturingEmailer{}
	svc := serviceOver(t, stores, emailer, user.Config{})
	const email, password = "alice@example.com", "correct-horse-battery"
	uid := registerCaptured(t, svc, emailer, email, password)
	if _, err := svc.Authenticate(ctx, email, password, "ua", "ip"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if err := svc.ChangePassword(ctx, uid, password, "a-second-passphrase"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
}
