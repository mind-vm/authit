package user_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/authit/user"
)

// The operator verbs recover an account without anything from its holder.
func TestOperatorRecoversAnAccount(t *testing.T) {
	f := newLockoutFixture(t, user.Config{MaxFailedLoginAttempts: 3, FailedLoginWindow: time.Minute})
	ctx := context.Background()
	const email, password = "erin@example.com", "correct-horse-battery"
	uid, _ := enrollTOTP(t, f, email, password)

	if _, err := f.svc.AccountState(ctx, "00000000-0000-4000-8000-000000000000"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an unknown account: got %v, want ErrNotFound", err)
	}

	// Throttle it and lock it.
	for range 3 {
		_, _ = f.svc.Authenticate(ctx, email, "wrong-horse-battery", "ua", "ip")
	}
	if err := f.lockouts.LockAccount(ctx, uid); err != nil {
		t.Fatal(err)
	}
	st, err := f.svc.AccountState(ctx, uid)
	if err != nil || !st.Locked || !st.Throttled || !st.TwoFactor {
		t.Fatalf("before recovery: %+v, %v; want locked, throttled, two-factor", st, err)
	}

	if err := f.svc.Unlock(ctx, "operator", uid); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := f.svc.ResetTwoFactor(ctx, "operator", uid); err != nil {
		t.Fatalf("ResetTwoFactor: %v", err)
	}
	if err := f.svc.ResetTwoFactor(ctx, "operator", uid); !errors.Is(err, user.ErrTwoFactorNotEnabled) {
		t.Fatalf("a second reset: got %v, want ErrTwoFactorNotEnabled", err)
	}
	st, _ = f.svc.AccountState(ctx, uid)
	if st.Locked || st.Throttled || st.TwoFactor {
		t.Fatalf("after recovery: %+v", st)
	}

	// The password alone now signs in, twice over.
	for range 2 {
		res, err := f.svc.Authenticate(ctx, email, password, "ua", "ip")
		if err != nil || res.Tokens == nil {
			t.Fatalf("sign-in after recovery: %+v, %v", res, err)
		}
	}
	n, err := f.svc.RevokeAllSessions(ctx, "operator", uid)
	if err != nil || n != 2 {
		t.Fatalf("RevokeAllSessions = %d, %v; want 2", n, err)
	}
	if sessions, _ := f.svc.ListSessions(ctx, uid, ""); len(sessions) != 0 {
		t.Fatalf("%d sessions survived", len(sessions))
	}

	f.emailer.lastResetToken = ""
	if err := f.svc.SendPasswordReset(ctx, uid); err != nil {
		t.Fatalf("SendPasswordReset: %v", err)
	}
	if f.emailer.lastResetToken == "" {
		t.Fatal("no reset link was mailed")
	}
}
