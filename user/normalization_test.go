package user_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/authit/user"
)

func TestNormalizeEmail(t *testing.T) {
	for in, want := range map[string]string{
		"Alice@Example.COM":     "alice@example.com",
		"  bob@example.com \t":  "bob@example.com",
		"\nCarol@Example.com\n": "carol@example.com",
		"dave@example.com":      "dave@example.com",
		"":                      "",
	} {
		if got := store.NormalizeEmail(in); got != want {
			t.Fatalf("NormalizeEmail(%q) = %q, want %q", in, got, want)
		}
	}
	// Deliberately NOT normalised: dot-stripping and +tag removal are
	// Gmail-specific and would merge distinct addresses elsewhere.
	for _, in := range []string{"a.b@example.com", "a+tag@example.com"} {
		if got := store.NormalizeEmail(in); got != in {
			t.Fatalf("NormalizeEmail(%q) = %q, want it left alone", in, got)
		}
	}
}

// TestEmailCaseDoesNotCreateASecondAccount is the user-visible half: which
// behaviour you got used to depend entirely on your store's collation.
func TestEmailCaseDoesNotCreateASecondAccount(t *testing.T) {
	ctx := context.Background()
	stores, users := freshStores()
	emailer := &capturingEmailer{}
	svc := serviceOver(t, stores, emailer, user.Config{})
	const password = "correct-horse-battery"

	u, err := svc.Register(ctx, "  Alice@Example.COM ", password)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if u.Email != "alice@example.com" {
		t.Fatalf("stored email = %q, want the normalised form", u.Email)
	}
	if _, err := svc.Register(ctx, "alice@example.com", password); !errors.Is(err, user.ErrEmailTaken) {
		t.Fatalf("expected ErrEmailTaken for a case variant, got %v", err)
	}
	// Every read path finds the same row regardless of the case supplied.
	if _, err := users.GetUserByEmail(ctx, "alice@example.com"); err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if err := svc.RequestEmailVerification(ctx, u.ID); err != nil {
		t.Fatalf("RequestEmailVerification: %v", err)
	}
	if err := svc.VerifyEmail(ctx, emailer.lastVerificationToken); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	for _, variant := range []string{"alice@example.com", "ALICE@EXAMPLE.COM", " Alice@Example.com "} {
		if _, err := svc.Authenticate(ctx, variant, password, "ua", "ip"); err != nil {
			t.Fatalf("Authenticate(%q): %v", variant, err)
		}
	}
	if err := svc.RequestPasswordReset(ctx, "ALICE@EXAMPLE.COM"); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if emailer.lastResetToken == "" {
		t.Fatal("a case variant must still find the account and send a reset")
	}
}

// TestThrottleCannotBeResetByVaryingCase is the security half. The
// failed-login counter is keyed by email, so if the lookup normalised and
// the counter did not, an attacker got a fresh budget per capitalisation.
func TestThrottleCannotBeResetByVaryingCase(t *testing.T) {
	ctx := context.Background()
	f := newLockoutFixture(t, user.Config{MaxFailedLoginAttempts: 3})
	registerCaptured(t, f.svc, f.emailer, "victim@example.com", "correct-horse-battery")

	variants := []string{"victim@example.com", "Victim@example.com", "VICTIM@EXAMPLE.COM"}
	for i, v := range variants {
		if _, err := f.svc.Authenticate(ctx, v, "wrong-horse-battery", "ua", "ip"); !errors.Is(err, user.ErrInvalidCredentials) {
			t.Fatalf("attempt %d (%q): %v", i+1, v, err)
		}
	}
	// Three failures across three capitalisations is still three failures.
	if _, err := f.svc.Authenticate(ctx, strings.ToUpper("victim@example.com"), "correct-horse-battery", "ua", "ip"); !errors.Is(err, user.ErrAccountLocked) {
		t.Fatalf("expected ErrAccountLocked, got %v", err)
	}
}
