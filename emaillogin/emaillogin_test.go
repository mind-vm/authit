package emaillogin_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/mind-vm/authit/emaillogin"
	"github.com/mind-vm/authit/memstore"
	"github.com/mind-vm/authit/ratelimit"
	"github.com/mind-vm/authit/store"
)

// capturingSender records what was delivered, standing in for a mail
// provider so a test can act as the person holding the inbox.
type capturingSender struct {
	lastToken string
	lastCode  string
	links     int
	codes     int
}

func (c *capturingSender) SendMagicLink(_ context.Context, _, token string) error {
	c.lastToken, c.links = token, c.links+1
	return nil
}

func (c *capturingSender) SendSignInCode(_ context.Context, _, code string) error {
	c.lastCode, c.codes = code, c.codes+1
	return nil
}

type fixture struct {
	svc    *emaillogin.Service
	users  *memstore.UserStore
	tokens *memstore.EmailLoginStore
	sender *capturingSender
}

func newFixture(t *testing.T, cfg emaillogin.Config) fixture {
	t.Helper()
	users := memstore.NewUserStore()
	tokens := memstore.NewEmailLoginStore()
	sender := &capturingSender{}
	svc, err := emaillogin.NewService(emaillogin.Stores{Users: users, Tokens: tokens}, sender, cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return fixture{svc: svc, users: users, tokens: tokens, sender: sender}
}

func TestMagicLinkSignsInAndCreatesTheAccount(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, emaillogin.Config{})

	if err := f.svc.RequestMagicLink(ctx, "  Alice@Example.COM "); err != nil {
		t.Fatalf("RequestMagicLink: %v", err)
	}
	res, err := f.svc.RedeemMagicLink(ctx, f.sender.lastToken)
	if err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}
	if !res.CreatedUser {
		t.Fatal("expected the account to be created on redemption")
	}
	if res.User.Email != "alice@example.com" {
		t.Fatalf("stored email = %q, want the normalised form", res.User.Email)
	}
	if res.User.PasswordHash != "" {
		t.Fatal("a passwordless sign-up must not invent a password")
	}
	// Redeeming the token IS the verification: the credential went to that
	// address and came back. A second confirmation email would ask the
	// user to prove what they just proved.
	if !res.User.EmailVerified {
		t.Fatal("redeeming a magic link should leave the address verified")
	}

	// Single use.
	if _, err := f.svc.RedeemMagicLink(ctx, f.sender.lastToken); !errors.Is(err, emaillogin.ErrInvalidToken) {
		t.Fatalf("a magic link must be single-use, got %v", err)
	}
}

// TestNoAccountIsCreatedOnRequest: creating one when the link is asked for
// would let anybody fill the user table with addresses they do not control.
func TestNoAccountIsCreatedOnRequest(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, emaillogin.Config{})
	if err := f.svc.RequestMagicLink(ctx, "stranger@example.com"); err != nil {
		t.Fatalf("RequestMagicLink: %v", err)
	}
	if _, err := f.users.GetUserByEmail(ctx, "stranger@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("requesting a link must not create an account")
	}
}

// TestRequestingRevealsNothingAboutTheAccount: this is a form anybody can
// type any address into.
func TestRequestingRevealsNothingAboutTheAccount(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, emaillogin.Config{DisableSignUp: true})
	if err := f.users.CreateUser(ctx, &store.User{ID: "u1", Email: "known@example.com"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	// Both succeed identically, even with sign-up off -- the refusal comes
	// later, at redemption, where only the inbox owner sees it.
	if err := f.svc.RequestMagicLink(ctx, "known@example.com"); err != nil {
		t.Fatalf("known address: %v", err)
	}
	if err := f.svc.RequestMagicLink(ctx, "unknown@example.com"); err != nil {
		t.Fatalf("unknown address must behave identically: %v", err)
	}
	if _, err := f.svc.RedeemMagicLink(ctx, f.sender.lastToken); !errors.Is(err, emaillogin.ErrSignUpDisabled) {
		t.Fatalf("expected ErrSignUpDisabled at redemption, got %v", err)
	}
}

// TestCodeGuessingIsBounded is the control the whole code flow rests on.
// Six digits is a million possibilities; without a limit it is guessable in
// an afternoon.
func TestCodeGuessingIsBounded(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, emaillogin.Config{MaxCodeAttempts: 3})
	const email = "alice@example.com"
	if err := f.svc.RequestSignInCode(ctx, email); err != nil {
		t.Fatalf("RequestSignInCode: %v", err)
	}
	real := f.sender.lastCode

	for i := 0; i < 3; i++ {
		wrong := strconv.Itoa(100000 + i)
		if wrong == real {
			wrong = "999999"
		}
		if _, err := f.svc.RedeemSignInCode(ctx, email, wrong); !errors.Is(err, emaillogin.ErrInvalidToken) {
			t.Fatalf("guess %d: %v", i+1, err)
		}
	}
	// The budget is spent, so even the real code no longer works: the
	// token was destroyed rather than merely refused, or it would still be
	// live for the next attempt.
	if _, err := f.svc.RedeemSignInCode(ctx, email, real); !errors.Is(err, emaillogin.ErrInvalidToken) {
		t.Fatalf("the correct code should be dead after the budget is spent, got %v", err)
	}
	if _, err := f.tokens.GetEmailLoginTokenByEmail(ctx, email, store.EmailLoginCode); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("an exhausted code must be deleted, not left pending")
	}
}

// TestRequestingANewCodeDestroysTheOld: two live codes halve the work of
// guessing, and an attacker can request as many as they like.
func TestRequestingANewCodeDestroysTheOld(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, emaillogin.Config{})
	const email = "alice@example.com"

	if err := f.svc.RequestSignInCode(ctx, email); err != nil {
		t.Fatalf("RequestSignInCode: %v", err)
	}
	first := f.sender.lastCode
	if err := f.svc.RequestSignInCode(ctx, email); err != nil {
		t.Fatalf("RequestSignInCode: %v", err)
	}
	second := f.sender.lastCode
	if first == second {
		t.Skip("the two codes collided; rerun")
	}
	if _, err := f.svc.RedeemSignInCode(ctx, email, first); !errors.Is(err, emaillogin.ErrInvalidToken) {
		t.Fatal("the superseded code must not still work")
	}
	if _, err := f.svc.RedeemSignInCode(ctx, email, second); err != nil {
		t.Fatalf("the current code should work: %v", err)
	}
}

// TestACodeIsOnlyValidForItsOwnAddress: six digits are not unique, so
// hashing the code alone would make one person's code redeemable by
// another.
func TestACodeIsOnlyValidForItsOwnAddress(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, emaillogin.Config{})
	if err := f.svc.RequestSignInCode(ctx, "alice@example.com"); err != nil {
		t.Fatalf("RequestSignInCode: %v", err)
	}
	aliceCode := f.sender.lastCode
	if err := f.svc.RequestSignInCode(ctx, "bob@example.com"); err != nil {
		t.Fatalf("RequestSignInCode: %v", err)
	}
	if _, err := f.svc.RedeemSignInCode(ctx, "bob@example.com", aliceCode); err == nil {
		t.Fatal("a code must not be redeemable for a different address")
	}
}

// TestACodeCannotBeRedeemedAsALink: the link path does not count guesses,
// so a low-entropy credential must not be redeemable through it.
func TestACodeCannotBeRedeemedAsALink(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, emaillogin.Config{})
	if err := f.svc.RequestSignInCode(ctx, "alice@example.com"); err != nil {
		t.Fatalf("RequestSignInCode: %v", err)
	}
	if _, err := f.svc.RedeemMagicLink(ctx, f.sender.lastCode); !errors.Is(err, emaillogin.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestExpiredCredentialsAreRefused(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, emaillogin.Config{LinkTTL: time.Nanosecond, CodeTTL: time.Nanosecond})
	const email = "alice@example.com"

	if err := f.svc.RequestMagicLink(ctx, email); err != nil {
		t.Fatalf("RequestMagicLink: %v", err)
	}
	if _, err := f.svc.RedeemMagicLink(ctx, f.sender.lastToken); !errors.Is(err, emaillogin.ErrInvalidToken) {
		t.Fatalf("an expired link must be refused, got %v", err)
	}
	if err := f.svc.RequestSignInCode(ctx, email); err != nil {
		t.Fatalf("RequestSignInCode: %v", err)
	}
	if _, err := f.svc.RedeemSignInCode(ctx, email, f.sender.lastCode); !errors.Is(err, emaillogin.ErrInvalidToken) {
		t.Fatalf("an expired code must be refused, got %v", err)
	}
}

// TestExistingAccountsSignInWithoutBeingRecreated.
func TestExistingAccountsSignInWithoutBeingRecreated(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, emaillogin.Config{})
	existing := &store.User{ID: "u1", Email: "alice@example.com", PasswordHash: "$argon2id$real"}
	if err := f.users.CreateUser(ctx, existing); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := f.svc.RequestMagicLink(ctx, "alice@example.com"); err != nil {
		t.Fatalf("RequestMagicLink: %v", err)
	}
	res, err := f.svc.RedeemMagicLink(ctx, f.sender.lastToken)
	if err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}
	if res.CreatedUser || res.User.ID != existing.ID {
		t.Fatalf("expected the existing account, got %+v", res)
	}
	// The password is untouched: a magic link is another way in, not a
	// way to take the existing one away.
	after, _ := f.users.GetUserByID(ctx, existing.ID)
	if after.PasswordHash != "$argon2id$real" {
		t.Fatal("signing in by link must not disturb the password")
	}
}

// TestRequestsAreRateLimited bounds using this flow to flood an inbox.
func TestRequestsAreRateLimited(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, emaillogin.Config{
		RateLimiter: ratelimit.NewMemory(ratelimit.MemoryConfig{Burst: 2, Interval: time.Hour}),
	})
	const email = "alice@example.com"
	for i := 0; i < 2; i++ {
		if err := f.svc.RequestMagicLink(ctx, email); err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
	}
	if err := f.svc.RequestMagicLink(ctx, email); !errors.Is(err, emaillogin.ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}
	if f.sender.links != 2 {
		t.Fatalf("sent %d emails, want 2: a refused request must not deliver", f.sender.links)
	}
}

// TestGeneratedCodesAreTheConfiguredLength and are all digits.
func TestGeneratedCodesAreTheConfiguredLength(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, emaillogin.Config{CodeLength: 8})
	if err := f.svc.RequestSignInCode(ctx, "alice@example.com"); err != nil {
		t.Fatalf("RequestSignInCode: %v", err)
	}
	code := f.sender.lastCode
	if len(code) != 8 {
		t.Fatalf("code %q is %d digits, want 8", code, len(code))
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			t.Fatalf("code %q contains a non-digit; leading zeros must be preserved as digits", code)
		}
	}
}
