// Package emaillogin implements the two passwordless email flows: a magic
// link, and a short sign-in code the user types.
//
// # They are the same flow with different entropy
//
// Both are request-deliver-redeem, and both prove one thing: that whoever
// completes them can read mail sent to that address. The difference is the
// credential. A magic link carries 256 bits and is redeemed by presenting
// it, so guessing is not a threat. A six-digit code carries about twenty,
// and is therefore only as safe as the limit on how many times it can be
// guessed — which is why Config.MaxCodeAttempts exists, why a wrong code
// is counted even though it did not match, and why requesting a new code
// destroys the old one rather than adding to a pool of valid answers.
//
// # Accounts are created on redemption, never on request
//
// A passwordless sign-in can create an account, and it does so only once
// the token comes back. Creating one when the link is requested would let
// anybody fill a user table with addresses they do not control, simply by
// typing them into a form. Delivering to an inbox and having the token
// return is what proves control, and until that happens nothing is stored
// against the address but a pending token.
//
// # What it does not do
//
// It issues no authit credential. Like pat, device, oidc and passkey, it
// answers "who is this" and leaves what to hand back to the host.
package emaillogin

import (
	"context"
	"errors"
	"time"

	"github.com/mind-vm/authit/audit"
	authitcrypto "github.com/mind-vm/authit/crypto"
	"github.com/mind-vm/authit/ratelimit"
	"github.com/mind-vm/authit/store"
)

// Sender delivers the credential. It is separate from user.EmailSender so
// that adding these flows does not change an interface every existing host
// already implements.
//
// The address is normalised. For SendMagicLink the token is the raw value
// to embed in a URL; for SendSignInCode it is the digits to show.
type Sender interface {
	SendMagicLink(ctx context.Context, email, token string) error
	SendSignInCode(ctx context.Context, email, code string) error
}

// NoopSender delivers nothing. It is the default, and is useful for tests
// and for hosts that deliver out of band.
type NoopSender struct{}

func (NoopSender) SendMagicLink(context.Context, string, string) error  { return nil }
func (NoopSender) SendSignInCode(context.Context, string, string) error { return nil }

// Stores are the ports this package needs.
type Stores struct {
	Users  store.UserStore
	Tokens store.EmailLoginStore
	// Tx is optional; see store.TxRunner. With it, creating an account and
	// consuming the token that authorised it are atomic.
	Tx store.TxRunner
}

// Config tunes the flows.
type Config struct {
	// LinkTTL is how long a magic link stays valid. Defaults to 15
	// minutes. It is short because the link is a bearer credential sitting
	// in an inbox, and inboxes are forwarded, synced and breached.
	LinkTTL time.Duration
	// CodeTTL defaults to 10 minutes, shorter still: the shorter a
	// low-entropy credential is live, the less an attacker's guessing
	// budget is worth.
	CodeTTL time.Duration
	// CodeLength defaults to 6 digits. Raising it buys entropy that
	// MaxCodeAttempts mostly makes unnecessary, at the cost of a code
	// people mistype.
	CodeLength int
	// MaxCodeAttempts is how many wrong guesses destroy a code. Defaults
	// to 5.
	//
	// This is the control the whole flow rests on. Six digits is a million
	// possibilities; five guesses per code makes a hit a one-in-two-hundred-
	// thousand event, and requesting a fresh code costs an email and starts
	// again from zero. Without it the code is guessable in an afternoon.
	MaxCodeAttempts int
	// DisableSignUp refuses to create an account for an address that
	// matches no existing user. The default is to create one, which is
	// safe here because the account is created on redemption -- proof of
	// inbox control -- and not on request.
	DisableSignUp bool
	// RateLimiter throttles requests and redemptions. Nil means
	// ratelimit.Noop. Keys:
	//
	//	email-login:request:<email>  a new link or code for an address
	//	email-login:redeem:<email>   a code redemption attempt
	//
	// The request key bounds using this flow to flood somebody's inbox.
	// The redeem key is a second line behind MaxCodeAttempts, bounding an
	// attacker who burns codes and requests fresh ones.
	RateLimiter ratelimit.Limiter
	// AuditLogger receives request and redemption events.
	AuditLogger audit.Logger
}

func (c Config) withDefaults() Config {
	if c.LinkTTL <= 0 {
		c.LinkTTL = 15 * time.Minute
	}
	if c.CodeTTL <= 0 {
		c.CodeTTL = 10 * time.Minute
	}
	if c.CodeLength <= 0 {
		c.CodeLength = 6
	}
	if c.MaxCodeAttempts <= 0 {
		c.MaxCodeAttempts = 5
	}
	if c.RateLimiter == nil {
		c.RateLimiter = ratelimit.Noop{}
	}
	return c
}

// Service implements the passwordless email flows.
type Service struct {
	stores Stores
	sender Sender
	audit  audit.Logger
	cfg    Config
}

// NewService constructs a Service. sender may be nil, in which case
// NoopSender is used.
func NewService(stores Stores, sender Sender, cfg Config) (*Service, error) {
	if stores.Users == nil || stores.Tokens == nil {
		return nil, errors.New("authit/emaillogin: Stores.Users and Stores.Tokens are required")
	}
	if sender == nil {
		sender = NoopSender{}
	}
	auditLogger := cfg.AuditLogger
	if auditLogger == nil {
		auditLogger = audit.NoopLogger{}
	}
	return &Service{stores: stores, sender: sender, audit: auditLogger, cfg: cfg.withDefaults()}, nil
}

// codeHash binds a code to the address it was sent to.
//
// Six digits are not unique -- two accounts can hold the same code at the
// same moment -- so hashing the code alone would make one person's code
// redeemable by another. Including the address makes the pair unique and
// scopes guessing to a single account.
func codeHash(email, code string) string {
	return authitcrypto.HashToken(email + "\x00" + code)
}
