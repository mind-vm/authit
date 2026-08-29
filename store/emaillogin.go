package store

import (
	"context"
	"time"
)

// EmailLoginKind distinguishes the two passwordless email flows, which
// differ in exactly one way that matters: how much entropy the credential
// carries.
type EmailLoginKind string

const (
	// EmailLoginLink is a magic link: a full-entropy opaque token in a URL,
	// looked up directly by its hash.
	EmailLoginLink EmailLoginKind = "link"
	// EmailLoginCode is a short numeric code the user types. It is looked
	// up by email address rather than by hash, because six digits are not
	// unique -- two accounts can hold the same code at the same moment --
	// and because a wrong guess still has to find the record in order to
	// be counted against the attempt limit.
	EmailLoginCode EmailLoginKind = "code"
)

// EmailLoginToken is an outstanding magic link or sign-in code.
//
// It is keyed by email rather than user id, because the account may not
// exist yet: a passwordless flow can create one, and it does so when the
// token is redeemed rather than when it is requested. See the emaillogin
// package for why that ordering matters.
type EmailLoginToken struct {
	ID    string
	Email string
	Kind  EmailLoginKind
	// TokenHash is the hash of the credential. For a link it is the hash
	// of the token alone; for a code it is the hash of the address and the
	// code together, so that a code is only ever valid for the address it
	// was sent to.
	TokenHash string
	// Attempts counts failed redemptions of a code. It is what makes a
	// six-digit credential survivable at all -- see MaxCodeAttempts.
	Attempts  int
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// EmailLoginStore persists outstanding magic links and sign-in codes.
type EmailLoginStore interface {
	CreateEmailLoginToken(ctx context.Context, t *EmailLoginToken) error
	// GetEmailLoginTokenByHash resolves a magic link.
	GetEmailLoginTokenByHash(ctx context.Context, hash string) (*EmailLoginToken, error)
	// GetEmailLoginTokenByEmail resolves the outstanding token for an
	// address, which is how a code redemption finds the record it must
	// count a failed guess against.
	GetEmailLoginTokenByEmail(ctx context.Context, email string, kind EmailLoginKind) (*EmailLoginToken, error)
	// MarkEmailLoginTokenUsed marks the token used, and reports
	// ErrNotFound if it was already used or is gone.
	//
	// This is a compare-and-set, not an update, and the difference is the
	// single-use property. Reading a token, seeing UsedAt is nil, and
	// writing it back lets two concurrent redemptions of one link both
	// observe an unused token and both succeed -- one credential, two
	// sessions. In SQL:
	//
	//	UPDATE email_login_tokens SET used_at = $2
	//	 WHERE id = $1 AND used_at IS NULL
	//
	// and no rows affected means somebody else won, which is ErrNotFound.
	// Callers treat winning this as the authorisation to proceed, so an
	// implementation that always reports success has removed the control
	// rather than weakened it.
	MarkEmailLoginTokenUsed(ctx context.Context, id string, usedAt time.Time) error

	// IncrementEmailLoginTokenAttempts adds one to the token's failed-guess
	// count and returns the new value, or ErrNotFound if it is gone.
	//
	// Atomic for the same reason, and it matters more here: the returned
	// count is what decides when a six-digit code is burned, and read-then-
	// write loses increments under concurrency. An attacker guessing in
	// parallel would get many tries charged as one, which is the entire
	// budget MaxCodeAttempts exists to impose. In SQL:
	//
	//	UPDATE email_login_tokens SET attempts = attempts + 1
	//	 WHERE id = $1 RETURNING attempts
	//
	// Return the value the database computed, never one added in Go.
	IncrementEmailLoginTokenAttempts(ctx context.Context, id string) (int, error)
	// DeleteEmailLoginTokens removes every outstanding token of that kind
	// for the address.
	//
	// Requesting a new credential must invalidate the old one. If ten
	// codes were live at once, guessing would be ten times easier, and an
	// attacker can ask for as many as they like.
	DeleteEmailLoginTokens(ctx context.Context, email string, kind EmailLoginKind) error
}
