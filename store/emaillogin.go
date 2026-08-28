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
	UpdateEmailLoginToken(ctx context.Context, t *EmailLoginToken) error
	// DeleteEmailLoginTokens removes every outstanding token of that kind
	// for the address.
	//
	// Requesting a new credential must invalidate the old one. If ten
	// codes were live at once, guessing would be ten times easier, and an
	// attacker can ask for as many as they like.
	DeleteEmailLoginTokens(ctx context.Context, email string, kind EmailLoginKind) error
}
