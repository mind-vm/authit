package store

import (
	"context"
	"time"
)

// Account is an external identity linked to a User: the record that says
// "the Google subject 1234 is this authit user".
//
// It is separate from User rather than columns on it because one user may
// hold several — a Google login and a GitHub login for the same person —
// and because an authit user may hold none at all, which is what a
// password-only account is.
//
// # The uniqueness that matters
//
// (Provider, ProviderAccountID) must be UNIQUE. That pair is the only thing
// establishing which user a sign-in belongs to; without the constraint, a
// duplicate row is an account takeover waiting for a race.
//
// Email is stored for display and for the linking decisions the oidc
// package makes, and is deliberately NOT unique: two providers can assert
// the same address, and one provider can assert an address that belongs to
// somebody else's authit account. Treating it as an identifier is the
// classic social-login vulnerability; see oidc.LinkingPolicy.
type Account struct {
	ID     string
	UserID string
	// Provider is the id of the provider that asserted this identity, e.g.
	// "google". It is the host's own name for it, matched exactly.
	Provider string
	// ProviderAccountID is the provider's stable subject identifier — not
	// the email address, which users change.
	ProviderAccountID string
	// Email is what the provider asserted at the last sign-in, normalised.
	Email string
	// EmailVerified records whether the provider claimed to have verified
	// the address. It is the provider's claim, not a fact.
	EmailVerified bool
	// AccessTokenEncrypted and RefreshTokenEncrypted hold the provider's
	// own OAuth tokens, if the host chose to keep them for calling the
	// provider's API later. They are ciphertext (AES-256-GCM, via the
	// crypto package) rather than plaintext, because a database that leaks
	// these leaks live access to the user's account at the provider.
	// Both are nil when token persistence is off, which is the default.
	AccessTokenEncrypted  []byte
	RefreshTokenEncrypted []byte
	// TokenExpiresAt is when AccessTokenEncrypted stops working.
	TokenExpiresAt *time.Time
	// Scopes are what the provider granted.
	Scopes    []string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// AccountStore persists linked external identities.
type AccountStore interface {
	CreateAccount(ctx context.Context, a *Account) error
	GetAccount(ctx context.Context, id string) (*Account, error)
	// GetAccountByProvider looks up the link by the provider's own subject
	// identifier. This is the query every social sign-in makes, and the
	// (provider, provider_account_id) index it needs must be UNIQUE.
	GetAccountByProvider(ctx context.Context, provider, providerAccountID string) (*Account, error)
	ListAccountsByUser(ctx context.Context, userID string) ([]*Account, error)
	UpdateAccount(ctx context.Context, a *Account) error
	DeleteAccount(ctx context.Context, id string) error
}
