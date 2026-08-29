package store

import (
	"context"
	"time"
)

// WebAuthnCredential is a registered authenticator — a passkey in a phone
// or password manager, or a hardware security key — bound to a User.
//
// # Data is the authoritative record
//
// Everything a signature check needs lives in Data, opaque to the store and
// to authit's own ports: it is whatever the passkey package's WebAuthn
// implementation serialises, and it must round-trip byte for byte. Store it
// as bytes, never as text — it is not UTF-8, and a text column will mangle
// it.
//
// The remaining fields are denormalised out of Data and rewritten on every
// update. They exist so a host can index, list and display credentials
// without decoding a blob, and so an operator can query for a clone
// warning. When they disagree with Data, Data wins.
//
// # The uniqueness that matters
//
// CredentialID must be UNIQUE. It is what an assertion is looked up by, and
// therefore the only thing deciding whose credential just signed the
// challenge; a duplicate makes that lookup a coin flip between two
// accounts.
type WebAuthnCredential struct {
	ID     string
	UserID string
	// CredentialID is the authenticator's own identifier for this
	// credential, as raw bytes. Not a string: it is arbitrary binary.
	CredentialID []byte
	// Data is the opaque, authoritative credential record. See above.
	Data []byte

	// Name is a user-facing label ("MacBook Touch ID", "YubiKey"), so
	// somebody with four passkeys can tell which to revoke.
	Name string
	// Transports are the authenticator's reported transports ("internal",
	// "usb", "nfc", "hybrid"), useful for tailoring UI prompts.
	Transports []string
	// BackupEligible and BackupState describe whether the credential is a
	// syncing passkey and whether it is currently backed up. A credential
	// that is not backup-eligible lives on exactly one device, so losing
	// that device loses the credential -- which is worth telling a user
	// before it is their only one.
	BackupEligible bool
	BackupState    bool
	// CloneWarning records that an assertion arrived with a signature
	// counter that did not advance, which is evidence the credential's
	// private key exists in more than one place. It is a column rather
	// than only a field inside Data so that "find every compromised
	// credential" is a query.
	CloneWarning bool

	LastUsedAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// WebAuthnCredentialStore persists registered authenticators.
type WebAuthnCredentialStore interface {
	CreateWebAuthnCredential(ctx context.Context, c *WebAuthnCredential) error
	GetWebAuthnCredential(ctx context.Context, id string) (*WebAuthnCredential, error)
	// GetWebAuthnCredentialByCredentialID is the lookup every assertion
	// makes. Its index must be UNIQUE; see the type's documentation.
	GetWebAuthnCredentialByCredentialID(ctx context.Context, credentialID []byte) (*WebAuthnCredential, error)
	ListWebAuthnCredentialsByUser(ctx context.Context, userID string) ([]*WebAuthnCredential, error)
	UpdateWebAuthnCredential(ctx context.Context, c *WebAuthnCredential) error
	DeleteWebAuthnCredential(ctx context.Context, id string) error
}

// WebAuthnChallenge is one in-flight WebAuthn ceremony.
//
// A ceremony spans two requests -- the browser is handed options, and comes
// back with a signature over the challenge inside them -- so the challenge
// has to survive in between. It survives here, and not in the caller's
// hands, because it is what the signature is checked against: a caller able
// to substitute it can present an assertion captured earlier and have it
// verified against its own expectations.
//
// # Data is the record
//
// Data is the ceremony state, opaque to the store: whatever the passkey
// package serialises, which must round-trip byte for byte. Store it as
// bytes, never as text -- it is not UTF-8, and a text column will mangle
// it. Nothing in the store may interpret it.
type WebAuthnChallenge struct {
	ID string
	// TokenHash is the hash of the handle held by the browser. The handle
	// itself is never stored, for the same reason a refresh token is not:
	// a leaked table should not yield live credentials.
	//
	// It must be UNIQUE. It is the only thing a ceremony is found by.
	TokenHash string
	// UserID is the account a *registration* ceremony belongs to, and nil
	// for a discoverable login, which names no user by design.
	//
	// authit never looks a challenge up by it, and never reads it back.
	// It is denormalised out of Data so a host can put a foreign key here
	// and have in-flight ceremonies cascade away with the account -- the
	// same reason WebAuthnCredential carries fields it does not strictly
	// need.
	UserID    *string
	Data      []byte
	ExpiresAt time.Time
	CreatedAt time.Time
}

// WebAuthnChallengeStore persists in-flight WebAuthn ceremonies.
//
// Two methods, and the second is the reason the port exists. There is
// deliberately no Get -- a caller that can read a challenge without
// consuming it can replay one -- no Update, because a challenge is written
// once, and no sweeper, because no other port here ships one (see
// schema.sql for the DELETE, which is yours to schedule).
type WebAuthnChallengeStore interface {
	CreateWebAuthnChallenge(ctx context.Context, c *WebAuthnChallenge) error

	// ConsumeWebAuthnChallenge atomically deletes the challenge and returns
	// what it held, or ErrNotFound if no row matched.
	//
	// Atomic is the whole method. Two callers presenting the same handle
	// concurrently must not both receive a row: exactly one deletes it and
	// sees it, and every other gets ErrNotFound. That race is precisely
	// what lets a captured assertion be replayed, and removing it is the
	// only reason this port is not just a map.
	//
	// In SQL it is one statement:
	//
	//	DELETE FROM webauthn_challenges WHERE token_hash = $1 RETURNING ...
	//
	// What matters is that the DELETE decides, not the read. Reading the
	// row first and returning it is fine -- the read may even be stale --
	// so long as the caller returns it only when its own delete removed
	// exactly one row, and reports ErrNotFound when it removed none. A
	// read that decides, with the delete as an afterthought, is the broken
	// version: two callers both read, both return, and the assertion is
	// accepted twice.
	//
	// Expiry is not judged here. An expired row is returned like any other
	// and refused by the passkey package; consuming it is still right,
	// since a spent challenge should not linger either way.
	ConsumeWebAuthnChallenge(ctx context.Context, tokenHash string) (*WebAuthnChallenge, error)
}
