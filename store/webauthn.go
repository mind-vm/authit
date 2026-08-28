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
