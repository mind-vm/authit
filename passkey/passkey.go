// Package passkey adds WebAuthn — passkeys, Touch ID, hardware security
// keys — to authit, both as a second factor after a password and as a
// primary credential that replaces one.
//
// # The two shapes, and why the difference matters
//
// A passkey used as a *second factor* proves possession of a device; the
// password was the first factor. A passkey used as the *only* factor has to
// carry both, and it does that through user verification: the authenticator
// asks for a PIN or a biometric before it will sign. Possession plus
// verification is two factors in one gesture — but only if user
// verification actually happened, which is why Config.UserVerification
// exists and why VerificationRequired is the default.
//
// Get that wrong and a passkey login is single-factor: anyone holding an
// unlocked device is the user.
//
// # What it does not do
//
// It issues no authit credential. Like pat, device and oidc, it answers
// "who is this, and how strongly" and leaves what to hand back to the host.
//
// It does not verify attestation against the FIDO Metadata Service. Doing
// so answers "is this authenticator model one I trust", which matters for
// enterprise deployments enforcing a hardware policy and is irrelevant to
// almost everybody else; it needs a metadata blob, its trust chain, and a
// refresh story. Registration here records the attestation the
// authenticator supplied, and does not judge it.
package passkey

import (
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	wan "github.com/go-webauthn/webauthn/webauthn"
	"github.com/mind-vm/authit/audit"
	"github.com/mind-vm/authit/store"
)

// Stores are the ports this package needs.
type Stores struct {
	Users       store.UserStore
	Credentials store.WebAuthnCredentialStore
	// Tx is optional; see store.TxRunner.
	Tx store.TxRunner
}

// CloneAction says what to do when an assertion's signature counter fails
// to advance.
//
// A counter that does not increase is the specification's one built-in
// signal that a credential's private key exists in more than one place —
// that somebody extracted it from a hardware key, or restored a backup of
// something that was not supposed to be backed up. The specification leaves
// the response to the relying party.
type CloneAction int

const (
	// CloneReject refuses the login and flags the credential. This is the
	// default: a counter regression means either a cloned authenticator or
	// a broken one, and neither is something to sign a user in on.
	CloneReject CloneAction = iota
	// CloneFlag records the warning on the credential and allows the
	// login. Choose it only knowing that authenticators do exist which
	// report a counter of zero forever — those never trigger this at all,
	// so a regression from a nonzero counter remains meaningful.
	CloneFlag
)

// Config tunes the package.
type Config struct {
	// RPDisplayName is shown to the user by the authenticator ("Example
	// Inc").
	RPDisplayName string
	// RPID is the relying party identifier: your registrable domain, with
	// no scheme, port or path ("example.com"). A credential is bound to it
	// permanently — change it and every passkey your users hold stops
	// working, with no migration.
	RPID string
	// RPOrigins are the exact origins allowed to complete a ceremony
	// ("https://example.com"). Every entry is checked against the origin
	// the browser reports, which is what stops a page on another site from
	// driving your authenticator.
	RPOrigins []string
	// UserVerification defaults to protocol.VerificationRequired. Lower it
	// only for a passkey used strictly as a second factor behind a
	// password, and understand that doing so makes a passkey-only login
	// single-factor.
	UserVerification protocol.UserVerificationRequirement
	// OnClone defaults to CloneReject.
	OnClone CloneAction
	// Timeout bounds how long a ceremony may take. Defaults to 60s.
	Timeout time.Duration
	// AuditLogger receives registration, login and revocation events.
	AuditLogger audit.Logger
}

func (c Config) withDefaults() Config {
	if c.UserVerification == "" {
		c.UserVerification = protocol.VerificationRequired
	}
	if c.Timeout <= 0 {
		c.Timeout = 60 * time.Second
	}
	return c
}

// Service runs the WebAuthn ceremonies.
type Service struct {
	stores Stores
	web    *wan.WebAuthn
	audit  audit.Logger
	cfg    Config
}

// NewService constructs a Service.
func NewService(stores Stores, cfg Config) (*Service, error) {
	if stores.Users == nil || stores.Credentials == nil {
		return nil, errors.New("authit/passkey: Stores.Users and Stores.Credentials are required")
	}
	if cfg.RPID == "" {
		return nil, ErrConfig
	}
	if len(cfg.RPOrigins) == 0 {
		// Without an origin list every origin is allowed, which removes
		// the check that stops another site from driving the ceremony.
		return nil, errors.New("authit/passkey: at least one RPOrigin is required")
	}
	cfg = cfg.withDefaults()

	web, err := wan.New(&wan.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
		Timeouts: wan.TimeoutsConfig{
			Login:        wan.TimeoutConfig{Enforce: true, Timeout: cfg.Timeout, TimeoutUVD: cfg.Timeout},
			Registration: wan.TimeoutConfig{Enforce: true, Timeout: cfg.Timeout, TimeoutUVD: cfg.Timeout},
		},
	})
	if err != nil {
		return nil, err
	}
	auditLogger := cfg.AuditLogger
	if auditLogger == nil {
		auditLogger = audit.NoopLogger{}
	}
	return &Service{stores: stores, web: web, audit: auditLogger, cfg: cfg}, nil
}
