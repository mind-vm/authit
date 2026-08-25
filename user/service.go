// Package user implements user registration, authentication, session
// management, password reset, email verification, and TOTP-based
// two-factor auth. It depends only on the store interfaces it needs (no
// concrete database) and on a jwt.Signer for token issuance.
package user

import (
	"errors"

	"github.com/mind-vm/authit/audit"
	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/store"
)

// Stores groups the persistence ports the user package needs. A host
// application supplies concrete implementations (or reuses memstore).
type Stores struct {
	Users              store.UserStore
	RefreshTokens      store.RefreshTokenStore
	PasswordResets     store.PasswordResetStore
	EmailVerifications store.EmailVerificationStore
	TOTP               store.TOTPStore
	PendingTwoFactor   store.PendingTwoFactorStore
	Lockouts           store.LockoutStore
}

// Service implements user auth flows.
type Service struct {
	stores  Stores
	signer  authitjwt.Signer
	emailer EmailSender
	audit   audit.Logger
	cfg     Config
}

// NewService constructs a Service. emailer may be nil, in which case
// NoopEmailSender is used (useful for tests or apps that deliver
// links out of band). Config.AuditLogger may be nil, in which case
// audit.NoopLogger is used.
func NewService(stores Stores, signer authitjwt.Signer, emailer EmailSender, cfg Config) (*Service, error) {
	if stores.Users == nil || stores.RefreshTokens == nil || stores.PasswordResets == nil ||
		stores.EmailVerifications == nil || stores.TOTP == nil || stores.PendingTwoFactor == nil ||
		stores.Lockouts == nil {
		return nil, errors.New("authit/user: all Stores fields are required")
	}
	if signer == nil {
		return nil, errors.New("authit/user: signer is required")
	}
	if emailer == nil {
		emailer = NoopEmailSender{}
	}
	auditLogger := cfg.AuditLogger
	if auditLogger == nil {
		auditLogger = audit.NoopLogger{}
	}
	return &Service{stores: stores, signer: signer, emailer: emailer, audit: auditLogger, cfg: cfg.withDefaults()}, nil
}
