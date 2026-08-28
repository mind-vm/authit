package superuser

import (
	"context"
	"errors"
	"time"

	"github.com/mind-vm/authit/audit"
	authitcrypto "github.com/mind-vm/authit/crypto"
	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/ratelimit"
	"github.com/mind-vm/authit/store"
)

// Stores groups the persistence ports the superuser package needs.
type Stores struct {
	Superusers    store.SuperuserStore
	RefreshTokens store.SuperuserRefreshTokenStore
	// Lockouts is optional; if nil, failed-login lockout is disabled.
	Lockouts store.LockoutStore
	// Tx is optional. Supplying it makes Refresh's rotation atomic; nil
	// leaves it as two independent writes. See store.TxRunner.
	Tx store.TxRunner
}

// Config tunes the superuser package's flows. Defaults are intentionally
// stricter than the user package's: short-lived access tokens, since
// operator sessions warrant more frequent re-authentication.
type Config struct {
	// Audience is the JWT audience claim that marks a token as belonging to
	// this plane. Defaults to DefaultAudience.
	Audience string
	// AccessTokenTTL defaults to 5 minutes.
	AccessTokenTTL time.Duration
	// RefreshTokenTTL defaults to 7 days.
	RefreshTokenTTL time.Duration
	// ImpersonationTTL defaults to 15 minutes.
	ImpersonationTTL time.Duration
	// MaxFailedLoginAttempts defaults to 5. Ignored if Stores.Lockouts is
	// nil.
	MaxFailedLoginAttempts int
	// FailedLoginWindow defaults to 15 minutes.
	FailedLoginWindow time.Duration
	// AuditLogger receives security-relevant events (login, lockout,
	// deactivation, impersonation). Nil means events are not recorded —
	// see package audit.
	AuditLogger audit.Logger
	// PasswordHasher hashes and verifies operator passwords. Nil means
	// crypto.DefaultHasher() — Argon2id. Existing hashes in any format
	// authit has written keep verifying, and are upgraded on next login.
	PasswordHasher authitcrypto.Hasher
	// PasswordValidator rejects unacceptable passwords when an operator
	// account is created. Nil means crypto.DefaultPasswordPolicy().
	// Consider a stricter policy here than on the user plane: these
	// accounts can impersonate.
	PasswordValidator authitcrypto.PasswordValidator
	// RateLimiter throttles Authenticate before the password KDF runs.
	// Nil means ratelimit.Noop. Keys:
	//
	//	superuser-login:ip:<ip>        per source address
	//	superuser-login:email:<email>  per account, normalised
	RateLimiter ratelimit.Limiter
}

func (c Config) withDefaults() Config {
	if c.Audience == "" {
		c.Audience = DefaultAudience
	}
	if c.AccessTokenTTL <= 0 {
		c.AccessTokenTTL = 5 * time.Minute
	}
	if c.RefreshTokenTTL <= 0 {
		c.RefreshTokenTTL = 7 * 24 * time.Hour
	}
	if c.ImpersonationTTL <= 0 {
		c.ImpersonationTTL = 15 * time.Minute
	}
	if c.MaxFailedLoginAttempts <= 0 {
		c.MaxFailedLoginAttempts = 5
	}
	if c.FailedLoginWindow <= 0 {
		c.FailedLoginWindow = 15 * time.Minute
	}
	if c.PasswordHasher == nil {
		c.PasswordHasher = authitcrypto.DefaultHasher()
	}
	if c.PasswordValidator == nil {
		c.PasswordValidator = authitcrypto.DefaultPasswordPolicy()
	}
	if c.RateLimiter == nil {
		c.RateLimiter = ratelimit.Noop{}
	}
	return c
}

// TokenPair is what a completed login/refresh returns.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// Service implements the superuser/operator auth plane.
type Service struct {
	stores Stores
	signer authitjwt.Signer
	audit  audit.Logger
	cfg    Config
}

// NewService constructs a Service. signer may be the same jwt.Signer used
// by the user package — audience separation, not a separate secret, is
// what keeps the two planes from accepting each other's tokens.
// Config.AuditLogger may be nil, in which case audit.NoopLogger is used.
func NewService(stores Stores, signer authitjwt.Signer, cfg Config) (*Service, error) {
	if stores.Superusers == nil || stores.RefreshTokens == nil {
		return nil, errors.New("authit/superuser: Stores.Superusers and Stores.RefreshTokens are required")
	}
	if signer == nil {
		return nil, errors.New("authit/superuser: signer is required")
	}
	auditLogger := cfg.AuditLogger
	if auditLogger == nil {
		auditLogger = audit.NoopLogger{}
	}
	return &Service{stores: stores, signer: signer, audit: auditLogger, cfg: cfg.withDefaults()}, nil
}

// Bootstrap creates the first superuser, and only the first: it fails with
// ErrAlreadyBootstrapped if any superuser already exists. Intended to be
// called once at application startup from a trusted source (e.g. an
// environment variable), never from an HTTP handler.
func (s *Service) Bootstrap(ctx context.Context, email, password, displayName string) (store.Superuser, error) {
	count, err := s.stores.Superusers.CountSuperusers(ctx)
	if err != nil {
		return store.Superuser{}, err
	}
	if count > 0 {
		return store.Superuser{}, ErrAlreadyBootstrapped
	}
	return s.createSuperuser(ctx, email, password, displayName, nil)
}

// CreateSuperuser creates an additional superuser, attributed to
// createdByID (another superuser's ID). There is no public registration
// endpoint for this plane by design — only an authenticated superuser (or
// Bootstrap) can create one.
func (s *Service) CreateSuperuser(ctx context.Context, email, password, displayName, createdByID string) (store.Superuser, error) {
	return s.createSuperuser(ctx, email, password, displayName, &createdByID)
}

func (s *Service) createSuperuser(ctx context.Context, email, password, displayName string, createdBy *string) (store.Superuser, error) {
	email = store.NormalizeEmail(email)
	if err := s.cfg.PasswordValidator(ctx, email, password); err != nil {
		return store.Superuser{}, err
	}
	hash, err := s.cfg.PasswordHasher.Hash(password)
	if err != nil {
		return store.Superuser{}, err
	}
	id, err := authitcrypto.NewID()
	if err != nil {
		return store.Superuser{}, err
	}
	now := time.Now()
	su := &store.Superuser{
		ID: id, Email: email, PasswordHash: hash, DisplayName: displayName,
		IsActive: true, CreatedBy: createdBy, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.stores.Superusers.CreateSuperuser(ctx, su); err != nil {
		return store.Superuser{}, err
	}
	createdByID := ""
	if createdBy != nil {
		createdByID = *createdBy
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventSuperuserCreated, Result: audit.ResultSuccess,
		ActorID: createdByID, TargetID: su.ID, Email: su.Email,
	})
	return *su, nil
}

// ListSuperusers lists every superuser account.
func (s *Service) ListSuperusers(ctx context.Context) ([]store.Superuser, error) {
	list, err := s.stores.Superusers.ListSuperusers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]store.Superuser, len(list))
	for i, su := range list {
		out[i] = *su
	}
	return out, nil
}

// Deactivate soft-deletes a superuser account and revokes all of its
// sessions. There is deliberately no reactivate: a deactivated superuser is
// not recoverable through this API.
func (s *Service) Deactivate(ctx context.Context, callerID, targetID string) error {
	if callerID == targetID {
		return ErrCannotDeactivateSelf
	}
	su, err := s.stores.Superusers.GetSuperuserByID(ctx, targetID)
	if err != nil {
		return err
	}
	su.IsActive = false
	su.UpdatedAt = time.Now()
	if err := s.stores.Superusers.UpdateSuperuser(ctx, su); err != nil {
		return err
	}
	if err := s.stores.RefreshTokens.RevokeAllSuperuserRefreshTokens(ctx, targetID); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventSuperuserDeactivated, Result: audit.ResultSuccess, ActorID: callerID, TargetID: targetID,
	})
	return nil
}
