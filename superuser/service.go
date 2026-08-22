package superuser

import (
	"context"
	"errors"
	"time"

	authitcrypto "github.com/jryannel/authit/crypto"
	authitjwt "github.com/jryannel/authit/jwt"
	"github.com/jryannel/authit/store"
	"github.com/jryannel/sqlb"
)

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
	// MaxFailedLoginAttempts defaults to 5.
	MaxFailedLoginAttempts int
	// FailedLoginWindow defaults to 15 minutes.
	FailedLoginWindow time.Duration
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
	db     *sqlb.DB
	signer authitjwt.Signer
	cfg    Config
}

// NewService constructs a Service over db, which must be backed by a database
// carrying authit's tables — see authitschema.Declare.
//
// signer may be the same jwt.Signer used by the user package — audience
// separation, not a separate secret, is what keeps the two planes from
// accepting each other's tokens.
//
// Lockout is no longer optional. It used to be, because it was a store a host
// might not have implemented; now it is two tables that come with the rest, so
// there is nothing to leave out and no nil to check.
func NewService(db *sqlb.DB, signer authitjwt.Signer, cfg Config) (*Service, error) {
	if db == nil {
		return nil, errors.New("authit/superuser: db is required")
	}
	if signer == nil {
		return nil, errors.New("authit/superuser: signer is required")
	}
	return &Service{db: db, signer: signer, cfg: cfg.withDefaults()}, nil
}

// Bootstrap creates the first superuser, and only the first: it fails with
// ErrAlreadyBootstrapped if any superuser already exists. Intended to be
// called once at application startup from a trusted source (e.g. an
// environment variable), never from an HTTP handler.
func (s *Service) Bootstrap(ctx context.Context, email, password, displayName string) (store.Superuser, error) {
	existing, err := sqlb.Query[store.Superuser]().Exists(ctx, s.db)
	if err != nil {
		return store.Superuser{}, err
	}
	if existing {
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
	hash, err := authitcrypto.HashPassword(password)
	if err != nil {
		return store.Superuser{}, err
	}
	row := store.Superuser{
		Email: email, PasswordHash: hash, DisplayName: displayName,
		IsActive: true, CreatedByID: createdBy,
	}
	inserted, err := sqlb.InsertRows(&row).Exec(ctx, s.db)
	if err != nil {
		return store.Superuser{}, err
	}
	return inserted[0], nil
}

// ListSuperusers lists every superuser account.
func (s *Service) ListSuperusers(ctx context.Context) ([]store.Superuser, error) {
	return sqlb.Query[store.Superuser]().All(ctx, s.db)
}

// Deactivate soft-deletes a superuser account and revokes all of its
// sessions. There is deliberately no reactivate: a deactivated superuser is
// not recoverable through this API.
func (s *Service) Deactivate(ctx context.Context, callerID, targetID string) error {
	if callerID == targetID {
		return ErrCannotDeactivateSelf
	}
	// Deactivating and revoking are one unit of work: an account marked
	// inactive whose sessions survived is still a usable operator session
	// until it expires, which is exactly what this call is meant to prevent.
	return s.db.WithTx(ctx, func(ctx context.Context, tx *sqlb.DB) error {
		updated, err := store.UpdateSuperuser().
			SetIsActive(false).
			SetUpdatedAt(time.Now()).
			Where(store.SuperuserCols.ID.Eq(targetID)).
			Stmt().Exec(ctx, tx)
		if err != nil {
			return err
		}
		// Update returns the rows it touched, so an empty result is how "no
		// such superuser" arrives — there is no separate lookup to do first.
		if len(updated) == 0 {
			return ErrNotFound
		}
		now := time.Now()
		_, err = store.UpdateSuperuserRefreshToken().
			SetRevokedAt(&now).
			Where(
				store.SuperuserRefreshTokenCols.SuperuserID.Eq(targetID),
				store.SuperuserRefreshTokenCols.RevokedAt.IsNull(),
			).
			Stmt().Exec(ctx, tx)
		return err
	})
}
