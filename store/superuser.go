package store

import (
	"context"
	"time"
)

// Superuser is an operator identity, deliberately unrelated to Team/Member
// roles: it has no organization and no role field. The only way to create
// one is through the superuser package's API (never exposed over a public
// registration endpoint), so a compromised user-facing flow can never
// mint one.
type Superuser struct {
	ID           string
	Email        string
	PasswordHash string
	DisplayName  string
	IsActive     bool
	CreatedBy    *string
	LastLoginAt  *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// SuperuserStore persists Superuser records.
type SuperuserStore interface {
	CreateSuperuser(ctx context.Context, s *Superuser) error
	GetSuperuserByID(ctx context.Context, id string) (*Superuser, error)
	GetSuperuserByEmail(ctx context.Context, email string) (*Superuser, error)
	ListSuperusers(ctx context.Context) ([]*Superuser, error)
	UpdateSuperuser(ctx context.Context, s *Superuser) error
	CountSuperusers(ctx context.Context) (int, error)
}

// SuperuserRefreshToken is the admin-plane equivalent of RefreshToken, kept
// in its own store/table so a leaked user-session store dump can't be
// replayed as an admin session.
type SuperuserRefreshToken struct {
	ID          string
	SuperuserID string
	TokenHash   string
	ExpiresAt   time.Time
	RevokedAt   *time.Time
	UserAgent   string
	IPAddress   string
	CreatedAt   time.Time
}

// SuperuserRefreshTokenStore persists admin-plane refresh tokens.
type SuperuserRefreshTokenStore interface {
	CreateSuperuserRefreshToken(ctx context.Context, t *SuperuserRefreshToken) error
	GetSuperuserRefreshTokenByHash(ctx context.Context, hash string) (*SuperuserRefreshToken, error)
	RevokeSuperuserRefreshToken(ctx context.Context, id string) error
	RevokeAllSuperuserRefreshTokens(ctx context.Context, superuserID string) error
}
