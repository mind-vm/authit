package store

import (
	"context"
	"time"
)

// PersonalAccessToken is a long-lived, named, scoped bearer credential a
// user creates for themselves — for a CLI, a script, or any caller that
// isn't going through an interactive login. Unlike RefreshToken, it is not
// paired with a short-lived access token: the raw value itself is the
// bearer credential, verified on every request via its hash.
type PersonalAccessToken struct {
	ID         string
	UserID     string
	Name       string
	TokenHash  string
	Scopes     []string
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
	CreatedAt  time.Time
}

// PersonalAccessTokenStore persists PersonalAccessToken records.
type PersonalAccessTokenStore interface {
	CreatePersonalAccessToken(ctx context.Context, t *PersonalAccessToken) error
	GetPersonalAccessToken(ctx context.Context, id string) (*PersonalAccessToken, error)
	GetPersonalAccessTokenByHash(ctx context.Context, hash string) (*PersonalAccessToken, error)
	ListPersonalAccessTokensByUser(ctx context.Context, userID string) ([]*PersonalAccessToken, error)
	UpdatePersonalAccessToken(ctx context.Context, t *PersonalAccessToken) error
}
