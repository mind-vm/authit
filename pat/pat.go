package pat

import (
	"context"
	"errors"
	"slices"
	"time"

	authitcrypto "github.com/jryannel/authit/crypto"
	"github.com/jryannel/authit/store"
	"github.com/jryannel/sqlb"
)

// CreateToken issues a new personal access token for userID. Returns the
// raw token exactly once — only its hash is persisted, so the caller must
// hand it to the user immediately.
func (s *Service) CreateToken(ctx context.Context, userID, name string, scopes []string, expiresAt *time.Time) (string, store.PersonalAccessToken, error) {
	if s.cfg.RequireExpiry && expiresAt == nil {
		return "", store.PersonalAccessToken{}, ErrExpiryRequired
	}
	if s.cfg.MaxExpiry != nil {
		max := time.Now().Add(*s.cfg.MaxExpiry)
		if expiresAt == nil || expiresAt.After(max) {
			return "", store.PersonalAccessToken{}, ErrExpiryTooFar
		}
	}

	raw, _, err := authitcrypto.GenerateOpaqueToken()
	if err != nil {
		return "", store.PersonalAccessToken{}, err
	}
	raw = s.cfg.Prefix + raw

	// ID and CreatedAt are left zero so the column defaults assign them; the
	// inserted row comes back carrying what the database actually stored.
	row := store.PersonalAccessToken{
		UserID: userID, Name: name, TokenHash: authitcrypto.HashToken(raw),
		Scopes: scopes, ExpiresAt: expiresAt,
	}
	inserted, err := sqlb.InsertRows(&row).Exec(ctx, s.db)
	if err != nil {
		return "", store.PersonalAccessToken{}, err
	}
	return raw, inserted[0], nil
}

// ListTokens lists every token belonging to userID (including expired or
// revoked ones, so a UI can show their status — filter by ExpiresAt/
// RevokedAt as needed).
func (s *Service) ListTokens(ctx context.Context, userID string) ([]store.PersonalAccessToken, error) {
	return sqlb.Query[store.PersonalAccessToken]().
		Where(store.PersonalAccessTokenCols.UserID.Eq(userID)).
		All(ctx, s.db)
}

// RevokeToken revokes a token, scoped to userID so a caller can't revoke
// another user's token.
func (s *Service) RevokeToken(ctx context.Context, userID, tokenID string) error {
	t, err := sqlb.Query[store.PersonalAccessToken]().
		Where(store.PersonalAccessTokenCols.ID.Eq(tokenID)).
		One(ctx, s.db)
	if err != nil {
		if errors.Is(err, sqlb.ErrNotFound) {
			return ErrInvalidToken
		}
		return err
	}
	if t.UserID != userID {
		return ErrNotOwner
	}
	if t.RevokedAt != nil {
		return nil
	}
	now := time.Now()
	_, err = store.UpdatePersonalAccessToken().
		SetRevokedAt(&now).
		Where(store.PersonalAccessTokenCols.ID.Eq(tokenID)).
		Stmt().Exec(ctx, s.db)
	return err
}

// Resolve validates a raw bearer token and returns the record it maps to,
// bumping LastUsedAt on success (best-effort: a failure to record that
// does not fail the resolution). Callers typically check HasScope against
// the result afterward.
func (s *Service) Resolve(ctx context.Context, rawToken string) (store.PersonalAccessToken, error) {
	t, err := sqlb.Query[store.PersonalAccessToken]().
		Where(store.PersonalAccessTokenCols.TokenHash.Eq(authitcrypto.HashToken(rawToken))).
		One(ctx, s.db)
	if err != nil {
		if errors.Is(err, sqlb.ErrNotFound) {
			return store.PersonalAccessToken{}, ErrInvalidToken
		}
		return store.PersonalAccessToken{}, err
	}
	if t.RevokedAt != nil {
		return store.PersonalAccessToken{}, ErrInvalidToken
	}
	if t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt) {
		return store.PersonalAccessToken{}, ErrInvalidToken
	}

	now := time.Now()
	// Best-effort: a token that resolved is resolved, whether or not we
	// managed to record that it was used.
	_, _ = store.UpdatePersonalAccessToken().
		SetLastUsedAt(&now).
		Where(store.PersonalAccessTokenCols.ID.Eq(t.ID)).
		Stmt().Exec(ctx, s.db)
	t.LastUsedAt = &now

	return t, nil
}

// HasScope reports whether t was granted scope.
func HasScope(t store.PersonalAccessToken, scope string) bool {
	return slices.Contains(t.Scopes, scope)
}
