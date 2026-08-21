package pat

import (
	"context"
	"errors"
	"slices"
	"time"

	authitcrypto "github.com/jryannel/authit/crypto"
	"github.com/jryannel/authit/store"
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

	id, err := authitcrypto.NewID()
	if err != nil {
		return "", store.PersonalAccessToken{}, err
	}
	t := &store.PersonalAccessToken{
		ID: id, UserID: userID, Name: name, TokenHash: authitcrypto.HashToken(raw),
		Scopes: scopes, ExpiresAt: expiresAt, CreatedAt: time.Now(),
	}
	if err := s.stores.Tokens.CreatePersonalAccessToken(ctx, t); err != nil {
		return "", store.PersonalAccessToken{}, err
	}
	return raw, *t, nil
}

// ListTokens lists every token belonging to userID (including expired or
// revoked ones, so a UI can show their status — filter by ExpiresAt/
// RevokedAt as needed).
func (s *Service) ListTokens(ctx context.Context, userID string) ([]store.PersonalAccessToken, error) {
	tokens, err := s.stores.Tokens.ListPersonalAccessTokensByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]store.PersonalAccessToken, len(tokens))
	for i, t := range tokens {
		out[i] = *t
	}
	return out, nil
}

// RevokeToken revokes a token, scoped to userID so a caller can't revoke
// another user's token.
func (s *Service) RevokeToken(ctx context.Context, userID, tokenID string) error {
	t, err := s.stores.Tokens.GetPersonalAccessToken(ctx, tokenID)
	if err != nil {
		return err
	}
	if t.UserID != userID {
		return ErrNotOwner
	}
	if t.RevokedAt != nil {
		return nil
	}
	now := time.Now()
	t.RevokedAt = &now
	return s.stores.Tokens.UpdatePersonalAccessToken(ctx, t)
}

// Resolve validates a raw bearer token and returns the record it maps to,
// bumping LastUsedAt on success (best-effort: a failure to record that
// does not fail the resolution). Callers typically check HasScope against
// the result afterward.
func (s *Service) Resolve(ctx context.Context, rawToken string) (store.PersonalAccessToken, error) {
	t, err := s.stores.Tokens.GetPersonalAccessTokenByHash(ctx, authitcrypto.HashToken(rawToken))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
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
	t.LastUsedAt = &now
	_ = s.stores.Tokens.UpdatePersonalAccessToken(ctx, t)

	return *t, nil
}

// HasScope reports whether t was granted scope.
func HasScope(t store.PersonalAccessToken, scope string) bool {
	return slices.Contains(t.Scopes, scope)
}
