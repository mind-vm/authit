package user

import (
	"context"
	"errors"

	authitcrypto "github.com/jryannel/authit/crypto"
)

// ListSessions returns every active (unrevoked, unexpired) session for a
// user. If currentRefreshToken is non-empty, the matching session (if any)
// is flagged IsCurrent.
func (s *Service) ListSessions(ctx context.Context, userID, currentRefreshToken string) ([]Session, error) {
	tokens, err := s.stores.RefreshTokens.ListActiveRefreshTokens(ctx, userID)
	if err != nil {
		return nil, err
	}
	var currentHash string
	if currentRefreshToken != "" {
		currentHash = authitcrypto.HashToken(currentRefreshToken)
	}
	sessions := make([]Session, 0, len(tokens))
	for _, t := range tokens {
		sessions = append(sessions, Session{
			ID:        t.ID,
			IsCurrent: currentHash != "" && t.TokenHash == currentHash,
			UserAgent: t.UserAgent,
			IPAddress: t.IPAddress,
			CreatedAt: t.CreatedAt,
			ExpiresAt: t.ExpiresAt,
		})
	}
	return sessions, nil
}

// RevokeSession revokes one session by ID, scoped to userID so a caller
// can't revoke another user's session.
func (s *Service) RevokeSession(ctx context.Context, userID, sessionID string) error {
	tokens, err := s.stores.RefreshTokens.ListActiveRefreshTokens(ctx, userID)
	if err != nil {
		return err
	}
	for _, t := range tokens {
		if t.ID == sessionID {
			return s.stores.RefreshTokens.RevokeRefreshToken(ctx, t.ID)
		}
	}
	return ErrSessionNotFound
}

// RevokeOtherSessions revokes every session for userID except the one
// matching currentRefreshToken.
func (s *Service) RevokeOtherSessions(ctx context.Context, userID, currentRefreshToken string) error {
	if currentRefreshToken == "" {
		return errors.New("authit/user: currentRefreshToken is required")
	}
	currentHash := authitcrypto.HashToken(currentRefreshToken)
	tokens, err := s.stores.RefreshTokens.ListActiveRefreshTokens(ctx, userID)
	if err != nil {
		return err
	}
	for _, t := range tokens {
		if t.TokenHash == currentHash {
			continue
		}
		if err := s.stores.RefreshTokens.RevokeRefreshToken(ctx, t.ID); err != nil {
			return err
		}
	}
	return nil
}
