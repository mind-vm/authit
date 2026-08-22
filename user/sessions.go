package user

import (
	"context"
	"errors"
	"time"

	authitcrypto "github.com/jryannel/authit/crypto"
	"github.com/jryannel/authit/store"
	"github.com/jryannel/sqlb"
)

// activeSessions is the shared predicate behind every session operation:
// a user's refresh tokens that are neither revoked nor expired.
func activeSessions(userID string) []sqlb.Pred {
	return []sqlb.Pred{
		store.RefreshTokenCols.UserID.Eq(userID),
		store.RefreshTokenCols.RevokedAt.IsNull(),
		store.RefreshTokenCols.ExpiresAt.Gt(time.Now()),
	}
}

// ListSessions returns every active (unrevoked, unexpired) session for a
// user. If currentRefreshToken is non-empty, the matching session (if any)
// is flagged IsCurrent.
func (s *Service) ListSessions(ctx context.Context, userID, currentRefreshToken string) ([]Session, error) {
	tokens, err := sqlb.Query[store.RefreshToken]().
		Where(activeSessions(userID)...).
		OrderBy(store.RefreshTokenCols.CreatedAt.Desc()).
		All(ctx, s.db)
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
	now := time.Now()
	// The userID predicate is the authorization check, done in the WHERE
	// clause rather than by reading the row first: a session belonging to
	// someone else matches nothing and is reported as not found, which is also
	// what a caller probing for other users' session ids should see.
	revoked, err := store.UpdateRefreshToken().
		SetRevokedAt(&now).
		Where(append(activeSessions(userID), store.RefreshTokenCols.ID.Eq(sessionID))...).
		Stmt().Exec(ctx, s.db)
	if err != nil {
		return err
	}
	if len(revoked) == 0 {
		return ErrSessionNotFound
	}
	return nil
}

// RevokeOtherSessions revokes every session for userID except the one
// matching currentRefreshToken.
func (s *Service) RevokeOtherSessions(ctx context.Context, userID, currentRefreshToken string) error {
	if currentRefreshToken == "" {
		return errors.New("authit/user: currentRefreshToken is required")
	}
	now := time.Now()
	_, err := store.UpdateRefreshToken().
		SetRevokedAt(&now).
		Where(append(activeSessions(userID),
			store.RefreshTokenCols.TokenHash.Neq(authitcrypto.HashToken(currentRefreshToken)))...).
		Stmt().Exec(ctx, s.db)
	return err
}
