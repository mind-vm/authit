package user

import (
	"context"
	"errors"
	"time"

	"github.com/mind-vm/authit/audit"
	authitcrypto "github.com/mind-vm/authit/crypto"
	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/store"
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
			if err := s.stores.RefreshTokens.RevokeRefreshToken(ctx, t.ID); err != nil {
				return err
			}
			s.audit.Log(ctx, audit.Event{Type: audit.EventUserSessionRevoked, Result: audit.ResultSuccess, ActorID: userID, TargetID: sessionID})
			return nil
		}
	}
	return ErrSessionNotFound
}

// RevokeOtherSessions revokes every session for userID except the one
// matching currentRefreshToken.
func (s *Service) RevokeOtherSessions(ctx context.Context, userID, currentRefreshToken string) error {
	if currentRefreshToken == "" {
		return ErrCurrentSessionRequired
	}
	currentHash := authitcrypto.HashToken(currentRefreshToken)
	tokens, err := s.stores.RefreshTokens.ListActiveRefreshTokens(ctx, userID)
	if err != nil {
		return err
	}
	revoked := 0
	for _, t := range tokens {
		if t.TokenHash == currentHash {
			continue
		}
		if err := s.stores.RefreshTokens.RevokeRefreshToken(ctx, t.ID); err != nil {
			return err
		}
		revoked++
	}
	if revoked > 0 {
		s.audit.Log(ctx, audit.Event{
			Type: audit.EventUserSessionRevoked, Result: audit.ResultSuccess, ActorID: userID,
			Metadata: map[string]any{"count": revoked, "scope": "other_sessions"},
		})
	}
	return nil
}

// SessionMode reports the configured session model, so a caller that must
// behave differently in each -- an HTTP route group deciding whether it
// serves /refresh at all -- can ask rather than be told twice.
func (s *Service) SessionMode() SessionMode { return s.cfg.SessionMode }

// ValidateSession resolves an opaque session token to its principal.
//
// This is the lookup that SessionModeOpaque buys: a session revoked a
// moment ago is refused here, by the next request, rather than staying
// usable until an access token expires. It satisfies
// authithttp.SessionValidator, and authithttp.SessionAuth is how a route
// group is wired to it.
//
// Revoked, expired and unknown are one answer, ErrInvalidToken, for the
// usual reason: telling them apart tells a caller holding a stolen token
// which kind of stolen it is.
//
// The error for a store failure is the store's own, unwrapped. That
// distinction is the whole reason this returns an error rather than a bool
// -- authithttp.StatusFor answers 500 to it and 401 to ErrInvalidToken, and
// a caller who collapses the two reports an outage as a wall of failed
// logins.
func (s *Service) ValidateSession(ctx context.Context, token string) (authitjwt.Claims, error) {
	if s.cfg.SessionMode != SessionModeOpaque {
		// A signed token would verify here by accident of being a string,
		// and then be looked up and not found, which reads as "your
		// session expired" rather than "this server is not configured the
		// way you think". Say the second.
		return authitjwt.Claims{}, ErrNotOpaqueSession
	}
	if token == "" {
		return authitjwt.Claims{}, ErrInvalidToken
	}
	t, err := s.stores.RefreshTokens.GetRefreshTokenByHash(ctx, authitcrypto.HashToken(token))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return authitjwt.Claims{}, ErrInvalidToken
		}
		return authitjwt.Claims{}, err
	}
	now := time.Now()
	if t.RevokedAt != nil || now.After(t.ExpiresAt) {
		return authitjwt.Claims{}, ErrInvalidToken
	}

	u, err := s.stores.Users.GetUserByID(ctx, t.UserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// The session outlived the account. Refused, not 500: the
			// credential is genuinely no longer good for anything.
			return authitjwt.Claims{}, ErrInvalidToken
		}
		return authitjwt.Claims{}, err
	}

	if err := s.extendSession(ctx, t, now); err != nil {
		return authitjwt.Claims{}, err
	}
	return newAccessClaims(u.ID, u.Email, t.ExpiresAt), nil
}

// extendSession pushes a session's expiry out, but only once enough of its
// life has passed.
//
// Extending on every request would mean a write on every request, which is
// the cost that makes people give up on server-side sessions. The threshold
// is Config.SessionSlidingWindow; a negative one disables extension, so a
// session expires a fixed time after it was issued no matter how busy.
func (s *Service) extendSession(ctx context.Context, t *store.RefreshToken, now time.Time) error {
	if s.cfg.SessionSlidingWindow < 0 {
		return nil
	}
	if now.Before(t.ExpiresAt.Add(-s.cfg.RefreshTokenTTL).Add(s.cfg.SessionSlidingWindow)) {
		return nil
	}
	expires := now.Add(s.cfg.RefreshTokenTTL)
	if err := s.stores.RefreshTokens.TouchRefreshToken(ctx, t.ID, expires); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Revoked between the read above and now. Not this call's
			// problem to report: the caller already holds a principal that
			// was valid when it was read, and the next request will be
			// refused.
			return nil
		}
		return err
	}
	t.ExpiresAt = expires
	return nil
}
