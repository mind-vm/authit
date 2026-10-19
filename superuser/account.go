package superuser

import (
	"context"
	"time"

	"github.com/mind-vm/authit/audit"
)

// What a signed-in operator does to its own account. Every verb names the
// session it was called from, which is the access token's jti.

// Session is one of an operator's signed-in devices.
type Session struct {
	ID        string
	IsCurrent bool
	UserAgent string
	IPAddress string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// ChangePassword replaces the operator's password and ends every other
// session, reporting how many: whoever else knew the old one is signed out
// with it.
func (s *Service) ChangePassword(ctx context.Context, superuserID, currentSessionID, current, next string) (int, error) {
	su, err := s.stores.Superusers.GetSuperuserByID(ctx, superuserID)
	if err != nil {
		return 0, err
	}
	if !s.cfg.PasswordHasher.Verify(current, su.PasswordHash) {
		s.audit.Log(ctx, audit.Event{Type: audit.EventSuperuserPasswordChanged, Result: audit.ResultFailure, ActorID: su.ID, Email: su.Email})
		return 0, ErrInvalidCredentials
	}
	if err := s.cfg.PasswordValidator(ctx, su.Email, next); err != nil {
		return 0, err
	}
	hash, err := s.cfg.PasswordHasher.Hash(next)
	if err != nil {
		return 0, err
	}
	su.PasswordHash, su.UpdatedAt = hash, time.Now()
	if err := s.stores.Superusers.UpdateSuperuser(ctx, su); err != nil {
		return 0, err
	}
	revoked, err := s.revokeOthers(ctx, superuserID, currentSessionID)
	if err != nil {
		return revoked, err
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventSuperuserPasswordChanged, Result: audit.ResultSuccess, ActorID: su.ID, Email: su.Email,
		Metadata: map[string]any{"sessions_revoked": revoked},
	})
	return revoked, nil
}

// ListSessions returns the operator's live sessions, oldest first.
func (s *Service) ListSessions(ctx context.Context, superuserID, currentSessionID string) ([]Session, error) {
	tokens, err := s.stores.RefreshTokens.ListActiveSuperuserRefreshTokens(ctx, superuserID)
	if err != nil {
		return nil, err
	}
	out := make([]Session, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, Session{
			ID: t.ID, IsCurrent: t.ID == currentSessionID, UserAgent: t.UserAgent, IPAddress: t.IPAddress,
			CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt,
		})
	}
	return out, nil
}

// RevokeSession ends one of the operator's own sessions. Another operator's
// session id is ErrSessionNotFound, like one that does not exist.
func (s *Service) RevokeSession(ctx context.Context, superuserID, sessionID string) error {
	tokens, err := s.stores.RefreshTokens.ListActiveSuperuserRefreshTokens(ctx, superuserID)
	if err != nil {
		return err
	}
	for _, t := range tokens {
		if t.ID != sessionID {
			continue
		}
		if err := s.stores.RefreshTokens.RevokeSuperuserRefreshToken(ctx, t.ID); err != nil {
			return err
		}
		s.audit.Log(ctx, audit.Event{Type: audit.EventSuperuserSessionRevoked, Result: audit.ResultSuccess, ActorID: superuserID, TargetID: sessionID})
		return nil
	}
	return ErrSessionNotFound
}

// RevokeOtherSessions ends every session but currentSessionID and reports
// how many it ended.
func (s *Service) RevokeOtherSessions(ctx context.Context, superuserID, currentSessionID string) (int, error) {
	n, err := s.revokeOthers(ctx, superuserID, currentSessionID)
	if err != nil {
		return 0, err
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventSuperuserSessionRevoked, Result: audit.ResultSuccess, ActorID: superuserID,
		Metadata: map[string]any{"count": n, "scope": "other_sessions"},
	})
	return n, nil
}

func (s *Service) revokeOthers(ctx context.Context, superuserID, keep string) (int, error) {
	tokens, err := s.stores.RefreshTokens.ListActiveSuperuserRefreshTokens(ctx, superuserID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, t := range tokens {
		if t.ID == keep {
			continue
		}
		if err := s.stores.RefreshTokens.RevokeSuperuserRefreshToken(ctx, t.ID); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
