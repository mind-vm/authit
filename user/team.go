package user

import (
	"context"
	"errors"
	"time"

	"github.com/mind-vm/authit/audit"
	authitcrypto "github.com/mind-vm/authit/crypto"
	"github.com/mind-vm/authit/store"
)

// SwitchTeam makes the session named by sessionToken act in teamID, and
// returns the session that replaces it. An empty teamID switches to no team.
//
// sessionToken is the refresh token in SessionModeJWT and the session token
// in SessionModeOpaque: the credential that names the session row. The
// session is rotated rather than edited, in both modes: the old token is
// spent and the caller carries the new one, so a copy of the old token
// cannot act in the new team. The new access token carries the team as
// Claims.TeamID, and so does ValidateSession for the new session token.
//
// The user must be an active member of teamID, or SwitchTeam returns
// ErrNotTeamMember and leaves the session as it was. An unknown, expired or
// revoked token is ErrInvalidToken; in SessionModeJWT a revoked one is a
// replayed refresh token and is handled as Refresh handles it, by revoking
// every session the user holds.
//
// The membership is checked again on every Refresh and ValidateSession, so
// a session acting in a team the user has left ends there. team.Service ends
// them sooner when its Stores.Sessions is set.
func (s *Service) SwitchTeam(ctx context.Context, sessionToken, teamID, userAgent, ipAddress string) (TokenPair, error) {
	if s.stores.Members == nil {
		return TokenPair{}, ErrNoMemberStore
	}
	if sessionToken == "" {
		return TokenPair{}, ErrInvalidToken
	}
	t, err := s.stores.RefreshTokens.GetRefreshTokenByHash(ctx, authitcrypto.HashToken(sessionToken))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return TokenPair{}, ErrInvalidToken
		}
		return TokenPair{}, err
	}
	if time.Now().After(t.ExpiresAt) {
		return TokenPair{}, ErrInvalidToken
	}
	// Before reuse detection, for the reason Refresh gives.
	if err := s.requireActiveMembership(ctx, t); err != nil {
		return TokenPair{}, err
	}
	if t.RevokedAt != nil {
		if s.cfg.SessionMode == SessionModeJWT {
			s.revokeFamilyOnReuse(ctx, t, userAgent, ipAddress)
		}
		return TokenPair{}, ErrInvalidToken
	}
	u, err := s.stores.Users.GetUserByID(ctx, t.UserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return TokenPair{}, ErrInvalidToken
		}
		return TokenPair{}, err
	}

	var target *string
	if teamID != "" {
		target = &teamID
	}
	var tokens TokenPair
	err = store.RunInTx(ctx, s.stores.Tx, func(ctx context.Context) error {
		if target != nil {
			if err := s.checkMembership(ctx, u.ID, teamID, ErrNotTeamMember); err != nil {
				return err
			}
		}
		consumed, err := s.stores.RefreshTokens.ConsumeRefreshToken(ctx, t.ID)
		if err != nil {
			return err
		}
		if !consumed {
			return errTokenSpent
		}
		tokens, err = s.issueSession(ctx, u.ID, u.Email, target, userAgent, ipAddress)
		return err
	})
	if errors.Is(err, errTokenSpent) {
		if s.cfg.SessionMode == SessionModeJWT {
			s.revokeFamilyOnReuse(ctx, t, userAgent, ipAddress)
		}
		return TokenPair{}, ErrInvalidToken
	}
	if err != nil {
		return TokenPair{}, err
	}

	var from string
	if t.TeamID != nil {
		from = *t.TeamID
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventUserTeamSwitched, Result: audit.ResultSuccess,
		ActorID: u.ID, Email: u.Email, UserAgent: userAgent, IPAddress: ipAddress,
		Metadata: map[string]any{"team_id": teamID, "from_team_id": from},
	})
	return tokens, nil
}

// requireActiveMembership refuses, as ErrInvalidToken, a session acting in
// a team its user is no longer an active member of, and revokes it: the
// session is over, not paused until the membership returns. A session
// without a team, or a Service without Stores.Members, has nothing to check.
func (s *Service) requireActiveMembership(ctx context.Context, t *store.RefreshToken) error {
	if t.TeamID == nil || s.stores.Members == nil {
		return nil
	}
	err := s.checkMembership(ctx, t.UserID, *t.TeamID, ErrInvalidToken)
	if errors.Is(err, ErrInvalidToken) && t.RevokedAt == nil {
		// Best effort: the request is refused either way.
		_ = s.stores.RefreshTokens.RevokeRefreshToken(ctx, t.ID)
		s.audit.Log(ctx, audit.Event{
			Type: audit.EventUserSessionRevoked, Result: audit.ResultSuccess, ActorID: t.UserID, TargetID: t.ID,
			Metadata: map[string]any{"team_id": *t.TeamID, "reason": "membership_ended"},
		})
	}
	return err
}

// checkMembership returns refused unless userID is an active member of
// teamID. A store failure is returned as itself, not as refused.
func (s *Service) checkMembership(ctx context.Context, userID, teamID string, refused error) error {
	m, err := s.stores.Members.GetMemberByUserAndTeam(ctx, userID, teamID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return refused
		}
		return err
	}
	if !m.IsActive {
		return refused
	}
	return nil
}
