package team

import (
	"context"
	"errors"
	"time"

	"github.com/jryannel/authit/audit"
	authitcrypto "github.com/jryannel/authit/crypto"
	"github.com/jryannel/authit/store"
)

// CreateInvitation invites email to join teamID with the given role,
// consulting Admission first (e.g. to enforce a seat limit). Returns the
// raw invitation token — hand it to the invitee (typically embedded in an
// emailed link); only its hash is persisted.
func (s *Service) CreateInvitation(ctx context.Context, teamID, invitedByMemberID, email string, role store.Role) (string, store.Invitation, error) {
	members, err := s.stores.Members.ListMembersByTeam(ctx, teamID)
	if err != nil {
		return "", store.Invitation{}, err
	}
	if err := s.admission.AdmitMember(ctx, teamID, len(members)); err != nil {
		return "", store.Invitation{}, err
	}

	raw, hash, err := authitcrypto.GenerateOpaqueToken()
	if err != nil {
		return "", store.Invitation{}, err
	}
	id, err := authitcrypto.NewID()
	if err != nil {
		return "", store.Invitation{}, err
	}
	now := time.Now()
	inv := &store.Invitation{
		ID: id, TeamID: teamID, Email: email, TokenHash: hash, Role: role,
		Status: store.InvitationPending, InvitedByID: invitedByMemberID,
		ExpiresAt: now.Add(s.cfg.InvitationTTL), CreatedAt: now, UpdatedAt: now,
	}
	if err := s.stores.Invitations.CreateInvitation(ctx, inv); err != nil {
		return "", store.Invitation{}, err
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventTeamInvitationCreated, Result: audit.ResultSuccess, ActorID: invitedByMemberID,
		TargetID: inv.ID, Email: email, Metadata: map[string]any{"team_id": teamID, "role": string(role)},
	})
	return raw, *inv, nil
}

// GetInvitationByToken looks up an invitation by its raw token without
// consuming it, for a "validate before showing the accept form" step. It
// returns ErrInvitationInvalid if the token is unknown, expired, or not
// pending.
func (s *Service) GetInvitationByToken(ctx context.Context, rawToken string) (store.Invitation, error) {
	inv, err := s.getPendingInvitation(ctx, rawToken)
	if err != nil {
		return store.Invitation{}, err
	}
	return *inv, nil
}

func (s *Service) getPendingInvitation(ctx context.Context, rawToken string) (*store.Invitation, error) {
	inv, err := s.stores.Invitations.GetInvitationByTokenHash(ctx, authitcrypto.HashToken(rawToken))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrInvitationInvalid
		}
		return nil, err
	}
	if inv.Status != store.InvitationPending || time.Now().After(inv.ExpiresAt) {
		return nil, ErrInvitationInvalid
	}
	return inv, nil
}

// AcceptInvitation consumes an invitation and creates a Member linking
// userID to the invitation's team with the invited role. email must match
// the address the invitation was sent to.
func (s *Service) AcceptInvitation(ctx context.Context, rawToken, userID, email, displayName string) (store.Member, error) {
	inv, err := s.getPendingInvitation(ctx, rawToken)
	if err != nil {
		return store.Member{}, err
	}
	if inv.Email != email {
		return store.Member{}, ErrEmailMismatch
	}

	members, err := s.stores.Members.ListMembersByTeam(ctx, inv.TeamID)
	if err != nil {
		return store.Member{}, err
	}
	if err := s.admission.AdmitMember(ctx, inv.TeamID, len(members)); err != nil {
		return store.Member{}, err
	}

	memberID, err := authitcrypto.NewID()
	if err != nil {
		return store.Member{}, err
	}
	now := time.Now()
	uid := userID
	m := &store.Member{
		ID: memberID, TeamID: inv.TeamID, UserID: &uid, Role: inv.Role,
		DisplayName: displayName, Email: email, IsActive: true,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := s.stores.Members.CreateMember(ctx, m); err != nil {
		return store.Member{}, err
	}

	inv.Status = store.InvitationAccepted
	inv.AcceptedAt = &now
	inv.UpdatedAt = now
	if err := s.stores.Invitations.UpdateInvitation(ctx, inv); err != nil {
		return store.Member{}, err
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventTeamInvitationAccepted, Result: audit.ResultSuccess, ActorID: userID,
		TargetID: inv.ID, Email: email, Metadata: map[string]any{"team_id": inv.TeamID},
	})
	return *m, nil
}

// RevokeInvitation marks a pending invitation revoked so its token can no
// longer be accepted.
func (s *Service) RevokeInvitation(ctx context.Context, invitationID string) error {
	inv, err := s.stores.Invitations.GetInvitation(ctx, invitationID)
	if err != nil {
		return err
	}
	inv.Status = store.InvitationRevoked
	inv.UpdatedAt = time.Now()
	if err := s.stores.Invitations.UpdateInvitation(ctx, inv); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventTeamInvitationRevoked, Result: audit.ResultSuccess,
		TargetID: inv.ID, Email: inv.Email, Metadata: map[string]any{"team_id": inv.TeamID},
	})
	return nil
}

// ListInvitationsByTeam lists every invitation for a team (pending,
// accepted, and revoked — the caller can filter by Status if needed).
func (s *Service) ListInvitationsByTeam(ctx context.Context, teamID string) ([]store.Invitation, error) {
	invitations, err := s.stores.Invitations.ListInvitationsByTeam(ctx, teamID)
	if err != nil {
		return nil, err
	}
	out := make([]store.Invitation, len(invitations))
	for i, inv := range invitations {
		out[i] = *inv
	}
	return out, nil
}
