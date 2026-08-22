package team

import (
	"context"
	"errors"
	"time"

	authitcrypto "github.com/jryannel/authit/crypto"
	"github.com/jryannel/authit/store"
	"github.com/jryannel/sqlb"
)

// CreateInvitation invites email to join teamID with the given role,
// consulting Admission first (e.g. to enforce a seat limit). Returns the
// raw invitation token — hand it to the invitee (typically embedded in an
// emailed link); only its hash is persisted.
func (s *Service) CreateInvitation(ctx context.Context, teamID, invitedByUserID, email string, role Role) (string, store.TeamInvitation, error) {
	raw, hash, err := authitcrypto.GenerateOpaqueToken()
	if err != nil {
		return "", store.TeamInvitation{}, err
	}

	var created store.TeamInvitation
	err = s.db.WithTx(ctx, func(ctx context.Context, tx *sqlb.DB) error {
		// The seat count and the insert are one unit of work; otherwise two
		// concurrent invitations both see the last free seat.
		count, err := sqlb.Query[store.TeamMember]().
			Where(store.TeamMemberCols.TeamID.Eq(teamID)).
			Count(ctx, tx)
		if err != nil {
			return err
		}
		if err := s.admission.AdmitMember(ctx, teamID, int(count)); err != nil {
			return err
		}

		inv := store.TeamInvitation{
			TeamID: teamID, Email: email, TokenHash: hash, Role: string(role),
			Status: store.TeamInvitationStatusPending, InvitedByID: invitedByUserID,
			ExpiresAt: time.Now().Add(s.cfg.InvitationTTL),
		}
		inserted, err := sqlb.InsertRows(&inv).Exec(ctx, tx)
		if err != nil {
			return err
		}
		created = inserted[0]
		return nil
	})
	if err != nil {
		return "", store.TeamInvitation{}, err
	}
	return raw, created, nil
}

// GetInvitationByToken looks up an invitation by its raw token without
// consuming it, for a "validate before showing the accept form" step. It
// returns ErrInvitationInvalid if the token is unknown, expired, or not
// pending.
func (s *Service) GetInvitationByToken(ctx context.Context, rawToken string) (store.TeamInvitation, error) {
	return s.pendingInvitation(ctx, s.db, rawToken)
}

func (s *Service) pendingInvitation(ctx context.Context, db *sqlb.DB, rawToken string) (store.TeamInvitation, error) {
	inv, err := sqlb.Query[store.TeamInvitation]().
		Where(store.TeamInvitationCols.TokenHash.Eq(authitcrypto.HashToken(rawToken))).
		One(ctx, db)
	if err != nil {
		if errors.Is(err, sqlb.ErrNotFound) {
			return store.TeamInvitation{}, ErrInvitationInvalid
		}
		return store.TeamInvitation{}, err
	}
	// Expiry is derived here rather than written back, which is why no sweeper
	// job is needed to keep the status column honest.
	if inv.Status != store.TeamInvitationStatusPending || time.Now().After(inv.ExpiresAt) {
		return store.TeamInvitation{}, ErrInvitationInvalid
	}
	return inv, nil
}

// AcceptInvitation consumes an invitation and creates a member linking
// userID to the invitation's team with the invited role. email must match
// the address the invitation was sent to.
func (s *Service) AcceptInvitation(ctx context.Context, rawToken, userID, email, displayName string) (store.TeamMember, error) {
	var created store.TeamMember
	err := s.db.WithTx(ctx, func(ctx context.Context, tx *sqlb.DB) error {
		// Re-read the invitation inside the transaction: consuming it and
		// creating the membership have to be atomic, or a token accepted twice
		// concurrently yields two memberships.
		inv, err := s.pendingInvitation(ctx, tx, rawToken)
		if err != nil {
			return err
		}
		if inv.Email != email {
			return ErrEmailMismatch
		}

		count, err := sqlb.Query[store.TeamMember]().
			Where(store.TeamMemberCols.TeamID.Eq(inv.TeamID)).
			Count(ctx, tx)
		if err != nil {
			return err
		}
		if err := s.admission.AdmitMember(ctx, inv.TeamID, int(count)); err != nil {
			return err
		}

		uid := userID
		m := store.TeamMember{
			TeamID: inv.TeamID, UserID: &uid, Role: inv.Role,
			DisplayName: displayName, Email: email, IsActive: true,
		}
		inserted, err := sqlb.InsertRows(&m).Exec(ctx, tx)
		if err != nil {
			return err
		}
		created = inserted[0]

		now := time.Now()
		_, err = store.UpdateTeamInvitation().
			SetStatus(store.TeamInvitationStatusAccepted).
			SetAcceptedAt(&now).
			SetUpdatedAt(now).
			Where(store.TeamInvitationCols.ID.Eq(inv.ID)).
			Stmt().Exec(ctx, tx)
		return err
	})
	if err != nil {
		return store.TeamMember{}, err
	}
	return created, nil
}

// RevokeInvitation marks a pending invitation revoked so its token can no
// longer be accepted.
func (s *Service) RevokeInvitation(ctx context.Context, invitationID string) error {
	updated, err := store.UpdateTeamInvitation().
		SetStatus(store.TeamInvitationStatusRevoked).
		SetUpdatedAt(time.Now()).
		Where(store.TeamInvitationCols.ID.Eq(invitationID)).
		Stmt().Exec(ctx, s.db)
	if err != nil {
		return err
	}
	if len(updated) == 0 {
		return ErrNotFound
	}
	return nil
}

// ListInvitationsByTeam lists every invitation for a team (pending,
// accepted, and revoked — the caller can filter by Status if needed).
func (s *Service) ListInvitationsByTeam(ctx context.Context, teamID string) ([]store.TeamInvitation, error) {
	return sqlb.Query[store.TeamInvitation]().
		Where(store.TeamInvitationCols.TeamID.Eq(teamID)).
		All(ctx, s.db)
}
