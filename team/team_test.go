package team_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jryannel/authit/internal/authittest"
	"github.com/jryannel/authit/store"
	"github.com/jryannel/authit/team"
	"github.com/jryannel/sqlb"
)

func newTestService(t *testing.T) (*team.Service, *sqlb.DB) {
	t.Helper()
	return serviceWithAdmission(t, nil)
}

func serviceWithAdmission(t *testing.T, admission team.Admission) (*team.Service, *sqlb.DB) {
	t.Helper()
	db := authittest.FreshDB(t)
	svc, err := team.NewService(db, admission, team.Config{})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, db
}

func TestCreateTeamCreatesOwnerMember(t *testing.T) {
	svc, db := newTestService(t)
	ctx := context.Background()

	ownerID := authittest.NewUser(t, db, "owner@example.com")
	tm, err := svc.CreateTeam(ctx, "Acme", "acme", ownerID, "Owner", "owner@example.com")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}

	if _, err := svc.CreateTeam(ctx, "Acme 2", "acme", ownerID, "Owner", "owner@example.com"); !errors.Is(err, team.ErrSlugTaken) {
		t.Fatalf("expected ErrSlugTaken, got %v", err)
	}

	members, err := svc.ListMembersByTeam(ctx, tm.ID)
	if err != nil {
		t.Fatalf("ListMembersByTeam: %v", err)
	}
	if len(members) != 1 || members[0].Role != string(team.RoleOwner) {
		t.Fatalf("expected a single owner member, got %+v", members)
	}
}

func TestInvitationAcceptFlow(t *testing.T) {
	svc, db := newTestService(t)
	ctx := context.Background()

	ownerID := authittest.NewUser(t, db, "owner@example.com")
	tm, err := svc.CreateTeam(ctx, "Acme", "acme", ownerID, "Owner", "owner@example.com")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	raw, inv, err := svc.CreateInvitation(ctx, tm.ID, ownerID, "invitee@example.com", team.RoleMember)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	if inv.Status != store.TeamInvitationStatusPending {
		t.Fatalf("expected pending invitation, got %s", inv.Status)
	}

	if _, err := svc.GetInvitationByToken(ctx, raw); err != nil {
		t.Fatalf("GetInvitationByToken: %v", err)
	}

	inviteeID := authittest.NewUser(t, db, "invitee@example.com")
	if _, err := svc.AcceptInvitation(ctx, raw, inviteeID, "wrong@example.com", "Invitee"); !errors.Is(err, team.ErrEmailMismatch) {
		t.Fatalf("expected ErrEmailMismatch, got %v", err)
	}

	member, err := svc.AcceptInvitation(ctx, raw, inviteeID, "invitee@example.com", "Invitee")
	if err != nil {
		t.Fatalf("AcceptInvitation: %v", err)
	}
	if member.Role != string(team.RoleMember) {
		t.Fatalf("expected member role, got %s", member.Role)
	}

	// Token is single-use: accepting again should fail.
	if _, err := svc.AcceptInvitation(ctx, raw, inviteeID, "invitee@example.com", "Invitee"); !errors.Is(err, team.ErrInvitationInvalid) {
		t.Fatalf("expected ErrInvitationInvalid on reuse, got %v", err)
	}

	members, err := svc.ListMembersByTeam(ctx, tm.ID)
	if err != nil {
		t.Fatalf("ListMembersByTeam: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(members))
	}
}

func TestRevokeInvitation(t *testing.T) {
	svc, db := newTestService(t)
	ctx := context.Background()

	ownerID := authittest.NewUser(t, db, "owner@example.com")
	tm, err := svc.CreateTeam(ctx, "Acme", "acme", ownerID, "Owner", "owner@example.com")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	raw, inv, err := svc.CreateInvitation(ctx, tm.ID, ownerID, "invitee@example.com", team.RoleMember)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	if err := svc.RevokeInvitation(ctx, inv.ID); err != nil {
		t.Fatalf("RevokeInvitation: %v", err)
	}
	inviteeID := authittest.NewUser(t, db, "invitee@example.com")
	if _, err := svc.AcceptInvitation(ctx, raw, inviteeID, "invitee@example.com", "Invitee"); !errors.Is(err, team.ErrInvitationInvalid) {
		t.Fatalf("expected ErrInvitationInvalid after revoke, got %v", err)
	}
}

func TestLastOwnerProtections(t *testing.T) {
	svc, db := newTestService(t)
	ctx := context.Background()

	ownerID := authittest.NewUser(t, db, "owner@example.com")
	tm, err := svc.CreateTeam(ctx, "Acme", "acme", ownerID, "Owner", "owner@example.com")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	owner, _ := svc.GetMemberByUserAndTeam(ctx, ownerID, tm.ID)

	if err := svc.UpdateMemberRole(ctx, owner.ID, team.RoleMember); !errors.Is(err, team.ErrLastOwner) {
		t.Fatalf("expected ErrLastOwner demoting sole owner, got %v", err)
	}
	if err := svc.RemoveMember(ctx, owner.ID); !errors.Is(err, team.ErrLastOwner) {
		t.Fatalf("expected ErrLastOwner removing sole owner, got %v", err)
	}

	// Adding a second owner should allow the first to be demoted.
	raw, _, err := svc.CreateInvitation(ctx, tm.ID, ownerID, "second-owner@example.com", team.RoleOwner)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	secondUserID := authittest.NewUser(t, db, "second-owner@example.com")
	if _, err := svc.AcceptInvitation(ctx, raw, secondUserID, "second-owner@example.com", "Second"); err != nil {
		t.Fatalf("AcceptInvitation: %v", err)
	}
	if err := svc.UpdateMemberRole(ctx, owner.ID, team.RoleMember); err != nil {
		t.Fatalf("UpdateMemberRole should now succeed: %v", err)
	}
}

func TestAdmissionRejectsMember(t *testing.T) {
	admitErr := errors.New("seat limit reached")
	svc, db := serviceWithAdmission(t, rejectAllAdmission{err: admitErr})
	ctx := context.Background()
	ownerID := authittest.NewUser(t, db, "owner@example.com")
	tm, err := svc.CreateTeam(ctx, "Acme", "acme", ownerID, "Owner", "owner@example.com")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if _, _, err := svc.CreateInvitation(ctx, tm.ID, ownerID, "invitee@example.com", team.RoleMember); !errors.Is(err, admitErr) {
		t.Fatalf("expected admission error, got %v", err)
	}
}

type rejectAllAdmission struct{ err error }

func (r rejectAllAdmission) AdmitMember(context.Context, string, int) error { return r.err }
