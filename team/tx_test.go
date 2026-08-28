package team_test

import (
	"context"
	"errors"
	"testing"

	"github.com/mind-vm/authit/memstore"
	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/authit/storetest"
	"github.com/mind-vm/authit/team"
)

type witnessedTeams struct {
	store.TeamStore
	w *storetest.TxWitness
}

func (s witnessedTeams) CreateTeam(ctx context.Context, t *store.Team) error {
	s.w.Record(ctx, "CreateTeam")
	return s.TeamStore.CreateTeam(ctx, t)
}

type witnessedMembers struct {
	store.MemberStore
	w *storetest.TxWitness
}

func (s witnessedMembers) CreateMember(ctx context.Context, m *store.Member) error {
	s.w.Record(ctx, "CreateMember")
	return s.MemberStore.CreateMember(ctx, m)
}

func (s witnessedMembers) ListMembersByTeam(ctx context.Context, teamID string) ([]*store.Member, error) {
	s.w.Record(ctx, "ListMembersByTeam")
	return s.MemberStore.ListMembersByTeam(ctx, teamID)
}

type witnessedInvitations struct {
	store.InvitationStore
	w *storetest.TxWitness
}

func (s witnessedInvitations) UpdateInvitation(ctx context.Context, i *store.Invitation) error {
	s.w.Record(ctx, "UpdateInvitation")
	return s.InvitationStore.UpdateInvitation(ctx, i)
}

// admissionWitness records whether the host's seat check ran inside the
// transaction, which is what makes a seat limit enforceable rather than
// advisory.
type admissionWitness struct {
	w   *storetest.TxWitness
	err error
}

func (a *admissionWitness) AdmitMember(ctx context.Context, _ string, _ int) error {
	a.w.Record(ctx, "AdmitMember")
	return a.err
}

func newTxTeamService(t *testing.T, admission team.Admission) (*team.Service, *storetest.TxProbe, *storetest.TxWitness) {
	t.Helper()
	w := storetest.NewTxWitness()
	probe := &storetest.TxProbe{}
	svc, err := team.NewService(team.Stores{
		Teams:       witnessedTeams{memstore.NewTeamStore(), w},
		Members:     witnessedMembers{memstore.NewMemberStore(), w},
		Invitations: witnessedInvitations{memstore.NewInvitationStore(), w},
		Tx:          probe,
	}, admission, team.Config{})
	if err != nil {
		t.Fatalf("team.NewService: %v", err)
	}
	return svc, probe, w
}

// TestCreateTeamIsAtomic: a team whose creation half-succeeded has no
// owner, and therefore nobody who can administer or delete it.
func TestCreateTeamIsAtomic(t *testing.T) {
	ctx := context.Background()
	svc, probe, w := newTxTeamService(t, nil)

	if _, err := svc.CreateTeam(ctx, "Acme", "acme", "u1", "Owner", "owner@example.com"); err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if probe.CallCount() != 1 {
		t.Fatalf("CreateTeam opened %d transactions, want 1", probe.CallCount())
	}
	w.AssertInTx(t, "CreateTeam")
	w.AssertInTx(t, "CreateMember")
}

// TestAcceptInvitationIsAtomic: a member created without the invitation
// being closed leaves a token that can be redeemed again.
func TestAcceptInvitationIsAtomic(t *testing.T) {
	ctx := context.Background()
	w := storetest.NewTxWitness()
	probe := &storetest.TxProbe{}
	svc, err := team.NewService(team.Stores{
		Teams:       witnessedTeams{memstore.NewTeamStore(), w},
		Members:     witnessedMembers{memstore.NewMemberStore(), w},
		Invitations: witnessedInvitations{memstore.NewInvitationStore(), w},
		Tx:          probe,
	}, &admissionWitness{w: w}, team.Config{})
	if err != nil {
		t.Fatalf("team.NewService: %v", err)
	}

	tm, err := svc.CreateTeam(ctx, "Acme", "acme", "u1", "Owner", "owner@example.com")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	raw, _, err := svc.CreateInvitation(ctx, tm.ID, "", "guest@example.com", store.RoleMember)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}

	w.Reset()
	if _, err := svc.AcceptInvitation(ctx, raw, "u2", "guest@example.com", "Guest"); err != nil {
		t.Fatalf("AcceptInvitation: %v", err)
	}
	w.AssertInTx(t, "CreateMember")
	w.AssertInTx(t, "UpdateInvitation")
	// The seat count and the seat check belong inside too, or two people
	// accepting at once each see a seat free and both take it.
	w.AssertInTx(t, "ListMembersByTeam")
	w.AssertInTx(t, "AdmitMember")
}

// TestRejectedAdmissionFailsTheWholeAcceptance: the host refusing a seat
// must leave no member behind and no invitation consumed.
func TestRejectedAdmissionFailsTheWholeAcceptance(t *testing.T) {
	ctx := context.Background()
	w := storetest.NewTxWitness()
	full := errors.New("seat limit reached")
	members := memstore.NewMemberStore()
	invitations := memstore.NewInvitationStore()
	// CreateInvitation pre-checks admission too, so the refusal is switched
	// on only for the acceptance under test.
	admission := &admissionWitness{w: w}
	svc, err := team.NewService(team.Stores{
		Teams:       memstore.NewTeamStore(),
		Members:     members,
		Invitations: invitations,
		Tx:          &storetest.TxProbe{},
	}, admission, team.Config{})
	if err != nil {
		t.Fatalf("team.NewService: %v", err)
	}

	tm, err := svc.CreateTeam(ctx, "Acme", "acme", "u1", "Owner", "owner@example.com")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	raw, inv, err := svc.CreateInvitation(ctx, tm.ID, "", "guest@example.com", store.RoleMember)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	admission.err = full
	if _, err := svc.AcceptInvitation(ctx, raw, "u2", "guest@example.com", "Guest"); !errors.Is(err, full) {
		t.Fatalf("expected the admission error to surface, got %v", err)
	}
	// The invitation must still be pending, so the person can be admitted
	// once a seat frees up rather than holding a spent token.
	got, err := invitations.GetInvitation(ctx, inv.ID)
	if err != nil {
		t.Fatalf("GetInvitation: %v", err)
	}
	if got.Status != store.InvitationPending {
		t.Fatalf("invitation status = %q, want it left pending", got.Status)
	}
	if _, err := members.GetMemberByUserAndTeam(ctx, "u2", tm.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a refused acceptance must not leave a member row behind")
	}
}

// TestNilTxRunnerKeepsWorking: the seam is optional.
func TestNilTxRunnerKeepsWorking(t *testing.T) {
	ctx := context.Background()
	svc, err := team.NewService(team.Stores{
		Teams:       memstore.NewTeamStore(),
		Members:     memstore.NewMemberStore(),
		Invitations: memstore.NewInvitationStore(),
	}, nil, team.Config{})
	if err != nil {
		t.Fatalf("team.NewService: %v", err)
	}
	tm, err := svc.CreateTeam(ctx, "Acme", "acme", "u1", "Owner", "owner@example.com")
	if err != nil {
		t.Fatalf("CreateTeam without a TxRunner: %v", err)
	}
	raw, _, err := svc.CreateInvitation(ctx, tm.ID, "", "guest@example.com", store.RoleMember)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	if _, err := svc.AcceptInvitation(ctx, raw, "u2", "guest@example.com", "Guest"); err != nil {
		t.Fatalf("AcceptInvitation without a TxRunner: %v", err)
	}
}
