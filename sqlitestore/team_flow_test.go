package sqlitestore_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/authit/team"
)

// TestTeamFlowsOverSQLite runs team.Service over the store with the
// TxRunner wired: an invitation accepted, the last-owner guard held against
// two owners demoting each other at once, and the cascades the schema owns.
func TestTeamFlowsOverSQLite(t *testing.T) {
	ctx := context.Background()
	s := fresh(t)
	now := time.Now()
	alice := &store.User{ID: uuid.NewString(), Email: "alice@example.com", CreatedAt: now, UpdatedAt: now}
	bob := &store.User{ID: uuid.NewString(), Email: "bob@example.com", CreatedAt: now, UpdatedAt: now}
	for _, u := range []*store.User{alice, bob} {
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	svc, err := team.NewService(team.Stores{Teams: s, Members: s, Invitations: s, Tx: s}, nil, team.Config{})
	if err != nil {
		t.Fatal(err)
	}

	acme, err := svc.CreateTeam(ctx, "Acme", "acme", alice.ID, "Alice", alice.Email)
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if _, err := svc.CreateTeam(ctx, "Acme 2", "acme", bob.ID, "Bob", bob.Email); !errors.Is(err, team.ErrSlugTaken) {
		t.Fatalf("CreateTeam with a taken slug = %v, want ErrSlugTaken", err)
	}
	owner, err := svc.GetMemberByUserAndTeam(ctx, alice.ID, acme.ID)
	if err != nil {
		t.Fatalf("the creator has no membership: %v", err)
	}
	raw, inv, err := svc.CreateInvitation(ctx, acme.ID, owner.ID, bob.Email, store.RoleOwner)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	second, err := svc.AcceptInvitation(ctx, raw, bob.ID, bob.Email, "Bob")
	if err != nil {
		t.Fatalf("AcceptInvitation: %v", err)
	}
	if _, err := svc.AcceptInvitation(ctx, raw, bob.ID, bob.Email, "Bob"); !errors.Is(err, team.ErrInvitationInvalid) {
		t.Fatalf("a second acceptance = %v, want ErrInvitationInvalid", err)
	}

	// Two owners demote each other at once. Exactly one may win: both
	// winning leaves a team nobody can administer.
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, id := range []string{owner.ID, second.ID} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = svc.UpdateMemberRole(ctx, id, store.RoleMember)
		}()
	}
	wg.Wait()
	won, lost := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			won++
		case errors.Is(err, team.ErrLastOwner):
			lost++
		default:
			t.Fatalf("UpdateMemberRole: %v", err)
		}
	}
	if won != 1 || lost != 1 {
		t.Fatalf("concurrent demotions: %d won and %d were refused, want one of each", won, lost)
	}
	members, err := svc.ListMembersByTeam(ctx, acme.ID)
	if err != nil {
		t.Fatal(err)
	}
	owners := 0
	for _, m := range members {
		if m.Role == store.RoleOwner && m.IsActive {
			owners++
		}
	}
	if owners != 1 {
		t.Fatalf("the team has %d active owners, want 1", owners)
	}

	// The inviter leaving clears the invitation's reference to them
	// rather than withdrawing it.
	if err := s.DeleteMember(ctx, owner.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetInvitation(ctx, inv.ID)
	if err != nil {
		t.Fatalf("the invitation went with its inviter: %v", err)
	}
	if got.InvitedByID != "" {
		t.Fatalf("InvitedByID = %q, want it cleared", got.InvitedByID)
	}

	// Deleting the team takes its members and invitations with it.
	if err := s.DeleteTeam(ctx, acme.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetMember(ctx, second.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a member outlived its team: %v", err)
	}
	if _, err := s.GetInvitation(ctx, inv.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an invitation outlived its team: %v", err)
	}
}
