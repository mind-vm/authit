package storetest

import (
	"errors"
	"testing"
	"time"

	"github.com/mind-vm/authit/store"
)

// RunTeamStore checks store.TeamStore.
func RunTeamStore(t *testing.T, newStore func(*testing.T) store.TeamStore, fx Fixtures) {
	t.Run("missing rows report ErrNotFound", func(t *testing.T) {
		s := newStore(t)
		_, err := s.GetTeam(ctx(), id(99))
		requireNotFound(t, "GetTeam", err)
		_, err = s.GetTeamBySlug(ctx(), "no-such-slug")
		// team.CreateTeam decides whether a slug is free by calling this
		// and checking for ErrNotFound. An adapter returning any other
		// error makes every team creation fail.
		requireNotFound(t, "GetTeamBySlug", err)
	})

	t.Run("create, read by id and slug, update, delete", func(t *testing.T) {
		s := newStore(t)
		now := time.Now()
		tm := &store.Team{ID: id(11), Name: "Acme", Slug: "acme", OwnerID: id(1), CreatedAt: now, UpdatedAt: now}
		requireNoError(t, "CreateTeam", s.CreateTeam(ctx(), tm))
		if tm.ID == "" {
			t.Fatal("CreateTeam must leave the team's ID populated")
		}

		byID, err := s.GetTeam(ctx(), tm.ID)
		requireNoError(t, "GetTeam", err)
		if byID.Slug != "acme" || byID.OwnerID != id(1) {
			t.Fatalf("round trip lost data: %+v", byID)
		}
		bySlug, err := s.GetTeamBySlug(ctx(), "acme")
		requireNoError(t, "GetTeamBySlug", err)
		if bySlug.ID != tm.ID {
			t.Fatalf("GetTeamBySlug returned %q, want %q", bySlug.ID, tm.ID)
		}

		tm.Name = "Acme Corp"
		requireNoError(t, "UpdateTeam", s.UpdateTeam(ctx(), tm))
		byID, err = s.GetTeam(ctx(), tm.ID)
		requireNoError(t, "GetTeam", err)
		if byID.Name != "Acme Corp" {
			t.Fatalf("Name = %q, want the updated value", byID.Name)
		}

		requireNoError(t, "DeleteTeam", s.DeleteTeam(ctx(), tm.ID))
		_, err = s.GetTeam(ctx(), tm.ID)
		requireNotFound(t, "GetTeam after delete", err)
	})
}

// RunMemberStore checks store.MemberStore.
func RunMemberStore(t *testing.T, newStore func(*testing.T) store.MemberStore, fx Fixtures) {
	mk := func(rowID, teamID string, userID *string, role store.Role, email string) *store.Member {
		return &store.Member{
			ID: rowID, TeamID: teamID, UserID: userID, Role: role,
			DisplayName: "Someone", Email: email, IsActive: true,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}
	}

	t.Run("missing rows report ErrNotFound", func(t *testing.T) {
		s := newStore(t)
		_, err := s.GetMember(ctx(), id(99))
		requireNotFound(t, "GetMember", err)
		_, err = s.GetMemberByUserAndTeam(ctx(), id(1), id(11))
		// Authorization asks this question. An adapter that returns some
		// other error for "not a member" makes every permission check fail
		// closed with a 500 instead of a clean 403.
		requireNotFound(t, "GetMemberByUserAndTeam", err)
	})

	t.Run("lookup by user and team", func(t *testing.T) {
		s := newStore(t)
		fx.ensureTeam(t, id(11), id(12))
		fx.ensureUser(t, id(1), id(2))
		requireNoError(t, "CreateMember", s.CreateMember(ctx(), mk(id(21), id(11), ptr(id(1)), store.RoleOwner, "a@example.com")))
		requireNoError(t, "CreateMember", s.CreateMember(ctx(), mk(id(22), id(12), ptr(id(1)), store.RoleMember, "a@example.com")))
		requireNoError(t, "CreateMember", s.CreateMember(ctx(), mk(id(23), id(11), ptr(id(2)), store.RoleMember, "b@example.com")))

		got, err := s.GetMemberByUserAndTeam(ctx(), id(1), id(11))
		requireNoError(t, "GetMemberByUserAndTeam", err)
		if got.ID != id(21) || got.Role != store.RoleOwner {
			// Returning the wrong team's membership would grant one team's
			// role inside another.
			t.Fatalf("got member %q with role %q, want m1/owner", got.ID, got.Role)
		}
	})

	t.Run("a member with no user never matches a user lookup", func(t *testing.T) {
		// Member.UserID is nullable so a team can track someone before
		// they have an account. Such a row must never satisfy
		// GetMemberByUserAndTeam, or an adapter comparing NULL loosely
		// could hand a caller somebody else's membership.
		s := newStore(t)
		fx.ensureTeam(t, id(11), id(12))
		fx.ensureUser(t, id(1), id(2))
		requireNoError(t, "CreateMember", s.CreateMember(ctx(), mk(id(21), id(11), nil, store.RoleMember, "ghost@example.com")))
		_, err := s.GetMemberByUserAndTeam(ctx(), "", id(11))
		requireNotFound(t, "GetMemberByUserAndTeam with an empty user id", err)

		got, err := s.GetMember(ctx(), id(21))
		requireNoError(t, "GetMember", err)
		if got.UserID != nil {
			t.Fatalf("UserID = %v, want nil to round trip as nil", *got.UserID)
		}
	})

	t.Run("listing is scoped", func(t *testing.T) {
		s := newStore(t)
		fx.ensureTeam(t, id(11), id(12))
		fx.ensureUser(t, id(1), id(2))
		requireNoError(t, "CreateMember", s.CreateMember(ctx(), mk(id(21), id(11), ptr(id(1)), store.RoleOwner, "a@example.com")))
		requireNoError(t, "CreateMember", s.CreateMember(ctx(), mk(id(22), id(11), ptr(id(2)), store.RoleMember, "b@example.com")))
		requireNoError(t, "CreateMember", s.CreateMember(ctx(), mk(id(23), id(12), ptr(id(1)), store.RoleAdmin, "a@example.com")))

		byTeam, err := s.ListMembersByTeam(ctx(), id(11))
		requireNoError(t, "ListMembersByTeam", err)
		if len(byTeam) != 2 {
			t.Fatalf("ListMembersByTeam returned %d members, want 2; leaking another team's roster is a tenancy break", len(byTeam))
		}
		byUser, err := s.ListMembershipsByUser(ctx(), id(1))
		requireNoError(t, "ListMembershipsByUser", err)
		if len(byUser) != 2 {
			t.Fatalf("ListMembershipsByUser returned %d, want 2", len(byUser))
		}
	})

	t.Run("update and delete", func(t *testing.T) {
		s := newStore(t)
		fx.ensureTeam(t, id(11))
		fx.ensureUser(t, id(1))
		m := mk(id(21), id(11), ptr(id(1)), store.RoleMember, "a@example.com")
		requireNoError(t, "CreateMember", s.CreateMember(ctx(), m))

		m.Role = store.RoleAdmin
		m.IsActive = false
		requireNoError(t, "UpdateMember", s.UpdateMember(ctx(), m))
		got, err := s.GetMember(ctx(), id(21))
		requireNoError(t, "GetMember", err)
		if got.Role != store.RoleAdmin || got.IsActive {
			t.Fatalf("role/active change did not persist: %+v", got)
		}

		requireNoError(t, "DeleteMember", s.DeleteMember(ctx(), id(21)))
		_, err = s.GetMember(ctx(), id(21))
		requireNotFound(t, "GetMember after delete", err)
	})

	t.Run("a deleted member is gone from every lookup", func(t *testing.T) {
		// GetMember is not the only way back to a row. A store that keeps
		// secondary indexes -- by user, by team -- has to prune them here
		// too, and the cost of not doing so is not a stale answer: the
		// index still names an id, the row behind it is gone, and the
		// reader dereferences the hole. Deleting a member is ordinary
		// (somebody leaves), so a store that only passes the GetMember
		// check above breaks on the next page load.
		s := newStore(t)
		fx.ensureTeam(t, id(11))
		fx.ensureUser(t, id(1))
		fx.ensureUser(t, id(2))
		requireNoError(t, "CreateMember", s.CreateMember(ctx(),
			mk(id(21), id(11), ptr(id(1)), store.RoleOwner, "a@example.com")))
		requireNoError(t, "CreateMember", s.CreateMember(ctx(),
			mk(id(22), id(11), ptr(id(2)), store.RoleMember, "b@example.com")))

		requireNoError(t, "DeleteMember", s.DeleteMember(ctx(), id(22)))

		if _, err := s.GetMemberByUserAndTeam(ctx(), id(2), id(11)); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("GetMemberByUserAndTeam after delete = %v, want ErrNotFound", err)
		}
		members, err := s.ListMembersByTeam(ctx(), id(11))
		requireNoError(t, "ListMembersByTeam", err)
		if len(members) != 1 || members[0].ID != id(21) {
			t.Fatalf("listing after delete = %+v, want only %s", members, id(21))
		}
		memberships, err := s.ListMembershipsByUser(ctx(), id(2))
		requireNoError(t, "ListMembershipsByUser", err)
		if len(memberships) != 0 {
			t.Fatalf("the deleted member still has memberships: %+v", memberships)
		}
	})
}

// RunInvitationStore checks store.InvitationStore.
func RunInvitationStore(t *testing.T, newStore func(*testing.T) store.InvitationStore, fx Fixtures) {
	mk := func(rowID, teamID, email, hash string, status store.InvitationStatus) *store.Invitation {
		return &store.Invitation{
			ID: rowID, TeamID: teamID, Email: email, TokenHash: hash,
			Role: store.RoleMember, Status: status, InvitedByID: id(21),
			ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}
	}

	t.Run("missing rows report ErrNotFound", func(t *testing.T) {
		s := newStore(t)
		_, err := s.GetInvitation(ctx(), id(99))
		requireNotFound(t, "GetInvitation", err)
		_, err = s.GetInvitationByTokenHash(ctx(), "no-such-hash")
		requireNotFound(t, "GetInvitationByTokenHash", err)
	})

	t.Run("non-pending invitations are still returned by hash", func(t *testing.T) {
		// The service decides what a revoked or accepted invitation means
		// by reading Status. A store that filters by status makes "already
		// used" indistinguishable from "never existed" — and, worse, hides
		// an accepted invitation from the code that would refuse to accept
		// it twice.
		s := newStore(t)
		fx.ensureTeam(t, id(11))
		inv := mk(id(61), id(11), "a@example.com", "h1", store.InvitationPending)
		requireNoError(t, "CreateInvitation", s.CreateInvitation(ctx(), inv))

		inv.Status = store.InvitationRevoked
		requireNoError(t, "UpdateInvitation", s.UpdateInvitation(ctx(), inv))

		got, err := s.GetInvitationByTokenHash(ctx(), "h1")
		requireNoError(t, "GetInvitationByTokenHash after revoke", err)
		if got.Status != store.InvitationRevoked {
			t.Fatalf("Status = %q, want revoked", got.Status)
		}
	})

	t.Run("accepted state round trips", func(t *testing.T) {
		s := newStore(t)
		fx.ensureTeam(t, id(11))
		inv := mk(id(61), id(11), "a@example.com", "h1", store.InvitationPending)
		requireNoError(t, "CreateInvitation", s.CreateInvitation(ctx(), inv))
		inv.Status = store.InvitationAccepted
		inv.AcceptedAt = ptr(time.Now())
		requireNoError(t, "UpdateInvitation", s.UpdateInvitation(ctx(), inv))

		got, err := s.GetInvitation(ctx(), id(61))
		requireNoError(t, "GetInvitation", err)
		if got.Status != store.InvitationAccepted || got.AcceptedAt == nil {
			t.Fatalf("acceptance did not persist: %+v", got)
		}
	})

	t.Run("listing is scoped to one team", func(t *testing.T) {
		s := newStore(t)
		fx.ensureTeam(t, id(11), id(12))
		requireNoError(t, "CreateInvitation", s.CreateInvitation(ctx(), mk(id(61), id(11), "a@example.com", "h1", store.InvitationPending)))
		requireNoError(t, "CreateInvitation", s.CreateInvitation(ctx(), mk(id(62), id(11), "b@example.com", "h2", store.InvitationPending)))
		requireNoError(t, "CreateInvitation", s.CreateInvitation(ctx(), mk(id(63), id(12), "c@example.com", "h3", store.InvitationPending)))

		list, err := s.ListInvitationsByTeam(ctx(), id(11))
		requireNoError(t, "ListInvitationsByTeam", err)
		if len(list) != 2 {
			t.Fatalf("ListInvitationsByTeam returned %d, want 2", len(list))
		}
		for _, inv := range list {
			if inv.TeamID != id(11) {
				t.Fatalf("listing for t1 returned an invitation from %q", inv.TeamID)
			}
		}
	})
}
