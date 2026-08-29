package authz_test

import (
	"testing"

	"github.com/mind-vm/authit/authz"
	"github.com/mind-vm/authit/store"
)

func member(role store.Role, active bool) store.Member {
	return store.Member{ID: "m1", TeamID: "t1", Role: role, IsActive: active}
}

// TestOnlyOwnersManageOwners is the line this package exists to draw, and
// the one that was wrong in the shipped authorizer until a security review
// found it.
//
// An admin that may grant the owner role grants it to itself. The
// last-owner guard then sees two owners and stops refusing to remove the
// founder -- so the guard holds right up until the moment it is needed.
func TestOnlyOwnersManageOwners(t *testing.T) {
	p := authz.DefaultPolicy()
	if !p.Can(member(store.RoleOwner, true), authz.ActionManageOwners) {
		t.Fatal("an owner must be able to manage owners")
	}
	if p.Can(member(store.RoleAdmin, true), authz.ActionManageOwners) {
		t.Fatal("an admin granting the owner role is a takeover; it must be refused")
	}
	if p.Can(member(store.RoleMember, true), authz.ActionManageOwners) {
		t.Fatal("a member must not manage owners")
	}
	// And an admin is still a real admin, so this is a line rather than a
	// blanket refusal.
	if !p.Can(member(store.RoleAdmin, true), authz.ActionManageMembers) {
		t.Fatal("an admin must still manage members")
	}
}

// TestInactiveMembersAreDeniedEverything. A deactivated colleague still has
// a membership row with a role on it, so a check that reads only the role
// says they may still act. That is the half people leave out, which is why
// Can takes a Member.
func TestInactiveMembersAreDeniedEverything(t *testing.T) {
	p := authz.DefaultPolicy()
	for _, role := range []store.Role{store.RoleOwner, store.RoleAdmin, store.RoleMember} {
		for _, a := range []authz.Action{
			authz.ActionViewTeam, authz.ActionManageMembers,
			authz.ActionManageInvitations, authz.ActionManageOwners,
		} {
			if p.Can(member(role, false), a) {
				t.Fatalf("an inactive %s was allowed to %s", role, a)
			}
		}
	}
	// CanRole deliberately does not consult membership state, so the
	// difference between the two is visible rather than accidental.
	if !p.CanRole(store.RoleOwner, authz.ActionManageOwners) {
		t.Fatal("CanRole ignores IsActive by design")
	}
}

// TestUnknownRolesAndActionsAreDenied. store.Role is an open set, so a
// policy is asked about roles it has never heard of. Default deny also
// means adding an Action to this package cannot silently widen a policy a
// host already wrote.
func TestUnknownRolesAndActionsAreDenied(t *testing.T) {
	p := authz.DefaultPolicy()
	if p.Can(member("auditor", true), authz.ActionViewTeam) {
		t.Fatal("an unknown role must be denied")
	}
	if p.Can(member(store.RoleOwner, true), authz.Action("do_anything")) {
		t.Fatal("an unknown action must be denied even for an owner")
	}
	if (authz.Policy{}).Can(member(store.RoleOwner, true), authz.ActionViewTeam) {
		t.Fatal("the zero Policy must grant nothing")
	}
	if !(authz.Policy{}).Empty() || authz.DefaultPolicy().Empty() {
		t.Fatal("Empty must distinguish an unset Policy from a populated one")
	}
}

// TestWithDoesNotMutateTheOriginal. A Policy handed to two handlers must
// not be widenable from one of them, so With copies.
func TestWithDoesNotMutateTheOriginal(t *testing.T) {
	base := authz.DefaultPolicy()
	extended := base.With("auditor", authz.ActionViewTeam)

	if !extended.Can(member("auditor", true), authz.ActionViewTeam) {
		t.Fatal("With must grant the actions it was given")
	}
	if base.Can(member("auditor", true), authz.ActionViewTeam) {
		t.Fatal("With must not widen the policy it was called on")
	}

	// It replaces a role's grant rather than adding to it, so a narrowed
	// role is actually narrowed.
	narrowed := base.With(store.RoleAdmin, authz.ActionViewTeam)
	if narrowed.Can(member(store.RoleAdmin, true), authz.ActionManageMembers) {
		t.Fatal("With must replace a role's grant, not merge into it")
	}
	if !base.Can(member(store.RoleAdmin, true), authz.ActionManageMembers) {
		t.Fatal("narrowing a copy must not narrow the original")
	}
}
