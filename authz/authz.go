// Package authz is the owner/admin/member check, written once.
//
// authit's position on authorization is unchanged and is worth restating,
// because this package could be mistaken for a reversal of it: a Role is a
// string, roles exist only inside a team, and no role can express a
// principal whose identity spans teams — a platform auditor, a support
// engineer, a consultant working across client organizations. Those belong
// in the host's own model, joined to authit by user id. The team package's
// documentation makes that argument at length and it still holds.
//
// What this package answers is a narrower question that argument never
// covered. "Authorization is yours" and "here is a correct owner/admin/member
// check you can use" are not in conflict. Every consumer of the team plane
// re-writes the same handful of role comparisons before every mutation, and
// that check — not the storage underneath it — is the part people get wrong.
// The evidence is in this repository: the check shipped in authhandlers let
// an admin grant itself the owner role and evict the founder, and it took a
// security review to notice.
//
// # What it is not
//
// Not a permission system. There are no resources, no wildcards, no
// per-team roles stored at runtime, no inheritance. Those exist in
// better-auth's organization plugin and they are what let a deployment build
// the mess described above. An Action here names a thing the team plane
// does, and the set is closed because the team plane is.
//
// Not required. Nothing in authit imports this to work; authhandlers uses it
// so that its own authorizer and a host's hand-written one cannot disagree.
// A host with its own model should write its own Policy, or its own
// authorizer entirely, and consult this for nothing.
package authz

import (
	"maps"

	"github.com/mind-vm/authit/store"
)

// Action names something the team plane does.
//
// The set is closed and small on purpose. It describes authit's own
// operations, not a host's: if your application has a notion of "may edit
// billing", that is yours to check, and squeezing it in here would make this
// package the permission system it is documented not to be.
//
// There is deliberately no resource parameter. Every action below is
// team-scoped, and a Member already names its team, so a free-form resource
// string would be a dimension nothing in authit populates and nothing in
// authit reads.
type Action string

const (
	// ActionViewTeam covers reading a team and its membership.
	ActionViewTeam Action = "view"
	// ActionManageMembers covers changing roles, activating and
	// deactivating members, and removing them.
	ActionManageMembers Action = "manage_members"
	// ActionManageInvitations covers creating, listing and revoking
	// invitations.
	ActionManageInvitations Action = "manage_invitations"
	// ActionManageOwners covers granting the owner role, and acting on a
	// member who already holds it.
	//
	// Separate from ActionManageMembers because owner is the one role
	// authit itself gives meaning to: the last-owner guards in the team
	// package are the only invariant the library enforces about who
	// controls a team. Granting member management is granting the power to
	// add and remove colleagues. It is not necessarily granting the power
	// to become the owner and remove the founder — and while these were one
	// action, it could not be anything else. That was a real escalation,
	// not a hypothetical one.
	ActionManageOwners Action = "manage_owners"
)

// Policy maps roles to the actions they may take.
//
// Unknown roles and unknown actions are denied. That is the direction a
// policy should fail in, and it means adding an Action to this package
// cannot silently widen a host's existing policy: the new action is granted
// to nobody until someone says otherwise.
//
// The zero Policy grants nothing, which is safe rather than useful. Start
// from DefaultPolicy.
type Policy struct {
	grants map[store.Role]map[Action]bool
}

// NewPolicy builds a Policy from role-to-actions grants.
func NewPolicy(grants map[store.Role][]Action) Policy {
	p := Policy{grants: make(map[store.Role]map[Action]bool, len(grants))}
	for role, actions := range grants {
		p.grants[role] = make(map[Action]bool, len(actions))
		for _, a := range actions {
			p.grants[role][a] = true
		}
	}
	return p
}

// DefaultPolicy is the conventional three-tier arrangement:
//
//	owner   every action, including ActionManageOwners
//	admin   view, manage members, manage invitations
//	member  view
//
// The line worth looking at is the one between owner and admin. An admin
// that could grant ActionManageOwners would grant it to itself, and the
// last-owner guard — which refuses to remove the final owner — is then
// satisfied by the owner the admin just minted. So it declines to remove the
// founder right up until the moment it does not.
func DefaultPolicy() Policy {
	return NewPolicy(map[store.Role][]Action{
		store.RoleOwner: {
			ActionViewTeam, ActionManageMembers, ActionManageInvitations, ActionManageOwners,
		},
		store.RoleAdmin: {
			ActionViewTeam, ActionManageMembers, ActionManageInvitations,
		},
		store.RoleMember: {
			ActionViewTeam,
		},
	})
}

// With returns a copy of p granting role the given actions, replacing any
// grant it already had.
//
// A copy, not a mutation, so a Policy shared between handlers cannot be
// widened from one of them. Use it to add a role your application defines:
//
//	p := authz.DefaultPolicy().With("auditor", authz.ActionViewTeam)
func (p Policy) With(role store.Role, actions ...Action) Policy {
	out := Policy{grants: make(map[store.Role]map[Action]bool, len(p.grants)+1)}
	for r, as := range p.grants {
		cp := make(map[Action]bool, len(as))
		maps.Copy(cp, as)
		out.grants[r] = cp
	}
	granted := make(map[Action]bool, len(actions))
	for _, a := range actions {
		granted[a] = true
	}
	out.grants[role] = granted
	return out
}

// Empty reports whether p grants nothing at all, which is what the zero
// value does. Callers that treat an unset Policy as "use the default" need
// to tell that apart from a policy deliberately granting nobody anything;
// this is how.
func (p Policy) Empty() bool { return len(p.grants) == 0 }

// Can reports whether m may perform action.
//
// It takes a Member rather than a Role because an inactive member is not
// authorized for anything, and that is the half of the check that gets
// forgotten: a deactivated colleague still has a membership row, and a role
// on it, and reading only the role says they may still act.
func (p Policy) Can(m store.Member, action Action) bool {
	if !m.IsActive {
		return false
	}
	return p.CanRole(m.Role, action)
}

// CanRole reports whether role alone grants action, ignoring whether the
// member holding it is active.
//
// For the uncommon case where there is no Member to consult — deciding what
// a role would permit before assigning it, or rendering a permissions
// table. Prefer Can wherever a Member exists.
func (p Policy) CanRole(role store.Role, action Action) bool {
	return p.grants[role][action]
}
