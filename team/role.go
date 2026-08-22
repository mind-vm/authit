package team

// Role is a member's permission level within a team.
//
// It lives here rather than in store because it is a domain concept, not a
// storage one: the column is a plain text column, and what the values mean is
// the host's business. The three below are a starting point, not a closed set —
// store and check any string you like. authit assigns special meaning to
// exactly one of them, RoleOwner, and only for the last-owner protections.
//
// # Roles are per-team, and only per-team
//
// A Role exists on a store.TeamMember, and a TeamMember exists in a team, so
// this type cannot express a principal whose identity spans teams: a platform
// auditor, a consultant, a support engineer working across many client
// organizations. That is a real limit rather than a gap waiting to be filled.
// Such an identity belongs in your own table, joined to authit by user id —
// and now that authit declares its tables into your registry, that join can be
// a real foreign key.
//
// The tell that you are about to fight the model: you find yourself inventing
// a team every privileged user joins, or writing one membership row per team
// to express a single global capability. Both fall over the moment such a
// principal must reach a team it holds no membership in at all.
//
// Composition is expected, not exceptional: one account is routinely both a
// cross-team principal in your model and an ordinary member of some team here.
type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
)
