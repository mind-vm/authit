package store

import (
	"context"
	"time"
)

// Role is a member's permission level within a team. The three-tier default
// below is a starting point, not a closed set — host applications may store
// and check any string value they like; authit's team package only assigns
// special meaning to RoleOwner (last-owner protections).
//
// Roles are per-team by design, and that is a real limit rather than a gap
// waiting to be filled. A Role only exists attached to a Member, and a Member
// only exists attached to a Team, so there is no way to express a principal
// whose identity spans teams — a platform-level auditor, a consultant, a
// support engineer, a coach working across many client organizations. Such an
// identity belongs in your own model, joined to authit by user id, not
// squeezed in here: the workarounds (a synthetic team everyone joins, or a
// membership row per team) both break as soon as the principal needs to reach
// a team it holds no membership in.
//
// The split that survives: authit answers "who is this", your model answers
// "what may they do". See the team package's doc comment.
type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
)

// Team is an organization/tenant that users belong to via Member records.
type Team struct {
	ID        string
	Name      string
	Slug      string
	OwnerID   string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// TeamStore persists Team records.
type TeamStore interface {
	CreateTeam(ctx context.Context, t *Team) error
	GetTeam(ctx context.Context, id string) (*Team, error)
	GetTeamBySlug(ctx context.Context, slug string) (*Team, error)
	UpdateTeam(ctx context.Context, t *Team) error
	DeleteTeam(ctx context.Context, id string) error
}

// Member is the join between a User and a Team, carrying the role that
// governs authorization within that team. UserID is nullable so a team can
// track a member (e.g. pending an invitation, or a login-less contact)
// before or without a linked User.
type Member struct {
	ID          string
	TeamID      string
	UserID      *string
	Role        Role
	DisplayName string
	Email       string
	IsActive    bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// MemberStore persists Member records.
type MemberStore interface {
	CreateMember(ctx context.Context, m *Member) error
	GetMember(ctx context.Context, id string) (*Member, error)
	GetMemberByUserAndTeam(ctx context.Context, userID, teamID string) (*Member, error)
	ListMembersByTeam(ctx context.Context, teamID string) ([]*Member, error)
	ListMembershipsByUser(ctx context.Context, userID string) ([]*Member, error)
	UpdateMember(ctx context.Context, m *Member) error
	DeleteMember(ctx context.Context, id string) error
}

// InvitationStatus is the lifecycle state of an Invitation. There is
// deliberately no "expired" status: expiry is derived from ExpiresAt at
// read time rather than written back.
type InvitationStatus string

const (
	InvitationPending  InvitationStatus = "pending"
	InvitationAccepted InvitationStatus = "accepted"
	InvitationRevoked  InvitationStatus = "revoked"
)

// Invitation represents an offer for an email address to join a Team with a
// given Role. Only the token's hash is persisted; the raw token is handed
// back to the caller once, at creation or resend.
type Invitation struct {
	ID          string
	TeamID      string
	Email       string
	TokenHash   string
	Role        Role
	Status      InvitationStatus
	InvitedByID string
	ExpiresAt   time.Time
	AcceptedAt  *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// InvitationStore persists Invitation records.
type InvitationStore interface {
	CreateInvitation(ctx context.Context, i *Invitation) error
	GetInvitation(ctx context.Context, id string) (*Invitation, error)
	GetInvitationByTokenHash(ctx context.Context, hash string) (*Invitation, error)
	ListInvitationsByTeam(ctx context.Context, teamID string) ([]*Invitation, error)
	UpdateInvitation(ctx context.Context, i *Invitation) error
}
