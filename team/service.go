// Package team implements team/organization management: creating teams,
// managing membership and roles, and inviting new members by email. It has
// no notion of HTTP or a specific database — persistence is defined by the
// store interfaces it depends on.
//
// Authorization is the caller's responsibility: methods that change roles
// or membership do not themselves check the caller's role. A host
// application checks (e.g.) "is the caller an owner or admin of this team?"
// before calling UpdateMemberRole or RemoveMember, typically using the
// caller's own Member record fetched via GetMemberByUserAndTeam.
package team

import (
	"context"
	"errors"
	"time"

	"github.com/jryannel/authit/store"
)

// Stores groups the persistence ports the team package needs.
type Stores struct {
	Teams       store.TeamStore
	Members     store.MemberStore
	Invitations store.InvitationStore
}

// Admission is consulted before a new member is admitted to a team, either
// by direct creation or invitation acceptance. It lets a host application
// enforce a seat limit (e.g. from its billing plan) without team needing to
// know anything about billing. The default, NopAdmission, admits everyone.
type Admission interface {
	AdmitMember(ctx context.Context, teamID string, currentCount int) error
}

// NopAdmission admits every member unconditionally.
type NopAdmission struct{}

func (NopAdmission) AdmitMember(context.Context, string, int) error { return nil }

// Config tunes the team package's flows.
type Config struct {
	// InvitationTTL is how long an invitation stays valid. Defaults to 7
	// days.
	InvitationTTL time.Duration
}

func (c Config) withDefaults() Config {
	if c.InvitationTTL <= 0 {
		c.InvitationTTL = 7 * 24 * time.Hour
	}
	return c
}

// Service implements team/membership/invitation flows.
type Service struct {
	stores    Stores
	admission Admission
	cfg       Config
}

// NewService constructs a Service. admission may be nil, in which case
// NopAdmission is used.
func NewService(stores Stores, admission Admission, cfg Config) (*Service, error) {
	if stores.Teams == nil || stores.Members == nil || stores.Invitations == nil {
		return nil, errors.New("authit/team: all Stores fields are required")
	}
	if admission == nil {
		admission = NopAdmission{}
	}
	return &Service{stores: stores, admission: admission, cfg: cfg.withDefaults()}, nil
}
