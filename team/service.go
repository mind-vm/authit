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
//
// # What this package is not
//
// This is multi-tenancy, not an authorization model, and the difference
// matters most in one place: a role here is always a role *in a team*. An
// identity that spans teams has no home in this model, and shouldn't be given
// one — build it in your own schema, joined to authit by user id, and keep
// using authit for authentication.
//
// The tell that you are about to fight the model: you find yourself inventing
// a team that every privileged user joins, or writing a membership row per
// team to express one global capability. Both fall over the moment such a
// principal must reach a team it holds no membership in at all. A flag or a
// table of your own, checked by your own code before you call in here, is the
// shape that keeps working.
//
// Composition is expected, not exceptional: one account is routinely both a
// cross-team principal in your model and an ordinary Member of some team
// here, and the two answer different questions about it.
package team

import (
	"context"
	"errors"
	"time"

	"github.com/mind-vm/authit/audit"
	"github.com/mind-vm/authit/store"
)

// Stores groups the persistence ports the team package needs.
type Stores struct {
	Teams       store.TeamStore
	Members     store.MemberStore
	Invitations store.InvitationStore
	// Tx is optional. Supplying it makes CreateTeam and AcceptInvitation
	// atomic, and runs the last-owner check of UpdateMemberRole,
	// SetMemberActive and RemoveMember in one transaction with the write it
	// guards; nil leaves them as independent writes. See store.TxRunner.
	// sqlitestore and pgstore both make that check hold under concurrency;
	// a host adapter on a database with weaker isolation than serializable
	// needs ListMembersByTeam to lock the rows it reads when called inside
	// the transaction, as pgstore's does.
	//
	// Note that Admission runs inside the transaction, so that a seat limit
	// is actually enforceable rather than advisory under concurrency: the
	// member count it is given and the member row that follows are then
	// consistent. Keep an AdmitMember implementation fast and free of
	// external I/O -- it holds a database transaction open.
	Tx store.TxRunner
	// Sessions is optional: the user plane's session store, usually the
	// same RefreshTokenStore user.Stores uses. With it set, deactivating or
	// removing a member also revokes that user's sessions acting in the
	// team (see user.Service.SwitchTeam), in the same transaction as the
	// change. Without it those sessions end at their next Refresh or
	// ValidateSession, provided user.Stores.Members is set.
	Sessions store.RefreshTokenStore
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
	// AuditLogger receives security-relevant events (membership and role
	// changes, invitations). Nil means events are not recorded — see
	// package audit.
	AuditLogger audit.Logger
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
	audit     audit.Logger
	cfg       Config
}

// NewService constructs a Service. admission may be nil, in which case
// NopAdmission is used. Config.AuditLogger may be nil, in which case
// audit.NoopLogger is used.
func NewService(stores Stores, admission Admission, cfg Config) (*Service, error) {
	if stores.Teams == nil || stores.Members == nil || stores.Invitations == nil {
		return nil, errors.New("authit/team: all Stores fields are required")
	}
	if admission == nil {
		admission = NopAdmission{}
	}
	auditLogger := cfg.AuditLogger
	if auditLogger == nil {
		auditLogger = audit.NoopLogger{}
	}
	return &Service{stores: stores, admission: admission, audit: auditLogger, cfg: cfg.withDefaults()}, nil
}
