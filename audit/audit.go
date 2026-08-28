// Package audit lets a host observe authit's security-relevant events —
// logins, lockouts, password and 2FA changes, session and token
// revocation, impersonation — without authit dictating where they end up.
//
// It is entirely opt-in: every service's Config carries an AuditLogger
// field, and leaving it nil means events are simply not recorded — the
// same nil-safe shape as user.Config's EmailSender or team.Config's
// Admission. A host that needs a compliance trail (SOC2, GDPR, PCI-DSS)
// implements Logger against its own log pipeline or SIEM; SlogLogger
// covers the common case of just wanting these events in application
// logs.
package audit

import "context"

// Logger receives audit events. Implementations must be safe for
// concurrent use — every service method that emits an event may be called
// from a different goroutine.
//
// Log takes no error return: a host that needs delivery guarantees (retry,
// buffering, an outbox) owns that inside its implementation. authit itself
// never lets a logging failure affect the outcome of the operation being
// audited — Log is called after the fact, best-effort.
type Logger interface {
	Log(ctx context.Context, event Event)
}

// NoopLogger discards every event. It is the default a service falls back
// to when its Config leaves AuditLogger nil.
type NoopLogger struct{}

// Log implements Logger by doing nothing.
func (NoopLogger) Log(context.Context, Event) {}

// EventType identifies what happened.
type EventType string

const (
	EventUserRegistered     EventType = "user.registered"
	EventUserLoginSucceeded EventType = "user.login.succeeded"
	EventUserLoginFailed    EventType = "user.login.failed"
	EventUserLoginLocked    EventType = "user.login.locked"
	EventUserLogout         EventType = "user.logout"
	EventUserTokenRefreshed EventType = "user.token.refreshed"
	// EventUserTokenReuse is emitted when an already-revoked refresh token
	// is presented before its expiry. That is evidence a token leaked, so
	// every session for the principal is revoked in response. Route this
	// one somewhere a human sees it.
	EventUserTokenReuse        EventType = "user.token.reuse_detected"
	EventUserSessionRevoked    EventType = "user.session.revoked"
	EventUserPasswordChanged   EventType = "user.password.changed"
	EventUserPasswordReset     EventType = "user.password.reset"
	EventUserEmailVerified     EventType = "user.email.verified"
	EventUserTwoFactorEnabled  EventType = "user.twofactor.enabled"
	EventUserTwoFactorDisabled EventType = "user.twofactor.disabled"
	// EventAccountLinked and EventAccountUnlinked record an external
	// identity being attached to or detached from a user. Linking is a
	// credential grant -- afterwards, that provider can sign this account
	// in -- so it belongs in the same trail as a password change.
	EventAccountLinked   EventType = "user.account.linked"
	EventAccountUnlinked EventType = "user.account.unlinked"

	EventSuperuserCreated        EventType = "superuser.created"
	EventSuperuserLoginSucceeded EventType = "superuser.login.succeeded"
	EventSuperuserLoginFailed    EventType = "superuser.login.failed"
	EventSuperuserLoginLocked    EventType = "superuser.login.locked"
	EventSuperuserLogout         EventType = "superuser.logout"
	EventSuperuserTokenRefreshed EventType = "superuser.token.refreshed"
	// EventSuperuserTokenReuse is the operator-plane counterpart of
	// EventUserTokenReuse.
	EventSuperuserTokenReuse   EventType = "superuser.token.reuse_detected"
	EventSuperuserDeactivated  EventType = "superuser.deactivated"
	EventSuperuserImpersonated EventType = "superuser.impersonated"

	EventTeamCreated             EventType = "team.created"
	EventTeamMemberRoleChanged   EventType = "team.member.role_changed"
	EventTeamMemberStatusChanged EventType = "team.member.status_changed"
	EventTeamMemberRemoved       EventType = "team.member.removed"
	EventTeamInvitationCreated   EventType = "team.invitation.created"
	EventTeamInvitationAccepted  EventType = "team.invitation.accepted"
	EventTeamInvitationRevoked   EventType = "team.invitation.revoked"

	EventPATCreated EventType = "pat.created"
	EventPATRevoked EventType = "pat.revoked"

	EventDeviceApproved EventType = "device.approved"
	EventDeviceDenied   EventType = "device.denied"
)

// Result is the outcome of the event.
type Result string

const (
	ResultSuccess Result = "success"
	ResultFailure Result = "failure"
	ResultDenied  Result = "denied"
)

// Event is one audit record.
type Event struct {
	Type   EventType
	Result Result

	// ActorID identifies who performed the action — a user, superuser, or
	// team member id, depending on Type. Empty when no principal is known
	// yet, e.g. a failed login against an email with no matching account.
	ActorID string
	// TargetID identifies what the action was performed on, when that
	// differs from ActorID — the deactivated superuser, the removed team
	// member, the impersonated user, the revoked token.
	TargetID string
	// Email identifies the acting or targeted principal by address, for
	// events where no id is available yet (registration, a failed login
	// before the account is known) or where the address is the natural
	// key (an invitation).
	Email string

	UserAgent string
	IPAddress string

	// Metadata carries event-specific detail — a team id and new role for
	// EventTeamMemberRoleChanged, a token name for EventPATCreated —
	// without growing Event's fixed shape for every plane's particulars.
	Metadata map[string]any
}
