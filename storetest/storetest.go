// Package storetest is a conformance suite for the store interfaces.
//
// authit's whole design rests on a host implementing store's ports against
// its own database, and nothing in the library can check that the
// implementation is right: an adapter that returns a nil pointer instead of
// store.ErrNotFound, or that filters revoked rows out of a Get, compiles
// perfectly and fails at runtime — sometimes as a security bug rather than
// an outage. This package is where those expectations are written down
// executably.
//
// Point it at your adapter from your own test file:
//
//	func TestMyStores(t *testing.T) {
//		storetest.RunAll(t, storetest.Stores{
//			Users: func(t *testing.T) store.UserStore { return newUserStore(t) },
//			// ...one factory per port you implement
//		})
//	}
//
// Each factory is called once per subtest and must return an empty store;
// use t.Cleanup for teardown. Leave a field nil to skip that port.
//
// # What it does not check
//
// Concurrency, transactional behaviour, and performance are out of scope —
// it runs single-goroutine against one store at a time. Nor does it dictate
// column names, types, or how a []string is stored. It checks behaviour
// authit's service packages actually rely on, and nothing else.
package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mind-vm/authit/store"
)

// Fixtures lets an adapter satisfy constraints its own schema imposes but
// the ports say nothing about.
//
// Each suite exercises one port in isolation, so it creates rows that refer
// to users, teams and operators that do not exist. Against memstore that is
// fine. Against a real schema with foreign keys -- authit's own schema.sql
// included -- those inserts are rejected, and the suite would be reporting
// a constraint the interfaces never promised.
//
// Supply the hooks you need; each is called before dependent rows are
// created, and may be called more than once with the same id, so make them
// idempotent. Leave them nil when nothing is required.
type Fixtures struct {
	EnsureUser      func(t *testing.T, userID string)
	EnsureTeam      func(t *testing.T, teamID string)
	EnsureSuperuser func(t *testing.T, superuserID string)
}

func (f Fixtures) ensureUser(t *testing.T, ids ...string) {
	t.Helper()
	if f.EnsureUser == nil {
		return
	}
	for _, id := range ids {
		f.EnsureUser(t, id)
	}
}

func (f Fixtures) ensureTeam(t *testing.T, ids ...string) {
	t.Helper()
	if f.EnsureTeam == nil {
		return
	}
	for _, id := range ids {
		f.EnsureTeam(t, id)
	}
}

func (f Fixtures) ensureSuperuser(t *testing.T, ids ...string) {
	t.Helper()
	if f.EnsureSuperuser == nil {
		return
	}
	for _, id := range ids {
		f.EnsureSuperuser(t, id)
	}
}

// Stores collects one factory per port. Nil fields are skipped.
type Stores struct {
	// Fixtures is consulted before rows with foreign keys are created.
	Fixtures Fixtures

	Users              func(*testing.T) store.UserStore
	RefreshTokens      func(*testing.T) store.RefreshTokenStore
	PasswordResets     func(*testing.T) store.PasswordResetStore
	EmailVerifications func(*testing.T) store.EmailVerificationStore
	TOTP               func(*testing.T) store.TOTPStore
	PendingTwoFactor   func(*testing.T) store.PendingTwoFactorStore
	Lockouts           func(*testing.T) store.LockoutStore
	Teams              func(*testing.T) store.TeamStore
	Members            func(*testing.T) store.MemberStore
	Invitations        func(*testing.T) store.InvitationStore
	PATs               func(*testing.T) store.PersonalAccessTokenStore
	Devices            func(*testing.T) store.DeviceAuthorizationStore
	Superusers         func(*testing.T) store.SuperuserStore
	SuperuserTokens    func(*testing.T) store.SuperuserRefreshTokenStore
}

// RunAll runs every suite for which a factory was supplied.
func RunAll(t *testing.T, s Stores) {
	t.Helper()
	if s.Users != nil {
		t.Run("UserStore", func(t *testing.T) { RunUserStore(t, s.Users, s.Fixtures) })
	}
	if s.RefreshTokens != nil {
		t.Run("RefreshTokenStore", func(t *testing.T) { RunRefreshTokenStore(t, s.RefreshTokens, s.Fixtures) })
	}
	if s.PasswordResets != nil {
		t.Run("PasswordResetStore", func(t *testing.T) { RunPasswordResetStore(t, s.PasswordResets, s.Fixtures) })
	}
	if s.EmailVerifications != nil {
		t.Run("EmailVerificationStore", func(t *testing.T) { RunEmailVerificationStore(t, s.EmailVerifications, s.Fixtures) })
	}
	if s.TOTP != nil {
		t.Run("TOTPStore", func(t *testing.T) { RunTOTPStore(t, s.TOTP, s.Fixtures) })
	}
	if s.PendingTwoFactor != nil {
		t.Run("PendingTwoFactorStore", func(t *testing.T) { RunPendingTwoFactorStore(t, s.PendingTwoFactor, s.Fixtures) })
	}
	if s.Lockouts != nil {
		t.Run("LockoutStore", func(t *testing.T) { RunLockoutStore(t, s.Lockouts, s.Fixtures) })
	}
	if s.Teams != nil {
		t.Run("TeamStore", func(t *testing.T) { RunTeamStore(t, s.Teams, s.Fixtures) })
	}
	if s.Members != nil {
		t.Run("MemberStore", func(t *testing.T) { RunMemberStore(t, s.Members, s.Fixtures) })
	}
	if s.Invitations != nil {
		t.Run("InvitationStore", func(t *testing.T) { RunInvitationStore(t, s.Invitations, s.Fixtures) })
	}
	if s.PATs != nil {
		t.Run("PersonalAccessTokenStore", func(t *testing.T) { RunPersonalAccessTokenStore(t, s.PATs, s.Fixtures) })
	}
	if s.Devices != nil {
		t.Run("DeviceAuthorizationStore", func(t *testing.T) { RunDeviceAuthorizationStore(t, s.Devices, s.Fixtures) })
	}
	if s.Superusers != nil {
		t.Run("SuperuserStore", func(t *testing.T) { RunSuperuserStore(t, s.Superusers, s.Fixtures) })
	}
	if s.SuperuserTokens != nil {
		t.Run("SuperuserRefreshTokenStore", func(t *testing.T) { RunSuperuserRefreshTokenStore(t, s.SuperuserTokens, s.Fixtures) })
	}
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

func ctx() context.Context { return context.Background() }

// requireNotFound is the single most-violated part of the contract. An
// adapter must report a missing row as store.ErrNotFound and nothing else:
// not a nil value with a nil error, not the driver's own sentinel. Every
// service package branches on errors.Is(err, store.ErrNotFound) to mean
// "no such thing", and treats anything else as a fault to propagate — so a
// bare sql.ErrNoRows turns "this email is free" into a 500, and a nil error
// turns it into a nil-pointer dereference.
func requireNotFound(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected an error for a missing row, got nil", what)
	}
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("%s: error must satisfy errors.Is(err, store.ErrNotFound), got %v", what, err)
	}
}

func requireNoError(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

// timeNear compares timestamps loosely. Backends legitimately truncate:
// Postgres keeps microseconds, MySQL DATETIME may keep whole seconds. The
// suite cares that a time round-trips as approximately itself, not that it
// survives to the nanosecond.
func timeNear(t *testing.T, what string, got, want time.Time) {
	t.Helper()
	if d := got.Sub(want); d > time.Second || d < -time.Second {
		t.Fatalf("%s: got %v, want within 1s of %v", what, got, want)
	}
}

func ptr[T any](v T) *T { return &v }

// id returns a deterministic UUID-shaped identifier.
//
// The suite must work against a uuid column as readily as a text one, so
// "u1" is not usable: Postgres rejects it outright, and an adapter storing
// ids as text would pass a test its sibling could not even run. These are
// valid v4-shaped UUIDs differing only in the last byte.
func id(n int) string {
	const hex = "0123456789abcdef"
	return "00000000-0000-4000-8000-0000000000" + string([]byte{hex[(n>>4)&0xf], hex[n&0xf]})
}
