package storetest

import (
	"errors"
	"testing"
	"time"

	"github.com/mind-vm/authit/store"
)

// RunPINStore checks store.PINStore.
func RunPINStore(t *testing.T, newStore func(*testing.T) store.PINStore, fx Fixtures) {
	t.Run("missing rows report ErrNotFound", func(t *testing.T) {
		s := newStore(t)
		_, err := s.GetPINCredential(ctx(), id(99))
		// pin.SignIn treats "no PIN" as a wrong PIN; any other error turns
		// a user without a PIN into a 500.
		requireNotFound(t, "GetPINCredential", err)
	})

	t.Run("set replaces, one PIN per user", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1), id(2))
		now := time.Now()
		requireNoError(t, "SetPINCredential", s.SetPINCredential(ctx(),
			&store.PINCredential{UserID: id(1), PINHash: "h1", CreatedAt: now, UpdatedAt: now}))
		requireNoError(t, "SetPINCredential", s.SetPINCredential(ctx(),
			&store.PINCredential{UserID: id(2), PINHash: "other", CreatedAt: now, UpdatedAt: now}))
		later := now.Add(time.Hour)
		// Setting a new PIN must replace the old one, not fail on the
		// user's existing row and not leave two to choose between.
		requireNoError(t, "SetPINCredential again", s.SetPINCredential(ctx(),
			&store.PINCredential{UserID: id(1), PINHash: "h2", CreatedAt: later, UpdatedAt: later}))

		got, err := s.GetPINCredential(ctx(), id(1))
		requireNoError(t, "GetPINCredential", err)
		if got.PINHash != "h2" {
			t.Fatalf("PINHash = %q, want the replacing hash", got.PINHash)
		}
		timeNear(t, "UpdatedAt", got.UpdatedAt, later)
		other, err := s.GetPINCredential(ctx(), id(2))
		requireNoError(t, "GetPINCredential", err)
		if other.PINHash != "other" {
			t.Fatalf("another user's PIN changed: %q", other.PINHash)
		}
	})

	t.Run("delete is idempotent", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1))
		now := time.Now()
		requireNoError(t, "SetPINCredential", s.SetPINCredential(ctx(),
			&store.PINCredential{UserID: id(1), PINHash: "h1", CreatedAt: now, UpdatedAt: now}))
		requireNoError(t, "DeletePINCredential", s.DeletePINCredential(ctx(), id(1)))
		_, err := s.GetPINCredential(ctx(), id(1))
		requireNotFound(t, "GetPINCredential after delete", err)
		requireNoError(t, "DeletePINCredential twice", s.DeletePINCredential(ctx(), id(1)))
	})
}

// RunBoundDeviceStore checks store.BoundDeviceStore.
func RunBoundDeviceStore(t *testing.T, newStore func(*testing.T) store.BoundDeviceStore, fx Fixtures) {
	mk := func(rowID, userID, hash string) *store.BoundDevice {
		return &store.BoundDevice{
			ID: rowID, UserID: userID, Name: "iPhone Safari", TokenHash: hash,
			UserAgent: "ua", IPAddress: "10.0.0.1", CreatedAt: time.Now(),
		}
	}

	t.Run("missing rows report ErrNotFound", func(t *testing.T) {
		s := newStore(t)
		_, err := s.GetBoundDevice(ctx(), id(99))
		requireNotFound(t, "GetBoundDevice", err)
		_, err = s.GetBoundDeviceByTokenHash(ctx(), "no-such-hash")
		// ValidateDevice runs this on every request from the device.
		requireNotFound(t, "GetBoundDeviceByTokenHash", err)
		requireNotFound(t, "TouchBoundDevice", s.TouchBoundDevice(ctx(), id(99), time.Now()))
		requireNotFound(t, "RevokeBoundDevice", s.RevokeBoundDevice(ctx(), id(99), time.Now()))
	})

	t.Run("round trip, with and without an expiry", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1))
		forever := mk(id(91), id(1), "h1")
		requireNoError(t, "CreateBoundDevice", s.CreateBoundDevice(ctx(), forever))
		expiring := mk(id(92), id(1), "h2")
		expiring.ExpiresAt = ptr(time.Now().Add(24 * time.Hour))
		requireNoError(t, "CreateBoundDevice", s.CreateBoundDevice(ctx(), expiring))

		got, err := s.GetBoundDeviceByTokenHash(ctx(), "h1")
		requireNoError(t, "GetBoundDeviceByTokenHash", err)
		if got.ID != id(91) || got.UserID != id(1) || got.Name != "iPhone Safari" || got.IPAddress != "10.0.0.1" {
			t.Fatalf("round trip lost data: %+v", got)
		}
		if got.ExpiresAt != nil {
			// nil is "signed in until revoked". Reading it back as a zero
			// instant would sign every such device out at once.
			t.Fatalf("ExpiresAt = %v, want nil", *got.ExpiresAt)
		}
		got, err = s.GetBoundDevice(ctx(), id(92))
		requireNoError(t, "GetBoundDevice", err)
		if got.ExpiresAt == nil {
			t.Fatal("ExpiresAt did not persist")
		}
		timeNear(t, "ExpiresAt", *got.ExpiresAt, *expiring.ExpiresAt)
	})

	t.Run("a token hash names one device", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1), id(2))
		requireNoError(t, "CreateBoundDevice", s.CreateBoundDevice(ctx(), mk(id(91), id(1), "h1")))
		if err := s.CreateBoundDevice(ctx(), mk(id(92), id(2), "h1")); !errors.Is(err, store.ErrConflict) {
			// Two devices behind one hash would sign one user in as the
			// other, whichever the lookup happened to find.
			t.Fatalf("a second device with the same token hash = %v, want ErrConflict", err)
		}
	})

	t.Run("touch records a use, and refuses a revoked device", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1))
		d := mk(id(91), id(1), "h1")
		requireNoError(t, "CreateBoundDevice", s.CreateBoundDevice(ctx(), d))
		used := time.Now()
		requireNoError(t, "TouchBoundDevice", s.TouchBoundDevice(ctx(), d.ID, used))
		got, err := s.GetBoundDevice(ctx(), d.ID)
		requireNoError(t, "GetBoundDevice", err)
		if got.LastUsedAt == nil {
			t.Fatal("LastUsedAt did not persist")
		}
		timeNear(t, "LastUsedAt", *got.LastUsedAt, used)

		requireNoError(t, "RevokeBoundDevice", s.RevokeBoundDevice(ctx(), d.ID, time.Now()))
		requireNotFound(t, "TouchBoundDevice on a revoked device", s.TouchBoundDevice(ctx(), d.ID, time.Now()))
	})

	t.Run("revoked devices are still returned, and revoking keeps the first instant", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1))
		d := mk(id(91), id(1), "h1")
		requireNoError(t, "CreateBoundDevice", s.CreateBoundDevice(ctx(), d))
		first := time.Now().Add(-time.Hour)
		requireNoError(t, "RevokeBoundDevice", s.RevokeBoundDevice(ctx(), d.ID, first))
		requireNoError(t, "RevokeBoundDevice twice", s.RevokeBoundDevice(ctx(), d.ID, time.Now()))

		got, err := s.GetBoundDeviceByTokenHash(ctx(), "h1")
		requireNoError(t, "GetBoundDeviceByTokenHash after revoke", err)
		if got.RevokedAt == nil {
			t.Fatal("RevokedAt did not persist")
		}
		timeNear(t, "RevokedAt", *got.RevokedAt, first)
	})

	t.Run("listing and revoking all are scoped to one user", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1), id(2))
		for _, d := range []*store.BoundDevice{mk(id(91), id(1), "h1"), mk(id(92), id(1), "h2"), mk(id(93), id(1), "h3"), mk(id(94), id(2), "h4")} {
			requireNoError(t, "CreateBoundDevice", s.CreateBoundDevice(ctx(), d))
		}
		requireNoError(t, "RevokeBoundDevice", s.RevokeBoundDevice(ctx(), id(93), time.Now()))

		list, err := s.ListBoundDevicesByUser(ctx(), id(1))
		requireNoError(t, "ListBoundDevicesByUser", err)
		if len(list) != 3 {
			t.Fatalf("listed %d devices, want 3, the revoked one included", len(list))
		}
		for _, d := range list {
			if d.UserID != id(1) {
				t.Fatalf("listing for u1 returned a device of %q", d.UserID)
			}
		}

		n, err := s.RevokeAllBoundDevices(ctx(), id(1), time.Now())
		requireNoError(t, "RevokeAllBoundDevices", err)
		if n != 2 {
			t.Fatalf("RevokeAllBoundDevices reported %d, want 2: the live ones only", n)
		}
		other, err := s.GetBoundDevice(ctx(), id(94))
		requireNoError(t, "GetBoundDevice", err)
		if other.RevokedAt != nil {
			t.Fatal("another user's device was revoked")
		}
	})
}
