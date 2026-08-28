package storetest

import (
	"slices"
	"testing"
	"time"

	"github.com/mind-vm/authit/store"
)

// RunTOTPStore checks store.TOTPStore.
func RunTOTPStore(t *testing.T, newStore func(*testing.T) store.TOTPStore, fx Fixtures) {
	t.Run("missing rows report ErrNotFound", func(t *testing.T) {
		s := newStore(t)
		_, err := s.GetTOTPSettingsByUserID(ctx(), id(90))
		requireNotFound(t, "GetTOTPSettingsByUserID", err)
	})

	t.Run("recovery code hashes round trip", func(t *testing.T) {
		// RecoveryCodeHashes is a []string with no obvious storage — a
		// Postgres text[], a join table and a JSON column are all
		// defensible — so this is the field most likely to be dropped,
		// reordered, or silently truncated by an adapter. Losing it means
		// every recovery code stops working, which surfaces only when
		// somebody has lost their phone.
		s := newStore(t)
		fx.ensureUser(t, id(1))
		settings := &store.TOTPSettings{
			ID: id(11), UserID: id(1), SecretEncrypted: []byte{1, 2, 3},
			Enabled: true, VerifiedAt: ptr(time.Now()),
			RecoveryCodeHashes: []string{"h1", "h2", "h3"},
			RecoveryCodesUsed:  0,
			CreatedAt:          time.Now(), UpdatedAt: time.Now(),
		}
		requireNoError(t, "CreateTOTPSettings", s.CreateTOTPSettings(ctx(), settings))

		got, err := s.GetTOTPSettingsByUserID(ctx(), id(1))
		requireNoError(t, "GetTOTPSettingsByUserID", err)
		if !slices.Equal(got.RecoveryCodeHashes, []string{"h1", "h2", "h3"}) {
			t.Fatalf("RecoveryCodeHashes = %v, want [h1 h2 h3] in order", got.RecoveryCodeHashes)
		}
		if !got.Enabled || got.VerifiedAt == nil {
			t.Fatalf("enrollment state did not round trip: %+v", got)
		}
		if string(got.SecretEncrypted) != string([]byte{1, 2, 3}) {
			t.Fatalf("SecretEncrypted = %v; it is ciphertext, so it must survive byte for byte", got.SecretEncrypted)
		}
	})

	t.Run("consuming a recovery code persists", func(t *testing.T) {
		// This is how a single-use recovery code becomes used. If the
		// update does not stick, every code is infinitely reusable.
		s := newStore(t)
		fx.ensureUser(t, id(1))
		settings := &store.TOTPSettings{
			ID: id(11), UserID: id(1), SecretEncrypted: []byte{9},
			Enabled: true, RecoveryCodeHashes: []string{"h1", "h2"},
		}
		requireNoError(t, "CreateTOTPSettings", s.CreateTOTPSettings(ctx(), settings))

		settings.RecoveryCodeHashes = []string{"h2"}
		settings.RecoveryCodesUsed = 1
		requireNoError(t, "UpdateTOTPSettings", s.UpdateTOTPSettings(ctx(), settings))

		got, err := s.GetTOTPSettingsByUserID(ctx(), id(1))
		requireNoError(t, "GetTOTPSettingsByUserID", err)
		if !slices.Equal(got.RecoveryCodeHashes, []string{"h2"}) || got.RecoveryCodesUsed != 1 {
			t.Fatalf("consumption did not persist: hashes=%v used=%d", got.RecoveryCodeHashes, got.RecoveryCodesUsed)
		}
	})

	t.Run("empty recovery code list round trips", func(t *testing.T) {
		// The all-codes-used case. An adapter that maps an empty slice to
		// NULL and back to a decode error breaks 2FA for exactly the users
		// who have already had a bad day.
		s := newStore(t)
		fx.ensureUser(t, id(1))
		settings := &store.TOTPSettings{
			ID: id(11), UserID: id(1), SecretEncrypted: []byte{9},
			Enabled: true, RecoveryCodeHashes: []string{}, RecoveryCodesUsed: 10,
		}
		requireNoError(t, "CreateTOTPSettings", s.CreateTOTPSettings(ctx(), settings))
		got, err := s.GetTOTPSettingsByUserID(ctx(), id(1))
		requireNoError(t, "GetTOTPSettingsByUserID", err)
		if len(got.RecoveryCodeHashes) != 0 {
			t.Fatalf("RecoveryCodeHashes = %v, want empty", got.RecoveryCodeHashes)
		}
	})

	t.Run("delete removes enrollment", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1))
		settings := &store.TOTPSettings{ID: id(11), UserID: id(1), SecretEncrypted: []byte{9}, Enabled: true}
		requireNoError(t, "CreateTOTPSettings", s.CreateTOTPSettings(ctx(), settings))
		requireNoError(t, "DeleteTOTPSettings", s.DeleteTOTPSettings(ctx(), id(1)))
		_, err := s.GetTOTPSettingsByUserID(ctx(), id(1))
		requireNotFound(t, "GetTOTPSettingsByUserID after delete", err)
	})
}

// RunPendingTwoFactorStore checks store.PendingTwoFactorStore.
func RunPendingTwoFactorStore(t *testing.T, newStore func(*testing.T) store.PendingTwoFactorStore, fx Fixtures) {
	t.Run("missing rows report ErrNotFound", func(t *testing.T) {
		s := newStore(t)
		_, err := s.GetPendingTwoFactorSessionByHash(ctx(), "nope")
		requireNotFound(t, "GetPendingTwoFactorSessionByHash", err)
	})

	t.Run("create, read, delete", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1))
		sess := &store.PendingTwoFactorSession{
			ID: id(41), UserID: id(1), TokenHash: "h1",
			ExpiresAt: time.Now().Add(5 * time.Minute), CreatedAt: time.Now(),
		}
		requireNoError(t, "CreatePendingTwoFactorSession", s.CreatePendingTwoFactorSession(ctx(), sess))
		if sess.ID == "" {
			t.Fatal("Create must leave the session's ID populated; Delete takes it")
		}
		got, err := s.GetPendingTwoFactorSessionByHash(ctx(), "h1")
		requireNoError(t, "GetPendingTwoFactorSessionByHash", err)
		if got.UserID != id(1) {
			t.Fatalf("UserID = %q, want u1", got.UserID)
		}
		requireNoError(t, "DeletePendingTwoFactorSession", s.DeletePendingTwoFactorSession(ctx(), sess.ID))
		// Deletion is what makes the pending session single-use: once 2FA
		// succeeds the token must not be replayable.
		_, err = s.GetPendingTwoFactorSessionByHash(ctx(), "h1")
		requireNotFound(t, "GetPendingTwoFactorSessionByHash after delete", err)
	})
}

// RunLockoutStore checks store.LockoutStore.
//
// This is the port with the footgun: it needs two tables, and the second
// has no authit type at all, so an adapter that implements only the
// attempts half compiles cleanly and fails at runtime.
func RunLockoutStore(t *testing.T, newStore func(*testing.T) store.LockoutStore, fx Fixtures) {
	attempt := func(rowID, email, ip string, at time.Time) *store.FailedLoginAttempt {
		return &store.FailedLoginAttempt{ID: rowID, Email: email, IPAddress: ip, CreatedAt: at}
	}

	t.Run("counting respects the time window", func(t *testing.T) {
		// The temporary lockout is *derived* from this count rather than
		// stored, so `since` is what makes it lift on its own. An adapter
		// that ignores the parameter and counts every attempt ever
		// recorded turns a 15-minute throttle back into a permanent lock —
		// the exact bug the derived design was introduced to remove.
		s := newStore(t)
		now := time.Now()
		requireNoError(t, "record", s.RecordFailedLoginAttempt(ctx(), attempt(id(91), "alice@example.com", "ip", now.Add(-time.Hour))))
		requireNoError(t, "record", s.RecordFailedLoginAttempt(ctx(), attempt(id(92), "alice@example.com", "ip", now.Add(-time.Minute))))
		requireNoError(t, "record", s.RecordFailedLoginAttempt(ctx(), attempt(id(93), "alice@example.com", "ip", now)))

		recent, err := s.CountRecentFailedLoginAttempts(ctx(), "alice@example.com", now.Add(-5*time.Minute))
		requireNoError(t, "CountRecentFailedLoginAttempts", err)
		if recent != 2 {
			t.Fatalf("recent attempts = %d, want 2; the `since` argument must filter", recent)
		}

		all, err := s.CountRecentFailedLoginAttempts(ctx(), "alice@example.com", now.Add(-24*time.Hour))
		requireNoError(t, "CountRecentFailedLoginAttempts", err)
		if all != 3 {
			t.Fatalf("attempts in a wide window = %d, want 3", all)
		}
	})

	t.Run("counting is scoped to one email", func(t *testing.T) {
		s := newStore(t)
		now := time.Now()
		requireNoError(t, "record", s.RecordFailedLoginAttempt(ctx(), attempt(id(91), "alice@example.com", "ip", now)))
		requireNoError(t, "record", s.RecordFailedLoginAttempt(ctx(), attempt(id(92), "bob@example.com", "ip", now)))
		n, err := s.CountRecentFailedLoginAttempts(ctx(), "alice@example.com", now.Add(-time.Minute))
		requireNoError(t, "count", err)
		if n != 1 {
			t.Fatalf("count = %d, want 1; one account's failures must not throttle another", n)
		}
	})

	t.Run("clearing is scoped to one email", func(t *testing.T) {
		s := newStore(t)
		now := time.Now()
		requireNoError(t, "record", s.RecordFailedLoginAttempt(ctx(), attempt(id(91), "alice@example.com", "ip", now)))
		requireNoError(t, "record", s.RecordFailedLoginAttempt(ctx(), attempt(id(92), "bob@example.com", "ip", now)))
		requireNoError(t, "clear", s.ClearFailedLoginAttempts(ctx(), "alice@example.com"))

		n, err := s.CountRecentFailedLoginAttempts(ctx(), "alice@example.com", now.Add(-time.Minute))
		requireNoError(t, "count", err)
		if n != 0 {
			t.Fatalf("after clearing, count = %d, want 0; a successful login must reset the counter", n)
		}
		n, err = s.CountRecentFailedLoginAttempts(ctx(), "bob@example.com", now.Add(-time.Minute))
		requireNoError(t, "count", err)
		if n != 1 {
			t.Fatalf("clearing one address wiped another's attempts (count = %d)", n)
		}
	})

	t.Run("the administrative lock is a second table", func(t *testing.T) {
		// If this subtest is the one that fails, the likely cause is an
		// adapter that implemented the attempts table and nothing else.
		// Nothing about store.LockoutStore's types hints that a second
		// table exists; see schema.sql's account_locks.
		s := newStore(t)
		fx.ensureUser(t, id(1), id(2))
		locked, err := s.IsAccountLocked(ctx(), id(1))
		requireNoError(t, "IsAccountLocked", err)
		if locked {
			t.Fatal("a fresh store must not report an account as locked")
		}

		requireNoError(t, "LockAccount", s.LockAccount(ctx(), id(1)))
		locked, err = s.IsAccountLocked(ctx(), id(1))
		requireNoError(t, "IsAccountLocked", err)
		if !locked {
			t.Fatal("LockAccount did not take effect")
		}

		// Scoped: locking one account must not lock another.
		locked, err = s.IsAccountLocked(ctx(), id(2))
		requireNoError(t, "IsAccountLocked", err)
		if locked {
			t.Fatal("locking one account locked another")
		}

		// Idempotent: authit documents that locking an already-locked
		// account is not an error, which is why the user-id column must be
		// UNIQUE rather than merely indexed.
		requireNoError(t, "LockAccount twice", s.LockAccount(ctx(), id(1)))

		requireNoError(t, "UnlockAccount", s.UnlockAccount(ctx(), id(1)))
		locked, err = s.IsAccountLocked(ctx(), id(1))
		requireNoError(t, "IsAccountLocked", err)
		if locked {
			t.Fatal("UnlockAccount did not take effect")
		}
		// Also idempotent, so an operator can unlock twice without an error.
		requireNoError(t, "UnlockAccount twice", s.UnlockAccount(ctx(), id(1)))
	})
}
