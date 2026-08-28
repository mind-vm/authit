package storetest

import (
	"slices"
	"testing"
	"time"

	"github.com/mind-vm/authit/store"
)

// RunPersonalAccessTokenStore checks store.PersonalAccessTokenStore.
func RunPersonalAccessTokenStore(t *testing.T, newStore func(*testing.T) store.PersonalAccessTokenStore, fx Fixtures) {
	mk := func(rowID, userID, name, hash string, scopes []string) *store.PersonalAccessToken {
		return &store.PersonalAccessToken{
			ID: rowID, UserID: userID, Name: name, TokenHash: hash,
			Scopes: scopes, CreatedAt: time.Now(),
		}
	}

	t.Run("missing rows report ErrNotFound", func(t *testing.T) {
		s := newStore(t)
		_, err := s.GetPersonalAccessToken(ctx(), id(99))
		requireNotFound(t, "GetPersonalAccessToken", err)
		_, err = s.GetPersonalAccessTokenByHash(ctx(), "no-such-hash")
		// Resolve runs this on every API request; an unknown token must be
		// a clean ErrNotFound, which the service turns into ErrInvalidToken.
		requireNotFound(t, "GetPersonalAccessTokenByHash", err)
	})

	t.Run("scopes round trip in order", func(t *testing.T) {
		// Scopes decide what the credential may do. An adapter that drops,
		// reorders or de-duplicates them silently changes an authorization
		// decision.
		s := newStore(t)
		fx.ensureUser(t, id(1))
		tok := mk(id(41), id(1), "laptop", "h1", []string{"read", "write", "admin"})
		requireNoError(t, "CreatePersonalAccessToken", s.CreatePersonalAccessToken(ctx(), tok))

		got, err := s.GetPersonalAccessTokenByHash(ctx(), "h1")
		requireNoError(t, "GetPersonalAccessTokenByHash", err)
		if !slices.Equal(got.Scopes, []string{"read", "write", "admin"}) {
			t.Fatalf("Scopes = %v, want [read write admin]", got.Scopes)
		}
		if got.Name != "laptop" {
			t.Fatalf("Name = %q", got.Name)
		}
	})

	t.Run("an empty scope list round trips", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1))
		requireNoError(t, "create", s.CreatePersonalAccessToken(ctx(), mk(id(41), id(1), "n", "h1", nil)))
		got, err := s.GetPersonalAccessTokenByHash(ctx(), "h1")
		requireNoError(t, "get", err)
		if len(got.Scopes) != 0 {
			t.Fatalf("Scopes = %v, want empty", got.Scopes)
		}
	})

	t.Run("revoked and expired tokens are still returned by hash", func(t *testing.T) {
		// Resolve reads RevokedAt and ExpiresAt itself. A store that
		// filtered them out would still be secure here, but it would also
		// make a revoked token indistinguishable from a forged one — and
		// it would break ListTokens showing a user what they revoked.
		s := newStore(t)
		fx.ensureUser(t, id(1))
		revoked := mk(id(41), id(1), "old", "h1", nil)
		requireNoError(t, "create", s.CreatePersonalAccessToken(ctx(), revoked))
		revoked.RevokedAt = ptr(time.Now())
		requireNoError(t, "update", s.UpdatePersonalAccessToken(ctx(), revoked))

		got, err := s.GetPersonalAccessTokenByHash(ctx(), "h1")
		requireNoError(t, "GetPersonalAccessTokenByHash after revoke", err)
		if got.RevokedAt == nil {
			t.Fatal("RevokedAt did not persist")
		}
	})

	t.Run("LastUsedAt persists", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1))
		tok := mk(id(41), id(1), "n", "h1", nil)
		requireNoError(t, "create", s.CreatePersonalAccessToken(ctx(), tok))
		used := time.Now()
		tok.LastUsedAt = &used
		requireNoError(t, "update", s.UpdatePersonalAccessToken(ctx(), tok))

		got, err := s.GetPersonalAccessToken(ctx(), id(41))
		requireNoError(t, "get", err)
		if got.LastUsedAt == nil {
			t.Fatal("LastUsedAt did not persist")
		}
		timeNear(t, "LastUsedAt", *got.LastUsedAt, used)
	})

	t.Run("listing is scoped to one user", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1), id(2))
		requireNoError(t, "create", s.CreatePersonalAccessToken(ctx(), mk(id(41), id(1), "a", "h1", nil)))
		requireNoError(t, "create", s.CreatePersonalAccessToken(ctx(), mk(id(42), id(1), "b", "h2", nil)))
		requireNoError(t, "create", s.CreatePersonalAccessToken(ctx(), mk(id(43), id(2), "c", "h3", nil)))

		list, err := s.ListPersonalAccessTokensByUser(ctx(), id(1))
		requireNoError(t, "ListPersonalAccessTokensByUser", err)
		if len(list) != 2 {
			t.Fatalf("listed %d tokens, want 2; showing another user's tokens is a disclosure", len(list))
		}
		for _, tok := range list {
			if tok.UserID != id(1) {
				t.Fatalf("listing for u1 returned a token owned by %q", tok.UserID)
			}
		}
	})
}

// RunDeviceAuthorizationStore checks store.DeviceAuthorizationStore.
func RunDeviceAuthorizationStore(t *testing.T, newStore func(*testing.T) store.DeviceAuthorizationStore, fx Fixtures) {
	mk := func(rowID, deviceHash, userCode string) *store.DeviceAuthorization {
		return &store.DeviceAuthorization{
			ID: rowID, DeviceCodeHash: deviceHash, UserCode: userCode,
			ClientID: "cli", Scope: "read write",
			Status: store.DeviceAuthorizationPending, IntervalSeconds: 5,
			ExpiresAt: time.Now().Add(15 * time.Minute), CreatedAt: time.Now(),
		}
	}

	t.Run("missing rows report ErrNotFound", func(t *testing.T) {
		s := newStore(t)
		_, err := s.GetDeviceAuthorizationByDeviceCodeHash(ctx(), "nope")
		requireNotFound(t, "GetDeviceAuthorizationByDeviceCodeHash", err)
		_, err = s.GetDeviceAuthorizationByUserCode(ctx(), "NOPE-NOPE")
		// A wrong user code must be ErrNotFound, because that is what the
		// device package charges against its guess budget. Any other error
		// bypasses the rate limit that the code's low entropy depends on.
		requireNotFound(t, "GetDeviceAuthorizationByUserCode", err)
	})

	t.Run("both lookups find the same row", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1))
		d := mk(id(71), "devicehash", "WDJB-MJHT")
		requireNoError(t, "CreateDeviceAuthorization", s.CreateDeviceAuthorization(ctx(), d))
		if d.ID == "" {
			t.Fatal("Create must leave the authorization's ID populated; Delete takes it")
		}

		byDevice, err := s.GetDeviceAuthorizationByDeviceCodeHash(ctx(), "devicehash")
		requireNoError(t, "GetDeviceAuthorizationByDeviceCodeHash", err)
		byUser, err := s.GetDeviceAuthorizationByUserCode(ctx(), "WDJB-MJHT")
		requireNoError(t, "GetDeviceAuthorizationByUserCode", err)
		if byDevice.ID != byUser.ID {
			t.Fatalf("the two lookups disagree: %q vs %q", byDevice.ID, byUser.ID)
		}
		if byUser.Scope != "read write" {
			t.Fatalf("Scope = %q; it is handed to the host's token issuer", byUser.Scope)
		}
	})

	t.Run("approval and interval updates persist", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1))
		d := mk(id(71), "devicehash", "WDJB-MJHT")
		requireNoError(t, "create", s.CreateDeviceAuthorization(ctx(), d))

		now := time.Now()
		d.Status = store.DeviceAuthorizationApproved
		d.UserID = ptr(id(1))
		d.LastPolledAt = &now
		// The slow_down response permanently widens the interval; if the
		// write is lost, a misbehaving client is told to slow down forever
		// and never actually is.
		d.IntervalSeconds = 10
		requireNoError(t, "UpdateDeviceAuthorization", s.UpdateDeviceAuthorization(ctx(), d))

		got, err := s.GetDeviceAuthorizationByDeviceCodeHash(ctx(), "devicehash")
		requireNoError(t, "get", err)
		if got.Status != store.DeviceAuthorizationApproved {
			t.Fatalf("Status = %q, want approved", got.Status)
		}
		if got.UserID == nil || *got.UserID != id(1) {
			t.Fatalf("UserID = %v, want u1; this is who the CLI is logged in as", got.UserID)
		}
		if got.IntervalSeconds != 10 {
			t.Fatalf("IntervalSeconds = %d, want 10", got.IntervalSeconds)
		}
		if got.LastPolledAt == nil {
			t.Fatal("LastPolledAt did not persist; without it slow_down cannot be detected")
		}
	})

	t.Run("delete makes a device code unusable", func(t *testing.T) {
		// A resolved authorization is deleted so it cannot be polled
		// twice. If the delete does not take, a device code stays
		// redeemable for the rest of its lifetime.
		s := newStore(t)
		fx.ensureUser(t, id(1))
		d := mk(id(71), "devicehash", "WDJB-MJHT")
		requireNoError(t, "create", s.CreateDeviceAuthorization(ctx(), d))
		requireNoError(t, "DeleteDeviceAuthorization", s.DeleteDeviceAuthorization(ctx(), d.ID))

		_, err := s.GetDeviceAuthorizationByDeviceCodeHash(ctx(), "devicehash")
		requireNotFound(t, "GetDeviceAuthorizationByDeviceCodeHash after delete", err)
		_, err = s.GetDeviceAuthorizationByUserCode(ctx(), "WDJB-MJHT")
		requireNotFound(t, "GetDeviceAuthorizationByUserCode after delete", err)
	})
}

// RunSuperuserStore checks store.SuperuserStore.
func RunSuperuserStore(t *testing.T, newStore func(*testing.T) store.SuperuserStore, fx Fixtures) {
	mk := func(rowID, email string) *store.Superuser {
		return &store.Superuser{
			ID: rowID, Email: email, PasswordHash: "$argon2id$fake",
			DisplayName: "Ops", IsActive: true,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}
	}

	t.Run("missing rows report ErrNotFound", func(t *testing.T) {
		s := newStore(t)
		_, err := s.GetSuperuserByID(ctx(), "nope")
		requireNotFound(t, "GetSuperuserByID", err)
		_, err = s.GetSuperuserByEmail(ctx(), "nobody@example.com")
		requireNotFound(t, "GetSuperuserByEmail", err)
	})

	t.Run("CountSuperusers gates Bootstrap", func(t *testing.T) {
		// Bootstrap refuses to run once any operator exists, and this
		// count is the only thing enforcing it. An adapter that always
		// returned 0 would leave an unauthenticated path to creating an
		// operator account open forever.
		s := newStore(t)
		n, err := s.CountSuperusers(ctx())
		requireNoError(t, "CountSuperusers", err)
		if n != 0 {
			t.Fatalf("a fresh store counted %d superusers, want 0", n)
		}
		requireNoError(t, "CreateSuperuser", s.CreateSuperuser(ctx(), mk(id(81), "ops@example.com")))
		n, err = s.CountSuperusers(ctx())
		requireNoError(t, "CountSuperusers", err)
		if n != 1 {
			t.Fatalf("CountSuperusers = %d, want 1", n)
		}
	})

	t.Run("create, read, list, deactivate", func(t *testing.T) {
		s := newStore(t)
		su := mk(id(81), "ops@example.com")
		requireNoError(t, "CreateSuperuser", s.CreateSuperuser(ctx(), su))
		requireNoError(t, "CreateSuperuser", s.CreateSuperuser(ctx(), mk(id(82), "ops2@example.com")))

		byEmail, err := s.GetSuperuserByEmail(ctx(), "ops@example.com")
		requireNoError(t, "GetSuperuserByEmail", err)
		if byEmail.ID != su.ID {
			t.Fatalf("GetSuperuserByEmail returned %q, want %q", byEmail.ID, su.ID)
		}

		list, err := s.ListSuperusers(ctx())
		requireNoError(t, "ListSuperusers", err)
		if len(list) != 2 {
			t.Fatalf("ListSuperusers returned %d, want 2", len(list))
		}

		su.IsActive = false
		requireNoError(t, "UpdateSuperuser", s.UpdateSuperuser(ctx(), su))
		got, err := s.GetSuperuserByID(ctx(), su.ID)
		requireNoError(t, "GetSuperuserByID", err)
		if got.IsActive {
			// Deactivation is how an operator is taken out of service;
			// Authenticate refuses an inactive account.
			t.Fatal("deactivation did not persist")
		}
		// A deactivated operator must still be findable, not filtered out,
		// or they can never be listed or reactivated.
		if _, err := s.GetSuperuserByEmail(ctx(), "ops@example.com"); err != nil {
			t.Fatalf("a deactivated superuser must still be readable: %v", err)
		}
	})
}

// RunSuperuserRefreshTokenStore checks store.SuperuserRefreshTokenStore.
func RunSuperuserRefreshTokenStore(t *testing.T, newStore func(*testing.T) store.SuperuserRefreshTokenStore, fx Fixtures) {
	mk := func(rowID, superuserID, hash string) *store.SuperuserRefreshToken {
		return &store.SuperuserRefreshToken{
			ID: rowID, SuperuserID: superuserID, TokenHash: hash,
			ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
		}
	}

	t.Run("missing rows report ErrNotFound", func(t *testing.T) {
		s := newStore(t)
		_, err := s.GetSuperuserRefreshTokenByHash(ctx(), "nope")
		requireNotFound(t, "GetSuperuserRefreshTokenByHash", err)
	})

	t.Run("revoked tokens are still returned by hash", func(t *testing.T) {
		// As on the user plane, reuse detection depends on finding the
		// revoked row. It matters more here: these tokens can impersonate.
		s := newStore(t)
		fx.ensureSuperuser(t, id(81))
		rt := mk(id(31), id(81), "h1")
		requireNoError(t, "create", s.CreateSuperuserRefreshToken(ctx(), rt))
		requireNoError(t, "revoke", s.RevokeSuperuserRefreshToken(ctx(), rt.ID))

		got, err := s.GetSuperuserRefreshTokenByHash(ctx(), "h1")
		requireNoError(t, "get after revoke", err)
		if got.RevokedAt == nil {
			t.Fatal("RevokeSuperuserRefreshToken must set RevokedAt")
		}
	})

	t.Run("RevokeAll is scoped to one operator", func(t *testing.T) {
		s := newStore(t)
		fx.ensureSuperuser(t, id(81), id(82))
		requireNoError(t, "create", s.CreateSuperuserRefreshToken(ctx(), mk(id(31), id(81), "h1")))
		requireNoError(t, "create", s.CreateSuperuserRefreshToken(ctx(), mk(id(32), id(82), "h2")))
		requireNoError(t, "revoke all", s.RevokeAllSuperuserRefreshTokens(ctx(), id(81)))

		got, err := s.GetSuperuserRefreshTokenByHash(ctx(), "h1")
		requireNoError(t, "get", err)
		if got.RevokedAt == nil {
			t.Fatal("the target operator's token should be revoked")
		}
		got, err = s.GetSuperuserRefreshTokenByHash(ctx(), "h2")
		requireNoError(t, "get", err)
		if got.RevokedAt != nil {
			t.Fatal("another operator's token must not be revoked")
		}
	})
}
