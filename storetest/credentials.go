package storetest

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"sync"
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

// RunAccountStore checks store.AccountStore.
func RunAccountStore(t *testing.T, newStore func(*testing.T) store.AccountStore, fx Fixtures) {
	mk := func(rowID, userID, provider, subject, email string) *store.Account {
		return &store.Account{
			ID: rowID, UserID: userID, Provider: provider, ProviderAccountID: subject,
			Email: email, EmailVerified: true, Scopes: []string{"openid", "email"},
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}
	}

	t.Run("missing rows report ErrNotFound", func(t *testing.T) {
		s := newStore(t)
		_, err := s.GetAccount(ctx(), id(99))
		requireNotFound(t, "GetAccount", err)
		_, err = s.GetAccountByProvider(ctx(), "google", "no-such-subject")
		// Every social sign-in makes this query, and the oidc package
		// branches on ErrNotFound to mean "not linked yet". Any other
		// error turns a first-time sign-in into a 500.
		requireNotFound(t, "GetAccountByProvider", err)
	})

	t.Run("lookup is by provider and subject together", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1), id(2))
		requireNoError(t, "create", s.CreateAccount(ctx(), mk(id(41), id(1), "google", "subject-1", "a@example.com")))
		requireNoError(t, "create", s.CreateAccount(ctx(), mk(id(42), id(2), "github", "subject-1", "b@example.com")))

		got, err := s.GetAccountByProvider(ctx(), "google", "subject-1")
		requireNoError(t, "GetAccountByProvider", err)
		if got.UserID != id(1) {
			// Two providers can hand out the same subject string. Keying
			// on the subject alone would sign the wrong person in.
			t.Fatalf("got user %q, want %q: the provider must be part of the key", got.UserID, id(1))
		}
	})

	t.Run("a provider subject links to at most one user", func(t *testing.T) {
		// The UNIQUE constraint on (provider, provider_account_id). A
		// second link for the same subject does not shadow the first --
		// it is refused. Without this, the query above becomes a coin
		// flip between two users, which is an account takeover.
		s := newStore(t)
		fx.ensureUser(t, id(1), id(2))
		requireNoError(t, "create", s.CreateAccount(ctx(), mk(id(41), id(1), "google", "subject-1", "a@example.com")))
		err := s.CreateAccount(ctx(), mk(id(42), id(2), "google", "subject-1", "attacker@example.com"))
		if err == nil {
			t.Fatal("a duplicate (provider, subject) must be refused; add a UNIQUE constraint")
		}
	})

	t.Run("one user may link several providers", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1))
		requireNoError(t, "create", s.CreateAccount(ctx(), mk(id(41), id(1), "google", "g-1", "a@example.com")))
		requireNoError(t, "create", s.CreateAccount(ctx(), mk(id(42), id(1), "github", "gh-1", "a@example.com")))

		list, err := s.ListAccountsByUser(ctx(), id(1))
		requireNoError(t, "ListAccountsByUser", err)
		if len(list) != 2 {
			t.Fatalf("listed %d accounts, want 2", len(list))
		}
	})

	t.Run("scopes and encrypted tokens round trip", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1))
		a := mk(id(41), id(1), "google", "g-1", "a@example.com")
		a.AccessTokenEncrypted = []byte{0x00, 0x01, 0xff, 0x7f}
		a.RefreshTokenEncrypted = []byte{0xde, 0xad}
		a.TokenExpiresAt = ptr(time.Now().Add(time.Hour))
		requireNoError(t, "create", s.CreateAccount(ctx(), a))

		got, err := s.GetAccount(ctx(), id(41))
		requireNoError(t, "GetAccount", err)
		if !slices.Equal(got.Scopes, []string{"openid", "email"}) {
			t.Fatalf("Scopes = %v", got.Scopes)
		}
		// Ciphertext, so it must survive byte for byte -- including the
		// zero byte, which a column typed as text will silently mangle.
		if !slices.Equal(got.AccessTokenEncrypted, a.AccessTokenEncrypted) {
			t.Fatalf("AccessTokenEncrypted = %v, want %v: store it as bytes, not text", got.AccessTokenEncrypted, a.AccessTokenEncrypted)
		}
		if got.TokenExpiresAt == nil {
			t.Fatal("TokenExpiresAt did not persist")
		}
	})

	t.Run("update and delete", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1))
		a := mk(id(41), id(1), "google", "g-1", "old@example.com")
		requireNoError(t, "create", s.CreateAccount(ctx(), a))

		a.Email = "new@example.com"
		a.EmailVerified = false
		requireNoError(t, "UpdateAccount", s.UpdateAccount(ctx(), a))
		got, err := s.GetAccount(ctx(), id(41))
		requireNoError(t, "GetAccount", err)
		if got.Email != "new@example.com" || got.EmailVerified {
			t.Fatalf("update did not persist: %+v", got)
		}

		requireNoError(t, "DeleteAccount", s.DeleteAccount(ctx(), id(41)))
		_, err = s.GetAccount(ctx(), id(41))
		requireNotFound(t, "GetAccount after delete", err)
		// Unlinking must free the subject, so the same provider identity
		// can be linked again -- to this user or another.
		_, err = s.GetAccountByProvider(ctx(), "google", "g-1")
		requireNotFound(t, "GetAccountByProvider after delete", err)
	})
}

// RunWebAuthnCredentialStore checks store.WebAuthnCredentialStore.
func RunWebAuthnCredentialStore(t *testing.T, newStore func(*testing.T) store.WebAuthnCredentialStore, fx Fixtures) {
	// Deliberately not valid UTF-8, and containing a zero byte: the blob
	// and the credential id are binary, and a column typed as text will
	// mangle both.
	blob := []byte{0x00, 0x7b, 0xff, 0xfe, 0x22, 0x7d}
	mk := func(rowID, userID string, credID []byte) *store.WebAuthnCredential {
		return &store.WebAuthnCredential{
			ID: rowID, UserID: userID, CredentialID: credID, Data: blob,
			Name: "Test Key", Transports: []string{"internal", "hybrid"},
			BackupEligible: true, BackupState: true,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}
	}

	t.Run("missing rows report ErrNotFound", func(t *testing.T) {
		s := newStore(t)
		_, err := s.GetWebAuthnCredential(ctx(), id(99))
		requireNotFound(t, "GetWebAuthnCredential", err)
		_, err = s.GetWebAuthnCredentialByCredentialID(ctx(), []byte("no-such-credential"))
		requireNotFound(t, "GetWebAuthnCredentialByCredentialID", err)
	})

	t.Run("binary fields round trip exactly", func(t *testing.T) {
		// Data is the authoritative credential record: the public key a
		// signature is checked against lives in it. A byte lost here is
		// every future login for that authenticator failing.
		s := newStore(t)
		fx.ensureUser(t, id(1))
		credID := []byte{0x00, 0x01, 0xff, 0x80, 0x7f}
		requireNoError(t, "create", s.CreateWebAuthnCredential(ctx(), mk(id(41), id(1), credID)))

		got, err := s.GetWebAuthnCredentialByCredentialID(ctx(), credID)
		requireNoError(t, "GetWebAuthnCredentialByCredentialID", err)
		if !slices.Equal(got.Data, blob) {
			t.Fatalf("Data = %v, want %v: store it as bytes, not text", got.Data, blob)
		}
		if !slices.Equal(got.CredentialID, credID) {
			t.Fatalf("CredentialID = %v, want %v", got.CredentialID, credID)
		}
		if !slices.Equal(got.Transports, []string{"internal", "hybrid"}) {
			t.Fatalf("Transports = %v", got.Transports)
		}
		if !got.BackupEligible || !got.BackupState {
			t.Fatalf("backup flags did not round trip: %+v", got)
		}
	})

	t.Run("a credential id belongs to at most one row", func(t *testing.T) {
		// The UNIQUE constraint. This lookup is the only thing deciding
		// whose credential just signed the challenge, so a duplicate makes
		// it a coin flip between two accounts.
		s := newStore(t)
		fx.ensureUser(t, id(1), id(2))
		credID := []byte{0x01, 0x02, 0x03}
		requireNoError(t, "create", s.CreateWebAuthnCredential(ctx(), mk(id(41), id(1), credID)))
		if err := s.CreateWebAuthnCredential(ctx(), mk(id(42), id(2), credID)); err == nil {
			t.Fatal("a duplicate credential id must be refused; add a UNIQUE constraint")
		}
	})

	t.Run("listing is scoped to one user", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1), id(2))
		requireNoError(t, "create", s.CreateWebAuthnCredential(ctx(), mk(id(41), id(1), []byte{1})))
		requireNoError(t, "create", s.CreateWebAuthnCredential(ctx(), mk(id(42), id(1), []byte{2})))
		requireNoError(t, "create", s.CreateWebAuthnCredential(ctx(), mk(id(43), id(2), []byte{3})))

		list, err := s.ListWebAuthnCredentialsByUser(ctx(), id(1))
		requireNoError(t, "ListWebAuthnCredentialsByUser", err)
		if len(list) != 2 {
			t.Fatalf("listed %d credentials, want 2", len(list))
		}
	})

	t.Run("sign count and clone warning persist", func(t *testing.T) {
		// The updated blob carries the new signature counter, and the
		// clone flag is what a compromised-credential query finds. An
		// update that does not stick means the counter never advances in
		// storage, so every subsequent login looks like a regression --
		// or, worse, a real regression never gets recorded.
		s := newStore(t)
		fx.ensureUser(t, id(1))
		c := mk(id(41), id(1), []byte{1})
		requireNoError(t, "create", s.CreateWebAuthnCredential(ctx(), c))

		used := time.Now()
		c.Data = []byte{0x09, 0x08, 0x00, 0x07}
		c.CloneWarning = true
		c.LastUsedAt = &used
		requireNoError(t, "UpdateWebAuthnCredential", s.UpdateWebAuthnCredential(ctx(), c))

		got, err := s.GetWebAuthnCredential(ctx(), id(41))
		requireNoError(t, "GetWebAuthnCredential", err)
		if !slices.Equal(got.Data, []byte{0x09, 0x08, 0x00, 0x07}) {
			t.Fatalf("the updated credential record did not persist: %v", got.Data)
		}
		if !got.CloneWarning {
			t.Fatal("CloneWarning did not persist; it is the only durable trace of a cloned authenticator")
		}
		if got.LastUsedAt == nil {
			t.Fatal("LastUsedAt did not persist")
		}
	})

	t.Run("delete frees the credential id", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1))
		credID := []byte{0x01, 0x02}
		requireNoError(t, "create", s.CreateWebAuthnCredential(ctx(), mk(id(41), id(1), credID)))
		requireNoError(t, "delete", s.DeleteWebAuthnCredential(ctx(), id(41)))

		_, err := s.GetWebAuthnCredential(ctx(), id(41))
		requireNotFound(t, "GetWebAuthnCredential after delete", err)
		// A revoked authenticator must be registerable again -- somebody
		// who removed a key by mistake should be able to add it back.
		_, err = s.GetWebAuthnCredentialByCredentialID(ctx(), credID)
		requireNotFound(t, "GetWebAuthnCredentialByCredentialID after delete", err)
	})
}

// RunWebAuthnChallengeStore checks store.WebAuthnChallengeStore.
//
// The suite is short because the port is, and one case carries most of the
// weight: consuming a challenge must be atomic. Everything else here would
// pass against a map with a Get and a Delete bolted together, and that
// implementation is exactly the one that lets a captured assertion be
// replayed.
func RunWebAuthnChallengeStore(t *testing.T, newStore func(*testing.T) store.WebAuthnChallengeStore, fx Fixtures) {
	// Binary, not UTF-8, with a zero byte: the ceremony state is a blob
	// and a text column will mangle it.
	blob := []byte{0x00, 0x7b, 0xff, 0xfe, 0x22, 0x7d}
	mk := func(rowID, hash string, userID *string, expires time.Time) *store.WebAuthnChallenge {
		return &store.WebAuthnChallenge{
			ID: rowID, TokenHash: hash, UserID: userID, Data: blob,
			ExpiresAt: expires, CreatedAt: time.Now(),
		}
	}

	t.Run("create then consume returns the row", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1))
		user := id(1)
		rec := mk(id(41), "hash-a", &user, time.Now().Add(time.Minute))
		requireNoError(t, "CreateWebAuthnChallenge", s.CreateWebAuthnChallenge(ctx(), rec))
		// The store may assign the id -- schema.sql defaults it to
		// gen_random_uuid(), and Create writes the stored row back over
		// the caller's. So rec.ID after this call is the authoritative
		// one, and a suite that compares against the id it passed in is
		// asserting a promise the port does not make.
		if rec.ID == "" {
			t.Fatal("Create must leave the stored id on the struct")
		}

		got, err := s.ConsumeWebAuthnChallenge(ctx(), "hash-a")
		requireNoError(t, "ConsumeWebAuthnChallenge", err)
		if !bytes.Equal(got.Data, blob) {
			t.Fatalf("Data did not round trip: %#v", got.Data)
		}
		if got.UserID == nil || *got.UserID != user {
			t.Fatalf("UserID did not round trip: %v", got.UserID)
		}
	})

	t.Run("a consumed challenge is gone", func(t *testing.T) {
		s := newStore(t)
		requireNoError(t, "CreateWebAuthnChallenge", s.CreateWebAuthnChallenge(ctx(),
			mk(id(41), "hash-a", nil, time.Now().Add(time.Minute))))
		_, err := s.ConsumeWebAuthnChallenge(ctx(), "hash-a")
		requireNoError(t, "first consume", err)

		_, err = s.ConsumeWebAuthnChallenge(ctx(), "hash-a")
		requireNotFound(t, "second consume", err)
	})

	t.Run("an unknown handle is ErrNotFound", func(t *testing.T) {
		s := newStore(t)
		_, err := s.ConsumeWebAuthnChallenge(ctx(), "never-existed")
		requireNotFound(t, "ConsumeWebAuthnChallenge", err)
	})

	t.Run("consuming one leaves the others", func(t *testing.T) {
		s := newStore(t)
		a := mk(id(41), "hash-a", nil, time.Now().Add(time.Minute))
		b := mk(id(42), "hash-b", nil, time.Now().Add(time.Minute))
		requireNoError(t, "create a", s.CreateWebAuthnChallenge(ctx(), a))
		requireNoError(t, "create b", s.CreateWebAuthnChallenge(ctx(), b))

		_, err := s.ConsumeWebAuthnChallenge(ctx(), "hash-a")
		requireNoError(t, "consume a", err)
		got, err := s.ConsumeWebAuthnChallenge(ctx(), "hash-b")
		requireNoError(t, "consume b", err)
		if got.ID != b.ID {
			t.Fatalf("consumed %s, want b (%s)", got.ID, b.ID)
		}
	})

	t.Run("an expired challenge is still returned", func(t *testing.T) {
		// Expiry is the caller's judgement, not the store's. Filtering it
		// here would leave the row behind on the one path that most wants
		// it gone, and would make "consumed" and "expired" different
		// states for a thing that has only one.
		s := newStore(t)
		rec := mk(id(41), "hash-a", nil, time.Now().Add(-time.Hour))
		requireNoError(t, "CreateWebAuthnChallenge", s.CreateWebAuthnChallenge(ctx(), rec))
		got, err := s.ConsumeWebAuthnChallenge(ctx(), "hash-a")
		requireNoError(t, "ConsumeWebAuthnChallenge", err)
		if got.ID != rec.ID {
			t.Fatalf("got %s, want %s", got.ID, rec.ID)
		}
	})

	t.Run("concurrent consumers: exactly one wins", func(t *testing.T) {
		// The case the port exists for. A Get followed by a Delete passes
		// every other test in this suite and fails this one, because two
		// callers can both read before either deletes -- and both then
		// finish the same ceremony, which is a replayed assertion
		// accepted twice.
		//
		// Repeated, and with more racers than cores, because one round is
		// not enough to catch it. The window between a read and a delete
		// is nanoseconds, so a single round of eight goroutines lets a
		// wrong implementation through most of the time -- measured, not
		// assumed: the first version of this test ran one round and passed
		// against a deliberately non-atomic store. Rounds are cheap and a
		// false pass here is the one that matters.
		const (
			racers = 32
			rounds = 200
		)
		s := newStore(t)
		for round := range rounds {
			hash := fmt.Sprintf("hash-%d", round)
			rec := mk(id(41), hash, nil, time.Now().Add(time.Minute))
			requireNoError(t, "CreateWebAuthnChallenge", s.CreateWebAuthnChallenge(ctx(), rec))

			var start sync.WaitGroup
			var done sync.WaitGroup
			start.Add(1)
			results := make([]error, racers)
			rows := make([]*store.WebAuthnChallenge, racers)
			for i := range racers {
				done.Add(1)
				go func() {
					defer done.Done()
					start.Wait()
					rows[i], results[i] = s.ConsumeWebAuthnChallenge(ctx(), hash)
				}()
			}
			start.Done()
			done.Wait()

			won := 0
			for i, err := range results {
				switch {
				case err == nil:
					won++
					if rows[i] == nil || rows[i].ID != rec.ID {
						t.Fatalf("winner %d got %v, want the row just created (%s)", i, rows[i], rec.ID)
					}
				case errors.Is(err, store.ErrNotFound):
				default:
					t.Fatalf("consumer %d: unexpected error %v", i, err)
				}
			}
			if won != 1 {
				t.Fatalf("round %d: %d of %d consumers got the challenge, want exactly 1; "+
					"consuming must delete and return in one step", round, won, racers)
			}
		}
	})
}
