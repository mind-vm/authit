package storetest

import (
	"testing"
	"time"

	"github.com/mind-vm/authit/store"
)

// RunUserStore checks store.UserStore.
func RunUserStore(t *testing.T, newStore func(*testing.T) store.UserStore, fx Fixtures) {
	t.Run("missing rows report ErrNotFound", func(t *testing.T) {
		s := newStore(t)
		_, err := s.GetUserByID(ctx(), id(99))
		requireNotFound(t, "GetUserByID", err)
		_, err = s.GetUserByEmail(ctx(), "nobody@example.com")
		requireNotFound(t, "GetUserByEmail", err)
	})

	t.Run("create then read back", func(t *testing.T) {
		s := newStore(t)
		now := time.Now()
		u := &store.User{
			ID: id(1), Email: "alice@example.com", PasswordHash: "$argon2id$fake",
			CreatedAt: now, UpdatedAt: now,
		}
		requireNoError(t, "CreateUser", s.CreateUser(ctx(), u))
		// After Create, the value must carry the id a later Get will find.
		// An adapter whose table generates the id has to write it back, or
		// the caller holds a row it cannot look up again.
		if u.ID == "" {
			t.Fatal("CreateUser must leave the user's ID populated")
		}

		got, err := s.GetUserByID(ctx(), u.ID)
		requireNoError(t, "GetUserByID", err)
		if got.Email != "alice@example.com" || got.PasswordHash != "$argon2id$fake" {
			t.Fatalf("round trip lost data: %+v", got)
		}
		timeNear(t, "CreatedAt", got.CreatedAt, now)

		byEmail, err := s.GetUserByEmail(ctx(), "alice@example.com")
		requireNoError(t, "GetUserByEmail", err)
		if byEmail.ID != u.ID {
			t.Fatalf("GetUserByEmail returned %q, want %q", byEmail.ID, u.ID)
		}
	})

	t.Run("email is stored verbatim", func(t *testing.T) {
		// authit normalises every address before it reaches a store (see
		// store.NormalizeEmail), so a store may compare however it likes —
		// but it must not rewrite what it was given. A store that upper-cases
		// or trims differently would return an address the service then
		// re-normalises into something that no longer matches.
		s := newStore(t)
		u := &store.User{ID: id(1), Email: "a.b+tag@example.com", PasswordHash: "h"}
		requireNoError(t, "CreateUser", s.CreateUser(ctx(), u))
		got, err := s.GetUserByEmail(ctx(), "a.b+tag@example.com")
		requireNoError(t, "GetUserByEmail", err)
		if got.Email != "a.b+tag@example.com" {
			t.Fatalf("email came back as %q; dots and +tags must survive", got.Email)
		}
	})

	t.Run("update persists", func(t *testing.T) {
		s := newStore(t)
		u := &store.User{ID: id(1), Email: "alice@example.com", PasswordHash: "old"}
		requireNoError(t, "CreateUser", s.CreateUser(ctx(), u))

		u.PasswordHash = "new"
		u.EmailVerified = true
		u.EmailVerifiedAt = ptr(time.Now())
		requireNoError(t, "UpdateUser", s.UpdateUser(ctx(), u))

		got, err := s.GetUserByID(ctx(), u.ID)
		requireNoError(t, "GetUserByID", err)
		if got.PasswordHash != "new" {
			// Rehash-on-login writes through this path; if it silently does
			// nothing, an upgraded corpus never actually upgrades.
			t.Fatalf("PasswordHash = %q, want the updated value", got.PasswordHash)
		}
		if !got.EmailVerified || got.EmailVerifiedAt == nil {
			t.Fatalf("verification state did not persist: %+v", got)
		}
	})
}

// RunRefreshTokenStore checks store.RefreshTokenStore.
func RunRefreshTokenStore(t *testing.T, newStore func(*testing.T) store.RefreshTokenStore, fx Fixtures) {
	mk := func(rowID, userID, hash string, expires time.Time) *store.RefreshToken {
		return &store.RefreshToken{
			ID: rowID, UserID: userID, TokenHash: hash,
			ExpiresAt: expires, CreatedAt: time.Now(),
		}
	}

	t.Run("missing rows report ErrNotFound", func(t *testing.T) {
		s := newStore(t)
		_, err := s.GetRefreshTokenByHash(ctx(), "no-such-hash")
		requireNotFound(t, "GetRefreshTokenByHash", err)
	})

	t.Run("revoked tokens are still returned by hash", func(t *testing.T) {
		// This one is load-bearing and easy to get wrong. It is tempting to
		// have the lookup filter out revoked rows, since callers mostly
		// want live tokens — but Refresh detects a stolen token by finding
		// a *revoked* one and reacting. A store that hides them turns
		// reuse detection off silently: replaying a stolen refresh token
		// would look exactly like an unknown one, and the user's other
		// sessions would never be revoked.
		s := newStore(t)
		fx.ensureUser(t, id(1))
		rt := mk(id(31), id(1), "hash1", time.Now().Add(time.Hour))
		requireNoError(t, "CreateRefreshToken", s.CreateRefreshToken(ctx(), rt))
		requireNoError(t, "RevokeRefreshToken", s.RevokeRefreshToken(ctx(), rt.ID))

		got, err := s.GetRefreshTokenByHash(ctx(), "hash1")
		requireNoError(t, "GetRefreshTokenByHash after revoke", err)
		if got.RevokedAt == nil {
			t.Fatal("RevokeRefreshToken must set RevokedAt")
		}
	})

	t.Run("ListActiveRefreshTokens excludes revoked and expired", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1), id(2))
		live := mk(id(31), id(1), "h1", time.Now().Add(time.Hour))
		revoked := mk(id(32), id(1), "h2", time.Now().Add(time.Hour))
		expired := mk(id(33), id(1), "h3", time.Now().Add(-time.Hour))
		other := mk(id(34), id(2), "h4", time.Now().Add(time.Hour))
		for _, rt := range []*store.RefreshToken{live, revoked, expired, other} {
			requireNoError(t, "CreateRefreshToken", s.CreateRefreshToken(ctx(), rt))
		}
		requireNoError(t, "RevokeRefreshToken", s.RevokeRefreshToken(ctx(), revoked.ID))

		list, err := s.ListActiveRefreshTokens(ctx(), id(1))
		requireNoError(t, "ListActiveRefreshTokens", err)
		if len(list) != 1 || list[0].ID != live.ID {
			ids := make([]string, len(list))
			for i, rt := range list {
				ids[i] = rt.ID
			}
			t.Fatalf("active sessions = %v, want only %q (this is what a user sees on their sessions page)", ids, live.ID)
		}
	})

	t.Run("RevokeAllUserRefreshTokens is scoped to one user", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1), id(2))
		mine := mk(id(31), id(1), "h1", time.Now().Add(time.Hour))
		theirs := mk(id(32), id(2), "h2", time.Now().Add(time.Hour))
		requireNoError(t, "CreateRefreshToken", s.CreateRefreshToken(ctx(), mine))
		requireNoError(t, "CreateRefreshToken", s.CreateRefreshToken(ctx(), theirs))

		requireNoError(t, "RevokeAllUserRefreshTokens", s.RevokeAllUserRefreshTokens(ctx(), id(1)))

		got, err := s.GetRefreshTokenByHash(ctx(), "h1")
		requireNoError(t, "GetRefreshTokenByHash", err)
		if got.RevokedAt == nil {
			t.Fatal("the target user's token should be revoked")
		}
		got, err = s.GetRefreshTokenByHash(ctx(), "h2")
		requireNoError(t, "GetRefreshTokenByHash", err)
		if got.RevokedAt != nil {
			t.Fatal("another user's token must not be revoked; reuse detection calls this on one principal")
		}
	})

	t.Run("revocation is idempotent", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1))
		rt := mk(id(31), id(1), "h1", time.Now().Add(time.Hour))
		requireNoError(t, "CreateRefreshToken", s.CreateRefreshToken(ctx(), rt))
		requireNoError(t, "RevokeRefreshToken", s.RevokeRefreshToken(ctx(), rt.ID))
		// Logout is documented as idempotent, and reuse detection may
		// revoke an already-revoked token.
		requireNoError(t, "RevokeRefreshToken twice", s.RevokeRefreshToken(ctx(), rt.ID))
	})
}

// RunPasswordResetStore checks store.PasswordResetStore.
func RunPasswordResetStore(t *testing.T, newStore func(*testing.T) store.PasswordResetStore, fx Fixtures) {
	t.Run("missing rows report ErrNotFound", func(t *testing.T) {
		s := newStore(t)
		_, err := s.GetPasswordResetTokenByHash(ctx(), "nope")
		requireNotFound(t, "GetPasswordResetTokenByHash", err)
	})

	t.Run("used tokens are still returned", func(t *testing.T) {
		// Same shape as revoked refresh tokens: the service decides what a
		// used token means by reading UsedAt. A store that hides them makes
		// "already used" indistinguishable from "never existed", which
		// costs the user a comprehensible error message.
		s := newStore(t)
		fx.ensureUser(t, id(1))
		tok := &store.PasswordResetToken{
			ID: id(41), UserID: id(1), TokenHash: "h1",
			ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
		}
		requireNoError(t, "CreatePasswordResetToken", s.CreatePasswordResetToken(ctx(), tok))
		requireNoError(t, "MarkPasswordResetTokenUsed", s.MarkPasswordResetTokenUsed(ctx(), tok.ID))

		got, err := s.GetPasswordResetTokenByHash(ctx(), "h1")
		requireNoError(t, "GetPasswordResetTokenByHash after use", err)
		if got.UsedAt == nil {
			t.Fatal("MarkPasswordResetTokenUsed must set UsedAt")
		}
	})

	t.Run("DeleteUserPasswordResetTokens is scoped to one user", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1), id(2))
		mine := &store.PasswordResetToken{ID: id(41), UserID: id(1), TokenHash: "h1", ExpiresAt: time.Now().Add(time.Hour)}
		theirs := &store.PasswordResetToken{ID: id(42), UserID: id(2), TokenHash: "h2", ExpiresAt: time.Now().Add(time.Hour)}
		requireNoError(t, "create", s.CreatePasswordResetToken(ctx(), mine))
		requireNoError(t, "create", s.CreatePasswordResetToken(ctx(), theirs))

		requireNoError(t, "DeleteUserPasswordResetTokens", s.DeleteUserPasswordResetTokens(ctx(), id(1)))
		_, err := s.GetPasswordResetTokenByHash(ctx(), "h1")
		requireNotFound(t, "the deleted user's token", err)
		if _, err := s.GetPasswordResetTokenByHash(ctx(), "h2"); err != nil {
			t.Fatalf("another user's reset token must survive: %v", err)
		}
	})
}

// RunEmailVerificationStore checks store.EmailVerificationStore.
func RunEmailVerificationStore(t *testing.T, newStore func(*testing.T) store.EmailVerificationStore, fx Fixtures) {
	t.Run("missing rows report ErrNotFound", func(t *testing.T) {
		s := newStore(t)
		_, err := s.GetEmailVerificationTokenByHash(ctx(), "nope")
		requireNotFound(t, "GetEmailVerificationTokenByHash", err)
	})

	t.Run("used tokens are still returned", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1))
		tok := &store.EmailVerificationToken{
			ID: id(51), UserID: id(1), TokenHash: "h1",
			ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
		}
		requireNoError(t, "create", s.CreateEmailVerificationToken(ctx(), tok))
		requireNoError(t, "mark used", s.MarkEmailVerificationTokenUsed(ctx(), tok.ID))
		got, err := s.GetEmailVerificationTokenByHash(ctx(), "h1")
		requireNoError(t, "get after use", err)
		if got.UsedAt == nil {
			t.Fatal("MarkEmailVerificationTokenUsed must set UsedAt")
		}
	})

	t.Run("DeleteUserEmailVerificationTokens is scoped to one user", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1), id(2))
		mine := &store.EmailVerificationToken{ID: id(51), UserID: id(1), TokenHash: "h1", ExpiresAt: time.Now().Add(time.Hour)}
		theirs := &store.EmailVerificationToken{ID: id(52), UserID: id(2), TokenHash: "h2", ExpiresAt: time.Now().Add(time.Hour)}
		requireNoError(t, "create", s.CreateEmailVerificationToken(ctx(), mine))
		requireNoError(t, "create", s.CreateEmailVerificationToken(ctx(), theirs))
		requireNoError(t, "delete", s.DeleteUserEmailVerificationTokens(ctx(), id(1)))
		_, err := s.GetEmailVerificationTokenByHash(ctx(), "h1")
		requireNotFound(t, "the deleted user's token", err)
		if _, err := s.GetEmailVerificationTokenByHash(ctx(), "h2"); err != nil {
			t.Fatalf("another user's verification token must survive: %v", err)
		}
	})
}
