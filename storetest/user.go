package storetest

import (
	"errors"
	"fmt"
	"sync"
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

	t.Run("touching extends a live token", func(t *testing.T) {
		s := newStore(t)
		fx.ensureUser(t, id(1))
		rt := mk(id(31), id(1), "h1", time.Now().Add(time.Hour))
		requireNoError(t, "CreateRefreshToken", s.CreateRefreshToken(ctx(), rt))

		want := time.Now().Add(48 * time.Hour)
		requireNoError(t, "TouchRefreshToken", s.TouchRefreshToken(ctx(), rt.ID, want))
		got, err := s.GetRefreshTokenByHash(ctx(), "h1")
		requireNoError(t, "GetRefreshTokenByHash", err)
		if !got.ExpiresAt.After(time.Now().Add(24 * time.Hour)) {
			t.Fatalf("ExpiresAt = %v, want it moved out to roughly %v", got.ExpiresAt, want)
		}
	})

	t.Run("touching a revoked token is refused", func(t *testing.T) {
		// The sliding expiry of user.SessionModeOpaque reads a session and
		// then extends it. Without this check a session revoked between
		// those two steps comes back with a fresh lifetime -- revocation
		// undone by the request it was racing.
		s := newStore(t)
		fx.ensureUser(t, id(1))
		rt := mk(id(31), id(1), "h1", time.Now().Add(time.Hour))
		requireNoError(t, "CreateRefreshToken", s.CreateRefreshToken(ctx(), rt))
		requireNoError(t, "RevokeRefreshToken", s.RevokeRefreshToken(ctx(), rt.ID))

		err := s.TouchRefreshToken(ctx(), rt.ID, time.Now().Add(48*time.Hour))
		requireNotFound(t, "TouchRefreshToken on a revoked token", err)
	})

	t.Run("touching a missing token is refused", func(t *testing.T) {
		s := newStore(t)
		err := s.TouchRefreshToken(ctx(), id(99), time.Now().Add(time.Hour))
		requireNotFound(t, "TouchRefreshToken", err)
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

// RunEmailLoginStore checks store.EmailLoginStore.
func RunEmailLoginStore(t *testing.T, newStore func(*testing.T) store.EmailLoginStore, fx Fixtures) {
	mk := func(rowID, email, hash string, kind store.EmailLoginKind, ttl time.Duration) *store.EmailLoginToken {
		return &store.EmailLoginToken{
			ID: rowID, Email: email, Kind: kind, TokenHash: hash,
			ExpiresAt: time.Now().Add(ttl), CreatedAt: time.Now(),
		}
	}

	t.Run("missing rows report ErrNotFound", func(t *testing.T) {
		s := newStore(t)
		_, err := s.GetEmailLoginTokenByHash(ctx(), "no-such-hash")
		requireNotFound(t, "GetEmailLoginTokenByHash", err)
		_, err = s.GetEmailLoginTokenByEmail(ctx(), "nobody@example.com", store.EmailLoginCode)
		requireNotFound(t, "GetEmailLoginTokenByEmail", err)
	})

	t.Run("lookup by email is scoped to the kind", func(t *testing.T) {
		// The kinds are separated because the code path counts guesses and
		// the link path does not. A lookup that ignored the kind could
		// hand a low-entropy code to the path with no attempt limit.
		s := newStore(t)
		requireNoError(t, "create", s.CreateEmailLoginToken(ctx(), mk(id(51), "a@example.com", "h-link", store.EmailLoginLink, time.Hour)))
		requireNoError(t, "create", s.CreateEmailLoginToken(ctx(), mk(id(52), "a@example.com", "h-code", store.EmailLoginCode, time.Hour)))

		got, err := s.GetEmailLoginTokenByEmail(ctx(), "a@example.com", store.EmailLoginCode)
		requireNoError(t, "GetEmailLoginTokenByEmail", err)
		if got.Kind != store.EmailLoginCode || got.TokenHash != "h-code" {
			t.Fatalf("got %+v, want the code token", got)
		}
	})

	t.Run("lookup by email is scoped to the address", func(t *testing.T) {
		s := newStore(t)
		requireNoError(t, "create", s.CreateEmailLoginToken(ctx(), mk(id(51), "a@example.com", "h-a", store.EmailLoginCode, time.Hour)))
		requireNoError(t, "create", s.CreateEmailLoginToken(ctx(), mk(id(52), "b@example.com", "h-b", store.EmailLoginCode, time.Hour)))

		got, err := s.GetEmailLoginTokenByEmail(ctx(), "b@example.com", store.EmailLoginCode)
		requireNoError(t, "GetEmailLoginTokenByEmail", err)
		if got.TokenHash != "h-b" {
			t.Fatalf("got %q, want b's token: a code must never resolve for another address", got.TokenHash)
		}
	})

	t.Run("attempt counts persist and come back from the store", func(t *testing.T) {
		// A six-digit code survives only because wrong guesses are
		// counted. An increment that does not stick means the counter is
		// always zero and the code is guessable without limit -- and a
		// returned count that was computed anywhere but in the store is
		// the same bug wearing a different hat.
		s := newStore(t)
		tok := mk(id(51), "a@example.com", "h", store.EmailLoginCode, time.Hour)
		requireNoError(t, "create", s.CreateEmailLoginToken(ctx(), tok))

		for want := 1; want <= 3; want++ {
			got, err := s.IncrementEmailLoginTokenAttempts(ctx(), id(51))
			requireNoError(t, "IncrementEmailLoginTokenAttempts", err)
			if got != want {
				t.Fatalf("increment returned %d, want %d", got, want)
			}
		}
		got, err := s.GetEmailLoginTokenByEmail(ctx(), "a@example.com", store.EmailLoginCode)
		requireNoError(t, "GetEmailLoginTokenByEmail", err)
		if got.Attempts != 3 {
			t.Fatalf("Attempts = %d, want 3; without this the guess limit does nothing", got.Attempts)
		}
	})

	t.Run("incrementing a token that is gone reports ErrNotFound", func(t *testing.T) {
		s := newStore(t)
		_, err := s.IncrementEmailLoginTokenAttempts(ctx(), id(99))
		requireNotFound(t, "IncrementEmailLoginTokenAttempts", err)
	})

	t.Run("marking used is a compare-and-set", func(t *testing.T) {
		// The single-use property lives here and nowhere else. A store
		// that marks used unconditionally lets two redemptions of one
		// magic link both succeed -- one credential, two sessions.
		s := newStore(t)
		tok := mk(id(51), "a@example.com", "h", store.EmailLoginLink, time.Hour)
		requireNoError(t, "create", s.CreateEmailLoginToken(ctx(), tok))

		requireNoError(t, "first mark", s.MarkEmailLoginTokenUsed(ctx(), id(51), time.Now()))
		requireNotFound(t, "second mark", s.MarkEmailLoginTokenUsed(ctx(), id(51), time.Now()))

		// Still readable afterwards: the service reads UsedAt, and the row
		// is evidence for an operator either way.
		got, err := s.GetEmailLoginTokenByHash(ctx(), "h")
		requireNoError(t, "GetEmailLoginTokenByHash after use", err)
		if got.UsedAt == nil {
			t.Fatal("UsedAt did not persist; the service reads it to enforce single use")
		}
	})

	t.Run("marking used is atomic: exactly one redemption wins", func(t *testing.T) {
		// Sequential compare-and-set is easy to satisfy by reading and
		// then writing, which is exactly the implementation that fails
		// under concurrency.
		//
		// Repeated, because one round is not enough. A store that reads,
		// releases its lock, and then writes was measured letting a second
		// redemption through in only about a fifth of rounds -- so a
		// single round passes it four times in five, which is worse than
		// having no test at all. Rounds are cheap; a false pass here is a
		// magic link that signs two people in.
		const (
			racers = 32
			rounds = 200
		)
		s := newStore(t)
		for round := range rounds {
			rowID := fmt.Sprintf("%s-%d", id(51), round)
			requireNoError(t, "create", s.CreateEmailLoginToken(ctx(),
				mk(rowID, "a@example.com", fmt.Sprintf("h-%d", round), store.EmailLoginLink, time.Hour)))

			var start, done sync.WaitGroup
			start.Add(1)
			results := make([]error, racers)
			for i := range racers {
				done.Add(1)
				go func() {
					defer done.Done()
					start.Wait()
					results[i] = s.MarkEmailLoginTokenUsed(ctx(), rowID, time.Now())
				}()
			}
			start.Done()
			done.Wait()

			won := 0
			for i, err := range results {
				switch {
				case err == nil:
					won++
				case errors.Is(err, store.ErrNotFound):
				default:
					t.Fatalf("redeemer %d: unexpected error %v", i, err)
				}
			}
			if won != 1 {
				t.Fatalf("round %d: %d of %d redemptions succeeded, want exactly 1; "+
					"marking used must be a compare-and-set, not a read then a write", round, won, racers)
			}
		}
	})

	t.Run("attempts are not lost when guesses arrive together", func(t *testing.T) {
		// Read-then-write loses increments under concurrency, so an
		// attacker guessing in parallel has many tries charged as one --
		// the entire budget MaxCodeAttempts exists to impose. Repeated for
		// the same reason as the case above.
		const (
			racers = 32
			rounds = 50
		)
		s := newStore(t)
		for round := range rounds {
			rowID := fmt.Sprintf("%s-%d", id(51), round)
			email := fmt.Sprintf("a%d@example.com", round)
			requireNoError(t, "create", s.CreateEmailLoginToken(ctx(),
				mk(rowID, email, fmt.Sprintf("h-%d", round), store.EmailLoginCode, time.Hour)))

			var start, done sync.WaitGroup
			start.Add(1)
			seen := make([]int, racers)
			for i := range racers {
				done.Add(1)
				go func() {
					defer done.Done()
					start.Wait()
					if n, err := s.IncrementEmailLoginTokenAttempts(ctx(), rowID); err == nil {
						seen[i] = n
					}
				}()
			}
			start.Done()
			done.Wait()

			got, err := s.GetEmailLoginTokenByEmail(ctx(), email, store.EmailLoginCode)
			requireNoError(t, "GetEmailLoginTokenByEmail", err)
			if got.Attempts != racers {
				t.Fatalf("round %d: Attempts = %d after %d concurrent guesses; increments must not be lost",
					round, got.Attempts, racers)
			}
			// Every caller must also have been told a distinct number, or
			// two guesses shared a budget slot.
			distinct := map[int]bool{}
			for _, n := range seen {
				if n != 0 && distinct[n] {
					t.Fatalf("round %d: two callers were both told attempt %d; "+
						"each guess must get its own count", round, n)
				}
				distinct[n] = true
			}
		}
	})

	t.Run("delete is scoped to one address and kind", func(t *testing.T) {
		// Requesting a new credential deletes the old one, so that two
		// live codes never halve the work of guessing. It must not take
		// anybody else's with it.
		s := newStore(t)
		requireNoError(t, "create", s.CreateEmailLoginToken(ctx(), mk(id(51), "a@example.com", "h-a-code", store.EmailLoginCode, time.Hour)))
		requireNoError(t, "create", s.CreateEmailLoginToken(ctx(), mk(id(52), "a@example.com", "h-a-link", store.EmailLoginLink, time.Hour)))
		requireNoError(t, "create", s.CreateEmailLoginToken(ctx(), mk(id(53), "b@example.com", "h-b-code", store.EmailLoginCode, time.Hour)))

		requireNoError(t, "delete", s.DeleteEmailLoginTokens(ctx(), "a@example.com", store.EmailLoginCode))

		_, err := s.GetEmailLoginTokenByHash(ctx(), "h-a-code")
		requireNotFound(t, "the deleted code", err)
		if _, err := s.GetEmailLoginTokenByHash(ctx(), "h-a-link"); err != nil {
			t.Fatalf("the same address's link must survive: %v", err)
		}
		if _, err := s.GetEmailLoginTokenByHash(ctx(), "h-b-code"); err != nil {
			t.Fatalf("another address's code must survive: %v", err)
		}
	})
}
