package sqlitestore_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/user"
)

// TestUserFlowsOverSQLite runs the user plane's real flows over the store,
// with the TxRunner wired, so the transactional paths take SQLite's write
// lock the way an app would.
func TestUserFlowsOverSQLite(t *testing.T) {
	ctx := context.Background()
	s := fresh(t)
	signer, err := authitjwt.NewHMACSigner([]byte(strings.Repeat("k", 32)),
		authitjwt.Defaults{Issuer: "sqlitestore-test", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := user.NewService(user.Stores{
		Users: s, RefreshTokens: s, PasswordResets: s, EmailVerifications: s,
		TOTP: s, PendingTwoFactor: s, Lockouts: s, Tx: s,
	}, signer, nil, user.Config{
		TOTPEncryptionKey: []byte(strings.Repeat("t", 32)),
		EmailVerification: user.EmailVerificationOptional,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.Register(ctx, "flow@example.com", "correct horse battery staple"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Concurrent refreshes, one per session: each rotation is a transaction
	// taking SQLite's write lock, so they queue. Every one must succeed, not
	// fail on the lock, and every token it issues must be stored.
	//
	// This does not refresh one token from several goroutines: user.Refresh
	// reads the token before its transaction and RevokeRefreshToken is
	// idempotent, so concurrent refreshes of one token can all rotate, on
	// pgstore as on this store. That is the service's guarantee to make.
	const n = 8
	tokens := make([]string, n)
	for i := range tokens {
		res, err := svc.Authenticate(ctx, "flow@example.com", "correct horse battery staple", "ua", "127.0.0.1")
		if err != nil || res.Tokens == nil {
			t.Fatalf("Authenticate: %v, %+v", err, res)
		}
		tokens[i] = res.Tokens.RefreshToken
	}
	rotated := make([]string, n)
	var wg sync.WaitGroup
	for i, tok := range tokens {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pair, err := svc.Refresh(ctx, tok, "ua", "127.0.0.1")
			if err != nil {
				t.Errorf("Refresh %d: %v", i, err)
				return
			}
			rotated[i] = pair.RefreshToken
		}()
	}
	wg.Wait()
	if t.Failed() {
		return
	}
	for i, tok := range rotated {
		if _, err := svc.Refresh(ctx, tok, "ua", "127.0.0.1"); err != nil {
			t.Fatalf("the token rotation %d issued does not refresh: %v", i, err)
		}
	}
}
