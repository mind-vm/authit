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
	res, err := svc.Authenticate(ctx, "flow@example.com", "correct horse battery staple", "ua", "127.0.0.1")
	if err != nil || res.Tokens == nil {
		t.Fatalf("Authenticate: %v, %+v", err, res)
	}

	// Concurrent refreshes of one token: rotation runs in a transaction, so
	// exactly one wins and the rest are refused as reuse. None of them may
	// fail on the lock itself.
	const n = 8
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		wins int
	)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.Refresh(ctx, res.Tokens.RefreshToken, "ua", "127.0.0.1")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
			case strings.Contains(err.Error(), "locked") || strings.Contains(err.Error(), "busy"):
				t.Errorf("Refresh failed on the lock: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d concurrent refreshes of one token succeeded, want exactly 1", wins)
	}
}
