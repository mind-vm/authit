package superuser_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/mind-vm/authit/memstore"
	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/authit/superuser"
)

// slowLookups holds every racer between reading a token and acting on it,
// as a database round trip would, so the race shows on an in-memory store.
type slowLookups struct {
	store.SuperuserRefreshTokenStore
}

func (s slowLookups) GetSuperuserRefreshTokenByHash(ctx context.Context, hash string) (*store.SuperuserRefreshToken, error) {
	t, err := s.SuperuserRefreshTokenStore.GetSuperuserRefreshTokenByHash(ctx, hash)
	time.Sleep(2 * time.Millisecond)
	return t, err
}

// TestConcurrentRefreshOfOneTokenIssuesOnePair is the user plane's test of
// the same name, for operator tokens, which can impersonate.
func TestConcurrentRefreshOfOneTokenIssuesOnePair(t *testing.T) {
	const racers = 16
	for round := 0; round < 20; round++ {
		svc, err := superuser.NewService(superuser.Stores{
			Superusers:    memstore.NewSuperuserStore(),
			RefreshTokens: slowLookups{memstore.NewSuperuserRefreshTokenStore()},
			Lockouts:      memstore.NewLockoutStore(),
		}, newSigner(t), superuser.Config{})
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}
		ctx := t.Context()
		if _, err := svc.Bootstrap(ctx, "root@example.com", "s3cret-passphrase!!", "Root"); err != nil {
			t.Fatalf("Bootstrap: %v", err)
		}
		res, err := svc.Authenticate(ctx, "root@example.com", "s3cret-passphrase!!", "ua", "ip")
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		token := res.Tokens.RefreshToken

		var (
			start sync.WaitGroup
			done  sync.WaitGroup
			mu    sync.Mutex
			won   int
		)
		start.Add(1)
		for i := 0; i < racers; i++ {
			done.Add(1)
			go func() {
				defer done.Done()
				start.Wait()
				if _, err := svc.Refresh(ctx, token, "ua", "ip"); err == nil {
					mu.Lock()
					won++
					mu.Unlock()
				}
			}()
		}
		start.Done()
		done.Wait()
		if won != 1 {
			t.Fatalf("round %d: %d of %d concurrent refreshes of one token succeeded, want exactly 1", round, won, racers)
		}
	}
}
