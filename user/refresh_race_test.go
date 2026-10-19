package user_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/authit/user"
)

// slowLookups holds every racer between reading a token and acting on it,
// as a database round trip would, so the race shows on an in-memory store.
type slowLookups struct{ store.RefreshTokenStore }

func (s slowLookups) GetRefreshTokenByHash(ctx context.Context, hash string) (*store.RefreshToken, error) {
	t, err := s.RefreshTokenStore.GetRefreshTokenByHash(ctx, hash)
	time.Sleep(2 * time.Millisecond)
	return t, err
}

// TestConcurrentRefreshOfOneTokenIssuesOnePair: a refresh token is single
// use. Two requests presenting it at the same moment must not both get a
// new pair, or a stolen token keeps working beside the real one and reuse
// detection never sees a revoked token to react to.
func TestConcurrentRefreshOfOneTokenIssuesOnePair(t *testing.T) {
	ctx := context.Background()
	const racers = 16
	for round := 0; round < 20; round++ {
		stores, _ := freshStores()
		stores.RefreshTokens = slowLookups{stores.RefreshTokens}
		emailer := &capturingEmailer{}
		svc := serviceOver(t, stores, emailer, user.Config{})
		const email, password = "race@example.com", "correct-horse-battery"
		registerCaptured(t, svc, emailer, email, password)
		res, err := svc.Authenticate(ctx, email, password, "ua", "ip")
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
