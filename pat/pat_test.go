package pat_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jryannel/authit/memstore"
	"github.com/jryannel/authit/pat"
)

func newTestService(t *testing.T, cfg pat.Config) *pat.Service {
	t.Helper()
	svc, err := pat.NewService(pat.Stores{Tokens: memstore.NewPersonalAccessTokenStore()}, cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func TestCreateAndResolve(t *testing.T) {
	svc := newTestService(t, pat.Config{Prefix: "mb_"})
	ctx := t.Context()

	raw, created, err := svc.CreateToken(ctx, "user-1", "laptop", []string{"read", "write"}, nil)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if !strings.HasPrefix(raw, "mb_") {
		t.Fatalf("expected mb_ prefix, got %q", raw)
	}
	if created.Name != "laptop" || created.LastUsedAt != nil {
		t.Fatalf("unexpected created token: %+v", created)
	}

	resolved, err := svc.Resolve(ctx, raw)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved.UserID != "user-1" || resolved.LastUsedAt == nil {
		t.Fatalf("expected LastUsedAt to be set after Resolve, got %+v", resolved)
	}
	if !pat.HasScope(resolved, "read") || pat.HasScope(resolved, "admin") {
		t.Fatal("HasScope did not behave as expected")
	}

	if _, err := svc.Resolve(ctx, "mb_not-a-real-token"); !errors.Is(err, pat.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for unknown token, got %v", err)
	}
}

func TestRevoke(t *testing.T) {
	svc := newTestService(t, pat.Config{})
	ctx := t.Context()

	raw, created, err := svc.CreateToken(ctx, "user-1", "laptop", nil, nil)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	if err := svc.RevokeToken(ctx, "user-2", created.ID); !errors.Is(err, pat.ErrNotOwner) {
		t.Fatalf("expected ErrNotOwner, got %v", err)
	}
	if err := svc.RevokeToken(ctx, "user-1", created.ID); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if _, err := svc.Resolve(ctx, raw); !errors.Is(err, pat.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken after revoke, got %v", err)
	}
}

func TestExpiry(t *testing.T) {
	svc := newTestService(t, pat.Config{})
	ctx := t.Context()

	past := time.Now().Add(-time.Minute)
	raw, _, err := svc.CreateToken(ctx, "user-1", "expired", nil, &past)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if _, err := svc.Resolve(ctx, raw); !errors.Is(err, pat.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for an already-expired token, got %v", err)
	}
}

func TestMaxExpiryAndRequireExpiry(t *testing.T) {
	maxDur := 24 * time.Hour
	svc := newTestService(t, pat.Config{MaxExpiry: &maxDur})
	ctx := t.Context()

	tooFar := time.Now().Add(48 * time.Hour)
	if _, _, err := svc.CreateToken(ctx, "user-1", "t", nil, &tooFar); !errors.Is(err, pat.ErrExpiryTooFar) {
		t.Fatalf("expected ErrExpiryTooFar, got %v", err)
	}
	if _, _, err := svc.CreateToken(ctx, "user-1", "t", nil, nil); !errors.Is(err, pat.ErrExpiryTooFar) {
		t.Fatalf("expected ErrExpiryTooFar for nil expiry when MaxExpiry is set, got %v", err)
	}

	svc2 := newTestService(t, pat.Config{RequireExpiry: true})
	if _, _, err := svc2.CreateToken(ctx, "user-1", "t", nil, nil); !errors.Is(err, pat.ErrExpiryRequired) {
		t.Fatalf("expected ErrExpiryRequired, got %v", err)
	}
}

func TestListTokens(t *testing.T) {
	svc := newTestService(t, pat.Config{})
	ctx := t.Context()
	if _, _, err := svc.CreateToken(ctx, "user-1", "a", nil, nil); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if _, _, err := svc.CreateToken(ctx, "user-1", "b", nil, nil); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if _, _, err := svc.CreateToken(ctx, "user-2", "c", nil, nil); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	tokens, err := svc.ListTokens(ctx, "user-1")
	if err != nil {
		t.Fatalf("ListTokens: %v", err)
	}
	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens for user-1, got %d", len(tokens))
	}
}
