package sqlitestore_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/mind-vm/authit/device"

	"github.com/mind-vm/authit/pat"
	"github.com/mind-vm/authit/store"
)

// TestTokenFlowsOverSQLite runs the pat and device services over the
// store: a personal access token resolves until it is revoked, and an
// approved device authorization hands the CLI its user exactly once.
func TestTokenFlowsOverSQLite(t *testing.T) {
	ctx := context.Background()
	s := fresh(t)
	now := time.Now()
	u := &store.User{ID: uuid.NewString(), Email: "cli@example.com", CreatedAt: now, UpdatedAt: now}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}

	pats, err := pat.NewService(pat.Stores{Tokens: s}, pat.Config{})
	if err != nil {
		t.Fatal(err)
	}
	raw, tok, err := pats.CreateToken(ctx, u.ID, "laptop", []string{"read", "write"}, nil)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	got, err := pats.Resolve(ctx, raw)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.UserID != u.ID || !pat.HasScope(got, "write") {
		t.Fatalf("Resolve = %+v", got)
	}
	if err := pats.RevokeToken(ctx, u.ID, tok.ID); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if _, err := pats.Resolve(ctx, raw); err == nil {
		t.Fatal("a revoked token still resolves")
	}

	devices, err := device.NewService(device.Stores{Authorizations: s}, device.Config{PollInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := devices.StartDeviceAuthorization(ctx, "cli", "read")
	if err != nil {
		t.Fatalf("StartDeviceAuthorization: %v", err)
	}
	if _, _, err := devices.PollDeviceToken(ctx, auth.DeviceCode); !errors.Is(err, device.ErrAuthorizationPending) {
		t.Fatalf("PollDeviceToken before approval = %v, want ErrAuthorizationPending", err)
	}
	if err := devices.ApproveDeviceAuthorization(ctx, u.ID, auth.UserCode); err != nil {
		t.Fatalf("ApproveDeviceAuthorization: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	userID, scope, err := devices.PollDeviceToken(ctx, auth.DeviceCode)
	if err != nil || userID != u.ID || scope != "read" {
		t.Fatalf("PollDeviceToken = %q, %q, %v", userID, scope, err)
	}
	if _, _, err := devices.PollDeviceToken(ctx, auth.DeviceCode); !errors.Is(err, device.ErrExpiredToken) {
		t.Fatalf("a second poll = %v, want ErrExpiredToken", err)
	}
}
