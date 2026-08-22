package device_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jryannel/authit/device"
	"github.com/jryannel/authit/internal/authittest"
)

// newTestService returns a service over a database of this test's own, plus
// the id of the user who will approve the request — device_authorizations.
// user_id references users, so an approver has to be a real one.
func newTestService(t *testing.T, cfg device.Config) (*device.Service, string) {
	t.Helper()
	db := authittest.FreshDB(t)
	svc, err := device.NewService(db, cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, authittest.NewUser(t, db, "approver@example.com")
}

func TestHappyPath(t *testing.T) {
	svc, approver := newTestService(t, device.Config{PollInterval: time.Millisecond})
	ctx := t.Context()

	auth, err := svc.StartDeviceAuthorization(ctx, "cli", "read write")
	if err != nil {
		t.Fatalf("StartDeviceAuthorization: %v", err)
	}
	if auth.DeviceCode == "" || !strings.Contains(auth.UserCode, "-") {
		t.Fatalf("unexpected authorization: %+v", auth)
	}

	// Poll before approval: pending.
	if _, _, err := svc.PollDeviceToken(ctx, auth.DeviceCode); !errors.Is(err, device.ErrAuthorizationPending) {
		t.Fatalf("expected ErrAuthorizationPending, got %v", err)
	}

	time.Sleep(2 * time.Millisecond)
	if err := svc.ApproveDeviceAuthorization(ctx, approver, auth.UserCode); err != nil {
		t.Fatalf("ApproveDeviceAuthorization: %v", err)
	}

	userID, scope, err := svc.PollDeviceToken(ctx, auth.DeviceCode)
	if err != nil {
		t.Fatalf("PollDeviceToken: %v", err)
	}
	if userID != approver || scope != "read write" {
		t.Fatalf("got userID=%q scope=%q", userID, scope)
	}

	// The record is single-use: polling again after success must fail.
	if _, _, err := svc.PollDeviceToken(ctx, auth.DeviceCode); !errors.Is(err, device.ErrExpiredToken) {
		t.Fatalf("expected ErrExpiredToken on re-poll after success, got %v", err)
	}
}

func TestDenied(t *testing.T) {
	svc, _ := newTestService(t, device.Config{PollInterval: time.Millisecond})
	ctx := t.Context()

	auth, err := svc.StartDeviceAuthorization(ctx, "cli", "")
	if err != nil {
		t.Fatalf("StartDeviceAuthorization: %v", err)
	}
	if err := svc.DenyDeviceAuthorization(ctx, auth.UserCode); err != nil {
		t.Fatalf("DenyDeviceAuthorization: %v", err)
	}
	if _, _, err := svc.PollDeviceToken(ctx, auth.DeviceCode); !errors.Is(err, device.ErrAccessDenied) {
		t.Fatalf("expected ErrAccessDenied, got %v", err)
	}
}

func TestUnknownDeviceCode(t *testing.T) {
	svc, _ := newTestService(t, device.Config{})
	if _, _, err := svc.PollDeviceToken(t.Context(), "not-a-real-device-code"); !errors.Is(err, device.ErrExpiredToken) {
		t.Fatalf("expected ErrExpiredToken for an unknown device code, got %v", err)
	}
}

func TestInvalidUserCode(t *testing.T) {
	svc, approver := newTestService(t, device.Config{})
	ctx := t.Context()
	if err := svc.ApproveDeviceAuthorization(ctx, approver, "ZZZZ-ZZZZ"); !errors.Is(err, device.ErrInvalidUserCode) {
		t.Fatalf("expected ErrInvalidUserCode, got %v", err)
	}
}

func TestSlowDown(t *testing.T) {
	svc, _ := newTestService(t, device.Config{PollInterval: time.Hour}) // effectively never satisfied within the test
	ctx := t.Context()

	auth, err := svc.StartDeviceAuthorization(ctx, "cli", "")
	if err != nil {
		t.Fatalf("StartDeviceAuthorization: %v", err)
	}
	if _, _, err := svc.PollDeviceToken(ctx, auth.DeviceCode); !errors.Is(err, device.ErrAuthorizationPending) {
		t.Fatalf("expected first poll to be pending, got %v", err)
	}
	if _, _, err := svc.PollDeviceToken(ctx, auth.DeviceCode); !errors.Is(err, device.ErrSlowDown) {
		t.Fatalf("expected ErrSlowDown on an immediate second poll, got %v", err)
	}
}

func TestExpiredDeviceCode(t *testing.T) {
	svc, _ := newTestService(t, device.Config{DeviceCodeTTL: time.Millisecond, PollInterval: time.Millisecond})
	ctx := t.Context()

	auth, err := svc.StartDeviceAuthorization(ctx, "cli", "")
	if err != nil {
		t.Fatalf("StartDeviceAuthorization: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if _, _, err := svc.PollDeviceToken(ctx, auth.DeviceCode); !errors.Is(err, device.ErrExpiredToken) {
		t.Fatalf("expected ErrExpiredToken, got %v", err)
	}
}
