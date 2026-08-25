package audit_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/mind-vm/authit/audit"
)

func TestNoopLoggerDiscardsEvents(t *testing.T) {
	var logger audit.Logger = audit.NoopLogger{}
	logger.Log(context.Background(), audit.Event{Type: audit.EventUserLoginSucceeded})
}

func TestSlogLoggerWritesEventFields(t *testing.T) {
	var buf strings.Builder
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := audit.SlogLogger{Logger: slog.New(handler)}

	logger.Log(context.Background(), audit.Event{
		Type:     audit.EventUserLoginSucceeded,
		Result:   audit.ResultSuccess,
		ActorID:  "user-1",
		Email:    "alice@example.com",
		Metadata: map[string]any{"via": "password"},
	})

	out := buf.String()
	for _, want := range []string{
		"authit audit event",
		"event_type=user.login.succeeded",
		"result=success",
		"actor_id=user-1",
		"email=alice@example.com",
		"via=password",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("log output %q does not contain %q", out, want)
		}
	}
}

func TestSlogLoggerWarnsOnFailure(t *testing.T) {
	var buf strings.Builder
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := audit.SlogLogger{Logger: slog.New(handler)}

	logger.Log(context.Background(), audit.Event{
		Type:   audit.EventUserLoginFailed,
		Result: audit.ResultFailure,
	})

	if !strings.Contains(buf.String(), "level=WARN") {
		t.Fatalf("expected a Warn-level log line, got %q", buf.String())
	}
}
