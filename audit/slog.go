package audit

import (
	"context"
	"log/slog"
)

// SlogLogger adapts a *slog.Logger to Logger, for the common case of
// wanting audit events in application logs rather than a dedicated
// system. The zero value logs to slog.Default().
type SlogLogger struct {
	// Logger receives every event. Nil uses slog.Default().
	Logger *slog.Logger
}

// Log implements Logger. Events whose Result is ResultFailure or
// ResultDenied log at Warn; everything else logs at Info.
func (l SlogLogger) Log(ctx context.Context, event Event) {
	logger := l.Logger
	if logger == nil {
		logger = slog.Default()
	}
	level := slog.LevelInfo
	if event.Result == ResultFailure || event.Result == ResultDenied {
		level = slog.LevelWarn
	}

	args := []any{
		slog.String("event_type", string(event.Type)),
		slog.String("result", string(event.Result)),
	}
	if event.ActorID != "" {
		args = append(args, slog.String("actor_id", event.ActorID))
	}
	if event.TargetID != "" {
		args = append(args, slog.String("target_id", event.TargetID))
	}
	if event.Email != "" {
		args = append(args, slog.String("email", event.Email))
	}
	if event.UserAgent != "" {
		args = append(args, slog.String("user_agent", event.UserAgent))
	}
	if event.IPAddress != "" {
		args = append(args, slog.String("ip_address", event.IPAddress))
	}
	for k, v := range event.Metadata {
		args = append(args, slog.Any(k, v))
	}
	logger.Log(ctx, level, "authit audit event", args...)
}
