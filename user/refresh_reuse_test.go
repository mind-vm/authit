package user_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mind-vm/authit/audit"
	"github.com/mind-vm/authit/user"
)

// recordingAudit captures events so a test can assert on what was
// reported, not merely on what was returned.
type recordingAudit struct{ events []audit.Event }

func (r *recordingAudit) Log(_ context.Context, e audit.Event) { r.events = append(r.events, e) }

func (r *recordingAudit) has(t audit.EventType) bool {
	for _, e := range r.events {
		if e.Type == t {
			return true
		}
	}
	return false
}

// TestRefreshTokenReuseRevokesTheFamily: Refresh rotates, so the legitimate
// holder never re-sends a token it already spent. A second use means two
// parties hold it, and there is no way to tell which is the attacker --
// so both lose, and only the party who knows the password can recover.
func TestRefreshTokenReuseRevokesTheFamily(t *testing.T) {
	ctx := context.Background()
	stores, _ := freshStores()
	emailer := &capturingEmailer{}
	rec := &recordingAudit{}
	svc := serviceOver(t, stores, emailer, user.Config{AuditLogger: rec})
	const email, password = "alice@example.com", "correct-horse-battery"
	uid := registerCaptured(t, svc, emailer, email, password)

	first, err := svc.Authenticate(ctx, email, password, "ua", "ip")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	stolen := first.Tokens.RefreshToken

	// The legitimate client refreshes, rotating the token.
	rotated, err := svc.Refresh(ctx, stolen, "ua", "ip")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// A second session, to prove the whole family goes -- not just the
	// chain the replayed token belonged to.
	other, err := svc.Authenticate(ctx, email, password, "ua", "ip")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	// The attacker now replays the token the legitimate client already spent.
	if _, err := svc.Refresh(ctx, stolen, "ua", "attacker-ip"); !errors.Is(err, user.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
	if !rec.has(audit.EventUserTokenReuse) {
		t.Fatal("reuse must be reported: it is the only signal a token leaked")
	}

	// Both the rotated token and the unrelated session are now dead.
	if _, err := svc.Refresh(ctx, rotated.RefreshToken, "ua", "ip"); !errors.Is(err, user.ErrInvalidToken) {
		t.Fatalf("the rotated token should have been revoked, got %v", err)
	}
	if _, err := svc.Refresh(ctx, other.Tokens.RefreshToken, "ua", "ip"); !errors.Is(err, user.ErrInvalidToken) {
		t.Fatalf("every session should have been revoked, got %v", err)
	}
	sessions, err := svc.ListSessions(ctx, uid, "")
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("expected no active sessions after reuse, got %d", len(sessions))
	}

	// Recovery is by logging in again, which needs the password.
	if _, err := svc.Authenticate(ctx, email, password, "ua", "ip"); err != nil {
		t.Fatalf("the user must be able to recover by logging in: %v", err)
	}
}

// TestRefreshReuseIsIndistinguishableFromGarbage: reporting reuse with a
// distinct error would confirm to an attacker that a stolen token was
// genuine and had already been spent.
func TestRefreshReuseIsIndistinguishableFromGarbage(t *testing.T) {
	ctx := context.Background()
	stores, _ := freshStores()
	emailer := &capturingEmailer{}
	svc := serviceOver(t, stores, emailer, user.Config{})
	const email, password = "bob@example.com", "correct-horse-battery"
	registerCaptured(t, svc, emailer, email, password)

	res, err := svc.Authenticate(ctx, email, password, "ua", "ip")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if _, err := svc.Refresh(ctx, res.Tokens.RefreshToken, "ua", "ip"); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	reuseErr := errorFrom(svc.Refresh(ctx, res.Tokens.RefreshToken, "ua", "ip"))
	garbageErr := errorFrom(svc.Refresh(ctx, "not-a-real-token", "ua", "ip"))
	if reuseErr == nil || garbageErr == nil || reuseErr.Error() != garbageErr.Error() {
		t.Fatalf("reuse (%v) and garbage (%v) must be reported identically", reuseErr, garbageErr)
	}
}

func errorFrom(_ user.TokenPair, err error) error { return err }

// TestLogoutThenReplayAlsoTripsDetection documents the accepted
// false-positive: a token revoked by Logout and then replayed looks exactly
// like a leak from here, because it is not distinguishable without storing
// a revocation reason. The session was already over, so revoking the rest
// is safe; it is recorded so the noise is visible.
func TestLogoutThenReplayAlsoTripsDetection(t *testing.T) {
	ctx := context.Background()
	stores, _ := freshStores()
	emailer := &capturingEmailer{}
	rec := &recordingAudit{}
	svc := serviceOver(t, stores, emailer, user.Config{AuditLogger: rec})
	const email, password = "carol@example.com", "correct-horse-battery"
	registerCaptured(t, svc, emailer, email, password)

	res, err := svc.Authenticate(ctx, email, password, "ua", "ip")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if err := svc.Logout(ctx, res.Tokens.RefreshToken); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := svc.Refresh(ctx, res.Tokens.RefreshToken, "ua", "ip"); !errors.Is(err, user.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
	if !rec.has(audit.EventUserTokenReuse) {
		t.Fatal("a replayed logged-out token is reported too; see the doc comment on Refresh")
	}
}

// TestExpiredRefreshTokenDoesNotTripDetection: an expired token is not
// evidence of theft, so it must not take the user's other sessions with it.
func TestExpiredRefreshTokenDoesNotTripDetection(t *testing.T) {
	ctx := context.Background()
	stores, _ := freshStores()
	emailer := &capturingEmailer{}
	rec := &recordingAudit{}
	svc := serviceOver(t, stores, emailer, user.Config{AuditLogger: rec, RefreshTokenTTL: time.Nanosecond})
	const email, password = "dave@example.com", "correct-horse-battery"
	registerCaptured(t, svc, emailer, email, password)

	res, err := svc.Authenticate(ctx, email, password, "ua", "ip")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if _, err := svc.Refresh(ctx, res.Tokens.RefreshToken, "ua", "ip"); !errors.Is(err, user.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
	if rec.has(audit.EventUserTokenReuse) {
		t.Fatal("an expired token is not evidence of a leak")
	}
}
