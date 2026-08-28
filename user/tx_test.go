package user_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/authit/storetest"
	"github.com/mind-vm/authit/user"
	"github.com/pquerna/otp/totp"
)

// witnessedRefreshTokens wraps a RefreshTokenStore and reports which of its
// operations ran inside a transaction.
type witnessedRefreshTokens struct {
	store.RefreshTokenStore
	w *storetest.TxWitness
}

func (s witnessedRefreshTokens) CreateRefreshToken(ctx context.Context, t *store.RefreshToken) error {
	s.w.Record(ctx, "CreateRefreshToken")
	return s.RefreshTokenStore.CreateRefreshToken(ctx, t)
}

func (s witnessedRefreshTokens) RevokeRefreshToken(ctx context.Context, id string) error {
	s.w.Record(ctx, "RevokeRefreshToken")
	return s.RefreshTokenStore.RevokeRefreshToken(ctx, id)
}

func (s witnessedRefreshTokens) RevokeAllUserRefreshTokens(ctx context.Context, userID string) error {
	s.w.Record(ctx, "RevokeAllUserRefreshTokens")
	return s.RefreshTokenStore.RevokeAllUserRefreshTokens(ctx, userID)
}

type witnessedLockouts struct {
	store.LockoutStore
	w *storetest.TxWitness
}

func (s witnessedLockouts) RecordFailedLoginAttempt(ctx context.Context, a *store.FailedLoginAttempt) error {
	s.w.Record(ctx, "RecordFailedLoginAttempt")
	return s.LockoutStore.RecordFailedLoginAttempt(ctx, a)
}

type witnessedTOTP struct {
	store.TOTPStore
	w *storetest.TxWitness
}

func (s witnessedTOTP) UpdateTOTPSettings(ctx context.Context, t *store.TOTPSettings) error {
	s.w.Record(ctx, "UpdateTOTPSettings")
	return s.TOTPStore.UpdateTOTPSettings(ctx, t)
}

type witnessedUsers struct {
	store.UserStore
	w *storetest.TxWitness
}

func (s witnessedUsers) UpdateUser(ctx context.Context, u *store.User) error {
	s.w.Record(ctx, "UpdateUser")
	return s.UserStore.UpdateUser(ctx, u)
}

type witnessedResets struct {
	store.PasswordResetStore
	w *storetest.TxWitness
}

func (s witnessedResets) MarkPasswordResetTokenUsed(ctx context.Context, id string) error {
	s.w.Record(ctx, "MarkPasswordResetTokenUsed")
	return s.PasswordResetStore.MarkPasswordResetTokenUsed(ctx, id)
}

type txFixture struct {
	svc     *user.Service
	emailer *capturingEmailer
	probe   *storetest.TxProbe
	witness *storetest.TxWitness
}

func newTxFixture(t *testing.T, cfg user.Config) txFixture {
	t.Helper()
	w := storetest.NewTxWitness()
	probe := &storetest.TxProbe{}
	stores, _ := freshStores()
	stores.RefreshTokens = witnessedRefreshTokens{stores.RefreshTokens, w}
	stores.Lockouts = witnessedLockouts{stores.Lockouts, w}
	stores.TOTP = witnessedTOTP{stores.TOTP, w}
	stores.Users = witnessedUsers{stores.Users, w}
	stores.PasswordResets = witnessedResets{stores.PasswordResets, w}
	stores.Tx = probe

	emailer := &capturingEmailer{}
	return txFixture{svc: serviceOver(t, stores, emailer, cfg), emailer: emailer, probe: probe, witness: w}
}

// TestRefreshRotatesInsideATransaction: revoke-then-create is the pair a
// crash between would log a user out of the session they were renewing.
func TestRefreshRotatesInsideATransaction(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, user.Config{})
	const email, password = "alice@example.com", "correct-horse-battery"
	registerCaptured(t, f.svc, f.emailer, email, password)

	res, err := f.svc.Authenticate(ctx, email, password, "ua", "ip")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if f.probe.CallCount() != 0 {
		t.Fatal("logging in is a single write and should not open a transaction")
	}
	f.witness.Reset()
	if _, err := f.svc.Refresh(ctx, res.Tokens.RefreshToken, "ua", "ip"); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if f.probe.CallCount() != 1 {
		t.Fatalf("Refresh opened %d transactions, want 1", f.probe.CallCount())
	}
	f.witness.AssertInTx(t, "RevokeRefreshToken")
	f.witness.AssertInTx(t, "CreateRefreshToken")
}

// TestReuseRevocationSurvivesTheErrorReturn is the subtle one. Refresh
// detects a replayed token, revokes every session, and then returns an
// error. If that revocation were inside the transaction, returning the
// error would roll it back — the detection would fire, report itself in
// the audit log, and undo its own response.
func TestReuseRevocationSurvivesTheErrorReturn(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, user.Config{})
	const email, password = "alice@example.com", "correct-horse-battery"
	registerCaptured(t, f.svc, f.emailer, email, password)

	res, err := f.svc.Authenticate(ctx, email, password, "ua", "ip")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	stolen := res.Tokens.RefreshToken
	if _, err := f.svc.Refresh(ctx, stolen, "ua", "ip"); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	f.witness.Reset()
	if _, err := f.svc.Refresh(ctx, stolen, "ua", "ip"); !errors.Is(err, user.ErrInvalidToken) {
		t.Fatalf("replay should be refused, got %v", err)
	}
	f.witness.AssertOutsideTx(t, "RevokeAllUserRefreshTokens")
}

// TestResetPasswordIsAtomic: setting the password without consuming the
// token leaves a live reset link in an inbox.
func TestResetPasswordIsAtomic(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, user.Config{})
	const email = "alice@example.com"
	registerCaptured(t, f.svc, f.emailer, email, "correct-horse-battery")

	if err := f.svc.RequestPasswordReset(ctx, email); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	f.witness.Reset()
	if err := f.svc.ResetPassword(ctx, f.emailer.lastResetToken, "a-new-valid-passphrase"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	f.witness.AssertInTx(t, "UpdateUser")
	f.witness.AssertInTx(t, "MarkPasswordResetTokenUsed")
	f.witness.AssertInTx(t, "RevokeAllUserRefreshTokens")
}

// TestTwoFactorBackupCodeConsumptionIsAtomic: a backup code marked used by
// a login that then failed is a single-use credential spent for nothing —
// at the moment the user has already lost their authenticator.
func TestTwoFactorBackupCodeConsumptionIsAtomic(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, user.Config{MaxFailedLoginAttempts: 5, FailedLoginWindow: time.Minute})
	const email, password = "alice@example.com", "correct-horse-battery"
	uid := registerCaptured(t, f.svc, f.emailer, email, password)

	setup, err := f.svc.BeginTwoFactorSetup(ctx, uid, email)
	if err != nil {
		t.Fatalf("BeginTwoFactorSetup: %v", err)
	}
	code, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	enrollment, err := f.svc.ConfirmTwoFactorSetup(ctx, uid, code)
	if err != nil {
		t.Fatalf("ConfirmTwoFactorSetup: %v", err)
	}

	res, err := f.svc.Authenticate(ctx, email, password, "ua", "ip")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	// A wrong code first: recording that failure must stay outside, or a
	// rollback would erase the attempt the rate limit counts.
	f.witness.Reset()
	if _, err := f.svc.VerifyTwoFactorLogin(ctx, res.PendingTwoFactorToken, "000000", "ua", "ip"); !errors.Is(err, user.ErrInvalidTwoFactor) {
		t.Fatalf("expected ErrInvalidTwoFactor, got %v", err)
	}
	f.witness.AssertOutsideTx(t, "RecordFailedLoginAttempt")

	f.witness.Reset()
	if _, err := f.svc.VerifyTwoFactorLogin(ctx, res.PendingTwoFactorToken, enrollment.BackupCodes[0], "ua", "ip"); err != nil {
		t.Fatalf("VerifyTwoFactorLogin with a backup code: %v", err)
	}
	f.witness.AssertInTx(t, "UpdateTOTPSettings")
	f.witness.AssertInTx(t, "CreateRefreshToken")
}

// TestTransactionFailureSurfaces: a transaction that cannot begin must
// fail the call rather than silently proceeding without one.
func TestTransactionFailureSurfaces(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, user.Config{})
	const email, password = "alice@example.com", "correct-horse-battery"
	registerCaptured(t, f.svc, f.emailer, email, password)
	res, err := f.svc.Authenticate(ctx, email, password, "ua", "ip")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	boom := errors.New("begin: connection refused")
	f.probe.Fail = boom
	if _, err := f.svc.Refresh(ctx, res.Tokens.RefreshToken, "ua", "ip"); !errors.Is(err, boom) {
		t.Fatalf("a failed transaction must surface, got %v", err)
	}
	// And the old token must still be usable: nothing was rotated.
	f.probe.Fail = nil
	if _, err := f.svc.Refresh(ctx, res.Tokens.RefreshToken, "ua", "ip"); err != nil {
		t.Fatalf("the refresh token should be untouched after a failed transaction: %v", err)
	}
}

// TestNilTxRunnerKeepsWorking: the seam is optional, and leaving it nil
// must change nothing.
func TestNilTxRunnerKeepsWorking(t *testing.T) {
	ctx := context.Background()
	stores, _ := freshStores()
	emailer := &capturingEmailer{}
	svc := serviceOver(t, stores, emailer, user.Config{})
	const email, password = "alice@example.com", "correct-horse-battery"
	registerCaptured(t, svc, emailer, email, password)

	res, err := svc.Authenticate(ctx, email, password, "ua", "ip")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if _, err := svc.Refresh(ctx, res.Tokens.RefreshToken, "ua", "ip"); err != nil {
		t.Fatalf("Refresh without a TxRunner: %v", err)
	}
	if err := svc.RequestPasswordReset(ctx, email); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if err := svc.ResetPassword(ctx, emailer.lastResetToken, "a-new-valid-passphrase"); err != nil {
		t.Fatalf("ResetPassword without a TxRunner: %v", err)
	}
}
