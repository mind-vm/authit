package passkey_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/mind-vm/authit/memstore"
	"github.com/mind-vm/authit/passkey"
	"github.com/mind-vm/authit/store"
)

const (
	testRPID   = "example.com"
	testOrigin = "https://example.com"
)

type fixture struct {
	svc   *passkey.Service
	users *memstore.UserStore
	creds *memstore.WebAuthnCredentialStore
	user  store.User
}

func newFixture(t *testing.T, cfg passkey.Config) fixture {
	t.Helper()
	users := memstore.NewUserStore()
	creds := memstore.NewWebAuthnCredentialStore()
	cfg.RPID, cfg.RPOrigins = testRPID, []string{testOrigin}
	if cfg.RPDisplayName == "" {
		cfg.RPDisplayName = "Example"
	}
	svc, err := passkey.NewService(passkey.Stores{Users: users, Credentials: creds}, cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	u := &store.User{ID: "3f0b1c2d-0000-4000-8000-000000000001", Email: "alice@example.com"}
	if err := users.CreateUser(context.Background(), u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return fixture{svc: svc, users: users, creds: creds, user: *u}
}

// enroll runs a full registration ceremony and returns the authenticator.
func (f fixture) enroll(t *testing.T, name string) *virtualAuthenticator {
	t.Helper()
	ctx := context.Background()
	auth := newAuthenticator(t)
	opts, sess, err := f.svc.BeginRegistration(ctx, f.user.ID)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	r := auth.register(t, challengeFrom(t, opts), testRPID, testOrigin)
	if _, err := f.svc.FinishRegistration(ctx, f.user.ID, name, sess, r); err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	return auth
}

// login runs an assertion for a known user.
func (f fixture) login(t *testing.T, auth *virtualAuthenticator) (passkey.Result, error) {
	t.Helper()
	ctx := context.Background()
	opts, sess, err := f.svc.BeginLogin(ctx, f.user.ID)
	if err != nil {
		return passkey.Result{}, err
	}
	r := auth.assert(t, challengeFrom(t, opts), testRPID, testOrigin, f.user.ID)
	return f.svc.FinishLogin(ctx, f.user.ID, sess, r)
}

func TestRegisterThenLogin(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, passkey.Config{})
	auth := f.enroll(t, "Test Key")

	list, err := f.svc.List(ctx, f.user.ID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].Name != "Test Key" {
		t.Fatalf("unexpected credential list: %+v", list)
	}
	if len(list[0].Data) == 0 {
		t.Fatal("the authoritative credential blob was not stored")
	}
	if !list[0].BackupEligible || !list[0].BackupState {
		t.Fatal("backup flags should be denormalised out of the credential")
	}

	auth.signCount++
	res, err := f.login(t, auth)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if res.User.ID != f.user.ID {
		t.Fatalf("logged in as %q, want %q", res.User.ID, f.user.ID)
	}
	if !res.UserVerified {
		t.Fatal("the authenticator set UV, so the result should report it")
	}
	if res.Credential.LastUsedAt == nil {
		t.Fatal("LastUsedAt should be stamped on login")
	}
}

// TestClonedAuthenticatorIsRejected: a signature counter that does not
// advance is the specification's one built-in signal that a private key
// has been copied.
func TestClonedAuthenticatorIsRejected(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, passkey.Config{})
	auth := f.enroll(t, "Test Key")

	auth.signCount = 5
	if _, err := f.login(t, auth); err != nil {
		t.Fatalf("first login: %v", err)
	}
	// The clone reports a counter that has gone backwards.
	auth.signCount = 3
	if _, err := f.login(t, auth); !errors.Is(err, passkey.ErrCloneWarning) {
		t.Fatalf("expected ErrCloneWarning, got %v", err)
	}
	// The flag must be recorded even though the login was refused, or the
	// next attempt looks like the first.
	list, err := f.svc.List(ctx, f.user.ID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if !list[0].CloneWarning {
		t.Fatal("the clone warning must persist; refusing the login is not enough")
	}
}

// TestCloneFlagPolicyAllowsTheLogin covers the opt-out, for deployments
// that would rather score the risk than block.
func TestCloneFlagPolicyAllowsTheLogin(t *testing.T) {
	f := newFixture(t, passkey.Config{OnClone: passkey.CloneFlag})
	auth := f.enroll(t, "Test Key")
	auth.signCount = 5
	if _, err := f.login(t, auth); err != nil {
		t.Fatalf("first login: %v", err)
	}
	auth.signCount = 3
	res, err := f.login(t, auth)
	if err != nil {
		t.Fatalf("CloneFlag should allow the login: %v", err)
	}
	if !res.Credential.CloneWarning {
		t.Fatal("the credential should still carry the warning")
	}
}

// TestUserVerificationIsRequired is the property that separates a
// two-factor passkey login from a one-factor one. Without it, anyone
// holding an unlocked device is the user.
func TestUserVerificationIsRequired(t *testing.T) {
	f := newFixture(t, passkey.Config{})
	auth := f.enroll(t, "Test Key")
	auth.signCount++
	auth.userVerified = false

	if _, err := f.login(t, auth); err == nil {
		t.Fatal("an assertion without user verification must be refused")
	}
}

// TestUserVerificationCanBeRelaxedForSecondFactorUse: behind a password,
// possession alone is the second factor and a PIN prompt is friction.
func TestUserVerificationCanBeRelaxedForSecondFactorUse(t *testing.T) {
	f := newFixture(t, passkey.Config{UserVerification: protocol.VerificationDiscouraged})
	auth := f.enroll(t, "Security Key")
	auth.signCount++
	auth.userVerified = false

	res, err := f.login(t, auth)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if res.UserVerified {
		t.Fatal("UserVerified should report what actually happened")
	}
}

// TestWrongOriginIsRejected: the origin check is what stops a page on
// another site from driving the user's authenticator.
func TestWrongOriginIsRejected(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, passkey.Config{})
	auth := f.enroll(t, "Test Key")
	auth.signCount++

	opts, sess, err := f.svc.BeginLogin(ctx, f.user.ID)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	r := auth.assert(t, challengeFrom(t, opts), testRPID, "https://evil.example", f.user.ID)
	if _, err := f.svc.FinishLogin(ctx, f.user.ID, sess, r); !errors.Is(err, passkey.ErrCeremony) {
		t.Fatalf("expected ErrCeremony for a foreign origin, got %v", err)
	}
}

// TestReplayedChallengeIsRejected: an assertion is only valid against the
// challenge it was asked for.
func TestReplayedChallengeIsRejected(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, passkey.Config{})
	auth := f.enroll(t, "Test Key")
	auth.signCount++

	// Capture a valid assertion for one ceremony...
	opts, _, err := f.svc.BeginLogin(ctx, f.user.ID)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	captured := auth.assert(t, challengeFrom(t, opts), testRPID, testOrigin, f.user.ID)

	// ...and present it against a different one.
	_, sess2, err := f.svc.BeginLogin(ctx, f.user.ID)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if _, err := f.svc.FinishLogin(ctx, f.user.ID, sess2, captured); !errors.Is(err, passkey.ErrCeremony) {
		t.Fatalf("expected ErrCeremony for a replayed assertion, got %v", err)
	}
}

// TestDiscoverableLoginResolvesTheOwner is the usernameless flow: no email
// typed, and the account comes from the credential.
func TestDiscoverableLoginResolvesTheOwner(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, passkey.Config{})
	auth := f.enroll(t, "Test Key")
	auth.signCount++

	opts, sess, err := f.svc.BeginDiscoverableLogin(ctx)
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}
	r := auth.assert(t, challengeFrom(t, opts), testRPID, testOrigin, f.user.ID)
	res, err := f.svc.FinishDiscoverableLogin(ctx, sess, r)
	if err != nil {
		t.Fatalf("FinishDiscoverableLogin: %v", err)
	}
	if res.User.ID != f.user.ID {
		t.Fatalf("resolved to %q, want %q", res.User.ID, f.user.ID)
	}
}

// TestDiscoverableLoginRejectsAForeignUserHandle: the handle comes from the
// authenticator, so it is attacker-controlled. Trusting it to name the
// account would let a valid assertion for one credential sign in as
// anybody.
//
// The WebAuthn library enforces this too (§7.2 step 6), so this passes with
// the package's own check removed. It pins the behaviour rather than that
// one check.
func TestDiscoverableLoginRejectsAForeignUserHandle(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, passkey.Config{})
	auth := f.enroll(t, "Test Key")
	auth.signCount++

	victim := &store.User{ID: "3f0b1c2d-0000-4000-8000-000000000002", Email: "victim@example.com"}
	if err := f.users.CreateUser(ctx, victim); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	opts, sess, err := f.svc.BeginDiscoverableLogin(ctx)
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}
	// A genuine signature from Alice's authenticator, claiming to be the
	// victim's account.
	r := auth.assert(t, challengeFrom(t, opts), testRPID, testOrigin, victim.ID)
	if _, err := f.svc.FinishDiscoverableLogin(ctx, sess, r); err == nil {
		t.Fatal("a user handle naming an account the credential does not belong to must be refused")
	}
}

// TestSameAuthenticatorCannotRegisterTwice: two rows for one credential id
// make the assertion lookup ambiguous about whose it is.
func TestSameAuthenticatorCannotRegisterTwice(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, passkey.Config{})
	auth := f.enroll(t, "Test Key")

	opts, sess, err := f.svc.BeginRegistration(ctx, f.user.ID)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	r := auth.register(t, challengeFrom(t, opts), testRPID, testOrigin)
	if _, err := f.svc.FinishRegistration(ctx, f.user.ID, "Again", sess, r); !errors.Is(err, passkey.ErrAlreadyRegistered) {
		t.Fatalf("expected ErrAlreadyRegistered, got %v", err)
	}
}

// TestRemoveRefusesToStrandAnAccount: no password and no authenticator
// means an account nobody can reach, including its owner.
func TestRemoveRefusesToStrandAnAccount(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, passkey.Config{})
	f.enroll(t, "Only Key")
	list, _ := f.svc.List(ctx, f.user.ID)

	if err := f.svc.Remove(ctx, f.user.ID, list[0].ID); !errors.Is(err, passkey.ErrLastCredential) {
		t.Fatalf("expected ErrLastCredential, got %v", err)
	}
	u, _ := f.users.GetUserByID(ctx, f.user.ID)
	u.PasswordHash = "$argon2id$real"
	if err := f.users.UpdateUser(ctx, u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if err := f.svc.Remove(ctx, f.user.ID, list[0].ID); err != nil {
		t.Fatalf("Remove: %v", err)
	}
}

// TestCredentialManagementIsScopedToTheOwner, and reports a foreign
// credential as absent rather than forbidden so ids cannot be probed.
func TestCredentialManagementIsScopedToTheOwner(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, passkey.Config{})
	f.enroll(t, "Alice's Key")
	list, _ := f.svc.List(ctx, f.user.ID)

	const stranger = "3f0b1c2d-0000-4000-8000-000000000009"
	if err := f.svc.Rename(ctx, stranger, list[0].ID, "mine now"); !errors.Is(err, passkey.ErrCredentialNotFound) {
		t.Fatalf("expected ErrCredentialNotFound, got %v", err)
	}
	if err := f.svc.Remove(ctx, stranger, list[0].ID); !errors.Is(err, passkey.ErrCredentialNotFound) {
		t.Fatalf("expected ErrCredentialNotFound, got %v", err)
	}
}

// TestConfigIsValidatedAtStartup: an empty origin list allows every origin,
// which removes the check that makes the ceremony safe.
func TestConfigIsValidatedAtStartup(t *testing.T) {
	stores := passkey.Stores{Users: memstore.NewUserStore(), Credentials: memstore.NewWebAuthnCredentialStore()}
	if _, err := passkey.NewService(stores, passkey.Config{RPOrigins: []string{testOrigin}}); err == nil {
		t.Fatal("an empty RPID must be refused")
	}
	if _, err := passkey.NewService(stores, passkey.Config{RPID: testRPID}); err == nil {
		t.Fatal("an empty RPOrigins must be refused")
	}
}

// TestLoginWithNoCredentials reports the situation rather than producing an
// assertion request nothing can answer.
func TestLoginWithNoCredentials(t *testing.T) {
	f := newFixture(t, passkey.Config{})
	if _, _, err := f.svc.BeginLogin(context.Background(), f.user.ID); !errors.Is(err, passkey.ErrNoCredentials) {
		t.Fatalf("expected ErrNoCredentials, got %v", err)
	}
}

// TestSessionCannotSupplyItsOwnOrigin is the property TestWrongOriginIsRejected
// only half covers.
//
// wan.SessionData carries per-ceremony overrides for the origin allowlist
// and the RP id, and the library prefers them over Config at verification
// time. So a caller who can edit the session does not have to defeat the
// origin check -- it substitutes its own one-entry allowlist and is checked
// against that. TestWrongOriginIsRejected misses this because it hands back
// the server's own session, where Origin is empty.
//
// Config.RPOrigins is documented as what stops a page on another site from
// driving the authenticator, so this must hold for a tampered session too.
func TestSessionCannotSupplyItsOwnOrigin(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, passkey.Config{})
	auth := f.enroll(t, "Test Key")
	auth.signCount++

	opts, sess, err := f.svc.BeginLogin(ctx, f.user.ID)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}

	// The attacker rewrites the session to allow their own origin, which
	// is exactly what a forgeable ceremony cookie hands them.
	var raw map[string]any
	if err := json.Unmarshal(sess, &raw); err != nil {
		t.Fatalf("unmarshal session: %v", err)
	}
	raw["origin"] = "https://evil.example"
	raw["rpId"] = testRPID
	tampered, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}

	r := auth.assert(t, challengeFrom(t, opts), testRPID, "https://evil.example", f.user.ID)
	if _, err := f.svc.FinishLogin(ctx, f.user.ID, tampered, r); !errors.Is(err, passkey.ErrCeremony) {
		t.Fatalf("a session-supplied origin must not widen RPOrigins, got %v", err)
	}
}

// TestSessionWithoutAnExpiryIsRejected. The library skips the expiry check
// entirely when Expires is zero, so a session without one never times out
// -- which turns a 60-second ceremony into an indefinite one for anyone who
// can edit the session. Both Begin calls set it, so an absent expiry did
// not come from here.
func TestSessionWithoutAnExpiryIsRejected(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, passkey.Config{})
	auth := f.enroll(t, "Test Key")
	auth.signCount++

	opts, sess, err := f.svc.BeginLogin(ctx, f.user.ID)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(sess, &raw); err != nil {
		t.Fatalf("unmarshal session: %v", err)
	}
	delete(raw, "expires")
	tampered, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}

	r := auth.assert(t, challengeFrom(t, opts), testRPID, testOrigin, f.user.ID)
	if _, err := f.svc.FinishLogin(ctx, f.user.ID, tampered, r); !errors.Is(err, passkey.ErrSession) {
		t.Fatalf("a session with no expiry must be refused, got %v", err)
	}
}
