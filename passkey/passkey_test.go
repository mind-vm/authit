package passkey_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

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
	challenges := memstore.NewWebAuthnChallengeStore()
	svc, err := passkey.NewService(passkey.Stores{
		Users: users, Credentials: creds, Challenges: challenges,
	}, cfg)
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
	stores := passkey.Stores{
		Users: memstore.NewUserStore(), Credentials: memstore.NewWebAuthnCredentialStore(),
		Challenges: memstore.NewWebAuthnChallengeStore(),
	}
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

// tamperingChallenges wraps a real challenge store and edits rows on the
// way out, standing in for a host store that is wrong, compromised, or
// merely creative. The ceremony state is no longer reachable by a caller,
// so this is the only way left to ask what the package does when the row it
// gets back is not the row it wrote.
type tamperingChallenges struct {
	inner store.WebAuthnChallengeStore
	edit  func(*store.WebAuthnChallenge)
}

func (c tamperingChallenges) CreateWebAuthnChallenge(ctx context.Context, ch *store.WebAuthnChallenge) error {
	return c.inner.CreateWebAuthnChallenge(ctx, ch)
}

func (c tamperingChallenges) ConsumeWebAuthnChallenge(ctx context.Context, hash string) (*store.WebAuthnChallenge, error) {
	ch, err := c.inner.ConsumeWebAuthnChallenge(ctx, hash)
	if err != nil {
		return nil, err
	}
	c.edit(ch)
	return ch, nil
}

// newTamperedFixture builds a fixture whose challenge rows are edited by
// edit between being written and being read back.
func newTamperedFixture(t *testing.T, edit func(*store.WebAuthnChallenge)) fixture {
	t.Helper()
	users := memstore.NewUserStore()
	creds := memstore.NewWebAuthnCredentialStore()
	svc, err := passkey.NewService(passkey.Stores{
		Users: users, Credentials: creds,
		Challenges: tamperingChallenges{inner: memstore.NewWebAuthnChallengeStore(), edit: edit},
	}, passkey.Config{
		RPDisplayName: "Example", RPID: testRPID, RPOrigins: []string{testOrigin},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	u := &store.User{ID: "3f0b1c2d-0000-4000-8000-000000000001", Email: "alice@example.com"}
	if err := users.CreateUser(context.Background(), u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return fixture{svc: svc, users: users, creds: creds, user: *u}
}

// TestCeremonyHandleIsSingleUse is the property the challenge store exists
// for, and the one the package did not have.
//
// A passkey assertion is a bearer credential until the challenge it answers
// is spent. If nothing spends it, an assertion captured once -- from a
// request log, an APM trace, a debug proxy -- is replayable, and the
// signature counter does not save it: go-webauthn exempts a counter of zero
// from the clone check, and every synced passkey reports zero forever.
func TestCeremonyHandleIsSingleUse(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, passkey.Config{})
	auth := f.enroll(t, "Test Key")
	auth.signCount++

	opts, sess, err := f.svc.BeginLogin(ctx, f.user.ID)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	challenge := challengeFrom(t, opts)

	if _, err := f.svc.FinishLogin(ctx, f.user.ID, sess, auth.assert(t, challenge, testRPID, testOrigin, f.user.ID)); err != nil {
		t.Fatalf("the first use must succeed: %v", err)
	}
	// The identical assertion, replayed. Nothing about the request differs
	// -- same handle, same bytes, same signature -- which is exactly the
	// attacker's position.
	if _, err := f.svc.FinishLogin(ctx, f.user.ID, sess, auth.assert(t, challenge, testRPID, testOrigin, f.user.ID)); !errors.Is(err, passkey.ErrSession) {
		t.Fatalf("a spent ceremony must not be redeemable again, got %v", err)
	}
}

// TestRegistrationHandleCannotFinishALogin. The two ceremonies are told
// apart by which Finish is called, so nothing stops a caller from calling
// the other one -- and a registration challenge answered as a login would
// verify against a challenge the account owner never asked to authenticate
// with. authhandlers separates them by cookie name, bound into the cookie's
// MAC, but a host calling this package directly has no cookie.
func TestRegistrationHandleCannotFinishALogin(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, passkey.Config{})
	f.enroll(t, "Test Key")

	_, regSess, err := f.svc.BeginRegistration(ctx, f.user.ID)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if _, err := f.svc.FinishDiscoverableLogin(ctx, regSess, postJSON(t, map[string]any{})); !errors.Is(err, passkey.ErrSession) {
		t.Fatalf("a registration handle must not finish a login, got %v", err)
	}

	_, loginSess, err := f.svc.BeginDiscoverableLogin(ctx)
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}
	if _, err := f.svc.FinishRegistration(ctx, f.user.ID, "x", loginSess, postJSON(t, map[string]any{})); !errors.Is(err, passkey.ErrSession) {
		t.Fatalf("a login handle must not finish a registration, got %v", err)
	}
}

// TestUnknownHandleIsRefused: a handle that never existed and one already
// spent are the same answer, so neither reports which it was.
func TestUnknownHandleIsRefused(t *testing.T) {
	f := newFixture(t, passkey.Config{})
	for name, sess := range map[string]passkey.Session{
		"empty":   {},
		"garbage": passkey.Session("not-a-real-handle"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := f.svc.FinishDiscoverableLogin(context.Background(), sess, postJSON(t, map[string]any{}))
			if !errors.Is(err, passkey.ErrSession) {
				t.Fatalf("got %v, want ErrSession", err)
			}
		})
	}
}

// TestExpiredCeremonyIsRefused. The store returns an expired row like any
// other -- consuming it is still right, since a spent challenge should not
// linger -- so refusing it is this package's job.
func TestExpiredCeremonyIsRefused(t *testing.T) {
	ctx := context.Background()
	f := newTamperedFixture(t, func(c *store.WebAuthnChallenge) {
		c.ExpiresAt = time.Now().Add(-time.Second)
	})
	_, sess, err := f.svc.BeginDiscoverableLogin(ctx)
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}
	if _, err := f.svc.FinishDiscoverableLogin(ctx, sess, postJSON(t, map[string]any{})); !errors.Is(err, passkey.ErrSession) {
		t.Fatalf("an expired ceremony must be refused, got %v", err)
	}
}

// TestStoredOriginCannotWidenTheAllowlist.
//
// wan.SessionData carries per-ceremony overrides for the origin allowlist
// and RP id, and the library prefers them over Config at verification time.
// authit never writes either, so a row carrying them is a row something
// else edited -- and Config.RPOrigins is documented as the thing that stops
// another site driving the authenticator, which should not become untrue
// because a store handed back something unexpected.
func TestStoredOriginCannotWidenTheAllowlist(t *testing.T) {
	ctx := context.Background()
	f := newTamperedFixture(t, func(c *store.WebAuthnChallenge) {
		var held map[string]any
		if err := json.Unmarshal(c.Data, &held); err != nil {
			return
		}
		sess, _ := held["session"].(map[string]any)
		if sess == nil {
			return
		}
		sess["origin"] = "https://evil.example"
		sess["rpId"] = testRPID
		c.Data, _ = json.Marshal(held)
	})
	auth := f.enroll(t, "Test Key")
	auth.signCount++

	opts, sess, err := f.svc.BeginLogin(ctx, f.user.ID)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	r := auth.assert(t, challengeFrom(t, opts), testRPID, "https://evil.example", f.user.ID)
	if _, err := f.svc.FinishLogin(ctx, f.user.ID, sess, r); !errors.Is(err, passkey.ErrCeremony) {
		t.Fatalf("a stored origin must not widen RPOrigins, got %v", err)
	}
}

// TestChallengeStoreIsRequired. Not optional the way Tx is: without it a
// challenge is redeemable more than once, which is the whole vulnerability.
func TestChallengeStoreIsRequired(t *testing.T) {
	_, err := passkey.NewService(passkey.Stores{
		Users: memstore.NewUserStore(), Credentials: memstore.NewWebAuthnCredentialStore(),
	}, passkey.Config{RPID: testRPID, RPOrigins: []string{testOrigin}})
	if err == nil {
		t.Fatal("a Service with no challenge store must be refused at construction")
	}
}
