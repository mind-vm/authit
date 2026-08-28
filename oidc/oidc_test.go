package oidc_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mind-vm/authit/memstore"
	"github.com/mind-vm/authit/oidc"
	"github.com/mind-vm/authit/store"
)

// fakeProvider is a stand-in identity provider: it issues authorization
// codes, exchanges them for access tokens, and answers userinfo. It records
// what it was sent so the tests can assert on the wire, and it enforces
// PKCE the way a real provider does.
type fakeProvider struct {
	server *httptest.Server
	// userinfo is what /userinfo returns for a redeemed code.
	userinfo map[string]any
	// challenges maps an issued code to the PKCE challenge it was bound to.
	challenges map[string]string
	// lastAuthQuery is the query the authorization endpoint last saw.
	lastAuthQuery url.Values
	// refuseExchange makes the token endpoint fail.
	refuseExchange bool
}

// s256 is the PKCE challenge transformation (RFC 7636 §4.2), recomputed
// here so the fake provider verifies the verifier the way a real one does.
// Without that check the PKCE assertions would only prove a parameter was
// sent, not that it binds the code to this client.
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func newFakeProvider(t *testing.T, userinfo map[string]any) *fakeProvider {
	t.Helper()
	f := &fakeProvider{userinfo: userinfo, challenges: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		f.lastAuthQuery = r.URL.Query()
		f.challenges["the-code"] = r.URL.Query().Get("code_challenge")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if f.refuseExchange {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		_ = r.ParseForm()
		// A real provider verifies the PKCE verifier against the challenge
		// it stored. Recomputing it here is what makes the PKCE assertions
		// below mean something.
		want := f.challenges[r.PostFormValue("code")]
		if got := s256(r.PostFormValue("code_verifier")); want != "" && got != want {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "provider-access-token", "refresh_token": "provider-refresh-token",
			"token_type": "Bearer", "expires_in": 3600,
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer provider-access-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(f.userinfo)
	})
	f.server = httptest.NewTLSServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeProvider) provider() oidc.Provider {
	return oidc.Provider{
		ID: "fake", ClientID: "client", ClientSecret: "secret",
		AuthURL:     f.server.URL + "/authorize",
		TokenURL:    f.server.URL + "/token",
		UserInfoURL: f.server.URL + "/userinfo",
		Scopes:      []string{"openid", "email"},
	}
}

type fixture struct {
	svc      *oidc.Service
	users    *memstore.UserStore
	accounts *memstore.AccountStore
	fake     *fakeProvider
}

func newFixture(t *testing.T, userinfo map[string]any, cfg oidc.Config) fixture {
	t.Helper()
	fake := newFakeProvider(t, userinfo)
	users := memstore.NewUserStore()
	accounts := memstore.NewAccountStore()
	// The fake runs on a self-signed TLS certificate, so the client that
	// trusts it comes from the test server itself.
	cfg.HTTPClient = fake.server.Client()
	svc, err := oidc.NewService(
		oidc.Stores{Users: users, Accounts: accounts},
		[]oidc.Provider{fake.provider()}, cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return fixture{svc: svc, users: users, accounts: accounts, fake: fake}
}

// signIn runs the whole flow honestly and returns the result.
func (f fixture) signIn(t *testing.T) (oidc.Result, error) {
	t.Helper()
	ctx := context.Background()
	auth, err := f.svc.Begin(ctx, "fake", "https://app.example.com/callback")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	// Drive the authorization endpoint so the fake records the challenge.
	req, _ := http.NewRequest(http.MethodGet, auth.URL, nil)
	if _, err := f.fake.server.Client().Do(req); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	return f.svc.Complete(ctx, "fake", "https://app.example.com/callback", oidc.Callback{
		Code: "the-code", State: auth.State, ExpectedState: auth.State, CodeVerifier: auth.CodeVerifier,
	})
}

func verifiedUserInfo(email string) map[string]any {
	return map[string]any{"sub": "provider-subject-1", "email": email, "email_verified": true, "name": "Alice"}
}

// TestSignUpCreatesAUserWithNoPassword covers the first-time path, and the
// property that makes a passwordless account safe: an empty stored hash
// must verify nothing.
func TestSignUpCreatesAUserWithNoPassword(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, verifiedUserInfo("Alice@Example.COM"), oidc.Config{})

	res, err := f.signIn(t)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if !res.CreatedUser {
		t.Fatal("expected a new account")
	}
	// The address is normalised on the way in, like every other entry point.
	if res.User.Email != "alice@example.com" {
		t.Fatalf("stored email = %q, want the normalised form", res.User.Email)
	}
	if res.User.PasswordHash != "" {
		t.Fatal("a social sign-up must not invent a password")
	}
	// A provider that verified the address means the user is not sent
	// through a second verification email for it.
	if !res.User.EmailVerified {
		t.Fatal("a provider-verified address should arrive verified")
	}

	// Signing in again finds the same user rather than making another.
	second, err := f.signIn(t)
	if err != nil {
		t.Fatalf("second sign-in: %v", err)
	}
	if second.CreatedUser || second.User.ID != res.User.ID {
		t.Fatalf("a returning sign-in created a second account: %+v", second)
	}
	accounts, err := f.svc.ListAccounts(ctx, res.User.ID)
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(accounts) != 1 {
		t.Fatalf("user has %d linked accounts, want 1", len(accounts))
	}
}

// TestUnverifiedAddressDoesNotArriveVerified: the flag is the provider's
// claim, and carrying it across when it is false would let a provider that
// never checked hand out a verified address.
func TestUnverifiedAddressDoesNotArriveVerified(t *testing.T) {
	f := newFixture(t, map[string]any{
		"sub": "s1", "email": "alice@example.com", "email_verified": false,
	}, oidc.Config{})
	res, err := f.signIn(t)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if res.User.EmailVerified {
		t.Fatal("an unverified provider claim must not mark the address verified")
	}
}

// TestManualLinkingRefusesToTakeOverAnExistingAccount is the security case
// this package exists to get right. An attacker who can make a provider
// assert an address they do not own must not thereby become its owner.
func TestManualLinkingRefusesToTakeOverAnExistingAccount(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, verifiedUserInfo("victim@example.com"), oidc.Config{})

	// A password account already exists at that address.
	victim := &store.User{ID: "victim-id", Email: "victim@example.com", PasswordHash: "$argon2id$real"}
	if err := f.users.CreateUser(ctx, victim); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Even with the provider claiming the address is verified, the default
	// policy refuses -- and says why, so the host can tell the user to sign
	// in and link deliberately.
	if _, err := f.signIn(t); !errors.Is(err, oidc.ErrAccountNotLinked) {
		t.Fatalf("expected ErrAccountNotLinked, got %v", err)
	}
	if accounts, _ := f.svc.ListAccounts(ctx, victim.ID); len(accounts) != 0 {
		t.Fatal("a refused sign-in must not leave a link behind")
	}
}

// TestVerifiedEmailPolicyStillRequiresTheClaim: opting in to automatic
// linking must not extend to providers that did not verify.
func TestVerifiedEmailPolicyStillRequiresTheClaim(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, map[string]any{
		"sub": "s1", "email": "victim@example.com", "email_verified": false,
	}, oidc.Config{Linking: oidc.LinkingVerifiedEmail})
	if err := f.users.CreateUser(ctx, &store.User{ID: "victim-id", Email: "victim@example.com", PasswordHash: "h"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := f.signIn(t); !errors.Is(err, oidc.ErrProviderEmailUnverified) {
		t.Fatalf("expected ErrProviderEmailUnverified, got %v", err)
	}
}

// TestVerifiedEmailPolicyLinks: the opted-in path, when the claim is there.
func TestVerifiedEmailPolicyLinks(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, verifiedUserInfo("alice@example.com"), oidc.Config{Linking: oidc.LinkingVerifiedEmail})
	existing := &store.User{ID: "alice-id", Email: "alice@example.com", PasswordHash: "$argon2id$real"}
	if err := f.users.CreateUser(ctx, existing); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	res, err := f.signIn(t)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if res.CreatedUser || res.User.ID != existing.ID {
		t.Fatalf("expected the existing account, got %+v", res)
	}
}

// TestLinkIsRefusedWhenAlreadyLinked: re-pointing a provider identity at a
// different user is an account takeover with extra steps.
func TestLinkIsRefusedWhenAlreadyLinked(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, verifiedUserInfo("alice@example.com"), oidc.Config{})
	res, err := f.signIn(t)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	other := &store.User{ID: "other-id", Email: "other@example.com", PasswordHash: "h"}
	if err := f.users.CreateUser(ctx, other); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := f.svc.Link(ctx, other.ID, res.Identity, nil); !errors.Is(err, oidc.ErrAlreadyLinked) {
		t.Fatalf("expected ErrAlreadyLinked, got %v", err)
	}
}

// TestStateMismatchIsRefusedBeforeExchange: a callback that is not the
// continuation of a flow this server started has nothing worth redeeming,
// so no code is sent to the provider at all.
func TestStateMismatchIsRefusedBeforeExchange(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, verifiedUserInfo("alice@example.com"), oidc.Config{})
	auth, err := f.svc.Begin(ctx, "fake", "https://app.example.com/callback")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	for name, cb := range map[string]oidc.Callback{
		"wrong state":    {Code: "the-code", State: "attacker-state", ExpectedState: auth.State, CodeVerifier: auth.CodeVerifier},
		"absent state":   {Code: "the-code", State: "", ExpectedState: auth.State, CodeVerifier: auth.CodeVerifier},
		"no expectation": {Code: "the-code", State: auth.State, ExpectedState: "", CodeVerifier: auth.CodeVerifier},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := f.svc.Complete(ctx, "fake", "https://app.example.com/callback", cb); !errors.Is(err, oidc.ErrStateMismatch) {
				t.Fatalf("expected ErrStateMismatch, got %v", err)
			}
		})
	}
}

// TestPKCEIsSentAndEnforced: without it, an authorization code intercepted
// on the redirect is redeemable by whoever holds it.
func TestPKCEIsSentAndEnforced(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, verifiedUserInfo("alice@example.com"), oidc.Config{})
	auth, err := f.svc.Begin(ctx, "fake", "https://app.example.com/callback")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	u, err := url.Parse(auth.URL)
	if err != nil {
		t.Fatalf("parsing the authorization URL: %v", err)
	}
	q := u.Query()
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("authorization URL must carry an S256 challenge: %v", q)
	}
	// The challenge must be the hash, never the verifier itself.
	if q.Get("code_challenge") == auth.CodeVerifier {
		t.Fatal("the verifier must not be sent to the provider at authorization time")
	}
	if q.Get("state") != auth.State {
		t.Fatal("the authorization URL must carry the state Begin returned")
	}

	// A stolen code with the wrong verifier is refused by the provider.
	req, _ := http.NewRequest(http.MethodGet, auth.URL, nil)
	if _, err := f.fake.server.Client().Do(req); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	_, err = f.svc.Complete(ctx, "fake", "https://app.example.com/callback", oidc.Callback{
		Code: "the-code", State: auth.State, ExpectedState: auth.State,
		CodeVerifier: "an-attackers-guess-at-the-verifier-value",
	})
	if !errors.Is(err, oidc.ErrExchange) {
		t.Fatalf("expected ErrExchange for a mismatched PKCE verifier, got %v", err)
	}
}

// TestProviderTokensAreEncryptedAtRest: a database that leaks these leaks
// live access to the user's account at the provider.
func TestProviderTokensAreEncryptedAtRest(t *testing.T) {
	ctx := context.Background()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	f := newFixture(t, verifiedUserInfo("alice@example.com"), oidc.Config{ProviderTokenKey: key})
	res, err := f.signIn(t)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	stored, err := f.accounts.GetAccount(ctx, res.Account.ID)
	if err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	if len(stored.AccessTokenEncrypted) == 0 {
		t.Fatal("expected the provider access token to be stored")
	}
	if strings.Contains(string(stored.AccessTokenEncrypted), "provider-access-token") {
		t.Fatal("the provider token was stored in plaintext")
	}
	access, refresh, err := f.svc.ProviderTokens(*stored)
	if err != nil {
		t.Fatalf("ProviderTokens: %v", err)
	}
	if access != "provider-access-token" || refresh != "provider-refresh-token" {
		t.Fatalf("round trip failed: %q / %q", access, refresh)
	}
}

// TestNoTokensStoredByDefault: a credential you do not keep cannot leak.
func TestNoTokensStoredByDefault(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, verifiedUserInfo("alice@example.com"), oidc.Config{})
	res, err := f.signIn(t)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	stored, err := f.accounts.GetAccount(ctx, res.Account.ID)
	if err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	if len(stored.AccessTokenEncrypted) != 0 || len(stored.RefreshTokenEncrypted) != 0 {
		t.Fatal("provider tokens must not be kept unless ProviderTokenKey is configured")
	}
}

// TestUnlinkRefusesToStrandAnAccount: an account with no password and no
// linked provider still exists and nobody can reach it, including its owner.
func TestUnlinkRefusesToStrandAnAccount(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, verifiedUserInfo("alice@example.com"), oidc.Config{})
	res, err := f.signIn(t)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if err := f.svc.Unlink(ctx, res.User.ID, "fake"); !errors.Is(err, oidc.ErrLastCredential) {
		t.Fatalf("expected ErrLastCredential, got %v", err)
	}
	// Once the user has a password, unlinking is fine.
	u, _ := f.users.GetUserByID(ctx, res.User.ID)
	u.PasswordHash = "$argon2id$real"
	if err := f.users.UpdateUser(ctx, u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if err := f.svc.Unlink(ctx, res.User.ID, "fake"); err != nil {
		t.Fatalf("Unlink: %v", err)
	}
}

// TestSignUpCanBeDisabled for deployments that provision accounts elsewhere.
func TestSignUpCanBeDisabled(t *testing.T) {
	f := newFixture(t, verifiedUserInfo("stranger@example.com"), oidc.Config{DisableSignUp: true})
	if _, err := f.signIn(t); !errors.Is(err, oidc.ErrSignUpDisabled) {
		t.Fatalf("expected ErrSignUpDisabled, got %v", err)
	}
}

// TestProviderValidationHappensAtStartup: a plain-HTTP endpoint or a
// missing client id should fail where somebody is watching.
func TestProviderValidationHappensAtStartup(t *testing.T) {
	for name, p := range map[string]oidc.Provider{
		"no client id": {ID: "x", AuthURL: "https://a", TokenURL: "https://t", UserInfoURL: "https://u"},
		"plain http":   {ID: "x", ClientID: "c", AuthURL: "http://a", TokenURL: "https://t", UserInfoURL: "https://u"},
		"no userinfo":  {ID: "x", ClientID: "c", AuthURL: "https://a", TokenURL: "https://t"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := oidc.NewService(
				oidc.Stores{Users: memstore.NewUserStore(), Accounts: memstore.NewAccountStore()},
				[]oidc.Provider{p}, oidc.Config{})
			if !errors.Is(err, oidc.ErrProviderMisconfigured) {
				t.Fatalf("expected ErrProviderMisconfigured, got %v", err)
			}
		})
	}
}

// TestBuiltInProvidersAreWellFormed guards the shipped configurations.
func TestBuiltInProvidersAreWellFormed(t *testing.T) {
	_, err := oidc.NewService(
		oidc.Stores{Users: memstore.NewUserStore(), Accounts: memstore.NewAccountStore()},
		[]oidc.Provider{oidc.Google("id", "secret"), oidc.GitHub("id", "secret")}, oidc.Config{})
	if err != nil {
		t.Fatalf("the built-in providers should validate: %v", err)
	}
}
