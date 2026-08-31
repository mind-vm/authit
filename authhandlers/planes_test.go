package authhandlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mind-vm/authit/authhandlers"
	"github.com/mind-vm/authit/authithttp"
	"github.com/mind-vm/authit/device"
	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/memstore"
	"github.com/mind-vm/authit/pat"
	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/authit/superuser"
	"github.com/mind-vm/authit/team"
	"github.com/mind-vm/authit/user"
)

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

type planes struct {
	signer *authitjwt.HMACSigner
	users  *user.Service
	teams  *team.Service
	pats   *pat.Service
	supers *superuser.Service
	device *device.Service
}

func newPlanes(t *testing.T) *planes {
	t.Helper()
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	signer, err := authitjwt.NewHMACSigner(secret, authitjwt.Defaults{Issuer: "authhandlers-test", TTL: time.Minute})
	if err != nil {
		t.Fatalf("NewHMACSigner: %v", err)
	}
	users, err := user.NewService(user.Stores{
		Users:              memstore.NewUserStore(),
		RefreshTokens:      memstore.NewRefreshTokenStore(),
		PasswordResets:     memstore.NewPasswordResetStore(),
		EmailVerifications: memstore.NewEmailVerificationStore(),
		TOTP:               memstore.NewTOTPStore(),
		PendingTwoFactor:   memstore.NewPendingTwoFactorStore(),
		Lockouts:           memstore.NewLockoutStore(),
	}, signer, nil, user.Config{EmailVerification: user.EmailVerificationOptional})
	if err != nil {
		t.Fatalf("user.NewService: %v", err)
	}
	teams, err := team.NewService(team.Stores{
		Teams:       memstore.NewTeamStore(),
		Members:     memstore.NewMemberStore(),
		Invitations: memstore.NewInvitationStore(),
	}, nil, team.Config{})
	if err != nil {
		t.Fatalf("team.NewService: %v", err)
	}
	pats, err := pat.NewService(pat.Stores{Tokens: memstore.NewPersonalAccessTokenStore()}, pat.Config{Prefix: "test_"})
	if err != nil {
		t.Fatalf("pat.NewService: %v", err)
	}
	supers, err := superuser.NewService(superuser.Stores{
		Superusers:    memstore.NewSuperuserStore(),
		RefreshTokens: memstore.NewSuperuserRefreshTokenStore(),
	}, signer, superuser.Config{})
	if err != nil {
		t.Fatalf("superuser.NewService: %v", err)
	}
	// A short poll interval keeps the tests fast while still exercising
	// the real RFC 8628 §3.5 slow_down logic rather than skipping past it.
	dev, err := device.NewService(device.Stores{Authorizations: memstore.NewDeviceAuthorizationStore()},
		device.Config{PollInterval: 10 * time.Millisecond, SlowDownIncrement: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("device.NewService: %v", err)
	}
	return &planes{signer: signer, users: users, teams: teams, pats: pats, supers: supers, device: dev}
}

// login registers a user and returns their id and access token.
func (p *planes) login(t *testing.T, email string) (userID, token string) {
	t.Helper()
	ctx := context.Background()
	const password = "correct-horse-battery"
	u, err := p.users.Register(ctx, email, password)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	res, err := p.users.Authenticate(ctx, email, password, "ua", "ip")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	return u.ID, res.Tokens.AccessToken
}

func do(t *testing.T, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		r = httptest.NewRequest(method, path, bytes.NewReader(buf))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// ---------------------------------------------------------------------------
// team: authorization
// ---------------------------------------------------------------------------

// TestTeamRoutesRequireAnAuthorizer: the team package does not check the
// caller's role, so a route group that skipped that check would let any
// authenticated user manage any team. Refusing at construction makes that
// impossible to do by omission.
func TestTeamRoutesRequireAnAuthorizer(t *testing.T) {
	p := newPlanes(t)
	defer func() {
		if recover() == nil {
			t.Fatal("NewTeamHandler must refuse a nil TeamAuthorizer")
		}
	}()
	authhandlers.NewTeamHandler(p.teams, authithttp.VerifierAuth(p.signer), nil)
}

// TestOutsiderCannotManageAnotherTeam is the privilege-escalation case the
// authorizer exists to prevent.
func TestOutsiderCannotManageAnotherTeam(t *testing.T) {
	p := newPlanes(t)
	h := authhandlers.NewTeamHandler(p.teams, authithttp.VerifierAuth(p.signer), authhandlers.RoleAuthorizer{Teams: p.teams})

	_, ownerToken := p.login(t, "owner@example.com")
	_, outsiderToken := p.login(t, "outsider@example.com")

	w := do(t, h, "POST", "/teams", ownerToken, map[string]string{
		"name": "Acme", "slug": "acme", "display_name": "Owner",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create team: %d %s", w.Code, w.Body)
	}
	created := decode[map[string]any](t, w)
	teamID := created["id"].(string)

	// Find the owner's member id, which the outsider will try to act on.
	w = do(t, h, "GET", "/teams/"+teamID+"/members", ownerToken, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list members: %d %s", w.Code, w.Body)
	}
	members := decode[[]map[string]any](t, w)
	if len(members) != 1 {
		t.Fatalf("expected the owner to be the only member, got %d", len(members))
	}
	memberID := members[0]["id"].(string)

	for _, c := range []struct {
		name, method, path string
		body               any
	}{
		{"view", "GET", "/teams/" + teamID, nil},
		{"list members", "GET", "/teams/" + teamID + "/members", nil},
		{"change role", "PATCH", "/members/" + memberID + "/role", map[string]string{"role": "member"}},
		{"deactivate", "PATCH", "/members/" + memberID + "/active", map[string]bool{"is_active": false}},
		{"remove", "DELETE", "/members/" + memberID, nil},
		{"invite", "POST", "/teams/" + teamID + "/invitations", map[string]string{"email": "x@example.com", "role": "member"}},
		{"list invitations", "GET", "/teams/" + teamID + "/invitations", nil},
	} {
		w := do(t, h, c.method, c.path, outsiderToken, c.body)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s: an outsider got %d, want 403: %s", c.name, w.Code, w.Body)
		}
	}
}

// TestPlainMemberCannotManageMembers: authenticated and in the team is not
// the same as allowed to change it.
func TestPlainMemberCannotManageMembers(t *testing.T) {
	ctx := context.Background()
	p := newPlanes(t)
	h := authhandlers.NewTeamHandler(p.teams, authithttp.VerifierAuth(p.signer), authhandlers.RoleAuthorizer{Teams: p.teams})

	ownerID, ownerToken := p.login(t, "owner@example.com")
	memberUserID, memberToken := p.login(t, "member@example.com")

	tm, err := p.teams.CreateTeam(ctx, "Acme", "acme", ownerID, "Owner", "owner@example.com")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	raw, _, err := p.teams.CreateInvitation(ctx, tm.ID, "", "member@example.com", store.RoleMember)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	if _, err := p.teams.AcceptInvitation(ctx, raw, memberUserID, "member@example.com", "Member"); err != nil {
		t.Fatalf("AcceptInvitation: %v", err)
	}

	// A plain member may look.
	if w := do(t, h, "GET", "/teams/"+tm.ID, memberToken, nil); w.Code != http.StatusOK {
		t.Fatalf("a member should be able to view: %d %s", w.Code, w.Body)
	}
	// But not touch.
	w := do(t, h, "POST", "/teams/"+tm.ID+"/invitations", memberToken,
		map[string]string{"email": "x@example.com", "role": "member"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("a plain member got %d inviting, want 403: %s", w.Code, w.Body)
	}
	// The owner may.
	w = do(t, h, "POST", "/teams/"+tm.ID+"/invitations", ownerToken,
		map[string]string{"email": "x@example.com", "role": "member"})
	if w.Code != http.StatusCreated {
		t.Fatalf("owner inviting: %d %s", w.Code, w.Body)
	}
}

// TestInvitationCannotBeAcceptedByTheWrongAccount: the email bound to an
// invitation is what makes it an invitation rather than a coupon. It must
// come from the token, never the request body.
func TestInvitationCannotBeAcceptedByTheWrongAccount(t *testing.T) {
	ctx := context.Background()
	p := newPlanes(t)
	h := authhandlers.NewTeamHandler(p.teams, authithttp.VerifierAuth(p.signer), authhandlers.RoleAuthorizer{Teams: p.teams})

	ownerID, ownerToken := p.login(t, "owner@example.com")
	_, attackerToken := p.login(t, "attacker@example.com")

	tm, err := p.teams.CreateTeam(ctx, "Acme", "acme", ownerID, "Owner", "owner@example.com")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	w := do(t, h, "POST", "/teams/"+tm.ID+"/invitations", ownerToken,
		map[string]string{"email": "invited@example.com", "role": "member"})
	if w.Code != http.StatusCreated {
		t.Fatalf("invite: %d %s", w.Code, w.Body)
	}
	token := decode[map[string]any](t, w)["token"].(string)

	// The attacker holds the token and claims to be the invitee. The body
	// has no email field at all, so there is nothing to lie with.
	w = do(t, h, "POST", "/invitations/accept", attackerToken,
		map[string]string{"token": token, "display_name": "Attacker"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("an invitation must not be acceptable by another account: %d %s", w.Code, w.Body)
	}
}

// TestCrossTeamInvitationRevocationIsRefused: authorization passes because
// the caller really does administer the team named in the path, so the
// ownership of the invitation itself has to be checked separately.
func TestCrossTeamInvitationRevocationIsRefused(t *testing.T) {
	ctx := context.Background()
	p := newPlanes(t)
	h := authhandlers.NewTeamHandler(p.teams, authithttp.VerifierAuth(p.signer), authhandlers.RoleAuthorizer{Teams: p.teams})

	aliceID, aliceToken := p.login(t, "alice@example.com")
	bobID, bobToken := p.login(t, "bob@example.com")

	teamA, err := p.teams.CreateTeam(ctx, "A", "a", aliceID, "Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	teamB, err := p.teams.CreateTeam(ctx, "B", "b", bobID, "Bob", "bob@example.com")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	w := do(t, h, "POST", "/teams/"+teamB.ID+"/invitations", bobToken,
		map[string]string{"email": "guest@example.com", "role": "member"})
	if w.Code != http.StatusCreated {
		t.Fatalf("invite: %d %s", w.Code, w.Body)
	}
	invID := decode[map[string]any](t, w)["invitation"].(map[string]any)["id"].(string)

	// Alice administers team A, and names it in the path, but the
	// invitation belongs to team B.
	w = do(t, h, "DELETE", "/teams/"+teamA.ID+"/invitations/"+invID, aliceToken, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-team revocation got %d, want 404: %s", w.Code, w.Body)
	}
	// Bob can still revoke his own.
	if w := do(t, h, "DELETE", "/teams/"+teamB.ID+"/invitations/"+invID, bobToken, nil); w.Code != http.StatusNoContent {
		t.Fatalf("owner revoking own invitation: %d %s", w.Code, w.Body)
	}
}

// ---------------------------------------------------------------------------
// superuser: audience separation
// ---------------------------------------------------------------------------

// TestUserTokenIsRejectedByOperatorRoutes is the boundary that makes a
// separate operator plane worth having. Both planes are signed by the same
// key, so only the audience check distinguishes them -- validating an
// operator route with a plain user verifier would hand every user
// Impersonate.
func TestUserTokenIsRejectedByOperatorRoutes(t *testing.T) {
	ctx := context.Background()
	p := newPlanes(t)
	h := authhandlers.NewSuperuserHandler(p.supers)

	if _, err := p.supers.Bootstrap(ctx, "ops@example.com", "correct-horse-battery", "Ops"); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	_, userToken := p.login(t, "alice@example.com")

	for _, c := range []struct {
		name, method, path string
		body               any
	}{
		{"list", "GET", "/superusers", nil},
		{"create", "POST", "/superusers", map[string]string{"email": "x@example.com", "password": "correct-horse-battery"}},
		{"impersonate", "POST", "/impersonate", map[string]string{"user_id": "u1", "user_email": "a@example.com"}},
	} {
		w := do(t, h, c.method, c.path, userToken, c.body)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s: a user token got %d, want 401: %s", c.name, w.Code, w.Body)
		}
	}

	// An operator token works on the same routes.
	tokens, err := p.supers.Authenticate(ctx, "ops@example.com", "correct-horse-battery", "ua", "ip")
	if err != nil {
		t.Fatalf("superuser Authenticate: %v", err)
	}
	if w := do(t, h, "GET", "/superusers", tokens.AccessToken, nil); w.Code != http.StatusOK {
		t.Fatalf("operator token on /superusers: %d %s", w.Code, w.Body)
	}
}

// ---------------------------------------------------------------------------
// pat
// ---------------------------------------------------------------------------

func TestPATRoutesActOnTheCallersOwnTokensOnly(t *testing.T) {
	p := newPlanes(t)
	h := authhandlers.NewPATHandler(p.pats, authithttp.VerifierAuth(p.signer))

	_, aliceToken := p.login(t, "alice@example.com")
	_, bobToken := p.login(t, "bob@example.com")

	w := do(t, h, "POST", "/me/tokens", aliceToken, map[string]any{
		"name": "laptop", "scopes": []string{"read"},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	created := decode[map[string]any](t, w)
	raw := created["token"].(string)
	if raw == "" {
		t.Fatal("the raw token must be returned once, at creation")
	}
	patObj := created["personal_access_token"].(map[string]any)
	if _, leaked := patObj["token_hash"]; leaked {
		t.Fatal("the stored hash must never be serialised")
	}
	tokenID := patObj["id"].(string)

	// Bob cannot see or revoke Alice's token, and gets 404 rather than 403
	// so the response is not an existence oracle.
	if w := do(t, h, "GET", "/me/tokens", bobToken, nil); w.Code != http.StatusOK {
		t.Fatalf("bob list: %d", w.Code)
	} else if got := decode[[]map[string]any](t, w); len(got) != 0 {
		t.Fatalf("bob should see no tokens, got %d", len(got))
	}
	if w := do(t, h, "DELETE", "/me/tokens/"+tokenID, bobToken, nil); w.Code != http.StatusNotFound {
		t.Fatalf("bob revoking alice's token got %d, want 404: %s", w.Code, w.Body)
	}
	// Alice can.
	if w := do(t, h, "DELETE", "/me/tokens/"+tokenID, aliceToken, nil); w.Code != http.StatusNoContent {
		t.Fatalf("alice revoking own token: %d %s", w.Code, w.Body)
	}
}

// ---------------------------------------------------------------------------
// device: RFC 8628 wire format
// ---------------------------------------------------------------------------

func newDeviceHandler(t *testing.T, p *planes) http.Handler {
	t.Helper()
	return authhandlers.NewDeviceHandler(p.device, authithttp.VerifierAuth(p.signer),
		func(_ context.Context, userID, scope string) (any, error) {
			return map[string]any{"access_token": "minted-for-" + userID, "token_type": "Bearer", "scope": scope}, nil
		}, "https://example.com/device")
}

func postForm(t *testing.T, h http.Handler, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// TestDeviceFlowWireFormat pins the protocol details a real CLI depends on:
// form-encoded requests, snake_case JSON, seconds not durations, and the
// RFC 6749 §5.2 error shape whose field is error_description, not message.
func TestDeviceFlowWireFormat(t *testing.T) {
	p := newPlanes(t)
	h := newDeviceHandler(t, p)
	userID, userToken := p.login(t, "alice@example.com")

	w := postForm(t, h, "/device/code", url.Values{"client_id": {"cli"}, "scope": {"read write"}})
	if w.Code != http.StatusOK {
		t.Fatalf("device/code: %d %s", w.Code, w.Body)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	codeResp := decode[map[string]any](t, w)
	for _, field := range []string{"device_code", "user_code", "verification_uri", "expires_in", "interval"} {
		if _, ok := codeResp[field]; !ok {
			t.Fatalf("device/code response is missing %q: %v", field, codeResp)
		}
	}
	if codeResp["verification_uri"] != "https://example.com/device" {
		t.Fatalf("verification_uri = %v", codeResp["verification_uri"])
	}
	// expires_in is seconds, not nanoseconds: a duration marshalled raw
	// would be off by a factor of a billion.
	if codeResp["expires_in"].(float64) != 900 {
		t.Fatalf("expires_in must be seconds, got %v", codeResp["expires_in"])
	}
	// interval must never be 0 or absent. A client that sees no interval
	// assumes 5 seconds (§3.2), so a sub-second configured interval
	// truncated to 0 would silently become slower than configured -- this
	// handler rounds up to 1 instead.
	if iv, ok := codeResp["interval"].(float64); !ok || iv < 1 {
		t.Fatalf("interval must always be present and at least 1, got %v", codeResp["interval"])
	}
	deviceCode := codeResp["device_code"].(string)
	userCode := codeResp["user_code"].(string)

	// Polling before approval: authorization_pending, in the OAuth error
	// shape, and 400 per RFC 6749 §5.2.
	w = postForm(t, h, "/device/token", url.Values{
		"grant_type": {authhandlers.DeviceGrantType}, "device_code": {deviceCode}, "client_id": {"cli"},
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("pending poll: %d %s", w.Code, w.Body)
	}
	pending := decode[map[string]any](t, w)
	if pending["error"] != "authorization_pending" {
		t.Fatalf("error = %v, want authorization_pending", pending["error"])
	}
	if _, ok := pending["error_description"]; !ok {
		t.Fatal("the OAuth error body uses error_description, not message")
	}

	// Wrong grant type is its own code.
	w = postForm(t, h, "/device/token", url.Values{"grant_type": {"password"}, "device_code": {deviceCode}})
	if got := decode[map[string]any](t, w)["error"]; got != "unsupported_grant_type" {
		t.Fatalf("error = %v, want unsupported_grant_type", got)
	}

	// Approve, then poll again -- respecting the interval this time.
	if w := do(t, h, "POST", "/device/approve", userToken, map[string]string{"user_code": userCode}); w.Code != http.StatusNoContent {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	time.Sleep(60 * time.Millisecond)
	w = postForm(t, h, "/device/token", url.Values{
		"grant_type": {authhandlers.DeviceGrantType}, "device_code": {deviceCode}, "client_id": {"cli"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("token after approval: %d %s", w.Code, w.Body)
	}
	issued := decode[map[string]any](t, w)
	if issued["access_token"] != "minted-for-"+userID {
		t.Fatalf("the host's issuer must produce the credential, got %v", issued)
	}
	if issued["scope"] != "read write" {
		t.Fatalf("scope should reach the issuer, got %v", issued["scope"])
	}
}

func TestDeviceDenialIsReportedAsAccessDenied(t *testing.T) {
	p := newPlanes(t)
	h := newDeviceHandler(t, p)
	_, userToken := p.login(t, "alice@example.com")

	w := postForm(t, h, "/device/code", url.Values{"client_id": {"cli"}})
	codeResp := decode[map[string]any](t, w)

	if w := do(t, h, "POST", "/device/deny", userToken, map[string]string{"user_code": codeResp["user_code"].(string)}); w.Code != http.StatusNoContent {
		t.Fatalf("deny: %d %s", w.Code, w.Body)
	}
	time.Sleep(30 * time.Millisecond)
	w = postForm(t, h, "/device/token", url.Values{
		"grant_type": {authhandlers.DeviceGrantType}, "device_code": {codeResp["device_code"].(string)},
	})
	if got := decode[map[string]any](t, w)["error"]; got != "access_denied" {
		t.Fatalf("error = %v, want access_denied", got)
	}
}

// TestDeviceHandlerRefusesIncompleteWiring: authit resolves who approved
// but does not mint, so an endpoint without an issuer cannot answer. Fail
// at startup rather than at 3am.
func TestDeviceHandlerRefusesIncompleteWiring(t *testing.T) {
	p := newPlanes(t)
	for _, c := range []struct {
		name   string
		issuer authhandlers.DeviceTokenIssuer
		uri    string
	}{
		{"no issuer", nil, "https://example.com/device"},
		{"no verification uri", func(context.Context, string, string) (any, error) { return nil, nil }, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("NewDeviceHandler should have refused")
				}
			}()
			authhandlers.NewDeviceHandler(p.device, authithttp.VerifierAuth(p.signer), c.issuer, c.uri)
		})
	}
}

// ---------------------------------------------------------------------------
// shared error mapping
// ---------------------------------------------------------------------------

// TestWeakPasswordAndRateLimitAreMapped: both sentinels arrived with recent
// hardening work and had no HTTP mapping, so they were surfacing as opaque
// 500s.
func TestWeakPasswordIsMapped(t *testing.T) {
	h, _, _ := newTestServer(t)
	w := do(t, h, "POST", "/register", "", map[string]string{
		"email": "alice@example.com", "password": "short",
	})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a weak password got %d, want 422: %s", w.Code, w.Body)
	}
	if got := decode[map[string]any](t, w)["error"]; got != "weak_password" {
		t.Fatalf("error code = %v, want weak_password", got)
	}
}

// TestDevicePollingTooFastIsSlowDown covers RFC 8628 §3.5's back-off
// signal. It gets its own fixture with a long poll interval so that two
// back-to-back requests are unambiguously too fast -- asserting this inside
// the main flow test made it depend on how long JSON decoding happened to
// take.
func TestDevicePollingTooFastIsSlowDown(t *testing.T) {
	p := newPlanes(t)
	dev, err := device.NewService(
		device.Stores{Authorizations: memstore.NewDeviceAuthorizationStore()},
		device.Config{PollInterval: time.Hour},
	)
	if err != nil {
		t.Fatalf("device.NewService: %v", err)
	}
	h := authhandlers.NewDeviceHandler(dev, authithttp.VerifierAuth(p.signer),
		func(context.Context, string, string) (any, error) { return map[string]any{}, nil },
		"https://example.com/device")

	w := postForm(t, h, "/device/code", url.Values{"client_id": {"cli"}})
	deviceCode := decode[map[string]any](t, w)["device_code"].(string)

	poll := func() string {
		w := postForm(t, h, "/device/token", url.Values{
			"grant_type": {authhandlers.DeviceGrantType}, "device_code": {deviceCode},
		})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("poll: %d %s", w.Code, w.Body)
		}
		return decode[map[string]any](t, w)["error"].(string)
	}
	if got := poll(); got != "authorization_pending" {
		t.Fatalf("first poll = %v, want authorization_pending", got)
	}
	if got := poll(); got != "slow_down" {
		t.Fatalf("a poll inside the interval = %v, want slow_down", got)
	}
}

// TestAdminCannotBecomeOwnerAndEvictTheFounder.
//
// RoleAuthorizer grants owner and admin the same TeamActionManageMembers,
// and the only invariant the team package enforces about owners is that the
// last one cannot be removed. An admin who can grant the owner role
// manufactures the second owner that guard is counting, and the founder
// stops being the last one -- so a role the library treats as the top of
// the team is reachable from below it, and the founder can then be removed
// with no way back in.
//
// Both routes that can grant it are covered. Gating only the role change
// would leave the same result available to any admin with a second address:
// AcceptInvitation copies the invitation's role onto the new member
// verbatim.
func TestAdminCannotBecomeOwnerAndEvictTheFounder(t *testing.T) {
	ctx := context.Background()
	p := newPlanes(t)
	h := authhandlers.NewTeamHandler(p.teams, authithttp.VerifierAuth(p.signer), authhandlers.RoleAuthorizer{Teams: p.teams})

	ownerID, ownerToken := p.login(t, "founder@example.com")
	adminUserID, adminToken := p.login(t, "admin@example.com")

	tm, err := p.teams.CreateTeam(ctx, "Acme", "acme", ownerID, "Founder", "founder@example.com")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	raw, _, err := p.teams.CreateInvitation(ctx, tm.ID, "", "admin@example.com", store.RoleAdmin)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	admin, err := p.teams.AcceptInvitation(ctx, raw, adminUserID, "admin@example.com", "Admin")
	if err != nil {
		t.Fatalf("AcceptInvitation: %v", err)
	}
	founder, err := p.teams.GetMemberByUserAndTeam(ctx, ownerID, tm.ID)
	if err != nil {
		t.Fatalf("GetMemberByUserAndTeam: %v", err)
	}

	// The admin is a real admin: ordinary member management still works,
	// so this is a check on the owner role and not a blanket refusal.
	if w := do(t, h, "POST", "/teams/"+tm.ID+"/invitations", adminToken,
		map[string]string{"email": "colleague@example.com", "role": "member"}); w.Code != http.StatusCreated {
		t.Fatalf("an admin must still be able to invite a member: %d %s", w.Code, w.Body)
	}

	// Route 1: promote yourself.
	if w := do(t, h, "PATCH", "/members/"+admin.ID+"/role", adminToken,
		map[string]string{"role": "owner"}); w.Code != http.StatusForbidden {
		t.Fatalf("an admin granting itself owner got %d, want 403: %s", w.Code, w.Body)
	}
	// Route 2: invite a second identity as owner.
	if w := do(t, h, "POST", "/teams/"+tm.ID+"/invitations", adminToken,
		map[string]string{"email": "admin-alt@example.com", "role": "owner"}); w.Code != http.StatusForbidden {
		t.Fatalf("an admin inviting an owner got %d, want 403: %s", w.Code, w.Body)
	}
	// And the founder cannot be pushed out directly either.
	if w := do(t, h, "DELETE", "/members/"+founder.ID, adminToken, nil); w.Code != http.StatusForbidden {
		t.Fatalf("an admin removing the owner got %d, want 403: %s", w.Code, w.Body)
	}
	if w := do(t, h, "PATCH", "/members/"+founder.ID+"/active", adminToken,
		map[string]bool{"is_active": false}); w.Code != http.StatusForbidden {
		t.Fatalf("an admin deactivating the owner got %d, want 403: %s", w.Code, w.Body)
	}

	// The owner may still do all of it -- the new action is a restriction
	// on admins, not a lock on the team.
	if w := do(t, h, "PATCH", "/members/"+admin.ID+"/role", ownerToken,
		map[string]string{"role": "owner"}); w.Code != http.StatusNoContent {
		t.Fatalf("an owner granting owner got %d, want 204: %s", w.Code, w.Body)
	}
}

// TestOpaqueSessionModeOverHTTP wires the user plane in
// user.SessionModeOpaque and drives it end to end: sign in, use the session
// on a protected route, revoke it, and find the very next request refused.
//
// The JWT-mode equivalent cannot assert that last step, which is the entire
// point of the mode -- there, a revoked session keeps working until the
// access token expires.
func TestOpaqueSessionModeOverHTTP(t *testing.T) {
	ctx := context.Background()
	p := newPlanes(t)

	svc, err := user.NewService(user.Stores{
		Users:              memstore.NewUserStore(),
		RefreshTokens:      memstore.NewRefreshTokenStore(),
		PasswordResets:     memstore.NewPasswordResetStore(),
		EmailVerifications: memstore.NewEmailVerificationStore(),
		TOTP:               memstore.NewTOTPStore(),
		PendingTwoFactor:   memstore.NewPendingTwoFactorStore(),
		Lockouts:           memstore.NewLockoutStore(),
	}, p.signer, nil, user.Config{
		SessionMode:       user.SessionModeOpaque,
		EmailVerification: user.EmailVerificationOptional,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	// UserSessionAuth is the whole wiring difference: a lookup per
	// request instead of a signature check.
	h := authhandlers.NewUserHandler(svc, authhandlers.UserSessionAuth(svc))

	u, err := svc.Register(ctx, "opaque@example.com", "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	w := do(t, h, "POST", "/login", "", map[string]string{
		"email": "opaque@example.com", "password": "correct-horse-battery-staple",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	body := decode[map[string]any](t, w)
	tokens, _ := body["tokens"].(map[string]any)
	token, _ := tokens["access_token"].(string)
	if token == "" {
		t.Fatalf("expected a session token, got %v", body)
	}
	if _, present := tokens["refresh_token"]; present {
		t.Fatalf("opaque mode must issue one credential, and must not carry the field at all: %v", tokens)
	}

	// The session works on a protected route.
	if w := do(t, h, "GET", "/me/sessions", token, nil); w.Code != http.StatusOK {
		t.Fatalf("listing sessions with a live session: %d %s", w.Code, w.Body)
	}

	// /refresh is absent, not broken: there is nothing to refresh.
	if w := do(t, h, "POST", "/refresh", "", map[string]string{"refresh_token": token}); w.Code != http.StatusNotFound {
		t.Fatalf("POST /refresh in opaque mode = %d, want 404: %s", w.Code, w.Body)
	}

	sessions, err := svc.ListSessions(ctx, u.ID, token)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected one session, got %+v", sessions)
	}
	if w := do(t, h, "DELETE", "/me/sessions/"+sessions[0].ID, token, nil); w.Code != http.StatusNoContent {
		t.Fatalf("revoking: %d %s", w.Code, w.Body)
	}

	// The next request. No waiting for anything to expire.
	if w := do(t, h, "GET", "/me/sessions", token, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("a revoked session got %d on the next request, want 401: %s", w.Code, w.Body)
	}
}

// TestOpaqueSessionLogoutAndRevokeOthers covers the two session operations
// that name the caller's *own* session, which is the thing opaque mode
// changes and the thing the first version of this suite did not test.
//
// In JWT mode both take the refresh token from the request body. In opaque
// mode there is no refresh token, so a client following the documented
// contract sends nothing -- and the handler then revoked nothing while
// answering 204, or refused with a 500. Logging out is not a place to
// return success without doing anything.
func TestOpaqueSessionLogoutAndRevokeOthers(t *testing.T) {
	ctx := context.Background()
	p := newPlanes(t)
	svc, err := user.NewService(user.Stores{
		Users:              memstore.NewUserStore(),
		RefreshTokens:      memstore.NewRefreshTokenStore(),
		PasswordResets:     memstore.NewPasswordResetStore(),
		EmailVerifications: memstore.NewEmailVerificationStore(),
		TOTP:               memstore.NewTOTPStore(),
		PendingTwoFactor:   memstore.NewPendingTwoFactorStore(),
		Lockouts:           memstore.NewLockoutStore(),
	}, p.signer, nil, user.Config{
		SessionMode:       user.SessionModeOpaque,
		EmailVerification: user.EmailVerificationOptional,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	h := authhandlers.NewUserHandler(svc, authhandlers.UserSessionAuth(svc))

	u, err := svc.Register(ctx, "opaque@example.com", "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	signIn := func(t *testing.T) string {
		t.Helper()
		w := do(t, h, "POST", "/login", "", map[string]string{
			"email": "opaque@example.com", "password": "correct-horse-battery-staple",
		})
		if w.Code != http.StatusOK {
			t.Fatalf("login: %d %s", w.Code, w.Body)
		}
		return decode[map[string]any](t, w)["tokens"].(map[string]any)["access_token"].(string)
	}

	t.Run("logout ends the session it was called with", func(t *testing.T) {
		token := signIn(t)
		// The body carries nothing: an opaque-mode client has no refresh
		// token to put in it. The session is the bearer credential.
		if w := do(t, h, "POST", "/logout", token, map[string]string{}); w.Code != http.StatusNoContent {
			t.Fatalf("logout: %d %s", w.Code, w.Body)
		}
		if w := do(t, h, "GET", "/me/sessions", token, nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("the session survived logout: %d %s", w.Code, w.Body)
		}
	})

	t.Run("revoke-others keeps the caller signed in", func(t *testing.T) {
		keep := signIn(t)
		other := signIn(t)

		if w := do(t, h, "POST", "/me/sessions/revoke-others", keep, map[string]string{}); w.Code != http.StatusNoContent {
			t.Fatalf("revoke-others: %d %s", w.Code, w.Body)
		}
		if w := do(t, h, "GET", "/me/sessions", keep, nil); w.Code != http.StatusOK {
			t.Fatalf("revoke-others revoked the caller's own session: %d %s", w.Code, w.Body)
		}
		if w := do(t, h, "GET", "/me/sessions", other, nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("another session survived revoke-others: %d %s", w.Code, w.Body)
		}
		sessions, err := svc.ListSessions(ctx, u.ID, keep)
		if err != nil {
			t.Fatalf("ListSessions: %v", err)
		}
		if len(sessions) != 1 || !sessions[0].IsCurrent {
			t.Fatalf("expected one session, marked current, got %+v", sessions)
		}
	})

	t.Run("listing marks the caller's own session current", func(t *testing.T) {
		token := signIn(t)
		w := do(t, h, "GET", "/me/sessions", token, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("listing: %d %s", w.Code, w.Body)
		}
		var current int
		for _, s := range decode[[]map[string]any](t, w) {
			if s["is_current"] == true {
				current++
			}
		}
		if current != 1 {
			t.Fatalf("expected exactly one session marked current, got %d", current)
		}
	})
}
