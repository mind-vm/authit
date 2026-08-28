// Package oidc adds sign-in with an external identity provider — Google,
// GitHub, your company's SSO — on top of authit's own accounts.
//
// # What it does and does not verify
//
// It runs the OAuth 2.0 authorization code flow with PKCE and state, and
// then asks the provider who the user is by calling the provider's userinfo
// endpoint with the freshly issued access token, over TLS.
//
// It deliberately does not parse or verify an OpenID Connect ID token.
// Verifying one properly means fetching the provider's JWKS, caching it,
// handling key rotation, and getting issuer, audience, expiry and nonce
// checks all right — a meaningful amount of security-critical machinery to
// carry. A direct TLS call to the provider's userinfo endpoint establishes
// the same fact with the same trust, works for providers that are OAuth 2.0
// but not OIDC (GitHub is the obvious one), and has no signature checking
// to get wrong. The cost is one HTTP round trip per sign-in.
//
// If you need ID token verification specifically — because a provider
// asserts claims only there, or because you must avoid the round trip —
// this package is not it.
//
// # What it refuses to decide for you
//
// Whether a social sign-in may take over an existing account is the
// security question in social login, and it is answered by
// LinkingPolicy — not by a default that quietly does the convenient thing.
// Read that type before configuring this package.
package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/mind-vm/authit/store"
)

// Identity is who a provider says the user is.
type Identity struct {
	// Provider is the Provider.ID this came from.
	Provider string
	// Subject is the provider's stable identifier for the user. It is what
	// authit keys the link on — never the email address, which users
	// change and which two providers can both assert.
	Subject string
	// Email is normalised, and may be empty: not every provider returns
	// one, and GitHub in particular omits it unless the user has a public
	// address or the "user:email" scope was granted.
	Email string
	// EmailVerified is the provider's claim that it verified the address.
	// It is a claim, not a fact, and providers differ in how much it is
	// worth. See LinkingPolicy.
	EmailVerified bool
	// Name is a display name, if the provider gave one.
	Name string
	// Raw is the decoded userinfo response, for claims this struct does
	// not model.
	Raw map[string]any
}

// Provider describes one external identity provider.
//
// There is no OIDC discovery here: the endpoints are given explicitly, so
// a deployment cannot be redirected by a change at a well-known URL, and
// nothing has to be fetched before the first sign-in.
type Provider struct {
	// ID names the provider in stored accounts. Changing it orphans every
	// existing link, so pick it once.
	ID string
	// ClientID and ClientSecret identify this application to the provider.
	ClientID     string
	ClientSecret string
	// AuthURL and TokenURL are the provider's OAuth 2.0 endpoints.
	AuthURL  string
	TokenURL string
	// UserInfoURL is called with the access token to learn who signed in.
	UserInfoURL string
	// Scopes are requested at authorization time. Whatever else you add,
	// the set must be enough for UserInfoURL to return a subject.
	Scopes []string
	// Map turns a decoded userinfo response into an Identity. Leave it nil
	// for the OIDC standard claims (sub, email, email_verified, name).
	Map func(raw map[string]any) (Identity, error)
	// AuthURLParams are extra query parameters added to the authorization
	// URL, e.g. {"prompt": "consent"} to force Google to re-issue a
	// refresh token.
	AuthURLParams map[string]string
}

func (p Provider) validate() error {
	switch {
	case p.ID == "":
		return fmt.Errorf("%w: ID is required", ErrProviderMisconfigured)
	case p.ClientID == "":
		return fmt.Errorf("%w: %s has no ClientID", ErrProviderMisconfigured, p.ID)
	case p.AuthURL == "" || p.TokenURL == "":
		return fmt.Errorf("%w: %s needs AuthURL and TokenURL", ErrProviderMisconfigured, p.ID)
	case p.UserInfoURL == "":
		return fmt.Errorf("%w: %s needs UserInfoURL", ErrProviderMisconfigured, p.ID)
	}
	// Endpoints must be HTTPS. The access token is a bearer credential and
	// the userinfo response decides who the user is; either over plain
	// HTTP is a sign-in anyone on the path can forge.
	for name, u := range map[string]string{"AuthURL": p.AuthURL, "TokenURL": p.TokenURL, "UserInfoURL": p.UserInfoURL} {
		if !strings.HasPrefix(u, "https://") {
			return fmt.Errorf("%w: %s %s must be https", ErrProviderMisconfigured, p.ID, name)
		}
	}
	return nil
}

// Google returns a Provider for Google Sign-In. Supply your own client
// credentials.
func Google(clientID, clientSecret string) Provider {
	return Provider{
		ID: "google", ClientID: clientID, ClientSecret: clientSecret,
		AuthURL:     "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:    "https://oauth2.googleapis.com/token",
		UserInfoURL: "https://openidconnect.googleapis.com/v1/userinfo",
		Scopes:      []string{"openid", "email", "profile"},
	}
}

// GitHub returns a Provider for GitHub. GitHub is OAuth 2.0 rather than
// OIDC, so its userinfo response uses its own field names and its notion of
// a verified email needs a second call — see the mapper below for what that
// means in practice.
func GitHub(clientID, clientSecret string) Provider {
	return Provider{
		ID: "github", ClientID: clientID, ClientSecret: clientSecret,
		AuthURL:     "https://github.com/login/oauth/authorize",
		TokenURL:    "https://github.com/login/oauth/access_token",
		UserInfoURL: "https://api.github.com/user",
		Scopes:      []string{"read:user", "user:email"},
		Map: func(raw map[string]any) (Identity, error) {
			idNum, ok := raw["id"].(float64)
			if !ok {
				return Identity{}, fmt.Errorf("%w: github userinfo has no numeric id", ErrIdentity)
			}
			email, _ := raw["email"].(string)
			name, _ := raw["name"].(string)
			return Identity{
				Subject: fmt.Sprintf("%d", int64(idNum)),
				Email:   store.NormalizeEmail(email),
				// GitHub's /user response says nothing about whether the
				// address is verified -- that needs /user/emails -- so it
				// is reported as unverified rather than assumed. With the
				// default LinkingManual policy this changes nothing; with
				// LinkingVerifiedEmail it means GitHub will not silently
				// take over an existing account, which is the right way
				// round for a claim we cannot see.
				EmailVerified: false,
				Name:          name,
				Raw:           raw,
			}, nil
		},
	}
}

// standardClaims maps the OIDC standard claims.
func standardClaims(raw map[string]any) (Identity, error) {
	sub, _ := raw["sub"].(string)
	if sub == "" {
		return Identity{}, fmt.Errorf("%w: userinfo response has no 'sub' claim", ErrIdentity)
	}
	email, _ := raw["email"].(string)
	name, _ := raw["name"].(string)
	// email_verified is a bool in the spec and a string at more than one
	// real provider.
	verified := false
	switch v := raw["email_verified"].(type) {
	case bool:
		verified = v
	case string:
		verified = v == "true"
	}
	return Identity{
		Subject:       sub,
		Email:         store.NormalizeEmail(email),
		EmailVerified: verified,
		Name:          name,
		Raw:           raw,
	}, nil
}

// fetchIdentity calls the provider's userinfo endpoint with accessToken.
func (s *Service) fetchIdentity(ctx context.Context, p Provider, accessToken string) (Identity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.UserInfoURL, nil)
	if err != nil {
		return Identity{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %w", ErrProviderUnreachable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Identity{}, fmt.Errorf("%w: userinfo returned %s", ErrProviderUnreachable, resp.Status)
	}

	var raw map[string]any
	if err := json.NewDecoder(limitBody(resp)).Decode(&raw); err != nil {
		return Identity{}, fmt.Errorf("%w: decoding userinfo: %w", ErrIdentity, err)
	}

	mapper := p.Map
	if mapper == nil {
		mapper = standardClaims
	}
	id, err := mapper(raw)
	if err != nil {
		return Identity{}, err
	}
	if id.Subject == "" {
		return Identity{}, fmt.Errorf("%w: provider %s returned no subject", ErrIdentity, p.ID)
	}
	id.Provider = p.ID
	id.Email = store.NormalizeEmail(id.Email)
	return id, nil
}
