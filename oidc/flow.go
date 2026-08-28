package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/mind-vm/authit/audit"
	authitcrypto "github.com/mind-vm/authit/crypto"
	"github.com/mind-vm/authit/store"
	"golang.org/x/oauth2"
)

// Authorization is what Begin hands back: where to send the user, and the
// two values the callback must be checked against.
type Authorization struct {
	// URL is where to redirect the browser.
	URL string
	// State must be given back to Complete as ExpectedState. It is what
	// makes the callback verifiably the continuation of this request
	// rather than one an attacker started.
	State string
	// CodeVerifier is the PKCE secret. It must reach Complete and must
	// never reach the provider until the exchange.
	CodeVerifier string
}

// Callback is what came back from the provider, plus what the host stored
// when the flow began.
type Callback struct {
	// Code is the authorization code from the callback query.
	Code string
	// State is the state parameter from the callback query.
	State string
	// ExpectedState is Authorization.State, as the host stored it.
	ExpectedState string
	// CodeVerifier is Authorization.CodeVerifier, as the host stored it.
	CodeVerifier string
}

// Begin builds the provider's authorization URL along with the state and
// PKCE verifier the callback will be checked against.
//
// Storing those two is the host's job, deliberately. They belong to one
// browser for one minute; a short-lived HttpOnly cookie is the usual home
// (see authithttp.CookieOptions for the attributes that matter). Keeping
// them here would mean another store port and a cleanup problem, to hold
// state that already has a natural place to live.
//
// redirectURI must match what is registered with the provider exactly.
func (s *Service) Begin(_ context.Context, providerID, redirectURI string) (Authorization, error) {
	p, err := s.Provider(providerID)
	if err != nil {
		return Authorization{}, err
	}
	state, err := authitcrypto.GenerateStateToken()
	if err != nil {
		return Authorization{}, err
	}
	verifier := oauth2.GenerateVerifier()

	cfg := s.oauthConfig(p, redirectURI)
	opts := []oauth2.AuthCodeOption{
		// PKCE. Without it, an authorization code intercepted on the
		// redirect -- by another app registered for the same custom
		// scheme, by a proxy, out of a Referer header -- is redeemable by
		// whoever holds it. With it, the code is useless without the
		// verifier, which never left this process.
		oauth2.S256ChallengeOption(verifier),
	}
	for k, v := range p.AuthURLParams {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}
	return Authorization{URL: cfg.AuthCodeURL(state, opts...), State: state, CodeVerifier: verifier}, nil
}

func (s *Service) oauthConfig(p Provider, redirectURI string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		RedirectURL:  redirectURI,
		Scopes:       p.Scopes,
		Endpoint:     oauth2.Endpoint{AuthURL: p.AuthURL, TokenURL: p.TokenURL},
	}
}

// Result is the outcome of a completed sign-in.
type Result struct {
	// User is the authit account this sign-in resolved to. It is not a
	// session: minting one is the host's call, exactly as it is for
	// pat and device.
	User store.User
	// Account is the provider link, as it now stands.
	Account store.Account
	// Identity is what the provider said.
	Identity Identity
	// CreatedUser reports whether this sign-in created the account, so a
	// host can run its own onboarding.
	CreatedUser bool
}

// Complete verifies the callback, exchanges the code, asks the provider who
// signed in, and resolves that to an authit user.
//
// It does not issue any authit credential. Like pat.Resolve and
// device.PollDeviceToken, it answers "who is this" and leaves what to hand
// back — a session, a token pair, something of your own — to the host.
func (s *Service) Complete(ctx context.Context, providerID, redirectURI string, cb Callback) (Result, error) {
	p, err := s.Provider(providerID)
	if err != nil {
		return Result{}, err
	}
	// Before anything else, and in constant time. A mismatched state means
	// this callback is not the continuation of a flow this server started,
	// so there is nothing here worth exchanging a code for.
	if cb.ExpectedState == "" || subtle.ConstantTimeCompare([]byte(cb.State), []byte(cb.ExpectedState)) != 1 {
		return Result{}, ErrStateMismatch
	}
	if cb.Code == "" {
		return Result{}, fmt.Errorf("%w: no authorization code", ErrExchange)
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, s.cfg.HTTPClient)
	tok, err := s.oauthConfig(p, redirectURI).Exchange(ctx, cb.Code, oauth2.VerifierOption(cb.CodeVerifier))
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrExchange, err)
	}

	identity, err := s.fetchIdentity(ctx, p, tok.AccessToken)
	if err != nil {
		return Result{}, err
	}
	return s.resolve(ctx, p, identity, tok)
}

// resolve turns a verified identity into a user, creating or linking as the
// configured policy allows.
func (s *Service) resolve(ctx context.Context, p Provider, identity Identity, tok *oauth2.Token) (Result, error) {
	// The identity is already linked: this is an ordinary returning
	// sign-in, and the email is irrelevant to it. Note that a change of
	// email at the provider does not move the account -- the link is on the
	// subject, which is the whole reason it is on the subject.
	existing, err := s.stores.Accounts.GetAccountByProvider(ctx, p.ID, identity.Subject)
	if err == nil {
		u, err := s.stores.Users.GetUserByID(ctx, existing.UserID)
		if err != nil {
			return Result{}, err
		}
		if err := s.refreshAccount(ctx, existing, identity, tok); err != nil {
			return Result{}, err
		}
		s.logEvent(ctx, audit.EventUserLoginSucceeded, u.ID, u.Email, p.ID)
		return Result{User: *u, Account: *existing, Identity: identity}, nil
	} else if !errorsIsNotFound(err) {
		return Result{}, err
	}

	// Unknown identity. Everything from here is the dangerous half.
	if identity.Email == "" {
		return Result{}, ErrNoEmail
	}

	byEmail, err := s.stores.Users.GetUserByEmail(ctx, identity.Email)
	switch {
	case err == nil:
		// An account already exists with this address. Whether this
		// sign-in may become that account is the question LinkingPolicy
		// answers -- see its documentation for what is at stake.
		if s.cfg.Linking != LinkingVerifiedEmail {
			return Result{}, ErrAccountNotLinked
		}
		if !identity.EmailVerified {
			return Result{}, ErrProviderEmailUnverified
		}
		acct, err := s.link(ctx, byEmail.ID, p, identity, tok)
		if err != nil {
			return Result{}, err
		}
		return Result{User: *byEmail, Account: acct, Identity: identity}, nil

	case errorsIsNotFound(err):
		if s.cfg.DisableSignUp {
			return Result{}, ErrSignUpDisabled
		}
		return s.signUp(ctx, p, identity, tok)

	default:
		return Result{}, err
	}
}

// signUp creates a user for an identity that matches nothing existing.
func (s *Service) signUp(ctx context.Context, p Provider, identity Identity, tok *oauth2.Token) (Result, error) {
	userID, err := authitcrypto.NewID()
	if err != nil {
		return Result{}, err
	}
	now := time.Now()
	u := &store.User{
		ID:    userID,
		Email: identity.Email,
		// No password. An empty hash verifies nothing -- crypto's
		// dispatching Verify recognises no algorithm in "" and returns
		// false -- so this account can be signed into only through a
		// linked provider until its owner sets a password.
		PasswordHash: "",
		// The provider's claim is carried across so that a verified
		// address does not force the user through a second verification
		// email for an address that provider just confirmed. An unverified
		// one stays unverified, and the host's own flow applies.
		EmailVerified: identity.EmailVerified,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if identity.EmailVerified {
		u.EmailVerifiedAt = &now
	}

	var acct store.Account
	if err := store.RunInTx(ctx, s.stores.Tx, func(ctx context.Context) error {
		if err := s.stores.Users.CreateUser(ctx, u); err != nil {
			return err
		}
		var err error
		acct, err = s.newAccount(ctx, u.ID, p, identity, tok)
		return err
	}); err != nil {
		return Result{}, err
	}
	s.logEvent(ctx, audit.EventUserRegistered, u.ID, u.Email, p.ID)
	return Result{User: *u, Account: acct, Identity: identity, CreatedUser: true}, nil
}

// Link attaches a provider identity to an already-authenticated user.
//
// This is the deliberate half of LinkingManual: the host authenticates the
// user by whatever means they already have, runs Begin/Complete's flow, and
// calls this. Because the user is proven first, no claim from the provider
// has to be trusted to decide whose account it is.
func (s *Service) Link(ctx context.Context, userID string, identity Identity, providerToken *oauth2.Token) (store.Account, error) {
	p, err := s.Provider(identity.Provider)
	if err != nil {
		return store.Account{}, err
	}
	if _, err := s.stores.Accounts.GetAccountByProvider(ctx, p.ID, identity.Subject); err == nil {
		// Already linked -- possibly to somebody else. Either way this is
		// refused rather than moved: silently re-pointing a provider
		// identity at a different user is an account takeover with extra
		// steps.
		return store.Account{}, ErrAlreadyLinked
	} else if !errorsIsNotFound(err) {
		return store.Account{}, err
	}
	return s.link(ctx, userID, p, identity, providerToken)
}

func (s *Service) link(ctx context.Context, userID string, p Provider, identity Identity, tok *oauth2.Token) (store.Account, error) {
	acct, err := s.newAccount(ctx, userID, p, identity, tok)
	if err != nil {
		return store.Account{}, err
	}
	s.logEvent(ctx, audit.EventAccountLinked, userID, identity.Email, p.ID)
	return acct, nil
}

func (s *Service) newAccount(ctx context.Context, userID string, p Provider, identity Identity, tok *oauth2.Token) (store.Account, error) {
	id, err := authitcrypto.NewID()
	if err != nil {
		return store.Account{}, err
	}
	now := time.Now()
	a := &store.Account{
		ID: id, UserID: userID, Provider: p.ID, ProviderAccountID: identity.Subject,
		Email: identity.Email, EmailVerified: identity.EmailVerified,
		Scopes: p.Scopes, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.attachTokens(a, tok); err != nil {
		return store.Account{}, err
	}
	if err := s.stores.Accounts.CreateAccount(ctx, a); err != nil {
		return store.Account{}, err
	}
	return *a, nil
}

// refreshAccount updates a returning sign-in's stored details.
func (s *Service) refreshAccount(ctx context.Context, a *store.Account, identity Identity, tok *oauth2.Token) error {
	a.Email = identity.Email
	a.EmailVerified = identity.EmailVerified
	a.UpdatedAt = time.Now()
	if err := s.attachTokens(a, tok); err != nil {
		return err
	}
	return s.stores.Accounts.UpdateAccount(ctx, a)
}

// attachTokens encrypts the provider's tokens if the host asked for them to
// be kept, and otherwise leaves the fields nil.
func (s *Service) attachTokens(a *store.Account, tok *oauth2.Token) error {
	if len(s.cfg.ProviderTokenKey) == 0 || tok == nil {
		return nil
	}
	if tok.AccessToken != "" {
		enc, err := authitcrypto.EncryptSecret(s.cfg.ProviderTokenKey, tok.AccessToken)
		if err != nil {
			return err
		}
		a.AccessTokenEncrypted = enc
	}
	if tok.RefreshToken != "" {
		enc, err := authitcrypto.EncryptSecret(s.cfg.ProviderTokenKey, tok.RefreshToken)
		if err != nil {
			return err
		}
		a.RefreshTokenEncrypted = enc
	}
	if !tok.Expiry.IsZero() {
		expiry := tok.Expiry
		a.TokenExpiresAt = &expiry
	}
	return nil
}

// ProviderTokens decrypts the provider's own tokens for an account, so a
// host can call the provider's API as the user.
//
// It returns empty strings when nothing was stored, which is the default.
func (s *Service) ProviderTokens(a store.Account) (accessToken, refreshToken string, err error) {
	if len(s.cfg.ProviderTokenKey) == 0 {
		return "", "", nil
	}
	if len(a.AccessTokenEncrypted) > 0 {
		accessToken, err = authitcrypto.DecryptSecret(s.cfg.ProviderTokenKey, a.AccessTokenEncrypted)
		if err != nil {
			return "", "", err
		}
	}
	if len(a.RefreshTokenEncrypted) > 0 {
		refreshToken, err = authitcrypto.DecryptSecret(s.cfg.ProviderTokenKey, a.RefreshTokenEncrypted)
		if err != nil {
			return "", "", err
		}
	}
	return accessToken, refreshToken, nil
}

// ListAccounts returns the providers a user has linked.
func (s *Service) ListAccounts(ctx context.Context, userID string) ([]store.Account, error) {
	list, err := s.stores.Accounts.ListAccountsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]store.Account, len(list))
	for i, a := range list {
		out[i] = *a
	}
	return out, nil
}

// Unlink removes a provider link.
//
// It refuses to remove the last thing a user can sign in with: an account
// with no password and no other linked provider would still exist and be
// unreachable by anybody, including its owner. A host that wants that
// outcome should delete the account instead, which is its own decision to
// make.
func (s *Service) Unlink(ctx context.Context, userID, providerID string) error {
	accounts, err := s.stores.Accounts.ListAccountsByUser(ctx, userID)
	if err != nil {
		return err
	}
	var target *store.Account
	for _, a := range accounts {
		if a.Provider == providerID {
			target = a
			break
		}
	}
	if target == nil {
		return store.ErrNotFound
	}
	if len(accounts) == 1 {
		u, err := s.stores.Users.GetUserByID(ctx, userID)
		if err != nil {
			return err
		}
		if u.PasswordHash == "" {
			return ErrLastCredential
		}
	}
	if err := s.stores.Accounts.DeleteAccount(ctx, target.ID); err != nil {
		return err
	}
	s.logEvent(ctx, audit.EventAccountUnlinked, userID, target.Email, providerID)
	return nil
}

// logEvent records an event, tagging it with the provider so a trail can
// distinguish a password login from a Google one.
func (s *Service) logEvent(ctx context.Context, t audit.EventType, actorID, email, providerID string) {
	s.audit.Log(ctx, audit.Event{
		Type: t, Result: audit.ResultSuccess, ActorID: actorID, Email: email,
		Metadata: map[string]any{"provider": providerID},
	})
}

// errorsIsNotFound reports whether err is store.ErrNotFound.
func errorsIsNotFound(err error) bool { return errors.Is(err, store.ErrNotFound) }

// AuthorizationURLFor is a convenience for hosts that build their own
// redirect: it parses Begin's URL so callers can inspect or adjust it.
func AuthorizationURLFor(a Authorization) (*url.URL, error) { return url.Parse(a.URL) }
