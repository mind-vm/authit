package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	wan "github.com/go-webauthn/webauthn/webauthn"
	"github.com/mind-vm/authit/audit"
	authitcrypto "github.com/mind-vm/authit/crypto"
	"github.com/mind-vm/authit/store"
)

// Options is the JSON to hand the browser. Write it as the response body;
// the page passes it to navigator.credentials.create() or .get().
//
// It is bytes rather than a struct so that the WebAuthn library's types do
// not leak into authit's API, and so a host can serve it without a
// re-encode.
type Options []byte

// Session is the ceremony state that must survive the round trip to the
// browser: the challenge, and which credentials were offered.
//
// The host stores it — a short-lived HttpOnly cookie or a server-side
// session — and gives it back to the matching Finish call. authit does not
// keep it, for the same reason it does not keep OAuth state: it belongs to
// one browser for one minute, and holding it would mean another store port
// and a cleanup problem.
//
// It is not a secret in the sense a token is, but it must not be
// attacker-controlled: the challenge inside is what the signature is
// checked against, so a caller who can substitute it can replay an old
// assertion. Store it somewhere the user cannot edit.
type Session []byte

// Result is a completed authentication.
type Result struct {
	// User is the authit account that just authenticated.
	User store.User
	// Credential is the authenticator that signed, as it now stands.
	Credential store.WebAuthnCredential
	// UserVerified reports whether the authenticator verified the user
	// with a PIN or biometric.
	//
	// It is the difference between one factor and two. A Service
	// configured with VerificationRequired refuses an assertion without
	// it, so this is always true there; it is reported so that a Service
	// configured otherwise can still tell, and can decide to ask for a
	// password as well.
	UserVerified bool
}

// webAuthnUser adapts an authit user and its credentials to the interface
// the WebAuthn implementation expects.
type webAuthnUser struct {
	u     store.User
	creds []wan.Credential
}

// WebAuthnID is the user handle the authenticator stores alongside a
// discoverable credential, and hands back at login.
//
// authit user ids are random UUIDv4 strings, so using one directly is
// within the 64-byte limit, carries no personal information, and needs no
// second column mapping handles to users. A host whose ids are sequential
// integers should not follow this: the handle is readable by anything with
// the device, and a guessable one leaks how many accounts exist.
func (w webAuthnUser) WebAuthnID() []byte                    { return []byte(w.u.ID) }
func (w webAuthnUser) WebAuthnName() string                  { return w.u.Email }
func (w webAuthnUser) WebAuthnDisplayName() string           { return w.u.Email }
func (w webAuthnUser) WebAuthnCredentials() []wan.Credential { return w.creds }

// loadUser builds the WebAuthn view of a user and their credentials.
func (s *Service) loadUser(ctx context.Context, userID string) (webAuthnUser, []*store.WebAuthnCredential, error) {
	u, err := s.stores.Users.GetUserByID(ctx, userID)
	if err != nil {
		return webAuthnUser{}, nil, err
	}
	stored, err := s.stores.Credentials.ListWebAuthnCredentialsByUser(ctx, userID)
	if err != nil {
		return webAuthnUser{}, nil, err
	}
	creds := make([]wan.Credential, 0, len(stored))
	for _, c := range stored {
		var cred wan.Credential
		// Data is authoritative; the denormalised columns are not
		// consulted here, so a host that lets them drift breaks its
		// listings and not its signature checks.
		if err := json.Unmarshal(c.Data, &cred); err != nil {
			return webAuthnUser{}, nil, err
		}
		creds = append(creds, cred)
	}
	return webAuthnUser{u: *u, creds: creds}, stored, nil
}

// ---------------------------------------------------------------------------
// registration
// ---------------------------------------------------------------------------

// BeginRegistration starts registering a new authenticator for a user who
// has already been authenticated by some other means.
//
// The caller must have authenticated the user first. This ceremony proves
// possession of an authenticator; it proves nothing about whose account it
// should be attached to, so calling it on an unauthenticated request lets
// anybody add their own passkey to somebody else's account.
func (s *Service) BeginRegistration(ctx context.Context, userID string) (Options, Session, error) {
	user, _, err := s.loadUser(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	creation, session, err := s.web.BeginRegistration(user,
		wan.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			// Ask for a discoverable credential so the user can later
			// sign in without typing anything. Preferred rather than
			// required: a security key with no room for one should still
			// be registerable as a second factor.
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: s.cfg.UserVerification,
		}),
		// Offer what the user already has, so the authenticator can refuse
		// to enrol itself twice rather than creating a second credential
		// the user cannot tell apart from the first.
		wan.WithExclusions(user.CredentialDescriptors()),
	)
	if err != nil {
		return nil, nil, err
	}
	return marshalCeremony(creation, session)
}

// CredentialDescriptors lists the user's existing credentials for exclusion.
func (w webAuthnUser) CredentialDescriptors() []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, 0, len(w.creds))
	for _, c := range w.creds {
		out = append(out, c.Descriptor())
	}
	return out
}

// FinishRegistration verifies the browser's response and stores the new
// credential. name is a user-facing label.
func (s *Service) FinishRegistration(ctx context.Context, userID, name string, sess Session, r *http.Request) (store.WebAuthnCredential, error) {
	user, _, err := s.loadUser(ctx, userID)
	if err != nil {
		return store.WebAuthnCredential{}, err
	}
	session, err := decodeSession(sess)
	if err != nil {
		return store.WebAuthnCredential{}, err
	}
	cred, err := s.web.FinishRegistration(user, session, r)
	if err != nil {
		return store.WebAuthnCredential{}, wrapCeremony(err)
	}

	// An authenticator that ignored the exclusion list, or a race between
	// two registrations, must not produce a second row for one credential
	// id: the assertion lookup would then be ambiguous about whose it is.
	if _, err := s.stores.Credentials.GetWebAuthnCredentialByCredentialID(ctx, cred.ID); err == nil {
		return store.WebAuthnCredential{}, ErrAlreadyRegistered
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.WebAuthnCredential{}, err
	}

	id, err := authitcrypto.NewID()
	if err != nil {
		return store.WebAuthnCredential{}, err
	}
	rec := &store.WebAuthnCredential{ID: id, UserID: userID, Name: name, CreatedAt: time.Now()}
	if err := applyCredential(rec, cred); err != nil {
		return store.WebAuthnCredential{}, err
	}
	if err := s.stores.Credentials.CreateWebAuthnCredential(ctx, rec); err != nil {
		return store.WebAuthnCredential{}, err
	}
	s.log(ctx, audit.EventPasskeyRegistered, userID, user.u.Email, rec.ID)
	return *rec, nil
}

// ---------------------------------------------------------------------------
// authentication
// ---------------------------------------------------------------------------

// BeginLogin starts an assertion for a known user — the shape used when the
// user has already typed an email, or when the passkey is a second factor
// behind a password.
func (s *Service) BeginLogin(ctx context.Context, userID string) (Options, Session, error) {
	user, stored, err := s.loadUser(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	if len(stored) == 0 {
		return nil, nil, ErrNoCredentials
	}
	assertion, session, err := s.web.BeginLogin(user, wan.WithUserVerification(s.cfg.UserVerification))
	if err != nil {
		return nil, nil, err
	}
	return marshalCeremony(assertion, session)
}

// FinishLogin verifies an assertion for a known user.
func (s *Service) FinishLogin(ctx context.Context, userID string, sess Session, r *http.Request) (Result, error) {
	user, _, err := s.loadUser(ctx, userID)
	if err != nil {
		return Result{}, err
	}
	session, err := decodeSession(sess)
	if err != nil {
		return Result{}, err
	}
	parsed, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		return Result{}, wrapCeremony(err)
	}
	cred, err := s.web.ValidateLogin(user, session, parsed)
	if err != nil {
		return Result{}, wrapCeremony(err)
	}
	return s.completeLogin(ctx, user.u, cred, assertionUserVerified(parsed))
}

// BeginDiscoverableLogin starts a usernameless sign-in: the browser offers
// whatever passkeys it holds for this relying party, and the assertion
// carries the user handle that identifies the account.
//
// This is the flow that makes a passkey feel like nothing at all — no email
// typed, no password. Note that it names no user, so it also cannot leak
// whether a given account exists.
func (s *Service) BeginDiscoverableLogin(_ context.Context) (Options, Session, error) {
	assertion, session, err := s.web.BeginDiscoverableLogin(wan.WithUserVerification(s.cfg.UserVerification))
	if err != nil {
		return nil, nil, err
	}
	return marshalCeremony(assertion, session)
}

// FinishDiscoverableLogin verifies a usernameless assertion and resolves it
// to the account that owns the credential.
func (s *Service) FinishDiscoverableLogin(ctx context.Context, sess Session, r *http.Request) (Result, error) {
	session, err := decodeSession(sess)
	if err != nil {
		return Result{}, err
	}

	parsed, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		return Result{}, wrapCeremony(err)
	}

	var resolved store.User
	cred, err := s.web.ValidateDiscoverableLogin(func(rawID, userHandle []byte) (wan.User, error) {
		// The credential is looked up by its own id -- never by the user
		// handle, which comes from the authenticator and is therefore
		// attacker-controlled. The handle is then checked against the
		// owner that lookup resolved to.
		//
		// The library performs the same comparison against
		// User.WebAuthnID (§7.2 step 6), so this is defence in depth
		// rather than the load-bearing check: removing it here does not
		// make the foreign-handle test fail. It is kept because the
		// property is one line to state and the alternative is relying on
		// a callback contract to be read correctly by every future
		// change.
		stored, err := s.stores.Credentials.GetWebAuthnCredentialByCredentialID(ctx, rawID)
		if err != nil {
			return nil, err
		}
		if string(userHandle) != stored.UserID {
			return nil, ErrCeremony
		}
		user, _, err := s.loadUser(ctx, stored.UserID)
		if err != nil {
			return nil, err
		}
		resolved = user.u
		return user, nil
	}, session, parsed)
	if err != nil {
		return Result{}, wrapCeremony(err)
	}
	return s.completeLogin(ctx, resolved, cred, assertionUserVerified(parsed))
}

// assertionUserVerified reads the UV flag out of THIS assertion.
//
// It deliberately does not read Credential.Flags, which carries the flags
// recorded when the credential was registered. Reading those would report
// user verification that happened once, months ago, for an assertion where
// it did not happen at all -- and Result.UserVerified exists precisely so a
// host can decide whether to ask for a password as well.
func assertionUserVerified(parsed *protocol.ParsedCredentialAssertionData) bool {
	return parsed.Response.AuthenticatorData.Flags.UserVerified()
}

// completeLogin applies the clone check and persists the credential's new
// state.
func (s *Service) completeLogin(ctx context.Context, u store.User, cred *wan.Credential, userVerified bool) (Result, error) {
	stored, err := s.stores.Credentials.GetWebAuthnCredentialByCredentialID(ctx, cred.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Result{}, ErrCredentialNotFound
		}
		return Result{}, err
	}

	// The counter did not advance. Record it either way -- the flag is the
	// only durable trace, and losing it because the login was refused
	// would mean the next attempt looks like the first.
	if cred.Authenticator.CloneWarning {
		stored.CloneWarning = true
		now := time.Now()
		stored.UpdatedAt = now
		if err := s.stores.Credentials.UpdateWebAuthnCredential(ctx, stored); err != nil {
			return Result{}, err
		}
		s.log(ctx, audit.EventPasskeyCloneWarning, u.ID, u.Email, stored.ID)
		if s.cfg.OnClone == CloneReject {
			return Result{}, ErrCloneWarning
		}
	}

	if s.cfg.UserVerification == protocol.VerificationRequired && !userVerified {
		// The library checks this too. Repeating it here is deliberate:
		// it is the single property separating a two-factor passkey login
		// from a one-factor one, and it should not depend on one library
		// call being passed the right option.
		return Result{}, ErrUserVerificationRequired
	}

	now := time.Now()
	stored.LastUsedAt = &now
	stored.UpdatedAt = now
	if err := applyCredential(stored, cred); err != nil {
		return Result{}, err
	}
	if err := s.stores.Credentials.UpdateWebAuthnCredential(ctx, stored); err != nil {
		return Result{}, err
	}
	s.log(ctx, audit.EventPasskeyLogin, u.ID, u.Email, stored.ID)
	return Result{User: u, Credential: *stored, UserVerified: userVerified}, nil
}

// applyCredential writes the authoritative blob and refreshes the
// denormalised columns from it.
func applyCredential(rec *store.WebAuthnCredential, cred *wan.Credential) error {
	data, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	rec.CredentialID = cred.ID
	rec.Data = data
	rec.BackupEligible = cred.Flags.BackupEligible
	rec.BackupState = cred.Flags.BackupState
	rec.Transports = make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		rec.Transports = append(rec.Transports, string(t))
	}
	if rec.UpdatedAt.IsZero() {
		rec.UpdatedAt = rec.CreatedAt
	}
	return nil
}

func marshalCeremony(options any, session *wan.SessionData) (Options, Session, error) {
	opts, err := json.Marshal(options)
	if err != nil {
		return nil, nil, err
	}
	sess, err := json.Marshal(session)
	if err != nil {
		return nil, nil, err
	}
	return opts, sess, nil
}

func decodeSession(sess Session) (wan.SessionData, error) {
	var out wan.SessionData
	if len(sess) == 0 {
		return out, ErrSession
	}
	if err := json.Unmarshal(sess, &out); err != nil {
		return out, ErrSession
	}
	return out, nil
}

// wrapCeremony collapses the library's verification failures into
// ErrCeremony, keeping the original for logs.
//
// Which specific check failed -- challenge, origin, signature, relying
// party -- is useful in a log and is an oracle in a response body, so the
// sentinel a caller matches on says only that it did not verify.
func wrapCeremony(err error) error {
	if err == nil {
		return nil
	}
	return errors.Join(ErrCeremony, err)
}

func (s *Service) log(ctx context.Context, t audit.EventType, userID, email, credentialID string) {
	result := audit.ResultSuccess
	if t == audit.EventPasskeyCloneWarning {
		result = audit.ResultDenied
	}
	s.audit.Log(ctx, audit.Event{
		Type: t, Result: result, ActorID: userID, Email: email,
		Metadata: map[string]any{"credential_id": credentialID},
	})
}

// ---------------------------------------------------------------------------
// management
// ---------------------------------------------------------------------------

// List returns a user's registered authenticators, for a settings page.
func (s *Service) List(ctx context.Context, userID string) ([]store.WebAuthnCredential, error) {
	stored, err := s.stores.Credentials.ListWebAuthnCredentialsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]store.WebAuthnCredential, len(stored))
	for i, c := range stored {
		out[i] = *c
	}
	return out, nil
}

// Rename relabels a credential. Somebody with four passkeys needs to be
// able to tell which one to revoke.
func (s *Service) Rename(ctx context.Context, userID, credentialID, name string) error {
	c, err := s.ownedCredential(ctx, userID, credentialID)
	if err != nil {
		return err
	}
	c.Name = name
	c.UpdatedAt = time.Now()
	return s.stores.Credentials.UpdateWebAuthnCredential(ctx, c)
}

// Remove revokes a credential — the button a user presses when a phone is
// lost.
//
// It refuses to remove the last thing the account can be reached with: a
// user with no password and no remaining authenticator still exists and
// nobody, including its owner, can sign in. Deleting the account is a
// different decision and belongs to the host.
func (s *Service) Remove(ctx context.Context, userID, credentialID string) error {
	c, err := s.ownedCredential(ctx, userID, credentialID)
	if err != nil {
		return err
	}
	all, err := s.stores.Credentials.ListWebAuthnCredentialsByUser(ctx, userID)
	if err != nil {
		return err
	}
	if len(all) == 1 {
		u, err := s.stores.Users.GetUserByID(ctx, userID)
		if err != nil {
			return err
		}
		if u.PasswordHash == "" {
			return ErrLastCredential
		}
	}
	if err := s.stores.Credentials.DeleteWebAuthnCredential(ctx, c.ID); err != nil {
		return err
	}
	s.log(ctx, audit.EventPasskeyRemoved, userID, "", c.ID)
	return nil
}

// ownedCredential fetches a credential and confirms it belongs to userID.
//
// A credential that exists but belongs to somebody else reports
// ErrCredentialNotFound rather than a distinct "not yours": the ids are
// opaque, and distinguishing the two would turn this into an oracle for
// probing which credential ids are real.
func (s *Service) ownedCredential(ctx context.Context, userID, credentialID string) (*store.WebAuthnCredential, error) {
	c, err := s.stores.Credentials.GetWebAuthnCredential(ctx, credentialID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrCredentialNotFound
		}
		return nil, err
	}
	if c.UserID != userID {
		return nil, ErrCredentialNotFound
	}
	return c, nil
}
