package oidc

import "errors"

var (
	// ErrUnknownProvider means no Provider with that ID was registered.
	ErrUnknownProvider = errors.New("authit/oidc: unknown provider")
	// ErrProviderMisconfigured means a Provider is missing something it
	// cannot work without. Returned from NewService, at startup.
	ErrProviderMisconfigured = errors.New("authit/oidc: provider misconfigured")
	// ErrProviderUnreachable means the provider could not be talked to, or
	// answered with something other than success. It is the provider's
	// fault or the network's, not the caller's: a 502, not a 401.
	ErrProviderUnreachable = errors.New("authit/oidc: provider unreachable")
	// ErrIdentity means the provider answered but the response could not be
	// turned into an Identity.
	ErrIdentity = errors.New("authit/oidc: provider returned an unusable identity")
	// ErrStateMismatch means the state parameter the provider sent back is
	// not the one this flow started with. That is a cross-site request
	// forgery attempt, or a badly resumed flow; either way the callback is
	// refused before any token is exchanged.
	ErrStateMismatch = errors.New("authit/oidc: state does not match")
	// ErrExchange means the authorization code could not be exchanged.
	ErrExchange = errors.New("authit/oidc: authorization code exchange failed")

	// ErrAccountNotLinked means the provider identity is genuine and
	// unknown, an authit account already exists with the same email
	// address, and the configured LinkingPolicy will not join them
	// automatically.
	//
	// This is not a failure. It is the safe outcome, and the host's move is
	// to tell the user "this address already has an account — sign in and
	// connect Google from your settings", then call Link.
	ErrAccountNotLinked = errors.New("authit/oidc: an account with this email exists but is not linked to this provider")
	// ErrSignUpDisabled means the identity is unknown, no account matches,
	// and Config.DisableSignUp is set.
	ErrSignUpDisabled = errors.New("authit/oidc: sign-up via this provider is disabled")
	// ErrProviderEmailUnverified means LinkingVerifiedEmail is configured
	// and the provider did not claim to have verified the address.
	ErrProviderEmailUnverified = errors.New("authit/oidc: provider did not verify the email address")
	// ErrAlreadyLinked means the provider identity is already linked, to
	// this user or another one.
	ErrAlreadyLinked = errors.New("authit/oidc: this provider identity is already linked to an account")
	// ErrLastCredential means unlinking would leave the user with no way to
	// sign in at all: no password, and no other linked provider.
	ErrLastCredential = errors.New("authit/oidc: cannot unlink the account's only remaining credential")
	// ErrNoEmail means the provider returned no email address, and one is
	// needed to create an account.
	ErrNoEmail = errors.New("authit/oidc: provider returned no email address")
)
