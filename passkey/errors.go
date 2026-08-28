package passkey

import "errors"

var (
	// ErrConfig means the Service was constructed without something it
	// cannot work without, such as an RPID.
	ErrConfig = errors.New("authit/passkey: RPID is required")
	// ErrCeremony means the browser's response did not verify: a bad
	// signature, a mismatched challenge, a wrong origin or relying party,
	// an expired ceremony. It is deliberately one error covering all of
	// them -- which specific check failed is useful in a log and is an
	// oracle in a response body.
	ErrCeremony = errors.New("authit/passkey: credential response did not verify")
	// ErrSession means the stored session data could not be decoded, so
	// the ceremony cannot be completed.
	ErrSession = errors.New("authit/passkey: ceremony session is missing or unreadable")
	// ErrCredentialNotFound means no registered credential matches.
	ErrCredentialNotFound = errors.New("authit/passkey: no such credential")
	// ErrNoCredentials means the user has registered no authenticators, so
	// there is nothing to sign a challenge with.
	ErrNoCredentials = errors.New("authit/passkey: user has no registered credentials")
	// ErrAlreadyRegistered means this authenticator is already registered.
	// Returned rather than silently re-registering, which would leave two
	// rows for one credential and make the assertion lookup ambiguous.
	ErrAlreadyRegistered = errors.New("authit/passkey: this authenticator is already registered")
	// ErrCloneWarning means the assertion's signature counter did not
	// advance, which is evidence the credential's private key exists in
	// more than one place. See CloneAction.
	ErrCloneWarning = errors.New("authit/passkey: signature counter did not advance; the authenticator may be cloned")
	// ErrUserVerificationRequired means the authenticator did not verify
	// the user, and this Service requires it.
	ErrUserVerificationRequired = errors.New("authit/passkey: authenticator did not verify the user")
	// ErrLastCredential means removing this credential would leave the
	// user unable to sign in at all.
	ErrLastCredential = errors.New("authit/passkey: cannot remove the account's only remaining credential")
)
