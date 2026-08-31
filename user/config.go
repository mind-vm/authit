package user

import (
	"time"

	"github.com/mind-vm/authit/audit"
	authitcrypto "github.com/mind-vm/authit/crypto"
	"github.com/mind-vm/authit/ratelimit"
)

// SessionMode decides what an authenticated caller carries and how a
// protected route checks it.
//
// The zero value is SessionModeJWT, so a Config that says nothing keeps the
// behaviour authit has always had.
type SessionMode int

const (
	// SessionModeJWT issues a short-lived signed access token plus a
	// long-lived opaque refresh token. Checking the access token is a
	// signature check: no database, no context, no way for it to fail
	// because a store is unreachable. That is what makes it the right
	// default for APIs, CLIs and multi-service fan-out, where a lookup per
	// service per request is the cost nobody wants to pay.
	//
	// The price is stated plainly because it is real: revoking a session
	// stops it being refreshable at once, but the access token it already
	// minted stays valid until it expires. AccessTokenTTL is that window.
	SessionModeJWT SessionMode = iota

	// SessionModeOpaque issues one random token, validated by looking it up
	// on every request. Revocation takes effect immediately, which is the
	// entire reason to choose it.
	//
	// It is a different shape, not a different encoding, and the
	// differences bite:
	//
	//   - There is no refresh token. The pair exists so that the common
	//     path avoids a lookup; once every request performs one, a second
	//     credential for avoiding lookups is ceremony. TokenPair.RefreshToken
	//     is empty and Refresh returns ErrWrongSessionMode.
	//   - Every protected request costs a round trip to the refresh-token
	//     store, which is the session store in this mode.
	//   - Authentication can now fail because a database is down, which is
	//     a 500 and not a 401. Use authithttp.SessionAuth, which classifies
	//     it, rather than treating every failure as unauthenticated.
	//
	// Sessions still expire after RefreshTokenTTL, extended on use once
	// SessionSlidingWindow has elapsed.
	SessionModeOpaque
)

// EmailVerificationPolicy decides whether Authenticate refuses a login from
// an account whose email address has not been verified yet.
//
// The zero value is EmailVerificationRequired, so a Config that says nothing
// about this gets the strict behaviour.
type EmailVerificationPolicy int

const (
	// EmailVerificationRequired refuses to authenticate a user whose
	// address is not verified, returning ErrEmailNotVerified. This is the
	// default, and the right choice for a self-serve signup where the
	// address is otherwise unproven.
	EmailVerificationRequired EmailVerificationPolicy = iota
	// EmailVerificationOptional lets an unverified address log in. It is
	// for hosts whose signup path already proves the address by other
	// means — an emailed, tokenised B2B invite; SSO/IdP provisioning that
	// arrives pre-verified — and for seeded demo/test accounts. Verified
	// state is still tracked on the user, so the host can still gate its
	// own features on User.EmailVerified; only login stops depending on
	// it.
	EmailVerificationOptional
)

// Config tunes the user package's flows. Zero-value fields are replaced
// with sane defaults by NewService.
type Config struct {
	// SessionMode selects the session model. Defaults to SessionModeJWT.
	SessionMode SessionMode
	// SessionSlidingWindow is how much of a session's life must elapse
	// before using it extends it, in SessionModeOpaque. Defaults to a
	// quarter of RefreshTokenTTL; a negative value disables extension, so
	// sessions expire a fixed time after being issued.
	//
	// A threshold rather than extending on every request, because the
	// latter is a write per request. Nothing here is consulted in
	// SessionModeJWT.
	SessionSlidingWindow time.Duration
	// AccessTokenTTL is how long an issued access JWT is valid for.
	// Ignored in SessionModeOpaque, which issues no JWT.
	AccessTokenTTL time.Duration
	// RefreshTokenTTL is how long a refresh token (session) stays valid if
	// never revoked.
	RefreshTokenTTL time.Duration
	// PasswordResetTTL is how long a password reset link stays valid.
	PasswordResetTTL time.Duration
	// EmailVerificationTTL is how long an email verification link stays
	// valid.
	EmailVerificationTTL time.Duration
	// PendingTwoFactorTTL is how long a caller has to complete the 2FA step
	// after a correct password before having to log in again.
	PendingTwoFactorTTL time.Duration
	// MaxFailedLoginAttempts is how many recent failed logins put an
	// address into temporary lockout. Both the password step and the
	// second-factor step count against it, and it is only reset once a
	// login fully succeeds -- so an attacker holding a valid password gets
	// this many guesses at the second factor per FailedLoginWindow, not
	// unlimited guesses.
	MaxFailedLoginAttempts int
	// FailedLoginWindow is the lookback window used when counting recent
	// failed attempts, and therefore also how long a temporary lockout
	// lasts: it lifts once the recorded attempts age out. Nothing has to
	// unlock the account, and no operator action is required.
	FailedLoginWindow time.Duration
	// TOTPIssuer is the issuer name embedded in generated TOTP QR codes.
	TOTPIssuer string
	// TOTPEncryptionKey encrypts TOTP secrets at rest (AES-256-GCM). Must be
	// exactly 32 bytes. Required if 2FA methods are used.
	TOTPEncryptionKey []byte
	// BackupCodeCount is how many backup codes are generated on 2FA setup.
	BackupCodeCount int
	// EmailVerification decides whether Authenticate gates login on
	// User.EmailVerified. Defaults to EmailVerificationRequired.
	EmailVerification EmailVerificationPolicy
	// AuditLogger receives security-relevant events (login, lockout,
	// password/2FA changes, session revocation). Nil means events are not
	// recorded — see package audit.
	AuditLogger audit.Logger
	// PasswordHasher hashes and verifies passwords. Nil means
	// crypto.DefaultHasher() — Argon2id at OWASP's recommended minimum.
	//
	// Changing this does not invalidate existing passwords: every Hasher
	// verifies any format authit has written, and Authenticate re-hashes a
	// user's password on their next successful login once the configured
	// hasher reports NeedsRehash. An application upgrading from a version
	// that hardcoded bcrypt migrates its corpus by doing nothing.
	PasswordHasher authitcrypto.Hasher
	// PasswordValidator rejects unacceptable passwords on registration,
	// change and reset. Nil means crypto.DefaultPasswordPolicy() (length
	// only). It is never consulted on login, so tightening it does not lock
	// out existing users; set it to a no-op func to disable it entirely.
	PasswordValidator authitcrypto.PasswordValidator
	// RateLimiter throttles the paths where refusing early matters. Nil
	// means ratelimit.Noop — the control is off, not broken.
	//
	// This does not replace rate limiting in your HTTP middleware, which
	// sees routes, headers and every request; it covers what middleware
	// cannot reach. Its most important job is refusing an attacker
	// *before* Authenticate runs the password KDF: Argon2id costs 19 MiB
	// and real CPU per attempt by default, so an unauthenticated flood is
	// a resource-exhaustion vector regardless of whether any password is
	// ever guessed.
	//
	// Keys passed to Allow, so an implementation can apply its own policy
	// per operation:
	//
	//	login:ip:<ip>                      Authenticate, per source address
	//	login:email:<email>                Authenticate, per account
	//	two-factor:ip:<ip>                 VerifyTwoFactorLogin
	//	two-factor:user:<user id>          VerifyTwoFactorLogin
	//	password-reset:email:<email>       RequestPasswordReset
	//	email-verification:email:<email>   RequestEmailVerificationByEmail
	//	email-verification:user:<user id>  RequestEmailVerification
	//
	// The email in a key is always the normalised form (see
	// store.NormalizeEmail), so case cannot be used to get a fresh budget.
	// An empty IP address is skipped rather than collapsing every caller
	// into one bucket, so a host that does not supply one loses the
	// per-address limit but keeps the rest.
	RateLimiter ratelimit.Limiter
	// Hooks are optional callbacks into the host's own code at the points
	// where a flow stops being authit's business. The zero value does
	// nothing. See Hooks for what Before and After each guarantee, which
	// differs depending on whether Stores.Tx is configured.
	Hooks Hooks
}

func (c Config) withDefaults() Config {
	if c.AccessTokenTTL <= 0 {
		c.AccessTokenTTL = 15 * time.Minute
	}
	if c.RefreshTokenTTL <= 0 {
		c.RefreshTokenTTL = 7 * 24 * time.Hour
	}
	if c.SessionSlidingWindow == 0 {
		// A quarter of the lifetime: a session in daily use never
		// expires under someone, and an idle one still ages out. Zero
		// means unset here, which is why disabling extension is spelled
		// as a negative rather than as zero.
		c.SessionSlidingWindow = c.RefreshTokenTTL / 4
	}
	if c.PasswordResetTTL <= 0 {
		c.PasswordResetTTL = time.Hour
	}
	if c.EmailVerificationTTL <= 0 {
		c.EmailVerificationTTL = 24 * time.Hour
	}
	if c.PendingTwoFactorTTL <= 0 {
		c.PendingTwoFactorTTL = 5 * time.Minute
	}
	if c.MaxFailedLoginAttempts <= 0 {
		c.MaxFailedLoginAttempts = 5
	}
	if c.FailedLoginWindow <= 0 {
		c.FailedLoginWindow = 15 * time.Minute
	}
	if c.TOTPIssuer == "" {
		c.TOTPIssuer = "authit"
	}
	if c.BackupCodeCount <= 0 {
		c.BackupCodeCount = 10
	}
	if c.PasswordHasher == nil {
		c.PasswordHasher = authitcrypto.DefaultHasher()
	}
	if c.PasswordValidator == nil {
		c.PasswordValidator = authitcrypto.DefaultPasswordPolicy()
	}
	if c.RateLimiter == nil {
		c.RateLimiter = ratelimit.Noop{}
	}
	return c
}
