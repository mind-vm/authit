package emaillogin

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/mind-vm/authit/audit"
	authitcrypto "github.com/mind-vm/authit/crypto"
	"github.com/mind-vm/authit/store"
)

// Result is a completed passwordless sign-in.
type Result struct {
	// User is the account this sign-in resolved to.
	User store.User
	// CreatedUser reports whether redeeming created the account, so a host
	// can run its own onboarding.
	CreatedUser bool
}

// RequestMagicLink emails a single-use sign-in link to the address.
//
// It always reports success, whether or not the address is registered.
// Passwordless sign-in is a form where anybody can type any address, so a
// response that differed would be a membership oracle for the whole user
// table — and the fix costs nothing, because the person who owns the inbox
// finds out either way and nobody else does.
func (s *Service) RequestMagicLink(ctx context.Context, email string) error {
	email = store.NormalizeEmail(email)
	if err := s.cfg.RateLimiter.Allow(ctx, "email-login:request:"+email); err != nil {
		return err
	}

	raw, hash, err := authitcrypto.GenerateOpaqueToken()
	if err != nil {
		return err
	}
	if err := s.issue(ctx, email, store.EmailLoginLink, hash, s.cfg.LinkTTL); err != nil {
		return err
	}
	if err := s.sender.SendMagicLink(ctx, email, raw); err != nil {
		return err
	}
	s.log(ctx, audit.EventEmailLoginRequested, "", email, string(store.EmailLoginLink))
	return nil
}

// RequestSignInCode emails a short numeric code to the address. Same
// no-enumeration behaviour as RequestMagicLink.
func (s *Service) RequestSignInCode(ctx context.Context, email string) error {
	email = store.NormalizeEmail(email)
	if err := s.cfg.RateLimiter.Allow(ctx, "email-login:request:"+email); err != nil {
		return err
	}

	code, err := authitcrypto.GenerateNumericCode(s.cfg.CodeLength)
	if err != nil {
		return err
	}
	if err := s.issue(ctx, email, store.EmailLoginCode, codeHash(email, code), s.cfg.CodeTTL); err != nil {
		return err
	}
	if err := s.sender.SendSignInCode(ctx, email, code); err != nil {
		return err
	}
	s.log(ctx, audit.EventEmailLoginRequested, "", email, string(store.EmailLoginCode))
	return nil
}

// issue destroys any outstanding token of that kind and stores a new one.
//
// The deletion is the point. Two live codes for one address halve the work
// of guessing, and an attacker can request as many as they like — so a new
// request replaces rather than accumulates.
func (s *Service) issue(ctx context.Context, email string, kind store.EmailLoginKind, hash string, ttl time.Duration) error {
	if err := s.stores.Tokens.DeleteEmailLoginTokens(ctx, email, kind); err != nil {
		return err
	}
	id, err := authitcrypto.NewID()
	if err != nil {
		return err
	}
	now := time.Now()
	return s.stores.Tokens.CreateEmailLoginToken(ctx, &store.EmailLoginToken{
		ID: id, Email: email, Kind: kind, TokenHash: hash,
		ExpiresAt: now.Add(ttl), CreatedAt: now,
	})
}

// RedeemMagicLink consumes a link token and resolves it to a user,
// creating the account if the address is new and sign-up is allowed.
func (s *Service) RedeemMagicLink(ctx context.Context, rawToken string) (Result, error) {
	t, err := s.stores.Tokens.GetEmailLoginTokenByHash(ctx, authitcrypto.HashToken(rawToken))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Result{}, ErrInvalidToken
		}
		return Result{}, err
	}
	// A code presented here would be a low-entropy credential redeemed
	// through the path that does not count guesses. The kinds are checked
	// rather than assumed distinct.
	if t.Kind != store.EmailLoginLink || !usable(t) {
		return Result{}, ErrInvalidToken
	}
	return s.consume(ctx, t)
}

// RedeemSignInCode consumes a numeric code for an address.
//
// A wrong code is counted against the token even though it did not match,
// and the token is destroyed once MaxCodeAttempts is reached. That counting
// is what makes six digits survivable: without it the code is guessable in
// an afternoon.
func (s *Service) RedeemSignInCode(ctx context.Context, email, code string) (Result, error) {
	email = store.NormalizeEmail(email)
	if err := s.cfg.RateLimiter.Allow(ctx, "email-login:redeem:"+email); err != nil {
		return Result{}, err
	}

	t, err := s.stores.Tokens.GetEmailLoginTokenByEmail(ctx, email, store.EmailLoginCode)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Result{}, ErrInvalidToken
		}
		return Result{}, err
	}
	if !usable(t) {
		return Result{}, ErrInvalidToken
	}

	// Constant time, though the comparison is between hashes rather than
	// between the codes themselves.
	if subtle.ConstantTimeCompare([]byte(t.TokenHash), []byte(codeHash(email, code))) != 1 {
		// The count comes back from the store rather than being computed
		// here. Reading Attempts and writing Attempts+1 loses increments
		// when guesses arrive together, and an attacker guessing in
		// parallel would have many tries charged as one -- which is the
		// whole budget this counter exists to impose.
		attempts, err := s.stores.Tokens.IncrementEmailLoginTokenAttempts(ctx, t.ID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				// Burned by a concurrent guess between the read and now.
				return Result{}, ErrInvalidToken
			}
			return Result{}, err
		}
		if attempts >= s.cfg.MaxCodeAttempts {
			// Burn the token rather than merely refusing this attempt. A
			// counter that only gates would leave the code live for the
			// next request, and the whole budget is the point.
			if err := s.stores.Tokens.DeleteEmailLoginTokens(ctx, email, store.EmailLoginCode); err != nil {
				return Result{}, err
			}
			s.log(ctx, audit.EventEmailLoginExhausted, "", email, string(store.EmailLoginCode))
			return Result{}, ErrInvalidToken
		}
		return Result{}, ErrInvalidToken
	}
	return s.consume(ctx, t)
}

// usable reports whether a token is still redeemable.
func usable(t *store.EmailLoginToken) bool {
	return t.UsedAt == nil && time.Now().Before(t.ExpiresAt)
}

// consume marks a token used and resolves or creates the account.
//
// usable() was checked before this, but a check is not a claim: two
// redemptions of one link can both read an unused token. Marking it used is
// a compare-and-set, and winning that is what authorises the rest -- a
// caller that loses gets the same ErrInvalidToken as one presenting a token
// that was never real.
//
// Where the mark sits differs by path, on purpose. Signing up marks first,
// inside the transaction that creates the account, so two redemptions of
// one link cannot race to create the same user. Resolving an existing one
// looks the user up first: a lookup that finds nothing takes the sign-up
// branch or refuses, and neither should have spent the credential on the
// way past.
//
// The cost is that a failure after this point burns the credential: the
// user asks for another link rather than retrying this one. That is the
// safe direction, and the only alternative -- marking used last -- is the
// race itself.
func (s *Service) consume(ctx context.Context, t *store.EmailLoginToken) (Result, error) {
	u, err := s.stores.Users.GetUserByEmail(ctx, t.Email)
	switch {
	case err == nil:
	case errors.Is(err, store.ErrNotFound):
		if s.cfg.DisableSignUp {
			// Refused here rather than at request time, so the request
			// endpoint still says nothing about which addresses exist.
			// Deliberately before the token is spent: sign-up being off is
			// a standing condition, not something a retry would fix, so
			// burning the credential would add nothing.
			return Result{}, ErrSignUpDisabled
		}
		return s.signUp(ctx, t)
	default:
		return Result{}, err
	}

	if err := s.stores.Tokens.MarkEmailLoginTokenUsed(ctx, t.ID, time.Now()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Result{}, ErrInvalidToken
		}
		return Result{}, err
	}
	s.log(ctx, audit.EventEmailLoginSucceeded, u.ID, u.Email, string(t.Kind))
	return Result{User: *u}, nil
}

// signUp creates an account for an address that has just proven it can
// receive mail.
func (s *Service) signUp(ctx context.Context, t *store.EmailLoginToken) (Result, error) {
	id, err := authitcrypto.NewID()
	if err != nil {
		return Result{}, err
	}
	now := time.Now()
	u := &store.User{
		ID: id, Email: t.Email,
		// No password. An empty hash verifies nothing, so this account is
		// reachable only by this flow until its owner sets one.
		PasswordHash: "",
		// Redeeming the token *is* the verification: the credential was
		// delivered to this address and came back. Sending a second
		// confirmation email would be asking the user to prove the thing
		// they just proved.
		EmailVerified:   true,
		EmailVerifiedAt: &now,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	// Marking used comes first, and inside the transaction. First, because
	// winning it is what authorises creating the account -- otherwise two
	// redemptions of one link race to create the same user and only the
	// email UNIQUE constraint stands between them, which is a constraint
	// violation surfacing as a 500 rather than a refusal. Inside, so that a
	// failed CreateUser rolls the marking back and the user can try again;
	// without a TxRunner the marking is still atomic on its own, and only
	// that rollback is lost.
	if err := store.RunInTx(ctx, s.stores.Tx, func(ctx context.Context) error {
		if err := s.stores.Tokens.MarkEmailLoginTokenUsed(ctx, t.ID, now); err != nil {
			return err
		}
		return s.stores.Users.CreateUser(ctx, u)
	}); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Result{}, ErrInvalidToken
		}
		return Result{}, err
	}
	s.log(ctx, audit.EventUserRegistered, u.ID, u.Email, string(t.Kind))
	s.log(ctx, audit.EventEmailLoginSucceeded, u.ID, u.Email, string(t.Kind))
	return Result{User: *u, CreatedUser: true}, nil
}

func (s *Service) log(ctx context.Context, typ audit.EventType, actorID, email, kind string) {
	result := audit.ResultSuccess
	if typ == audit.EventEmailLoginExhausted {
		result = audit.ResultDenied
	}
	s.audit.Log(ctx, audit.Event{
		Type: typ, Result: result, ActorID: actorID, Email: email,
		Metadata: map[string]any{"kind": kind},
	})
}
