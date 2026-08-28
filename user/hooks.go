package user

import (
	"context"

	"github.com/mind-vm/authit/store"
)

// Hooks are optional callbacks into a host's own code at the points where
// "what happens when a user registers" stops being authit's business and
// starts being the application's: provisioning a workspace, refusing an
// address outside your domain, stamping a last-seen timestamp.
//
// Every field is nil-safe; leaving one unset means nothing happens there.
// A hook's error is returned to the caller unchanged, so a host can define
// its own sentinels and match them with errors.Is.
//
// # Before and After mean different things
//
// A Before hook is a gate. It runs before anything is written, and
// returning an error refuses the operation cleanly — nothing happened.
//
// An After hook runs once the operation has succeeded, and whether its
// error can still undo anything depends on Stores.Tx:
//
//   - With a TxRunner configured, After hooks run inside the same
//     transaction as the operation's own writes. Returning an error rolls
//     the whole thing back, so "create the account only if provisioning
//     succeeds" actually holds.
//   - Without one, the writes have already landed independently. The error
//     still reaches the caller, but the user exists, the session is issued,
//     the password is changed. Treat the hook as a notification.
//
// That difference is worth deciding about deliberately. If an After hook
// guards something that must not half-happen, configure a TxRunner.
//
// # What a hook must not do
//
// Hooks run in the request's goroutine, and with a TxRunner they run inside
// an open database transaction. Slow work — sending mail, calling a
// third-party API — belongs in a queue the hook writes to, not in the hook.
//
// Values are passed by copy, so mutating one changes nothing. A hook that
// wants to alter stored state should write it through its own store.
type Hooks struct {
	// BeforeRegister runs before a new account is created, with the
	// normalised address. Returning an error refuses the registration.
	//
	// It fires before authit checks whether the address is already taken,
	// so it is reached even for a duplicate registration: it is a cheap
	// gate — an invite-only check, a domain allow-list — and making it pay
	// for a database round trip first would defeat the point.
	BeforeRegister func(ctx context.Context, email string) error

	// AfterRegister runs once the account exists.
	AfterRegister func(ctx context.Context, u store.User) error

	// BeforeAuthenticate runs before the password is verified, with the
	// normalised address. Returning an error refuses the login.
	//
	// It runs after rate limiting and the lockout check, so it cannot be
	// used to bypass either, and before the password hash comparison, so
	// refusing here costs no KDF work.
	BeforeAuthenticate func(ctx context.Context, email string) error

	// AfterAuthenticate runs when a login has *fully* succeeded — which
	// for an account with two-factor enabled means after the second
	// factor, not after the password. A hook stamping a last-seen
	// timestamp must not fire for a login that stopped half way.
	AfterAuthenticate func(ctx context.Context, u store.User) error

	// AfterPasswordChange runs after ChangePassword or ResetPassword, with
	// the user as they now are.
	AfterPasswordChange func(ctx context.Context, u store.User) error
}

func (h Hooks) beforeRegister(ctx context.Context, email string) error {
	if h.BeforeRegister == nil {
		return nil
	}
	return h.BeforeRegister(ctx, email)
}

func (h Hooks) afterRegister(ctx context.Context, u store.User) error {
	if h.AfterRegister == nil {
		return nil
	}
	return h.AfterRegister(ctx, u)
}

func (h Hooks) beforeAuthenticate(ctx context.Context, email string) error {
	if h.BeforeAuthenticate == nil {
		return nil
	}
	return h.BeforeAuthenticate(ctx, email)
}

func (h Hooks) afterAuthenticate(ctx context.Context, u store.User) error {
	if h.AfterAuthenticate == nil {
		return nil
	}
	return h.AfterAuthenticate(ctx, u)
}

func (h Hooks) afterPasswordChange(ctx context.Context, u store.User) error {
	if h.AfterPasswordChange == nil {
		return nil
	}
	return h.AfterPasswordChange(ctx, u)
}

// txIf runs fn inside a transaction when atomic is true, and directly
// otherwise.
//
// A flow that writes once and then calls a hook that is not configured has
// nothing to make atomic, and opening a transaction for it would cost a
// round trip per login to guard a no-op. So the flows whose only second
// participant is an After hook take a transaction only when that hook
// exists; the genuinely multi-write flows always do.
func (s *Service) txIf(ctx context.Context, atomic bool, fn func(context.Context) error) error {
	if !atomic {
		return fn(ctx)
	}
	return store.RunInTx(ctx, s.stores.Tx, fn)
}
