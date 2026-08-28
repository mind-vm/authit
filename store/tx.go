package store

import "context"

// TxRunner runs a group of store operations atomically.
//
// It is optional everywhere it appears: leave the field nil and the flows
// below run exactly as they always have, as a sequence of independent
// writes. Supplying one closes the windows where a crash between two writes
// leaves inconsistent state — a rotated refresh token that was revoked but
// never replaced, a team with no owner, an invitation accepted by a member
// row that was never created.
//
// # The contract, which is the whole difficulty
//
// authit calls store methods with the context RunInTx hands to fn. It has
// no other way to tell a store "this call belongs to that transaction":
// every port takes a context and nothing else in common, and widening them
// all to take a transaction handle would put a database concept into
// interfaces whose entire purpose is not having one.
//
// So the contract is:
//
//	Every store method called with the context passed to fn MUST take part
//	in the transaction. Every store method called with any other context
//	MUST NOT.
//
// That is a real obligation on the implementation, not a formality. The
// usual shape is for RunInTx to begin a transaction, stash the handle in
// the context it passes to fn, and for each store method to look for that
// handle and use it when present, falling back to the pool when absent. An
// implementation whose stores ignore the context and always use the pool
// will compile, pass its own tests, and silently provide no atomicity at
// all — every write inside fn commits independently, and returning an error
// from fn rolls back nothing.
//
// If you cannot honour that, leave the field nil. Losing atomicity you
// never had is better than believing in atomicity you do not have.
//
// # Semantics
//
//   - fn returning nil commits; fn returning an error rolls back, and
//     RunInTx returns that error unchanged so callers can still match
//     sentinels with errors.Is.
//   - A panic inside fn must roll back before it propagates.
//   - Nesting is not used by authit and need not be supported.
//   - Retrying fn on serialization failure is allowed but not required. If
//     you do retry, note that fn may run more than once, so authit keeps
//     side effects that are not store writes — audit events in particular —
//     outside the transaction.
type TxRunner interface {
	RunInTx(ctx context.Context, fn func(ctx context.Context) error) error
}

// RunInTx runs fn inside tx, or directly when tx is nil.
//
// It is the one-line shim authit's service packages use so that "no
// TxRunner configured" and "TxRunner configured" share a single code path.
// A host has no reason to call it, having its own TxRunner to hand.
func RunInTx(ctx context.Context, tx TxRunner, fn func(context.Context) error) error {
	if tx == nil {
		return fn(ctx)
	}
	return tx.RunInTx(ctx, fn)
}
