package storetest

import (
	"context"
	"sync"
	"testing"
)

// txKey marks a context as being inside a TxProbe's fn.
type txKey struct{}

// InTx reports whether ctx is the one a TxProbe handed to its callback.
//
// This is the same mechanism a real TxRunner uses — stash a handle in the
// context, have store methods look for it — with the handle replaced by a
// marker. A store double can call it to record which operations a service
// enrolled in the transaction, which is the only externally observable
// thing about the seam.
func InTx(ctx context.Context) bool {
	return ctx.Value(txKey{}) != nil
}

// TxProbe is a store.TxRunner for tests. It records how a service used the
// seam and can be made to fail.
//
// It provides no atomicity whatsoever: nothing is rolled back, because
// there is nothing to roll back an in-memory map with. It is not a
// substitute for testing a real implementation against a real database. It
// answers a different and still useful question — did the service put the
// right writes inside the transaction, and keep the wrong ones out.
type TxProbe struct {
	mu sync.Mutex
	// Calls counts how many times RunInTx was entered.
	Calls int
	// Fail, when non-nil, is returned instead of running fn — standing in
	// for a transaction that could not begin.
	Fail error
}

func (p *TxProbe) RunInTx(ctx context.Context, fn func(context.Context) error) error {
	p.mu.Lock()
	p.Calls++
	fail := p.Fail
	p.mu.Unlock()
	if fail != nil {
		return fail
	}
	return fn(context.WithValue(ctx, txKey{}, struct{}{}))
}

// CallCount returns Calls under the probe's lock.
func (p *TxProbe) CallCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Calls
}

// TxWitness records, per operation name, whether it was called inside a
// transaction. Store doubles report into it; a test then asserts which
// operations were enrolled.
type TxWitness struct {
	mu   sync.Mutex
	seen map[string][]bool
}

// NewTxWitness returns an empty witness.
func NewTxWitness() *TxWitness {
	return &TxWitness{seen: map[string][]bool{}}
}

// Reset forgets every recorded call.
//
// Most store operations are used both inside and outside a transaction --
// CreateRefreshToken is part of an atomic rotation in Refresh and a lone
// write in Authenticate, and both are correct. Call Reset immediately
// before the operation under test so the assertions describe that
// operation rather than everything the fixture did to reach it.
func (w *TxWitness) Reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.seen = map[string][]bool{}
}

// Record notes one call of op, and whether it saw a transaction context.
func (w *TxWitness) Record(ctx context.Context, op string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.seen[op] = append(w.seen[op], InTx(ctx))
}

// AssertInTx fails unless op was called at least once and every call was
// inside a transaction.
func (w *TxWitness) AssertInTx(t *testing.T, op string) {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	calls, ok := w.seen[op]
	if !ok || len(calls) == 0 {
		t.Fatalf("%s was never called", op)
	}
	for i, in := range calls {
		if !in {
			t.Fatalf("%s call %d ran outside the transaction; it is one of the writes that must land atomically", op, i+1)
		}
	}
}

// AssertOutsideTx fails unless op was called at least once and every call
// was outside a transaction.
//
// This is the direction that catches the subtler mistake. A write that
// must survive the surrounding call returning an error — recording a failed
// login, revoking a token family after detecting reuse — is undone by a
// rollback if it is swept into the transaction with everything else.
func (w *TxWitness) AssertOutsideTx(t *testing.T, op string) {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	calls, ok := w.seen[op]
	if !ok || len(calls) == 0 {
		t.Fatalf("%s was never called", op)
	}
	for i, in := range calls {
		if in {
			t.Fatalf("%s call %d ran inside the transaction; a rollback would undo it", op, i+1)
		}
	}
}
