package sqlbstore

import (
	"context"

	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/sqlb"
)

// WebAuthnChallengeAdapter implements store.WebAuthnChallengeStore over an
// app's sqlb row type R.
type WebAuthnChallengeAdapter[R any] struct {
	Table[R, store.WebAuthnChallenge]
	DB              sqlb.Executor
	TokenHashColumn string
}

func (a WebAuthnChallengeAdapter[R]) CreateWebAuthnChallenge(ctx context.Context, c *store.WebAuthnChallenge) error {
	v, err := a.Table.Create(ctx, a.DB, *c)
	if err != nil {
		return err
	}
	*c = v
	return nil
}

// ConsumeWebAuthnChallenge reads the row, then deletes it, and returns it
// only if that delete is the one that removed it.
//
// The obvious implementation is DELETE ... RETURNING in one statement, and
// that is what the port's documentation describes. sqlb's Delete surfaces
// returned rows only to an AfterDeleteRows hook, not to the caller, so this
// takes the other road to the same guarantee: the read may be stale and is
// not trusted to decide anything, and the DELETE's affected-row count is
// what settles who won. Concurrent callers all read the row; exactly one
// removes it and returns it, and the rest see zero rows affected and report
// ErrNotFound.
//
// Getting this wrong is not a wrong answer, it is a replayed assertion
// accepted twice, so if this adapter is ever rewritten: the delete decides.
func (a WebAuthnChallengeAdapter[R]) ConsumeWebAuthnChallenge(ctx context.Context, tokenHash string) (*store.WebAuthnChallenge, error) {
	v, err := a.Table.GetBy(ctx, a.DB, a.TokenHashColumn, tokenHash)
	if err != nil {
		return nil, err
	}
	n, err := sqlb.DeleteRows[R]().Where(sqlb.F(a.TokenHashColumn).Eq(tokenHash)).Exec(ctx, a.DB)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, store.ErrNotFound
	}
	return &v, nil
}
