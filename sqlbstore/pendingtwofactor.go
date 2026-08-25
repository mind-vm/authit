package sqlbstore

import (
	"context"

	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/sqlb"
)

// PendingTwoFactorAdapter implements store.PendingTwoFactorStore over an
// app's sqlb row type R.
type PendingTwoFactorAdapter[R any] struct {
	Table[R, store.PendingTwoFactorSession]
	DB              sqlb.Executor
	TokenHashColumn string
}

func (a PendingTwoFactorAdapter[R]) CreatePendingTwoFactorSession(ctx context.Context, s *store.PendingTwoFactorSession) error {
	v, err := a.Table.Create(ctx, a.DB, *s)
	if err != nil {
		return err
	}
	*s = v
	return nil
}

func (a PendingTwoFactorAdapter[R]) GetPendingTwoFactorSessionByHash(ctx context.Context, hash string) (*store.PendingTwoFactorSession, error) {
	v, err := a.Table.GetBy(ctx, a.DB, a.TokenHashColumn, hash)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (a PendingTwoFactorAdapter[R]) DeletePendingTwoFactorSession(ctx context.Context, id string) error {
	return a.Table.Delete(ctx, a.DB, id)
}
