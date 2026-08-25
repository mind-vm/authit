package sqlbstore

import (
	"context"

	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/sqlb"
)

// SuperuserAdapter implements store.SuperuserStore over an app's sqlb row
// type R.
type SuperuserAdapter[R any] struct {
	Table[R, store.Superuser]
	DB          sqlb.Executor
	EmailColumn string
}

func (a SuperuserAdapter[R]) CreateSuperuser(ctx context.Context, s *store.Superuser) error {
	v, err := a.Table.Create(ctx, a.DB, *s)
	if err != nil {
		return err
	}
	*s = v
	return nil
}

func (a SuperuserAdapter[R]) GetSuperuserByID(ctx context.Context, id string) (*store.Superuser, error) {
	v, err := a.Table.GetBy(ctx, a.DB, a.IDColumn, id)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (a SuperuserAdapter[R]) GetSuperuserByEmail(ctx context.Context, email string) (*store.Superuser, error) {
	v, err := a.Table.GetBy(ctx, a.DB, a.EmailColumn, email)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (a SuperuserAdapter[R]) ListSuperusers(ctx context.Context) ([]*store.Superuser, error) {
	rows, err := a.Table.ListWhere(ctx, a.DB)
	if err != nil {
		return nil, err
	}
	return ptrs(rows), nil
}

func (a SuperuserAdapter[R]) UpdateSuperuser(ctx context.Context, s *store.Superuser) error {
	return a.Table.Update(ctx, a.DB, *s)
}

func (a SuperuserAdapter[R]) CountSuperusers(ctx context.Context) (int, error) {
	n, err := a.Table.CountWhere(ctx, a.DB)
	return int(n), err
}
