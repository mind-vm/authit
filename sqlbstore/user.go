package sqlbstore

import (
	"context"

	"github.com/jryannel/authit/store"
	"github.com/jryannel/sqlb"
)

// UserAdapter implements store.UserStore over an app's sqlb row type R.
type UserAdapter[R any] struct {
	Table[R, store.User]
	DB sqlb.Executor
	// EmailColumn names the column GetUserByEmail filters on.
	EmailColumn string
}

func (a UserAdapter[R]) CreateUser(ctx context.Context, u *store.User) error {
	v, err := a.Table.Create(ctx, a.DB, *u)
	if err != nil {
		return err
	}
	*u = v
	return nil
}

func (a UserAdapter[R]) GetUserByID(ctx context.Context, id string) (*store.User, error) {
	v, err := a.Table.GetBy(ctx, a.DB, a.IDColumn, id)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (a UserAdapter[R]) GetUserByEmail(ctx context.Context, email string) (*store.User, error) {
	v, err := a.Table.GetBy(ctx, a.DB, a.EmailColumn, email)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (a UserAdapter[R]) UpdateUser(ctx context.Context, u *store.User) error {
	return a.Table.Update(ctx, a.DB, *u)
}
