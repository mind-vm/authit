package sqlbstore

import (
	"context"
	"time"

	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/sqlb"
)

// EmailVerificationAdapter implements store.EmailVerificationStore over an
// app's sqlb row type R.
type EmailVerificationAdapter[R any] struct {
	Table[R, store.EmailVerificationToken]
	DB              sqlb.Executor
	UserIDColumn    string
	TokenHashColumn string
	UsedAtColumn    string
}

func (a EmailVerificationAdapter[R]) CreateEmailVerificationToken(ctx context.Context, t *store.EmailVerificationToken) error {
	v, err := a.Table.Create(ctx, a.DB, *t)
	if err != nil {
		return err
	}
	*t = v
	return nil
}

func (a EmailVerificationAdapter[R]) GetEmailVerificationTokenByHash(ctx context.Context, hash string) (*store.EmailVerificationToken, error) {
	v, err := a.Table.GetBy(ctx, a.DB, a.TokenHashColumn, hash)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (a EmailVerificationAdapter[R]) MarkEmailVerificationTokenUsed(ctx context.Context, id string) error {
	now := time.Now()
	return a.Table.SetColumnWhere(ctx, a.DB, a.UsedAtColumn, &now, sqlb.F(a.IDColumn).Eq(id))
}

func (a EmailVerificationAdapter[R]) DeleteUserEmailVerificationTokens(ctx context.Context, userID string) error {
	_, err := a.Table.DeleteWhere(ctx, a.DB, sqlb.F(a.UserIDColumn).Eq(userID))
	return err
}
