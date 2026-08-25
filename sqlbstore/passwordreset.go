package sqlbstore

import (
	"context"
	"time"

	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/sqlb"
)

// PasswordResetAdapter implements store.PasswordResetStore over an app's
// sqlb row type R.
type PasswordResetAdapter[R any] struct {
	Table[R, store.PasswordResetToken]
	DB              sqlb.Executor
	UserIDColumn    string
	TokenHashColumn string
	UsedAtColumn    string
}

func (a PasswordResetAdapter[R]) CreatePasswordResetToken(ctx context.Context, t *store.PasswordResetToken) error {
	v, err := a.Table.Create(ctx, a.DB, *t)
	if err != nil {
		return err
	}
	*t = v
	return nil
}

func (a PasswordResetAdapter[R]) GetPasswordResetTokenByHash(ctx context.Context, hash string) (*store.PasswordResetToken, error) {
	v, err := a.Table.GetBy(ctx, a.DB, a.TokenHashColumn, hash)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (a PasswordResetAdapter[R]) MarkPasswordResetTokenUsed(ctx context.Context, id string) error {
	now := time.Now()
	return a.Table.SetColumnWhere(ctx, a.DB, a.UsedAtColumn, &now, sqlb.F(a.IDColumn).Eq(id))
}

func (a PasswordResetAdapter[R]) DeleteUserPasswordResetTokens(ctx context.Context, userID string) error {
	_, err := a.Table.DeleteWhere(ctx, a.DB, sqlb.F(a.UserIDColumn).Eq(userID))
	return err
}
