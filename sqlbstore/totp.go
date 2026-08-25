package sqlbstore

import (
	"context"

	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/sqlb"
)

// TOTPAdapter implements store.TOTPStore over an app's sqlb row type R.
type TOTPAdapter[R any] struct {
	Table[R, store.TOTPSettings]
	DB           sqlb.Executor
	UserIDColumn string
}

func (a TOTPAdapter[R]) CreateTOTPSettings(ctx context.Context, t *store.TOTPSettings) error {
	v, err := a.Table.Create(ctx, a.DB, *t)
	if err != nil {
		return err
	}
	*t = v
	return nil
}

func (a TOTPAdapter[R]) GetTOTPSettingsByUserID(ctx context.Context, userID string) (*store.TOTPSettings, error) {
	v, err := a.Table.GetBy(ctx, a.DB, a.UserIDColumn, userID)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (a TOTPAdapter[R]) UpdateTOTPSettings(ctx context.Context, t *store.TOTPSettings) error {
	return a.Table.Update(ctx, a.DB, *t)
}

func (a TOTPAdapter[R]) DeleteTOTPSettings(ctx context.Context, userID string) error {
	_, err := a.Table.DeleteWhere(ctx, a.DB, sqlb.F(a.UserIDColumn).Eq(userID))
	return err
}
