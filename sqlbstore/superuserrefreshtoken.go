package sqlbstore

import (
	"context"
	"time"

	"github.com/jryannel/authit/store"
	"github.com/jryannel/sqlb"
)

// SuperuserRefreshTokenAdapter implements store.SuperuserRefreshTokenStore
// over an app's sqlb row type R.
type SuperuserRefreshTokenAdapter[R any] struct {
	Table[R, store.SuperuserRefreshToken]
	DB                sqlb.Executor
	SuperuserIDColumn string
	TokenHashColumn   string
	RevokedAtColumn   string
}

func (a SuperuserRefreshTokenAdapter[R]) CreateSuperuserRefreshToken(ctx context.Context, t *store.SuperuserRefreshToken) error {
	v, err := a.Table.Create(ctx, a.DB, *t)
	if err != nil {
		return err
	}
	*t = v
	return nil
}

func (a SuperuserRefreshTokenAdapter[R]) GetSuperuserRefreshTokenByHash(ctx context.Context, hash string) (*store.SuperuserRefreshToken, error) {
	v, err := a.Table.GetBy(ctx, a.DB, a.TokenHashColumn, hash)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (a SuperuserRefreshTokenAdapter[R]) RevokeSuperuserRefreshToken(ctx context.Context, id string) error {
	now := time.Now()
	return a.Table.SetColumnWhere(ctx, a.DB, a.RevokedAtColumn, &now, sqlb.F(a.IDColumn).Eq(id))
}

func (a SuperuserRefreshTokenAdapter[R]) RevokeAllSuperuserRefreshTokens(ctx context.Context, superuserID string) error {
	now := time.Now()
	return a.Table.SetColumnWhere(ctx, a.DB, a.RevokedAtColumn, &now,
		sqlb.F(a.SuperuserIDColumn).Eq(superuserID), sqlb.F(a.RevokedAtColumn).IsNull())
}
