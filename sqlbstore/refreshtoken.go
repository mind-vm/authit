package sqlbstore

import (
	"context"
	"time"

	"github.com/jryannel/authit/store"
	"github.com/jryannel/sqlb"
)

// RefreshTokenAdapter implements store.RefreshTokenStore over an app's
// sqlb row type R.
type RefreshTokenAdapter[R any] struct {
	Table[R, store.RefreshToken]
	DB sqlb.Executor
	// UserIDColumn, TokenHashColumn, RevokedAtColumn, ExpiresAtColumn name
	// the corresponding columns — needed beyond IDColumn because
	// RevokeAllUserRefreshTokens and ListActiveRefreshTokens filter on
	// more than the primary key.
	UserIDColumn    string
	TokenHashColumn string
	RevokedAtColumn string
	ExpiresAtColumn string
}

func (a RefreshTokenAdapter[R]) CreateRefreshToken(ctx context.Context, t *store.RefreshToken) error {
	v, err := a.Table.Create(ctx, a.DB, *t)
	if err != nil {
		return err
	}
	*t = v
	return nil
}

func (a RefreshTokenAdapter[R]) GetRefreshTokenByHash(ctx context.Context, hash string) (*store.RefreshToken, error) {
	v, err := a.Table.GetBy(ctx, a.DB, a.TokenHashColumn, hash)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (a RefreshTokenAdapter[R]) RevokeRefreshToken(ctx context.Context, id string) error {
	now := time.Now()
	return a.Table.SetColumnWhere(ctx, a.DB, a.RevokedAtColumn, &now, sqlb.F(a.IDColumn).Eq(id))
}

func (a RefreshTokenAdapter[R]) RevokeAllUserRefreshTokens(ctx context.Context, userID string) error {
	now := time.Now()
	return a.Table.SetColumnWhere(ctx, a.DB, a.RevokedAtColumn, &now,
		sqlb.F(a.UserIDColumn).Eq(userID), sqlb.F(a.RevokedAtColumn).IsNull())
}

func (a RefreshTokenAdapter[R]) ListActiveRefreshTokens(ctx context.Context, userID string) ([]*store.RefreshToken, error) {
	rows, err := a.Table.ListWhere(ctx, a.DB,
		sqlb.F(a.UserIDColumn).Eq(userID),
		sqlb.F(a.RevokedAtColumn).IsNull(),
		sqlb.F(a.ExpiresAtColumn).Gt(time.Now()),
	)
	if err != nil {
		return nil, err
	}
	out := make([]*store.RefreshToken, len(rows))
	for i := range rows {
		out[i] = &rows[i]
	}
	return out, nil
}
