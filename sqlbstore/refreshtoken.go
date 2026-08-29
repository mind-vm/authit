package sqlbstore

import (
	"context"
	"fmt"
	"time"

	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/sqlb"
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

// TouchRefreshToken extends a live token's expiry, and refuses a revoked or
// missing one.
//
// Whether a row was updated decides, which is why this does not go through
// Table.SetColumnWhere like its neighbours -- that helper discards what the
// update returned, and here it is the answer. The revoked_at IS NULL predicate is the
// load-bearing half: in user.SessionModeOpaque a request reads a session
// and then extends it, so without it a session revoked between those two
// steps comes back with a fresh lifetime and the revocation is undone by
// the request that raced it.
func (a RefreshTokenAdapter[R]) TouchRefreshToken(ctx context.Context, id string, expiresAt time.Time) error {
	updated, err := sqlb.UpdateRows[R]().
		Set(a.ExpiresAtColumn, expiresAt).
		Where(sqlb.F(a.IDColumn).Eq(id), sqlb.F(a.RevokedAtColumn).IsNull()).
		Exec(ctx, a.DB)
	if err != nil {
		return fmt.Errorf("sqlbstore: extending refresh token: %w", err)
	}
	if len(updated) == 0 {
		return store.ErrNotFound
	}
	return nil
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
