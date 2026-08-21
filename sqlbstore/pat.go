package sqlbstore

import (
	"context"

	"github.com/jryannel/authit/store"
	"github.com/jryannel/sqlb"
)

// PersonalAccessTokenAdapter implements store.PersonalAccessTokenStore
// against an app's sqlb-generated row type R (e.g. mybrain.APIToken),
// given a Table[R, store.PersonalAccessToken] describing the mapping.
//
// DB must be an unhooked executor: resolving a token is what establishes
// the identity a hook later scopes by, so it cannot itself run behind one
// — same requirement as every other identity-resolving query in a sqlb
// app.
type PersonalAccessTokenAdapter[R any] struct {
	Table[R, store.PersonalAccessToken]
	DB sqlb.Executor
	// UserIDColumn and TokenHashColumn name the columns
	// ListPersonalAccessTokensByUser and GetPersonalAccessTokenByHash
	// filter on, respectively.
	UserIDColumn    string
	TokenHashColumn string
}

func (a PersonalAccessTokenAdapter[R]) CreatePersonalAccessToken(ctx context.Context, t *store.PersonalAccessToken) error {
	v, err := a.Table.Create(ctx, a.DB, *t)
	if err != nil {
		return err
	}
	*t = v
	return nil
}

func (a PersonalAccessTokenAdapter[R]) GetPersonalAccessToken(ctx context.Context, id string) (*store.PersonalAccessToken, error) {
	v, err := a.Table.GetBy(ctx, a.DB, a.IDColumn, id)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (a PersonalAccessTokenAdapter[R]) GetPersonalAccessTokenByHash(ctx context.Context, hash string) (*store.PersonalAccessToken, error) {
	v, err := a.Table.GetBy(ctx, a.DB, a.TokenHashColumn, hash)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (a PersonalAccessTokenAdapter[R]) ListPersonalAccessTokensByUser(ctx context.Context, userID string) ([]*store.PersonalAccessToken, error) {
	rows, err := a.Table.ListBy(ctx, a.DB, a.UserIDColumn, userID)
	if err != nil {
		return nil, err
	}
	out := make([]*store.PersonalAccessToken, len(rows))
	for i := range rows {
		out[i] = &rows[i]
	}
	return out, nil
}

func (a PersonalAccessTokenAdapter[R]) UpdatePersonalAccessToken(ctx context.Context, t *store.PersonalAccessToken) error {
	return a.Table.Update(ctx, a.DB, *t)
}
