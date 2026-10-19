package pgstore

import (
	"context"

	"github.com/mind-vm/authit/pgstore/internal/db"
	"github.com/mind-vm/authit/store"
)

// Personal access tokens and RFC 8628 device authorizations: the two
// credentials a user hands to a CLI or a script.

var (
	_ store.PersonalAccessTokenStore = (*Store)(nil)
	_ store.DeviceAuthorizationStore = (*Store)(nil)
)

func (s *Store) CreatePersonalAccessToken(ctx context.Context, t *store.PersonalAccessToken) error {
	return mapErr(s.q(ctx).CreatePersonalAccessToken(ctx, db.CreatePersonalAccessTokenParams{
		ID: t.ID, UserID: t.UserID, Name: t.Name, TokenHash: t.TokenHash, Scopes: nonNil(t.Scopes),
		ExpiresAt: t.ExpiresAt, LastUsedAt: t.LastUsedAt, RevokedAt: t.RevokedAt, CreatedAt: t.CreatedAt,
	}))
}

func (s *Store) GetPersonalAccessToken(ctx context.Context, id string) (*store.PersonalAccessToken, error) {
	if !isID(id) {
		return nil, store.ErrNotFound
	}
	r, err := s.q(ctx).GetPersonalAccessToken(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	return toPersonalAccessToken(r), nil
}

func (s *Store) GetPersonalAccessTokenByHash(ctx context.Context, hash string) (*store.PersonalAccessToken, error) {
	r, err := s.q(ctx).GetPersonalAccessTokenByHash(ctx, hash)
	if err != nil {
		return nil, mapErr(err)
	}
	return toPersonalAccessToken(r), nil
}

func (s *Store) ListPersonalAccessTokensByUser(ctx context.Context, userID string) ([]*store.PersonalAccessToken, error) {
	if !isID(userID) {
		return []*store.PersonalAccessToken{}, nil
	}
	rows, err := s.q(ctx).ListPersonalAccessTokensByUser(ctx, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]*store.PersonalAccessToken, 0, len(rows))
	for _, r := range rows {
		out = append(out, toPersonalAccessToken(r))
	}
	return out, nil
}

func (s *Store) UpdatePersonalAccessToken(ctx context.Context, t *store.PersonalAccessToken) error {
	if !isID(t.ID) {
		return store.ErrNotFound
	}
	return affected(s.q(ctx).UpdatePersonalAccessToken(ctx, db.UpdatePersonalAccessTokenParams{
		ID: t.ID, UserID: t.UserID, Name: t.Name, TokenHash: t.TokenHash, Scopes: nonNil(t.Scopes),
		ExpiresAt: t.ExpiresAt, LastUsedAt: t.LastUsedAt, RevokedAt: t.RevokedAt,
	}))
}

func toPersonalAccessToken(r db.AuthPersonalAccessToken) *store.PersonalAccessToken {
	return &store.PersonalAccessToken{
		ID: r.ID, UserID: r.UserID, Name: r.Name, TokenHash: r.TokenHash, Scopes: r.Scopes,
		ExpiresAt: r.ExpiresAt, LastUsedAt: r.LastUsedAt, RevokedAt: r.RevokedAt, CreatedAt: r.CreatedAt,
	}
}

func (s *Store) CreateDeviceAuthorization(ctx context.Context, d *store.DeviceAuthorization) error {
	return mapErr(s.q(ctx).CreateDeviceAuthorization(ctx, db.CreateDeviceAuthorizationParams{
		ID: d.ID, DeviceCodeHash: d.DeviceCodeHash, UserCode: d.UserCode, ClientID: d.ClientID,
		Scope: d.Scope, Status: string(d.Status), UserID: d.UserID, ExpiresAt: d.ExpiresAt,
		IntervalSeconds: int32(d.IntervalSeconds), LastPolledAt: d.LastPolledAt, CreatedAt: d.CreatedAt,
	}))
}

func (s *Store) GetDeviceAuthorizationByDeviceCodeHash(ctx context.Context, hash string) (*store.DeviceAuthorization, error) {
	r, err := s.q(ctx).GetDeviceAuthorizationByDeviceCodeHash(ctx, hash)
	if err != nil {
		return nil, mapErr(err)
	}
	return toDeviceAuthorization(r), nil
}

func (s *Store) GetDeviceAuthorizationByUserCode(ctx context.Context, userCode string) (*store.DeviceAuthorization, error) {
	r, err := s.q(ctx).GetDeviceAuthorizationByUserCode(ctx, userCode)
	if err != nil {
		return nil, mapErr(err)
	}
	return toDeviceAuthorization(r), nil
}

func (s *Store) UpdateDeviceAuthorization(ctx context.Context, d *store.DeviceAuthorization) error {
	if !isID(d.ID) {
		return store.ErrNotFound
	}
	return affected(s.q(ctx).UpdateDeviceAuthorization(ctx, db.UpdateDeviceAuthorizationParams{
		ID: d.ID, DeviceCodeHash: d.DeviceCodeHash, UserCode: d.UserCode, ClientID: d.ClientID,
		Scope: d.Scope, Status: string(d.Status), UserID: d.UserID, ExpiresAt: d.ExpiresAt,
		IntervalSeconds: int32(d.IntervalSeconds), LastPolledAt: d.LastPolledAt,
	}))
}

// DeleteDeviceAuthorization succeeds for a row that is already gone: the
// device package deletes a resolved authorization and ignores the result.
func (s *Store) DeleteDeviceAuthorization(ctx context.Context, id string) error {
	if !isID(id) {
		return nil
	}
	return mapErr(s.q(ctx).DeleteDeviceAuthorization(ctx, id))
}

func toDeviceAuthorization(r db.AuthDeviceAuthorization) *store.DeviceAuthorization {
	return &store.DeviceAuthorization{
		ID: r.ID, DeviceCodeHash: r.DeviceCodeHash, UserCode: r.UserCode, ClientID: r.ClientID,
		Scope: r.Scope, Status: store.DeviceAuthorizationStatus(r.Status), UserID: r.UserID,
		ExpiresAt: r.ExpiresAt, IntervalSeconds: int(r.IntervalSeconds), LastPolledAt: r.LastPolledAt,
		CreatedAt: r.CreatedAt,
	}
}
