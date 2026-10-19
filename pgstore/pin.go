package pgstore

import (
	"context"
	"time"

	"github.com/mind-vm/authit/pgstore/internal/db"
	"github.com/mind-vm/authit/store"
)

// The pin package's two ports: a user's PIN, and the devices signed in
// with it.

var (
	_ store.PINStore         = (*Store)(nil)
	_ store.BoundDeviceStore = (*Store)(nil)
)

func (s *Store) SetPINCredential(ctx context.Context, c *store.PINCredential) error {
	return mapErr(s.q(ctx).SetPINCredential(ctx, db.SetPINCredentialParams{
		UserID: c.UserID, PinHash: c.PINHash, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
	}))
}

func (s *Store) GetPINCredential(ctx context.Context, userID string) (*store.PINCredential, error) {
	if !isID(userID) {
		return nil, store.ErrNotFound
	}
	r, err := s.q(ctx).GetPINCredential(ctx, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	return &store.PINCredential{UserID: r.UserID, PINHash: r.PinHash, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}, nil
}

func (s *Store) DeletePINCredential(ctx context.Context, userID string) error {
	if !isID(userID) {
		return nil
	}
	return mapErr(s.q(ctx).DeletePINCredential(ctx, userID))
}

func (s *Store) CreateBoundDevice(ctx context.Context, d *store.BoundDevice) error {
	return mapErr(s.q(ctx).CreateBoundDevice(ctx, db.CreateBoundDeviceParams{
		ID: d.ID, UserID: d.UserID, Name: d.Name, TokenHash: d.TokenHash, UserAgent: d.UserAgent,
		IpAddress: d.IPAddress, ExpiresAt: d.ExpiresAt, LastUsedAt: d.LastUsedAt, RevokedAt: d.RevokedAt,
		CreatedAt: d.CreatedAt,
	}))
}

func (s *Store) GetBoundDevice(ctx context.Context, id string) (*store.BoundDevice, error) {
	if !isID(id) {
		return nil, store.ErrNotFound
	}
	r, err := s.q(ctx).GetBoundDevice(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	return toBoundDevice(r), nil
}

func (s *Store) GetBoundDeviceByTokenHash(ctx context.Context, hash string) (*store.BoundDevice, error) {
	r, err := s.q(ctx).GetBoundDeviceByTokenHash(ctx, hash)
	if err != nil {
		return nil, mapErr(err)
	}
	return toBoundDevice(r), nil
}

func (s *Store) ListBoundDevicesByUser(ctx context.Context, userID string) ([]*store.BoundDevice, error) {
	if !isID(userID) {
		return []*store.BoundDevice{}, nil
	}
	rows, err := s.q(ctx).ListBoundDevicesByUser(ctx, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]*store.BoundDevice, 0, len(rows))
	for _, r := range rows {
		out = append(out, toBoundDevice(r))
	}
	return out, nil
}

func (s *Store) TouchBoundDevice(ctx context.Context, id string, at time.Time) error {
	if !isID(id) {
		return store.ErrNotFound
	}
	return affected(s.q(ctx).TouchBoundDevice(ctx, db.TouchBoundDeviceParams{ID: id, LastUsedAt: &at}))
}

func (s *Store) RevokeBoundDevice(ctx context.Context, id string, at time.Time) error {
	if !isID(id) {
		return store.ErrNotFound
	}
	return affected(s.q(ctx).RevokeBoundDevice(ctx, db.RevokeBoundDeviceParams{ID: id, RevokedAt: &at}))
}

func (s *Store) RevokeAllBoundDevices(ctx context.Context, userID string, at time.Time) (int, error) {
	if !isID(userID) {
		return 0, nil
	}
	n, err := s.q(ctx).RevokeAllBoundDevices(ctx, db.RevokeAllBoundDevicesParams{UserID: userID, RevokedAt: &at})
	return int(n), mapErr(err)
}

func toBoundDevice(r db.AuthBoundDevice) *store.BoundDevice {
	return &store.BoundDevice{
		ID: r.ID, UserID: r.UserID, Name: r.Name, TokenHash: r.TokenHash, UserAgent: r.UserAgent,
		IPAddress: r.IpAddress, ExpiresAt: r.ExpiresAt, LastUsedAt: r.LastUsedAt, RevokedAt: r.RevokedAt,
		CreatedAt: r.CreatedAt,
	}
}
