package sqlitestore

import (
	"context"
	"time"

	"github.com/mind-vm/authit/store"
)

// The pin package's two ports: a user's PIN, and the devices signed in
// with it.

var (
	_ store.PINStore         = (*Store)(nil)
	_ store.BoundDeviceStore = (*Store)(nil)
)

// SetPINCredential replaces an existing PIN in place, keeping the row's
// created_at.
func (s *Store) SetPINCredential(ctx context.Context, c *store.PINCredential) error {
	userID, err := ref(c.UserID)
	if err != nil {
		return err
	}
	c.UserID = userID
	return s.exec(ctx, `INSERT INTO auth_pin_credentials (user_id, pin_hash, created_at, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (user_id) DO UPDATE SET pin_hash = excluded.pin_hash, updated_at = excluded.updated_at`,
		c.UserID, c.PINHash, ts(c.CreatedAt), ts(c.UpdatedAt))
}

func (s *Store) GetPINCredential(ctx context.Context, userID string) (*store.PINCredential, error) {
	userID, ok := canon(userID)
	if !ok {
		return nil, store.ErrNotFound
	}
	return one(ctx, s.q(ctx), func(r scanner) (*store.PINCredential, error) {
		var c store.PINCredential
		err := r.Scan(&c.UserID, &c.PINHash, tm{&c.CreatedAt}, tm{&c.UpdatedAt})
		return &c, err
	}, `SELECT user_id, pin_hash, created_at, updated_at FROM auth_pin_credentials WHERE user_id = ?`, userID)
}

func (s *Store) DeletePINCredential(ctx context.Context, userID string) error {
	userID, ok := canon(userID)
	if !ok {
		return nil
	}
	return s.exec(ctx, `DELETE FROM auth_pin_credentials WHERE user_id = ?`, userID)
}

const boundDeviceCols = `id, user_id, name, token_hash, user_agent, ip_address,
	expires_at, last_used_at, revoked_at, created_at`

func scanBoundDevice(r scanner) (*store.BoundDevice, error) {
	var d store.BoundDevice
	err := r.Scan(&d.ID, &d.UserID, &d.Name, &d.TokenHash, &d.UserAgent, &d.IPAddress,
		tmPtr{&d.ExpiresAt}, tmPtr{&d.LastUsedAt}, tmPtr{&d.RevokedAt}, tm{&d.CreatedAt})
	return &d, err
}

func (s *Store) CreateBoundDevice(ctx context.Context, d *store.BoundDevice) error {
	if err := newID(&d.ID); err != nil {
		return err
	}
	userID, err := ref(d.UserID)
	if err != nil {
		return err
	}
	d.UserID = userID
	return s.exec(ctx, `INSERT INTO auth_bound_devices (`+boundDeviceCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.ID, d.UserID, d.Name, d.TokenHash, d.UserAgent, d.IPAddress,
		tsPtr(d.ExpiresAt), tsPtr(d.LastUsedAt), tsPtr(d.RevokedAt), ts(d.CreatedAt))
}

func (s *Store) GetBoundDevice(ctx context.Context, id string) (*store.BoundDevice, error) {
	id, ok := canon(id)
	if !ok {
		return nil, store.ErrNotFound
	}
	return one(ctx, s.q(ctx), scanBoundDevice, `SELECT `+boundDeviceCols+` FROM auth_bound_devices WHERE id = ?`, id)
}

// GetBoundDeviceByTokenHash returns revoked and expired devices too: the
// service reads both columns itself.
func (s *Store) GetBoundDeviceByTokenHash(ctx context.Context, hash string) (*store.BoundDevice, error) {
	return one(ctx, s.q(ctx), scanBoundDevice,
		`SELECT `+boundDeviceCols+` FROM auth_bound_devices WHERE token_hash = ?`, hash)
}

func (s *Store) ListBoundDevicesByUser(ctx context.Context, userID string) ([]*store.BoundDevice, error) {
	userID, ok := canon(userID)
	if !ok {
		return []*store.BoundDevice{}, nil
	}
	return collect(ctx, s.q(ctx), scanBoundDevice, `SELECT `+boundDeviceCols+` FROM auth_bound_devices
		WHERE user_id = ? ORDER BY created_at, id`, userID)
}

// TouchBoundDevice does not touch a revoked device, so a use racing a
// revocation cannot write over it.
func (s *Store) TouchBoundDevice(ctx context.Context, id string, at time.Time) error {
	id, ok := canon(id)
	if !ok {
		return store.ErrNotFound
	}
	return s.execRow(ctx, `UPDATE auth_bound_devices SET last_used_at = ? WHERE id = ? AND revoked_at IS NULL`, ts(at), id)
}

func (s *Store) RevokeBoundDevice(ctx context.Context, id string, at time.Time) error {
	id, ok := canon(id)
	if !ok {
		return store.ErrNotFound
	}
	return s.execRow(ctx, `UPDATE auth_bound_devices SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?`, ts(at), id)
}

func (s *Store) RevokeAllBoundDevices(ctx context.Context, userID string, at time.Time) (int, error) {
	userID, ok := canon(userID)
	if !ok {
		return 0, nil
	}
	n, err := s.execCount(ctx, `UPDATE auth_bound_devices SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
		ts(at), userID)
	return int(n), err
}
