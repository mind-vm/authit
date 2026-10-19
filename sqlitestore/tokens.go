package sqlitestore

import (
	"context"

	"github.com/mind-vm/authit/store"
)

// Personal access tokens and RFC 8628 device authorizations: the two
// credentials a user hands to a CLI or a script.

var (
	_ store.PersonalAccessTokenStore = (*Store)(nil)
	_ store.DeviceAuthorizationStore = (*Store)(nil)
)

const patCols = `id, user_id, name, token_hash, scopes, expires_at, last_used_at, revoked_at, created_at`

func scanPersonalAccessToken(r scanner) (*store.PersonalAccessToken, error) {
	var t store.PersonalAccessToken
	err := r.Scan(&t.ID, &t.UserID, &t.Name, &t.TokenHash, strs{&t.Scopes}, tmPtr{&t.ExpiresAt},
		tmPtr{&t.LastUsedAt}, tmPtr{&t.RevokedAt}, tm{&t.CreatedAt})
	return &t, err
}

func (s *Store) CreatePersonalAccessToken(ctx context.Context, t *store.PersonalAccessToken) error {
	if err := newID(&t.ID); err != nil {
		return err
	}
	userID, err := ref(t.UserID)
	if err != nil {
		return err
	}
	t.UserID = userID
	scopes, err := list(t.Scopes)
	if err != nil {
		return err
	}
	return s.exec(ctx, `INSERT INTO auth_personal_access_tokens (`+patCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.UserID, t.Name, t.TokenHash, scopes, tsPtr(t.ExpiresAt), tsPtr(t.LastUsedAt),
		tsPtr(t.RevokedAt), ts(t.CreatedAt))
}

func (s *Store) GetPersonalAccessToken(ctx context.Context, id string) (*store.PersonalAccessToken, error) {
	id, ok := canon(id)
	if !ok {
		return nil, store.ErrNotFound
	}
	return one(ctx, s.q(ctx), scanPersonalAccessToken,
		`SELECT `+patCols+` FROM auth_personal_access_tokens WHERE id = ?`, id)
}

// GetPersonalAccessTokenByHash returns revoked and expired tokens too: the
// service reads both columns itself.
func (s *Store) GetPersonalAccessTokenByHash(ctx context.Context, hash string) (*store.PersonalAccessToken, error) {
	return one(ctx, s.q(ctx), scanPersonalAccessToken,
		`SELECT `+patCols+` FROM auth_personal_access_tokens WHERE token_hash = ?`, hash)
}

func (s *Store) ListPersonalAccessTokensByUser(ctx context.Context, userID string) ([]*store.PersonalAccessToken, error) {
	userID, ok := canon(userID)
	if !ok {
		return []*store.PersonalAccessToken{}, nil
	}
	return collect(ctx, s.q(ctx), scanPersonalAccessToken, `SELECT `+patCols+` FROM auth_personal_access_tokens
		WHERE user_id = ? ORDER BY created_at, id`, userID)
}

func (s *Store) UpdatePersonalAccessToken(ctx context.Context, t *store.PersonalAccessToken) error {
	id, ok := canon(t.ID)
	if !ok {
		return store.ErrNotFound
	}
	userID, err := ref(t.UserID)
	if err != nil {
		return err
	}
	scopes, err := list(t.Scopes)
	if err != nil {
		return err
	}
	return s.execRow(ctx, `UPDATE auth_personal_access_tokens
		SET user_id = ?, name = ?, token_hash = ?, scopes = ?, expires_at = ?, last_used_at = ?, revoked_at = ?
		WHERE id = ?`,
		userID, t.Name, t.TokenHash, scopes, tsPtr(t.ExpiresAt), tsPtr(t.LastUsedAt), tsPtr(t.RevokedAt), id)
}

const deviceAuthorizationCols = `id, device_code_hash, user_code, client_id, scope, status, user_id,
	expires_at, interval_seconds, last_polled_at, created_at`

func scanDeviceAuthorization(r scanner) (*store.DeviceAuthorization, error) {
	var d store.DeviceAuthorization
	err := r.Scan(&d.ID, &d.DeviceCodeHash, &d.UserCode, &d.ClientID, &d.Scope, &d.Status, &d.UserID,
		tm{&d.ExpiresAt}, &d.IntervalSeconds, tmPtr{&d.LastPolledAt}, tm{&d.CreatedAt})
	return &d, err
}

func (s *Store) CreateDeviceAuthorization(ctx context.Context, d *store.DeviceAuthorization) error {
	if err := newID(&d.ID); err != nil {
		return err
	}
	userID, err := refPtr(d.UserID)
	if err != nil {
		return err
	}
	return s.exec(ctx, `INSERT INTO auth_device_authorizations (`+deviceAuthorizationCols+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.ID, d.DeviceCodeHash, d.UserCode, d.ClientID, d.Scope, string(d.Status), userID,
		ts(d.ExpiresAt), d.IntervalSeconds, tsPtr(d.LastPolledAt), ts(d.CreatedAt))
}

func (s *Store) GetDeviceAuthorizationByDeviceCodeHash(ctx context.Context, hash string) (*store.DeviceAuthorization, error) {
	return one(ctx, s.q(ctx), scanDeviceAuthorization,
		`SELECT `+deviceAuthorizationCols+` FROM auth_device_authorizations WHERE device_code_hash = ?`, hash)
}

func (s *Store) GetDeviceAuthorizationByUserCode(ctx context.Context, userCode string) (*store.DeviceAuthorization, error) {
	return one(ctx, s.q(ctx), scanDeviceAuthorization,
		`SELECT `+deviceAuthorizationCols+` FROM auth_device_authorizations WHERE user_code = ?`, userCode)
}

func (s *Store) UpdateDeviceAuthorization(ctx context.Context, d *store.DeviceAuthorization) error {
	id, ok := canon(d.ID)
	if !ok {
		return store.ErrNotFound
	}
	userID, err := refPtr(d.UserID)
	if err != nil {
		return err
	}
	return s.execRow(ctx, `UPDATE auth_device_authorizations
		SET device_code_hash = ?, user_code = ?, client_id = ?, scope = ?, status = ?, user_id = ?,
		    expires_at = ?, interval_seconds = ?, last_polled_at = ?
		WHERE id = ?`,
		d.DeviceCodeHash, d.UserCode, d.ClientID, d.Scope, string(d.Status), userID,
		ts(d.ExpiresAt), d.IntervalSeconds, tsPtr(d.LastPolledAt), id)
}

// DeleteDeviceAuthorization succeeds for a row that is already gone: the
// device package deletes a resolved authorization and ignores the result.
func (s *Store) DeleteDeviceAuthorization(ctx context.Context, id string) error {
	id, ok := canon(id)
	if !ok {
		return nil
	}
	return s.exec(ctx, `DELETE FROM auth_device_authorizations WHERE id = ?`, id)
}
