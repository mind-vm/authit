package sqlitestore

import (
	"context"
	"time"

	"github.com/mind-vm/authit/store"
)

const accountCols = `id, user_id, provider, provider_account_id, email, email_verified,
	access_token_encrypted, refresh_token_encrypted, token_expires_at, scopes, created_at, updated_at`

func scanAccount(r scanner) (*store.Account, error) {
	var a store.Account
	err := r.Scan(&a.ID, &a.UserID, &a.Provider, &a.ProviderAccountID, &a.Email, &a.EmailVerified,
		&a.AccessTokenEncrypted, &a.RefreshTokenEncrypted, tmPtr{&a.TokenExpiresAt}, strs{&a.Scopes},
		tm{&a.CreatedAt}, tm{&a.UpdatedAt})
	return &a, err
}

func (s *Store) CreateAccount(ctx context.Context, a *store.Account) error {
	if err := newID(&a.ID); err != nil {
		return err
	}
	userID, err := ref(a.UserID)
	if err != nil {
		return err
	}
	a.UserID = userID
	scopes, err := list(a.Scopes)
	if err != nil {
		return err
	}
	return s.exec(ctx, `INSERT INTO auth_accounts (`+accountCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.UserID, a.Provider, a.ProviderAccountID, a.Email, a.EmailVerified,
		a.AccessTokenEncrypted, a.RefreshTokenEncrypted, tsPtr(a.TokenExpiresAt), scopes,
		ts(a.CreatedAt), ts(a.UpdatedAt))
}

func (s *Store) GetAccount(ctx context.Context, id string) (*store.Account, error) {
	id, ok := canon(id)
	if !ok {
		return nil, store.ErrNotFound
	}
	return one(ctx, s.q(ctx), scanAccount, `SELECT `+accountCols+` FROM auth_accounts WHERE id = ?`, id)
}

func (s *Store) GetAccountByProvider(ctx context.Context, provider, providerAccountID string) (*store.Account, error) {
	return one(ctx, s.q(ctx), scanAccount, `SELECT `+accountCols+` FROM auth_accounts
		WHERE provider = ? AND provider_account_id = ?`, provider, providerAccountID)
}

func (s *Store) ListAccountsByUser(ctx context.Context, userID string) ([]*store.Account, error) {
	userID, ok := canon(userID)
	if !ok {
		return []*store.Account{}, nil
	}
	return collect(ctx, s.q(ctx), scanAccount, `SELECT `+accountCols+` FROM auth_accounts
		WHERE user_id = ? ORDER BY created_at, id`, userID)
}

func (s *Store) UpdateAccount(ctx context.Context, a *store.Account) error {
	id, ok := canon(a.ID)
	if !ok {
		return store.ErrNotFound
	}
	userID, err := ref(a.UserID)
	if err != nil {
		return err
	}
	scopes, err := list(a.Scopes)
	if err != nil {
		return err
	}
	return s.execRow(ctx, `UPDATE auth_accounts
		SET user_id = ?, provider = ?, provider_account_id = ?, email = ?, email_verified = ?,
		    access_token_encrypted = ?, refresh_token_encrypted = ?, token_expires_at = ?,
		    scopes = ?, updated_at = ?
		WHERE id = ?`,
		userID, a.Provider, a.ProviderAccountID, a.Email, a.EmailVerified,
		a.AccessTokenEncrypted, a.RefreshTokenEncrypted, tsPtr(a.TokenExpiresAt), scopes, ts(a.UpdatedAt), id)
}

func (s *Store) DeleteAccount(ctx context.Context, id string) error {
	id, ok := canon(id)
	if !ok {
		return store.ErrNotFound
	}
	return s.execRow(ctx, `DELETE FROM auth_accounts WHERE id = ?`, id)
}

const webAuthnCredentialCols = `id, user_id, credential_id, data, name, transports,
	backup_eligible, backup_state, clone_warning, last_used_at, created_at, updated_at`

func scanWebAuthnCredential(r scanner) (*store.WebAuthnCredential, error) {
	var c store.WebAuthnCredential
	err := r.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.Data, &c.Name, strs{&c.Transports},
		&c.BackupEligible, &c.BackupState, &c.CloneWarning, tmPtr{&c.LastUsedAt}, tm{&c.CreatedAt}, tm{&c.UpdatedAt})
	return &c, err
}

func (s *Store) CreateWebAuthnCredential(ctx context.Context, c *store.WebAuthnCredential) error {
	if err := newID(&c.ID); err != nil {
		return err
	}
	userID, err := ref(c.UserID)
	if err != nil {
		return err
	}
	c.UserID = userID
	transports, err := list(c.Transports)
	if err != nil {
		return err
	}
	return s.exec(ctx, `INSERT INTO auth_webauthn_credentials (`+webAuthnCredentialCols+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.UserID, c.CredentialID, c.Data, c.Name, transports,
		c.BackupEligible, c.BackupState, c.CloneWarning, tsPtr(c.LastUsedAt), ts(c.CreatedAt), ts(c.UpdatedAt))
}

func (s *Store) GetWebAuthnCredential(ctx context.Context, id string) (*store.WebAuthnCredential, error) {
	id, ok := canon(id)
	if !ok {
		return nil, store.ErrNotFound
	}
	return one(ctx, s.q(ctx), scanWebAuthnCredential,
		`SELECT `+webAuthnCredentialCols+` FROM auth_webauthn_credentials WHERE id = ?`, id)
}

func (s *Store) GetWebAuthnCredentialByCredentialID(ctx context.Context, credentialID []byte) (*store.WebAuthnCredential, error) {
	return one(ctx, s.q(ctx), scanWebAuthnCredential,
		`SELECT `+webAuthnCredentialCols+` FROM auth_webauthn_credentials WHERE credential_id = ?`, credentialID)
}

func (s *Store) ListWebAuthnCredentialsByUser(ctx context.Context, userID string) ([]*store.WebAuthnCredential, error) {
	userID, ok := canon(userID)
	if !ok {
		return []*store.WebAuthnCredential{}, nil
	}
	return collect(ctx, s.q(ctx), scanWebAuthnCredential, `SELECT `+webAuthnCredentialCols+`
		FROM auth_webauthn_credentials WHERE user_id = ? ORDER BY created_at, id`, userID)
}

func (s *Store) UpdateWebAuthnCredential(ctx context.Context, c *store.WebAuthnCredential) error {
	id, ok := canon(c.ID)
	if !ok {
		return store.ErrNotFound
	}
	transports, err := list(c.Transports)
	if err != nil {
		return err
	}
	return s.execRow(ctx, `UPDATE auth_webauthn_credentials
		SET credential_id = ?, data = ?, name = ?, transports = ?, backup_eligible = ?,
		    backup_state = ?, clone_warning = ?, last_used_at = ?, updated_at = ?
		WHERE id = ?`,
		c.CredentialID, c.Data, c.Name, transports, c.BackupEligible,
		c.BackupState, c.CloneWarning, tsPtr(c.LastUsedAt), ts(c.UpdatedAt), id)
}

func (s *Store) DeleteWebAuthnCredential(ctx context.Context, id string) error {
	id, ok := canon(id)
	if !ok {
		return store.ErrNotFound
	}
	return s.execRow(ctx, `DELETE FROM auth_webauthn_credentials WHERE id = ?`, id)
}

const webAuthnChallengeCols = `id, token_hash, user_id, data, expires_at, created_at`

func (s *Store) CreateWebAuthnChallenge(ctx context.Context, c *store.WebAuthnChallenge) error {
	if err := newID(&c.ID); err != nil {
		return err
	}
	userID, err := refPtr(c.UserID)
	if err != nil {
		return err
	}
	if u, ok := userID.(string); ok {
		c.UserID = &u
	}
	return s.exec(ctx, `INSERT INTO auth_webauthn_challenges (`+webAuthnChallengeCols+`) VALUES (?, ?, ?, ?, ?, ?)`,
		c.ID, c.TokenHash, userID, c.Data, ts(c.ExpiresAt), ts(c.CreatedAt))
}

// ConsumeWebAuthnChallenge lets the DELETE decide, so two redemptions of one
// challenge cannot both get the row.
func (s *Store) ConsumeWebAuthnChallenge(ctx context.Context, tokenHash string) (*store.WebAuthnChallenge, error) {
	return one(ctx, s.q(ctx), func(r scanner) (*store.WebAuthnChallenge, error) {
		var c store.WebAuthnChallenge
		err := r.Scan(&c.ID, &c.TokenHash, &c.UserID, &c.Data, tm{&c.ExpiresAt}, tm{&c.CreatedAt})
		return &c, err
	}, `DELETE FROM auth_webauthn_challenges WHERE token_hash = ? RETURNING `+webAuthnChallengeCols, tokenHash)
}

const emailLoginTokenCols = `id, email, kind, token_hash, attempts, expires_at, used_at, created_at`

func scanEmailLoginToken(r scanner) (*store.EmailLoginToken, error) {
	var t store.EmailLoginToken
	err := r.Scan(&t.ID, &t.Email, &t.Kind, &t.TokenHash, &t.Attempts, tm{&t.ExpiresAt}, tmPtr{&t.UsedAt}, tm{&t.CreatedAt})
	return &t, err
}

func (s *Store) CreateEmailLoginToken(ctx context.Context, t *store.EmailLoginToken) error {
	if err := newID(&t.ID); err != nil {
		return err
	}
	return s.exec(ctx, `INSERT INTO auth_email_login_tokens (`+emailLoginTokenCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Email, string(t.Kind), t.TokenHash, t.Attempts, ts(t.ExpiresAt), tsPtr(t.UsedAt), ts(t.CreatedAt))
}

func (s *Store) GetEmailLoginTokenByHash(ctx context.Context, hash string) (*store.EmailLoginToken, error) {
	return one(ctx, s.q(ctx), scanEmailLoginToken,
		`SELECT `+emailLoginTokenCols+` FROM auth_email_login_tokens WHERE token_hash = ?`, hash)
}

func (s *Store) GetEmailLoginTokenByEmail(ctx context.Context, email string, kind store.EmailLoginKind) (*store.EmailLoginToken, error) {
	return one(ctx, s.q(ctx), scanEmailLoginToken, `SELECT `+emailLoginTokenCols+` FROM auth_email_login_tokens
		WHERE email = ? AND kind = ?
		ORDER BY created_at DESC, id DESC
		LIMIT 1`, email, string(kind))
}

// MarkEmailLoginTokenUsed is a compare-and-set: no row means another
// redemption won.
func (s *Store) MarkEmailLoginTokenUsed(ctx context.Context, id string, usedAt time.Time) error {
	id, ok := canon(id)
	if !ok {
		return store.ErrNotFound
	}
	return s.execRow(ctx, `UPDATE auth_email_login_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL`,
		ts(usedAt), id)
}

// IncrementEmailLoginTokenAttempts lets the database compute the count, so
// parallel guesses each cost one.
func (s *Store) IncrementEmailLoginTokenAttempts(ctx context.Context, id string) (int, error) {
	id, ok := canon(id)
	if !ok {
		return 0, store.ErrNotFound
	}
	var n int
	err := s.q(ctx).QueryRowContext(ctx,
		`UPDATE auth_email_login_tokens SET attempts = attempts + 1 WHERE id = ? RETURNING attempts`, id).Scan(&n)
	if err != nil {
		return 0, mapErr(err)
	}
	return n, nil
}

func (s *Store) DeleteEmailLoginTokens(ctx context.Context, email string, kind store.EmailLoginKind) error {
	return s.exec(ctx, `DELETE FROM auth_email_login_tokens WHERE email = ? AND kind = ?`, email, string(kind))
}
