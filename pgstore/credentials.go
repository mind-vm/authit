package pgstore

import (
	"context"
	"time"

	"github.com/mind-vm/authit/pgstore/internal/db"
	"github.com/mind-vm/authit/store"
)

func (s *Store) CreateAccount(ctx context.Context, a *store.Account) error {
	return mapErr(s.q(ctx).CreateAccount(ctx, db.CreateAccountParams{
		ID: a.ID, UserID: a.UserID, Provider: a.Provider, ProviderAccountID: a.ProviderAccountID,
		Email: a.Email, EmailVerified: a.EmailVerified, AccessTokenEncrypted: a.AccessTokenEncrypted,
		RefreshTokenEncrypted: a.RefreshTokenEncrypted, TokenExpiresAt: a.TokenExpiresAt,
		Scopes: nonNil(a.Scopes), CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt,
	}))
}

func (s *Store) GetAccount(ctx context.Context, id string) (*store.Account, error) {
	if !isID(id) {
		return nil, store.ErrNotFound
	}
	r, err := s.q(ctx).GetAccount(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	return toAccount(r), nil
}

func (s *Store) GetAccountByProvider(ctx context.Context, provider, providerAccountID string) (*store.Account, error) {
	r, err := s.q(ctx).GetAccountByProvider(ctx, db.GetAccountByProviderParams{
		Provider: provider, ProviderAccountID: providerAccountID,
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return toAccount(r), nil
}

func (s *Store) ListAccountsByUser(ctx context.Context, userID string) ([]*store.Account, error) {
	if !isID(userID) {
		return []*store.Account{}, nil
	}
	rows, err := s.q(ctx).ListAccountsByUser(ctx, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]*store.Account, 0, len(rows))
	for _, r := range rows {
		out = append(out, toAccount(r))
	}
	return out, nil
}

func (s *Store) UpdateAccount(ctx context.Context, a *store.Account) error {
	if !isID(a.ID) {
		return store.ErrNotFound
	}
	return affected(s.q(ctx).UpdateAccount(ctx, db.UpdateAccountParams{
		ID: a.ID, UserID: a.UserID, Provider: a.Provider, ProviderAccountID: a.ProviderAccountID,
		Email: a.Email, EmailVerified: a.EmailVerified, AccessTokenEncrypted: a.AccessTokenEncrypted,
		RefreshTokenEncrypted: a.RefreshTokenEncrypted, TokenExpiresAt: a.TokenExpiresAt,
		Scopes: nonNil(a.Scopes), UpdatedAt: a.UpdatedAt,
	}))
}

func (s *Store) DeleteAccount(ctx context.Context, id string) error {
	if !isID(id) {
		return store.ErrNotFound
	}
	return affected(s.q(ctx).DeleteAccount(ctx, id))
}

func toAccount(r db.AuthAccount) *store.Account {
	return &store.Account{
		ID: r.ID, UserID: r.UserID, Provider: r.Provider, ProviderAccountID: r.ProviderAccountID,
		Email: r.Email, EmailVerified: r.EmailVerified, AccessTokenEncrypted: r.AccessTokenEncrypted,
		RefreshTokenEncrypted: r.RefreshTokenEncrypted, TokenExpiresAt: r.TokenExpiresAt,
		Scopes: r.Scopes, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

func (s *Store) CreateWebAuthnCredential(ctx context.Context, c *store.WebAuthnCredential) error {
	return mapErr(s.q(ctx).CreateWebAuthnCredential(ctx, db.CreateWebAuthnCredentialParams{
		ID: c.ID, UserID: c.UserID, CredentialID: c.CredentialID, Data: c.Data, Name: c.Name,
		Transports: nonNil(c.Transports), BackupEligible: c.BackupEligible, BackupState: c.BackupState,
		CloneWarning: c.CloneWarning, LastUsedAt: c.LastUsedAt, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
	}))
}

func (s *Store) GetWebAuthnCredential(ctx context.Context, id string) (*store.WebAuthnCredential, error) {
	if !isID(id) {
		return nil, store.ErrNotFound
	}
	r, err := s.q(ctx).GetWebAuthnCredential(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	return toWebAuthnCredential(r), nil
}

func (s *Store) GetWebAuthnCredentialByCredentialID(ctx context.Context, credentialID []byte) (*store.WebAuthnCredential, error) {
	r, err := s.q(ctx).GetWebAuthnCredentialByCredentialID(ctx, credentialID)
	if err != nil {
		return nil, mapErr(err)
	}
	return toWebAuthnCredential(r), nil
}

func (s *Store) ListWebAuthnCredentialsByUser(ctx context.Context, userID string) ([]*store.WebAuthnCredential, error) {
	if !isID(userID) {
		return []*store.WebAuthnCredential{}, nil
	}
	rows, err := s.q(ctx).ListWebAuthnCredentialsByUser(ctx, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]*store.WebAuthnCredential, 0, len(rows))
	for _, r := range rows {
		out = append(out, toWebAuthnCredential(r))
	}
	return out, nil
}

func (s *Store) UpdateWebAuthnCredential(ctx context.Context, c *store.WebAuthnCredential) error {
	if !isID(c.ID) {
		return store.ErrNotFound
	}
	return affected(s.q(ctx).UpdateWebAuthnCredential(ctx, db.UpdateWebAuthnCredentialParams{
		ID: c.ID, CredentialID: c.CredentialID, Data: c.Data, Name: c.Name,
		Transports: nonNil(c.Transports), BackupEligible: c.BackupEligible, BackupState: c.BackupState,
		CloneWarning: c.CloneWarning, LastUsedAt: c.LastUsedAt, UpdatedAt: c.UpdatedAt,
	}))
}

func (s *Store) DeleteWebAuthnCredential(ctx context.Context, id string) error {
	if !isID(id) {
		return store.ErrNotFound
	}
	return affected(s.q(ctx).DeleteWebAuthnCredential(ctx, id))
}

func toWebAuthnCredential(r db.AuthWebauthnCredential) *store.WebAuthnCredential {
	return &store.WebAuthnCredential{
		ID: r.ID, UserID: r.UserID, CredentialID: r.CredentialID, Data: r.Data, Name: r.Name,
		Transports: r.Transports, BackupEligible: r.BackupEligible, BackupState: r.BackupState,
		CloneWarning: r.CloneWarning, LastUsedAt: r.LastUsedAt, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

func (s *Store) CreateWebAuthnChallenge(ctx context.Context, c *store.WebAuthnChallenge) error {
	return mapErr(s.q(ctx).CreateWebAuthnChallenge(ctx, db.CreateWebAuthnChallengeParams{
		ID: c.ID, TokenHash: c.TokenHash, UserID: c.UserID, Data: c.Data, ExpiresAt: c.ExpiresAt, CreatedAt: c.CreatedAt,
	}))
}

func (s *Store) ConsumeWebAuthnChallenge(ctx context.Context, tokenHash string) (*store.WebAuthnChallenge, error) {
	r, err := s.q(ctx).ConsumeWebAuthnChallenge(ctx, tokenHash)
	if err != nil {
		return nil, mapErr(err)
	}
	return &store.WebAuthnChallenge{
		ID: r.ID, TokenHash: r.TokenHash, UserID: r.UserID, Data: r.Data, ExpiresAt: r.ExpiresAt, CreatedAt: r.CreatedAt,
	}, nil
}

func (s *Store) CreateEmailLoginToken(ctx context.Context, t *store.EmailLoginToken) error {
	return mapErr(s.q(ctx).CreateEmailLoginToken(ctx, db.CreateEmailLoginTokenParams{
		ID: t.ID, Email: t.Email, Kind: string(t.Kind), TokenHash: t.TokenHash, Attempts: int32(t.Attempts),
		ExpiresAt: t.ExpiresAt, UsedAt: t.UsedAt, CreatedAt: t.CreatedAt,
	}))
}

func (s *Store) GetEmailLoginTokenByHash(ctx context.Context, hash string) (*store.EmailLoginToken, error) {
	r, err := s.q(ctx).GetEmailLoginTokenByHash(ctx, hash)
	if err != nil {
		return nil, mapErr(err)
	}
	return toEmailLoginToken(r), nil
}

func (s *Store) GetEmailLoginTokenByEmail(ctx context.Context, email string, kind store.EmailLoginKind) (*store.EmailLoginToken, error) {
	r, err := s.q(ctx).GetEmailLoginTokenByEmail(ctx, db.GetEmailLoginTokenByEmailParams{Email: email, Kind: string(kind)})
	if err != nil {
		return nil, mapErr(err)
	}
	return toEmailLoginToken(r), nil
}

func (s *Store) MarkEmailLoginTokenUsed(ctx context.Context, id string, usedAt time.Time) error {
	if !isID(id) {
		return store.ErrNotFound
	}
	return affected(s.q(ctx).MarkEmailLoginTokenUsed(ctx, db.MarkEmailLoginTokenUsedParams{ID: id, UsedAt: &usedAt}))
}

func (s *Store) IncrementEmailLoginTokenAttempts(ctx context.Context, id string) (int, error) {
	if !isID(id) {
		return 0, store.ErrNotFound
	}
	n, err := s.q(ctx).IncrementEmailLoginTokenAttempts(ctx, id)
	if err != nil {
		return 0, mapErr(err)
	}
	return int(n), nil
}

func (s *Store) DeleteEmailLoginTokens(ctx context.Context, email string, kind store.EmailLoginKind) error {
	return mapErr(s.q(ctx).DeleteEmailLoginTokens(ctx, db.DeleteEmailLoginTokensParams{Email: email, Kind: string(kind)}))
}

func toEmailLoginToken(r db.AuthEmailLoginToken) *store.EmailLoginToken {
	return &store.EmailLoginToken{
		ID: r.ID, Email: r.Email, Kind: store.EmailLoginKind(r.Kind), TokenHash: r.TokenHash,
		Attempts: int(r.Attempts), ExpiresAt: r.ExpiresAt, UsedAt: r.UsedAt, CreatedAt: r.CreatedAt,
	}
}
