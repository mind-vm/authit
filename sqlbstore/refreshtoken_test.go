package sqlbstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/mind-vm/authit/sqlbstore"
	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/sqlb"
)

type testRefreshToken struct {
	ID        string     `db:"id" sqlb:"type:uuid,pk,default"`
	UserID    string     `db:"user_id" sqlb:"type:uuid"`
	Hash      string     `db:"hash" sqlb:"type:text"`
	ExpiresAt time.Time  `db:"expires_at" sqlb:"type:timestamptz"`
	RevokedAt *time.Time `db:"revoked_at" sqlb:"type:timestamptz"`
	CreatedAt time.Time  `db:"created_at" sqlb:"type:timestamptz,default"`
}

func (testRefreshToken) TableName() string { return "sqlbstore_test_refresh_tokens" }

func refreshTokenAdapter(db sqlb.Executor) sqlbstore.RefreshTokenAdapter[testRefreshToken] {
	return sqlbstore.RefreshTokenAdapter[testRefreshToken]{
		Table: sqlbstore.Table[testRefreshToken, store.RefreshToken]{
			ToRow: func(t store.RefreshToken) testRefreshToken {
				return testRefreshToken{UserID: t.UserID, Hash: t.TokenHash, ExpiresAt: t.ExpiresAt, RevokedAt: t.RevokedAt}
			},
			FromRow: func(r testRefreshToken) store.RefreshToken {
				return store.RefreshToken{ID: r.ID, UserID: r.UserID, TokenHash: r.Hash, ExpiresAt: r.ExpiresAt, RevokedAt: r.RevokedAt, CreatedAt: r.CreatedAt}
			},
			GetID:    func(t store.RefreshToken) string { return t.ID },
			SetID:    func(r testRefreshToken, id string) testRefreshToken { r.ID = id; return r },
			IDColumn: "id",
			ToUpdateColumns: func(t store.RefreshToken) map[string]any {
				return map[string]any{"revoked_at": t.RevokedAt}
			},
		},
		DB:              db,
		UserIDColumn:    "user_id",
		TokenHashColumn: "hash",
		RevokedAtColumn: "revoked_at",
		ExpiresAtColumn: "expires_at",
	}
}

func TestRefreshTokenAdapter(t *testing.T) {
	pool := testPool(t)
	db := applyDDL(t, pool, `
		CREATE TABLE IF NOT EXISTS sqlbstore_test_refresh_tokens (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id uuid NOT NULL,
			hash text NOT NULL,
			expires_at timestamptz NOT NULL,
			revoked_at timestamptz,
			created_at timestamptz NOT NULL DEFAULT now()
		)`, "sqlbstore_test_refresh_tokens")
	a := refreshTokenAdapter(db)
	ctx := context.Background()

	userID := "22222222-2222-2222-2222-222222222222"
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)

	live := &store.RefreshToken{UserID: userID, TokenHash: "h-live", ExpiresAt: future}
	expired := &store.RefreshToken{UserID: userID, TokenHash: "h-expired", ExpiresAt: past}
	toRevoke := &store.RefreshToken{UserID: userID, TokenHash: "h-revoke-me", ExpiresAt: future}
	otherUserID := "22222222-9999-9999-9999-999999999999"
	other := &store.RefreshToken{UserID: otherUserID, TokenHash: "h-other", ExpiresAt: future}
	for _, tok := range []*store.RefreshToken{live, expired, toRevoke, other} {
		if err := a.CreateRefreshToken(ctx, tok); err != nil {
			t.Fatalf("CreateRefreshToken: %v", err)
		}
	}

	fetched, err := a.GetRefreshTokenByHash(ctx, "h-live")
	if err != nil {
		t.Fatalf("GetRefreshTokenByHash: %v", err)
	}
	if fetched.ID != live.ID {
		t.Fatalf("unexpected token: %+v", fetched)
	}

	if err := a.RevokeRefreshToken(ctx, toRevoke.ID); err != nil {
		t.Fatalf("RevokeRefreshToken: %v", err)
	}

	// Active list must exclude: expired, revoked, and other users' tokens.
	active, err := a.ListActiveRefreshTokens(ctx, userID)
	if err != nil {
		t.Fatalf("ListActiveRefreshTokens: %v", err)
	}
	if len(active) != 1 || active[0].ID != live.ID {
		t.Fatalf("expected exactly [live], got %+v", active)
	}

	if err := a.RevokeAllUserRefreshTokens(ctx, userID); err != nil {
		t.Fatalf("RevokeAllUserRefreshTokens: %v", err)
	}
	active, err = a.ListActiveRefreshTokens(ctx, userID)
	if err != nil {
		t.Fatalf("ListActiveRefreshTokens (after revoke-all): %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("expected no active tokens after RevokeAllUserRefreshTokens, got %+v", active)
	}

	// The other user's token must survive RevokeAllUserRefreshTokens.
	otherActive, err := a.ListActiveRefreshTokens(ctx, otherUserID)
	if err != nil {
		t.Fatalf("ListActiveRefreshTokens (other-user): %v", err)
	}
	if len(otherActive) != 1 || otherActive[0].ID != other.ID {
		t.Fatalf("expected other user's token untouched, got %+v", otherActive)
	}
}
