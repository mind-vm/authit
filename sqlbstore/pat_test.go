package sqlbstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/jryannel/authit/sqlbstore"
	"github.com/jryannel/authit/store"
	"github.com/jryannel/sqlb"
)

// testToken mirrors the shape a real app's sqlb-generated row type has —
// deliberately using different field/column names than store.
// PersonalAccessToken (Owner instead of UserID, Label instead of Name) to
// prove the adapter doesn't require schema conformity.
type testToken struct {
	ID         string     `db:"id" sqlb:"type:uuid,pk,default"`
	Owner      string     `db:"owner_id" sqlb:"type:uuid"`
	Label      *string    `db:"label" sqlb:"type:text"`
	Hash       string     `db:"hash" sqlb:"type:text"`
	Scopes     []string   `db:"scopes" sqlb:"type:text"`
	ExpiresAt  *time.Time `db:"expires_at" sqlb:"type:timestamptz"`
	RevokedAt  *time.Time `db:"revoked_at" sqlb:"type:timestamptz"`
	LastUsedAt *time.Time `db:"last_used_at" sqlb:"type:timestamptz"`
	CreatedAt  time.Time  `db:"created_at" sqlb:"type:timestamptz,default"`
}

func (testToken) TableName() string { return "sqlbstore_test_tokens" }

func adapter(db sqlb.Executor) sqlbstore.PersonalAccessTokenAdapter[testToken] {
	return sqlbstore.PersonalAccessTokenAdapter[testToken]{
		Table: sqlbstore.Table[testToken, store.PersonalAccessToken]{
			ToRow: func(t store.PersonalAccessToken) testToken {
				return testToken{
					Owner: t.UserID, Label: nullable(t.Name), Hash: t.TokenHash,
					Scopes: t.Scopes, ExpiresAt: t.ExpiresAt, RevokedAt: t.RevokedAt, LastUsedAt: t.LastUsedAt,
				}
			},
			FromRow: func(r testToken) store.PersonalAccessToken {
				return store.PersonalAccessToken{
					ID: r.ID, UserID: r.Owner, Name: deref(r.Label), TokenHash: r.Hash,
					Scopes: r.Scopes, ExpiresAt: r.ExpiresAt, RevokedAt: r.RevokedAt,
					LastUsedAt: r.LastUsedAt, CreatedAt: r.CreatedAt,
				}
			},
			GetID:    func(t store.PersonalAccessToken) string { return t.ID },
			SetID:    func(r testToken, id string) testToken { r.ID = id; return r },
			IDColumn: "id",
			ToUpdateColumns: func(t store.PersonalAccessToken) map[string]any {
				return map[string]any{
					"label": nullable(t.Name), "scopes": t.Scopes, "expires_at": t.ExpiresAt,
					"revoked_at": t.RevokedAt, "last_used_at": t.LastUsedAt,
				}
			},
		},
		DB:              db,
		UserIDColumn:    "owner_id",
		TokenHashColumn: "hash",
	}
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// testDB creates/drops a throwaway table for TestPersonalAccessTokenAdapterCRUD.
func testDB(t *testing.T) sqlb.Executor {
	t.Helper()
	pool := testPool(t)
	return applyDDL(t, pool, `
		CREATE TABLE IF NOT EXISTS sqlbstore_test_tokens (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			owner_id uuid NOT NULL,
			label text,
			hash text NOT NULL,
			scopes text[],
			expires_at timestamptz,
			revoked_at timestamptz,
			last_used_at timestamptz,
			created_at timestamptz NOT NULL DEFAULT now()
		)`, "sqlbstore_test_tokens")
}

func TestPersonalAccessTokenAdapterCRUD(t *testing.T) {
	db := testDB(t)
	a := adapter(db)
	ctx := context.Background()

	ownerID := "11111111-1111-1111-1111-111111111111"
	t1 := &store.PersonalAccessToken{UserID: ownerID, Name: "laptop", TokenHash: "hash-1", Scopes: []string{"read", "write"}}
	if err := a.CreatePersonalAccessToken(ctx, t1); err != nil {
		t.Fatalf("CreatePersonalAccessToken: %v", err)
	}
	if t1.ID == "" || t1.CreatedAt.IsZero() {
		t.Fatalf("expected DB-defaulted ID/CreatedAt to be populated, got %+v", t1)
	}

	byID, err := a.GetPersonalAccessToken(ctx, t1.ID)
	if err != nil {
		t.Fatalf("GetPersonalAccessToken: %v", err)
	}
	if byID.Name != "laptop" || byID.UserID != ownerID {
		t.Fatalf("unexpected row: %+v", byID)
	}

	byHash, err := a.GetPersonalAccessTokenByHash(ctx, "hash-1")
	if err != nil {
		t.Fatalf("GetPersonalAccessTokenByHash: %v", err)
	}
	if byHash.ID != t1.ID {
		t.Fatalf("expected same row by hash, got %+v", byHash)
	}

	if _, err := a.GetPersonalAccessTokenByHash(ctx, "no-such-hash"); err != store.ErrNotFound {
		t.Fatalf("expected store.ErrNotFound, got %v", err)
	}

	t2 := &store.PersonalAccessToken{UserID: ownerID, Name: "phone", TokenHash: "hash-2"}
	if err := a.CreatePersonalAccessToken(ctx, t2); err != nil {
		t.Fatalf("CreatePersonalAccessToken (t2): %v", err)
	}

	list, err := a.ListPersonalAccessTokensByUser(ctx, ownerID)
	if err != nil {
		t.Fatalf("ListPersonalAccessTokensByUser: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(list))
	}

	now := time.Now().Round(time.Millisecond)
	byID.LastUsedAt = &now
	if err := a.UpdatePersonalAccessToken(ctx, byID); err != nil {
		t.Fatalf("UpdatePersonalAccessToken: %v", err)
	}
	reread, err := a.GetPersonalAccessToken(ctx, t1.ID)
	if err != nil {
		t.Fatalf("GetPersonalAccessToken (reread): %v", err)
	}
	if reread.LastUsedAt == nil || !reread.LastUsedAt.Equal(now) {
		t.Fatalf("expected LastUsedAt to persist, got %+v", reread.LastUsedAt)
	}
	// Update must not have touched unrelated fields (name, hash).
	if reread.Name != "laptop" || reread.TokenHash != "hash-1" {
		t.Fatalf("update touched unrelated columns: %+v", reread)
	}
}
