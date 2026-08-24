package sqlbstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/jryannel/authit/sqlbstore"
	"github.com/jryannel/authit/store"
)

type testSuperuser struct {
	ID           string    `db:"id" sqlb:"type:uuid,pk,default"`
	Email        string    `db:"email" sqlb:"type:text"`
	PasswordHash string    `db:"password_hash" sqlb:"type:text"`
	DisplayName  string    `db:"display_name" sqlb:"type:text"`
	IsActive     bool      `db:"is_active" sqlb:"type:bool,default"`
	CreatedAt    time.Time `db:"created_at" sqlb:"type:timestamptz,default"`
}

func (testSuperuser) TableName() string { return "sqlbstore_test_superusers" }

// TestSuperuserAdapterNoPredicateListAndCount exercises ListWhere/CountWhere
// called with zero predicates (ListSuperusers/CountSuperusers have no
// natural filter column — "every row") — worth its own test since every
// other adapter always supplies at least one predicate.
func TestSuperuserAdapterNoPredicateListAndCount(t *testing.T) {
	pool := testPool(t)
	db := applyDDL(t, pool, `
		CREATE TABLE IF NOT EXISTS sqlbstore_test_superusers (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			email text NOT NULL UNIQUE,
			password_hash text NOT NULL,
			display_name text NOT NULL,
			is_active boolean NOT NULL DEFAULT true,
			created_at timestamptz NOT NULL DEFAULT now()
		)`, "sqlbstore_test_superusers")

	a := sqlbstore.SuperuserAdapter[testSuperuser]{
		Table: sqlbstore.Table[testSuperuser, store.Superuser]{
			ToRow: func(s store.Superuser) testSuperuser {
				return testSuperuser{Email: s.Email, PasswordHash: s.PasswordHash, DisplayName: s.DisplayName, IsActive: s.IsActive}
			},
			FromRow: func(r testSuperuser) store.Superuser {
				return store.Superuser{ID: r.ID, Email: r.Email, PasswordHash: r.PasswordHash, DisplayName: r.DisplayName, IsActive: r.IsActive, CreatedAt: r.CreatedAt}
			},
			GetID:    func(s store.Superuser) string { return s.ID },
			SetID:    func(r testSuperuser, id string) testSuperuser { r.ID = id; return r },
			IDColumn: "id",
			ToUpdateColumns: func(s store.Superuser) map[string]any {
				return map[string]any{"display_name": s.DisplayName, "is_active": s.IsActive}
			},
		},
		DB:          db,
		EmailColumn: "email",
	}
	ctx := context.Background()

	n, err := a.CountSuperusers(ctx)
	if err != nil {
		t.Fatalf("CountSuperusers (empty): %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 superusers, got %d", n)
	}

	for i := range 3 {
		email := []string{"root@example.com", "second@example.com", "third@example.com"}[i]
		su := &store.Superuser{Email: email, PasswordHash: "hash", DisplayName: "Admin", IsActive: true}
		if err := a.CreateSuperuser(ctx, su); err != nil {
			t.Fatalf("CreateSuperuser: %v", err)
		}
	}

	n, err = a.CountSuperusers(ctx)
	if err != nil {
		t.Fatalf("CountSuperusers: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 superusers, got %d", n)
	}

	list, err := a.ListSuperusers(ctx)
	if err != nil {
		t.Fatalf("ListSuperusers: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 superusers listed, got %d", len(list))
	}

	byEmail, err := a.GetSuperuserByEmail(ctx, "second@example.com")
	if err != nil {
		t.Fatalf("GetSuperuserByEmail: %v", err)
	}
	byEmail.IsActive = false
	if err := a.UpdateSuperuser(ctx, byEmail); err != nil {
		t.Fatalf("UpdateSuperuser: %v", err)
	}
	reread, err := a.GetSuperuserByID(ctx, byEmail.ID)
	if err != nil {
		t.Fatalf("GetSuperuserByID: %v", err)
	}
	if reread.IsActive {
		t.Fatal("expected IsActive=false to persist")
	}
	if reread.Email != "second@example.com" {
		t.Fatalf("update touched unrelated columns: %+v", reread)
	}
}
