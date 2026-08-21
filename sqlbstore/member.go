package sqlbstore

import (
	"context"

	"github.com/jryannel/authit/store"
	"github.com/jryannel/sqlb"
)

// MemberAdapter implements store.MemberStore over an app's sqlb row type
// R.
type MemberAdapter[R any] struct {
	Table[R, store.Member]
	DB           sqlb.Executor
	TeamIDColumn string
	UserIDColumn string
}

func (a MemberAdapter[R]) CreateMember(ctx context.Context, m *store.Member) error {
	v, err := a.Table.Create(ctx, a.DB, *m)
	if err != nil {
		return err
	}
	*m = v
	return nil
}

func (a MemberAdapter[R]) GetMember(ctx context.Context, id string) (*store.Member, error) {
	v, err := a.Table.GetBy(ctx, a.DB, a.IDColumn, id)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (a MemberAdapter[R]) GetMemberByUserAndTeam(ctx context.Context, userID, teamID string) (*store.Member, error) {
	v, err := a.Table.GetWhere(ctx, a.DB, sqlb.F(a.UserIDColumn).Eq(userID), sqlb.F(a.TeamIDColumn).Eq(teamID))
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (a MemberAdapter[R]) ListMembersByTeam(ctx context.Context, teamID string) ([]*store.Member, error) {
	rows, err := a.Table.ListBy(ctx, a.DB, a.TeamIDColumn, teamID)
	if err != nil {
		return nil, err
	}
	return ptrs(rows), nil
}

func (a MemberAdapter[R]) ListMembershipsByUser(ctx context.Context, userID string) ([]*store.Member, error) {
	rows, err := a.Table.ListBy(ctx, a.DB, a.UserIDColumn, userID)
	if err != nil {
		return nil, err
	}
	return ptrs(rows), nil
}

func (a MemberAdapter[R]) UpdateMember(ctx context.Context, m *store.Member) error {
	return a.Table.Update(ctx, a.DB, *m)
}

func (a MemberAdapter[R]) DeleteMember(ctx context.Context, id string) error {
	return a.Table.Delete(ctx, a.DB, id)
}

// ptrs returns a slice of pointers into a copy of vs, one per element —
// used by every List* method that must return []*T per its store
// interface while Table.ListWhere/ListBy return []T.
func ptrs[T any](vs []T) []*T {
	out := make([]*T, len(vs))
	for i := range vs {
		out[i] = &vs[i]
	}
	return out
}
