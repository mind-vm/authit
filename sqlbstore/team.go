package sqlbstore

import (
	"context"

	"github.com/jryannel/authit/store"
	"github.com/jryannel/sqlb"
)

// TeamAdapter implements store.TeamStore over an app's sqlb row type R.
type TeamAdapter[R any] struct {
	Table[R, store.Team]
	DB sqlb.Executor
	// SlugColumn names the column GetTeamBySlug filters on.
	SlugColumn string
}

func (a TeamAdapter[R]) CreateTeam(ctx context.Context, t *store.Team) error {
	v, err := a.Table.Create(ctx, a.DB, *t)
	if err != nil {
		return err
	}
	*t = v
	return nil
}

func (a TeamAdapter[R]) GetTeam(ctx context.Context, id string) (*store.Team, error) {
	v, err := a.Table.GetBy(ctx, a.DB, a.IDColumn, id)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (a TeamAdapter[R]) GetTeamBySlug(ctx context.Context, slug string) (*store.Team, error) {
	v, err := a.Table.GetBy(ctx, a.DB, a.SlugColumn, slug)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (a TeamAdapter[R]) UpdateTeam(ctx context.Context, t *store.Team) error {
	return a.Table.Update(ctx, a.DB, *t)
}

func (a TeamAdapter[R]) DeleteTeam(ctx context.Context, id string) error {
	return a.Table.Delete(ctx, a.DB, id)
}
