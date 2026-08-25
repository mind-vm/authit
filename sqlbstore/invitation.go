package sqlbstore

import (
	"context"

	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/sqlb"
)

// InvitationAdapter implements store.InvitationStore over an app's sqlb
// row type R.
type InvitationAdapter[R any] struct {
	Table[R, store.Invitation]
	DB              sqlb.Executor
	TeamIDColumn    string
	TokenHashColumn string
}

func (a InvitationAdapter[R]) CreateInvitation(ctx context.Context, i *store.Invitation) error {
	v, err := a.Table.Create(ctx, a.DB, *i)
	if err != nil {
		return err
	}
	*i = v
	return nil
}

func (a InvitationAdapter[R]) GetInvitation(ctx context.Context, id string) (*store.Invitation, error) {
	v, err := a.Table.GetBy(ctx, a.DB, a.IDColumn, id)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (a InvitationAdapter[R]) GetInvitationByTokenHash(ctx context.Context, hash string) (*store.Invitation, error) {
	v, err := a.Table.GetBy(ctx, a.DB, a.TokenHashColumn, hash)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (a InvitationAdapter[R]) ListInvitationsByTeam(ctx context.Context, teamID string) ([]*store.Invitation, error) {
	rows, err := a.Table.ListBy(ctx, a.DB, a.TeamIDColumn, teamID)
	if err != nil {
		return nil, err
	}
	return ptrs(rows), nil
}

func (a InvitationAdapter[R]) UpdateInvitation(ctx context.Context, i *store.Invitation) error {
	return a.Table.Update(ctx, a.DB, *i)
}
