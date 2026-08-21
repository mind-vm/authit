package sqlbstore

import (
	"context"

	"github.com/jryannel/authit/store"
	"github.com/jryannel/sqlb"
)

// DeviceAuthorizationAdapter implements store.DeviceAuthorizationStore
// over an app's sqlb row type R.
type DeviceAuthorizationAdapter[R any] struct {
	Table[R, store.DeviceAuthorization]
	DB                   sqlb.Executor
	DeviceCodeHashColumn string
	UserCodeColumn       string
}

func (a DeviceAuthorizationAdapter[R]) CreateDeviceAuthorization(ctx context.Context, d *store.DeviceAuthorization) error {
	v, err := a.Table.Create(ctx, a.DB, *d)
	if err != nil {
		return err
	}
	*d = v
	return nil
}

func (a DeviceAuthorizationAdapter[R]) GetDeviceAuthorizationByDeviceCodeHash(ctx context.Context, hash string) (*store.DeviceAuthorization, error) {
	v, err := a.Table.GetBy(ctx, a.DB, a.DeviceCodeHashColumn, hash)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (a DeviceAuthorizationAdapter[R]) GetDeviceAuthorizationByUserCode(ctx context.Context, userCode string) (*store.DeviceAuthorization, error) {
	v, err := a.Table.GetBy(ctx, a.DB, a.UserCodeColumn, userCode)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (a DeviceAuthorizationAdapter[R]) UpdateDeviceAuthorization(ctx context.Context, d *store.DeviceAuthorization) error {
	return a.Table.Update(ctx, a.DB, *d)
}

func (a DeviceAuthorizationAdapter[R]) DeleteDeviceAuthorization(ctx context.Context, id string) error {
	return a.Table.Delete(ctx, a.DB, id)
}
