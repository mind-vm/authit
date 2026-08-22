package device

import (
	"context"
	"errors"
	"fmt"
	"time"

	authitcrypto "github.com/jryannel/authit/crypto"
	"github.com/jryannel/authit/store"
	"github.com/jryannel/sqlb"
)

// StartDeviceAuthorization begins a new device-authorization-grant request
// for the given clientID/scope (both host-application-defined and
// optional — pass "" for either if the host doesn't distinguish clients or
// scopes).
func (s *Service) StartDeviceAuthorization(ctx context.Context, clientID, scope string) (Authorization, error) {
	rawDeviceCode, deviceCodeHash, err := authitcrypto.GenerateOpaqueToken()
	if err != nil {
		return Authorization{}, err
	}

	userCode, err := s.uniqueUserCode(ctx)
	if err != nil {
		return Authorization{}, err
	}

	row := store.DeviceAuthorization{
		DeviceCodeHash: deviceCodeHash, UserCode: userCode,
		ClientID: clientID, Scope: scope, Status: store.DeviceAuthorizationStatusPending,
		ExpiresAt:       time.Now().Add(s.cfg.DeviceCodeTTL),
		IntervalSeconds: int32(s.cfg.PollInterval.Seconds()),
	}
	if _, err := sqlb.InsertRows(&row).Exec(ctx, s.db); err != nil {
		return Authorization{}, err
	}

	return Authorization{
		DeviceCode: rawDeviceCode,
		UserCode:   userCode,
		ExpiresIn:  s.cfg.DeviceCodeTTL,
		Interval:   s.cfg.PollInterval,
	}, nil
}

func (s *Service) uniqueUserCode(ctx context.Context) (string, error) {
	for range 5 {
		code, err := authitcrypto.GenerateUserCode()
		if err != nil {
			return "", err
		}
		taken, err := sqlb.Query[store.DeviceAuthorization]().
			Where(store.DeviceAuthorizationCols.UserCode.Eq(code)).
			Exists(ctx, s.db)
		if err != nil {
			return "", err
		}
		if !taken {
			return code, nil
		}
	}
	return "", fmt.Errorf("authit/device: could not generate a unique user code")
}

// ApproveDeviceAuthorization marks the device authorization identified by
// userCode as approved by callerUserID. Call this from an
// already-authenticated web session after the user types/confirms the
// code — device does not itself authenticate callerUserID.
func (s *Service) ApproveDeviceAuthorization(ctx context.Context, callerUserID, userCode string) error {
	d, err := s.pendingByUserCode(ctx, userCode)
	if err != nil {
		return err
	}
	_, err = store.UpdateDeviceAuthorization().
		SetStatus(store.DeviceAuthorizationStatusApproved).
		SetUserID(&callerUserID).
		Where(store.DeviceAuthorizationCols.ID.Eq(d.ID)).
		Stmt().Exec(ctx, s.db)
	return err
}

// DenyDeviceAuthorization marks the device authorization identified by
// userCode as denied, so the CLI's poll terminates with ErrAccessDenied.
func (s *Service) DenyDeviceAuthorization(ctx context.Context, userCode string) error {
	d, err := s.pendingByUserCode(ctx, userCode)
	if err != nil {
		return err
	}
	_, err = store.UpdateDeviceAuthorization().
		SetStatus(store.DeviceAuthorizationStatusDenied).
		Where(store.DeviceAuthorizationCols.ID.Eq(d.ID)).
		Stmt().Exec(ctx, s.db)
	return err
}

func (s *Service) pendingByUserCode(ctx context.Context, userCode string) (store.DeviceAuthorization, error) {
	d, err := sqlb.Query[store.DeviceAuthorization]().
		Where(store.DeviceAuthorizationCols.UserCode.Eq(userCode)).
		One(ctx, s.db)
	if err != nil {
		if errors.Is(err, sqlb.ErrNotFound) {
			return store.DeviceAuthorization{}, ErrInvalidUserCode
		}
		return store.DeviceAuthorization{}, err
	}
	if d.Status != store.DeviceAuthorizationStatusPending || time.Now().After(d.ExpiresAt) {
		return store.DeviceAuthorization{}, ErrInvalidUserCode
	}
	return d, nil
}

// PollDeviceToken is what the CLI calls repeatedly with the device_code it
// received from StartDeviceAuthorization. On success it returns the ID of
// the user who approved the request (and the scope that was requested) —
// it is then the host application's job to mint whatever credential it
// wants to hand the CLI. Once a device authorization resolves to a
// terminal outcome (approved or denied), the record is deleted so it
// cannot be polled again.
func (s *Service) PollDeviceToken(ctx context.Context, rawDeviceCode string) (userID, scope string, err error) {
	d, err := sqlb.Query[store.DeviceAuthorization]().
		Where(store.DeviceAuthorizationCols.DeviceCodeHash.Eq(authitcrypto.HashToken(rawDeviceCode))).
		One(ctx, s.db)
	if err != nil {
		if errors.Is(err, sqlb.ErrNotFound) {
			return "", "", ErrExpiredToken
		}
		return "", "", err
	}

	now := time.Now()
	if now.After(d.ExpiresAt) {
		s.discard(ctx, d.ID)
		return "", "", ErrExpiredToken
	}

	interval := time.Duration(d.IntervalSeconds) * time.Second
	if d.LastPolledAt != nil && now.Sub(*d.LastPolledAt) < interval {
		// The increment is permanent, per RFC 8628 §3.5: a client that polled
		// too fast once is told to slow down for the rest of this request's
		// life, not just for this poll.
		_, _ = store.UpdateDeviceAuthorization().
			SetIntervalSeconds(d.IntervalSeconds+int32(s.cfg.SlowDownIncrement.Seconds())).
			SetLastPolledAt(&now).
			Where(store.DeviceAuthorizationCols.ID.Eq(d.ID)).
			Stmt().Exec(ctx, s.db)
		return "", "", ErrSlowDown
	}

	switch d.Status {
	case store.DeviceAuthorizationStatusDenied:
		s.discard(ctx, d.ID)
		return "", "", ErrAccessDenied
	case store.DeviceAuthorizationStatusApproved:
		s.discard(ctx, d.ID)
		if d.UserID == nil {
			return "", "", ErrExpiredToken
		}
		return *d.UserID, d.Scope, nil
	default: // pending
		_, _ = store.UpdateDeviceAuthorization().
			SetLastPolledAt(&now).
			Where(store.DeviceAuthorizationCols.ID.Eq(d.ID)).
			Stmt().Exec(ctx, s.db)
		return "", "", ErrAuthorizationPending
	}
}

// discard removes a resolved authorization so it cannot be polled twice.
// Best-effort: the caller has already decided the outcome, and a row that
// outlives its own expiry is refused by the expiry check anyway.
func (s *Service) discard(ctx context.Context, id string) {
	_, _ = sqlb.DeleteRows[store.DeviceAuthorization]().
		Where(store.DeviceAuthorizationCols.ID.Eq(id)).
		Exec(ctx, s.db)
}
