package device

import (
	"context"
	"errors"
	"fmt"
	"time"

	authitcrypto "github.com/jryannel/authit/crypto"
	"github.com/jryannel/authit/store"
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

	id, err := authitcrypto.NewID()
	if err != nil {
		return Authorization{}, err
	}
	now := time.Now()
	d := &store.DeviceAuthorization{
		ID: id, DeviceCodeHash: deviceCodeHash, UserCode: userCode,
		ClientID: clientID, Scope: scope, Status: store.DeviceAuthorizationPending,
		ExpiresAt: now.Add(s.cfg.DeviceCodeTTL), IntervalSeconds: int(s.cfg.PollInterval.Seconds()),
		CreatedAt: now,
	}
	if err := s.stores.Authorizations.CreateDeviceAuthorization(ctx, d); err != nil {
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
		if _, err := s.stores.Authorizations.GetDeviceAuthorizationByUserCode(ctx, code); errors.Is(err, store.ErrNotFound) {
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
	d.Status = store.DeviceAuthorizationApproved
	d.UserID = &callerUserID
	return s.stores.Authorizations.UpdateDeviceAuthorization(ctx, d)
}

// DenyDeviceAuthorization marks the device authorization identified by
// userCode as denied, so the CLI's poll terminates with ErrAccessDenied.
func (s *Service) DenyDeviceAuthorization(ctx context.Context, userCode string) error {
	d, err := s.pendingByUserCode(ctx, userCode)
	if err != nil {
		return err
	}
	d.Status = store.DeviceAuthorizationDenied
	return s.stores.Authorizations.UpdateDeviceAuthorization(ctx, d)
}

func (s *Service) pendingByUserCode(ctx context.Context, userCode string) (*store.DeviceAuthorization, error) {
	d, err := s.stores.Authorizations.GetDeviceAuthorizationByUserCode(ctx, userCode)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrInvalidUserCode
		}
		return nil, err
	}
	if d.Status != store.DeviceAuthorizationPending || time.Now().After(d.ExpiresAt) {
		return nil, ErrInvalidUserCode
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
	d, err := s.stores.Authorizations.GetDeviceAuthorizationByDeviceCodeHash(ctx, authitcrypto.HashToken(rawDeviceCode))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", "", ErrExpiredToken
		}
		return "", "", err
	}

	now := time.Now()
	if now.After(d.ExpiresAt) {
		_ = s.stores.Authorizations.DeleteDeviceAuthorization(ctx, d.ID)
		return "", "", ErrExpiredToken
	}

	interval := time.Duration(d.IntervalSeconds) * time.Second
	if d.LastPolledAt != nil && now.Sub(*d.LastPolledAt) < interval {
		d.IntervalSeconds += int(s.cfg.SlowDownIncrement.Seconds())
		d.LastPolledAt = &now
		_ = s.stores.Authorizations.UpdateDeviceAuthorization(ctx, d)
		return "", "", ErrSlowDown
	}

	switch d.Status {
	case store.DeviceAuthorizationDenied:
		_ = s.stores.Authorizations.DeleteDeviceAuthorization(ctx, d.ID)
		return "", "", ErrAccessDenied
	case store.DeviceAuthorizationApproved:
		_ = s.stores.Authorizations.DeleteDeviceAuthorization(ctx, d.ID)
		if d.UserID == nil {
			return "", "", ErrExpiredToken
		}
		return *d.UserID, d.Scope, nil
	default: // pending
		d.LastPolledAt = &now
		_ = s.stores.Authorizations.UpdateDeviceAuthorization(ctx, d)
		return "", "", ErrAuthorizationPending
	}
}
