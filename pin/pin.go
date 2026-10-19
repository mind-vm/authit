package pin

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/mind-vm/authit/audit"
	authitcrypto "github.com/mind-vm/authit/crypto"
	"github.com/mind-vm/authit/ratelimit"
	"github.com/mind-vm/authit/store"
)

// SignInResult is a successful SignIn.
type SignInResult struct {
	// Token is the device's bearer credential. It is returned here once and
	// stored only as its hash; hand it to the device and nowhere else.
	Token  string
	Device store.BoundDevice
	User   store.User
}

// ImportedDevice is a device bound by another implementation, carried over
// by ImportDevice with the hash of its token.
type ImportedDevice struct {
	UserID string
	Name   string
	// TokenHash is hex(SHA-256(token)), upper or lower case.
	TokenHash  string
	UserAgent  string
	IPAddress  string
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
	// CreatedAt is when the device was bound; zero means now.
	CreatedAt time.Time
}

// SetPIN sets userID's PIN, replacing any PIN they had, and lifts a lock
// from wrong PINs. operatorID is who set it, for the audit trail; whether
// they may is the caller's decision.
func (s *Service) SetPIN(ctx context.Context, operatorID, userID, pin string) error {
	if !s.wellFormed(pin) {
		return ErrInvalidPIN
	}
	hash, err := s.cfg.Hasher.Hash(pin)
	if err != nil {
		return err
	}
	if err := s.storePIN(ctx, userID, hash); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.Event{Type: audit.EventPINSet, Result: audit.ResultSuccess, ActorID: operatorID, TargetID: userID})
	return nil
}

// ImportPINHash stores a PIN hash written elsewhere -- bcrypt ($2a$, $2b$,
// $2y$) or Argon2id in PHC form -- as userID's PIN, and lifts a lock. A
// bcrypt hash is re-hashed with Config.Hasher at the next successful
// sign-in, when the PIN is at hand.
func (s *Service) ImportPINHash(ctx context.Context, operatorID, userID, hash string) error {
	if !strings.HasPrefix(hash, "$2") && !strings.HasPrefix(hash, "$argon2id$") {
		return ErrInvalidImport
	}
	if err := s.storePIN(ctx, userID, hash); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.Event{Type: audit.EventPINCredentialImport, Result: audit.ResultSuccess, ActorID: operatorID, TargetID: userID})
	return nil
}

func (s *Service) storePIN(ctx context.Context, userID, hash string) error {
	if _, err := s.stores.Users.GetUserByID(ctx, userID); err != nil {
		return err
	}
	now := time.Now()
	if err := s.stores.PINs.SetPINCredential(ctx, &store.PINCredential{
		UserID: userID, PINHash: hash, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		return err
	}
	// A new PIN lifts the lock: the person locked out is usually the one
	// who asked the office for it.
	return s.stores.Lockouts.ClearFailedLoginAttempts(ctx, userKey(userID))
}

// ClearPIN removes userID's PIN, so they can no longer sign in a new
// device. Devices already bound stay bound; RevokeAllDevices ends those.
func (s *Service) ClearPIN(ctx context.Context, operatorID, userID string) error {
	if err := s.stores.PINs.DeletePINCredential(ctx, userID); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.Event{Type: audit.EventPINCleared, Result: audit.ResultSuccess, ActorID: operatorID, TargetID: userID})
	return nil
}

func (s *Service) wellFormed(pin string) bool {
	if len(pin) != s.cfg.PINLength {
		return false
	}
	for _, c := range pin {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// SignIn checks login and pin and, when both are right, binds a new device
// for the user and returns its token.
//
// Every failure that is not a lock is ErrInvalidCredentials, whether the
// login was unknown, the user had no PIN, or the PIN was wrong, and each
// costs the same hash computation. Config.MaxFailedAttempts of them within
// Config.LockDuration make SignIn return ErrLocked for that login, a known
// one or not, until they age out or an operator sets a new PIN. The
// failures of a known user are counted per user, so the several logins
// that resolve to one person share one budget.
//
// A login an operator has locked (store.LockoutStore.LockAccount) is
// ErrLocked too. Hooks.BeforeBind can refuse a user once the PIN is
// verified; its error is returned as it is.
func (s *Service) SignIn(ctx context.Context, login, pin, deviceName, userAgent, ipAddress string) (SignInResult, error) {
	login = strings.TrimSpace(login)
	normalized := strings.ToLower(login)
	if err := ratelimit.AllowEach(ctx, s.cfg.RateLimiter, "pin:ip:"+ipAddress, "pin:login:"+normalized); err != nil {
		s.audit.Log(ctx, audit.Event{
			Type: audit.EventPINSignInFailed, Result: audit.ResultDenied, UserAgent: userAgent, IPAddress: ipAddress,
			Metadata: map[string]any{"reason": "rate_limited"},
		})
		return SignInResult{}, err
	}

	userID, err := s.resolve(ctx, login)
	if err != nil {
		return SignInResult{}, err
	}
	// The lock is kept by user once the login resolves, so a person's
	// personnel number and address share one budget, and by login when it
	// does not, so an unknown login locks like a known one and the lock
	// tells nobody which logins exist.
	lockKey := loginKey(normalized)
	if userID != "" {
		lockKey = userKey(userID)
	}
	now := time.Now()
	locked, err := s.chargeAttempt(ctx, lockKey, ipAddress, now)
	if err != nil {
		return SignInResult{}, err
	}
	if !locked && userID != "" {
		if locked, err = s.stores.Lockouts.IsAccountLocked(ctx, userID); err != nil {
			return SignInResult{}, err
		}
	}
	if locked {
		s.audit.Log(ctx, audit.Event{
			Type: audit.EventPINSignInLocked, Result: audit.ResultDenied, ActorID: userID,
			UserAgent: userAgent, IPAddress: ipAddress,
		})
		return SignInResult{}, ErrLocked
	}

	var u *store.User
	var cred *store.PINCredential
	if userID != "" {
		if u, err = s.stores.Users.GetUserByID(ctx, userID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return SignInResult{}, err
		}
		if u != nil {
			if cred, err = s.stores.PINs.GetPINCredential(ctx, userID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return SignInResult{}, err
			}
		}
	}
	if cred == nil {
		// Nothing to check against, but the same work as if there were:
		// a fast "no" would tell a caller the login is unknown.
		s.cfg.Hasher.Verify(pin, s.dummy())
	}
	if cred == nil || !s.cfg.Hasher.Verify(pin, cred.PINHash) {
		// Already counted by chargeAttempt.
		s.audit.Log(ctx, audit.Event{
			Type: audit.EventPINSignInFailed, Result: audit.ResultFailure, ActorID: userID,
			UserAgent: userAgent, IPAddress: ipAddress,
		})
		return SignInResult{}, ErrInvalidCredentials
	}

	s.rehashIfNeeded(ctx, cred, pin)
	if err := s.stores.Lockouts.ClearFailedLoginAttempts(ctx, lockKey); err != nil {
		return SignInResult{}, err
	}
	if s.cfg.Hooks.BeforeBind != nil {
		if err := s.cfg.Hooks.BeforeBind(ctx, *u); err != nil {
			s.audit.Log(ctx, audit.Event{
				Type: audit.EventPINSignInFailed, Result: audit.ResultDenied, ActorID: u.ID,
				UserAgent: userAgent, IPAddress: ipAddress, Metadata: map[string]any{"reason": "refused_by_hook"},
			})
			return SignInResult{}, err
		}
	}

	raw, hash, err := authitcrypto.GenerateOpaqueToken()
	if err != nil {
		return SignInResult{}, err
	}
	id, err := authitcrypto.NewID()
	if err != nil {
		return SignInResult{}, err
	}
	name := strings.TrimSpace(deviceName)
	if name == "" {
		name = "Device"
	}
	d := &store.BoundDevice{
		ID: id, UserID: u.ID, Name: name, TokenHash: hash,
		UserAgent: userAgent, IPAddress: ipAddress, LastUsedAt: &now, CreatedAt: now,
	}
	if s.cfg.DeviceTokenTTL > 0 {
		expires := now.Add(s.cfg.DeviceTokenTTL)
		d.ExpiresAt = &expires
	}
	atomic := s.cfg.Hooks.AfterSignIn != nil
	run := func(ctx context.Context) error {
		if err := s.stores.Devices.CreateBoundDevice(ctx, d); err != nil {
			return err
		}
		if s.cfg.Hooks.AfterSignIn != nil {
			return s.cfg.Hooks.AfterSignIn(ctx, *u, *d)
		}
		return nil
	}
	if atomic {
		err = store.RunInTx(ctx, s.stores.Tx, run)
	} else {
		err = run(ctx)
	}
	if err != nil {
		return SignInResult{}, err
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventPINSignInSucceeded, Result: audit.ResultSuccess, ActorID: u.ID, TargetID: d.ID,
		Email: u.Email, UserAgent: userAgent, IPAddress: ipAddress,
	})
	return SignInResult{Token: raw, Device: *d, User: *u}, nil
}

// resolve returns the user id login names, or "" for none.
func (s *Service) resolve(ctx context.Context, login string) (string, error) {
	if login == "" {
		return "", nil
	}
	id, err := s.resolver.ResolveLogin(ctx, login)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	return id, err
}

// chargeAttempt counts this attempt against key before the PIN is checked,
// and reports whether the budget is spent.
//
// Charging first and refunding on success, rather than counting only the
// failures, is what makes the limit hold under concurrency: requests that
// all read the count before any of them failed would each get a guess, and
// with a six-digit PIN the limit is the whole defence. A request that finds
// the budget already spent is refused without being charged, so the lock
// lifts LockDuration after the last guess that was actually tried.
//
// Not best-effort, unlike the user plane's failure counter: an attempt
// that cannot be counted is not tried.
func (s *Service) chargeAttempt(ctx context.Context, key, ipAddress string, now time.Time) (locked bool, err error) {
	since := now.Add(-s.cfg.LockDuration)
	n, err := s.stores.Lockouts.CountRecentFailedLoginAttempts(ctx, key, since)
	if err != nil {
		return false, err
	}
	if n >= s.cfg.MaxFailedAttempts {
		return true, nil
	}
	id, err := authitcrypto.NewID()
	if err != nil {
		return false, err
	}
	if err := s.stores.Lockouts.RecordFailedLoginAttempt(ctx, &store.FailedLoginAttempt{
		ID: id, Email: key, IPAddress: ipAddress, CreatedAt: now,
	}); err != nil {
		return false, err
	}
	// Counted again with this attempt in: of requests racing past the
	// first check, those beyond the budget find out here.
	n, err = s.stores.Lockouts.CountRecentFailedLoginAttempts(ctx, key, since)
	if err != nil {
		return false, err
	}
	return n > s.cfg.MaxFailedAttempts, nil
}

// rehashIfNeeded moves a PIN hashed by an older or weaker algorithm --
// typically an imported bcrypt hash -- to Config.Hasher, now that the PIN
// is at hand. Best-effort: the stored hash verifies either way.
func (s *Service) rehashIfNeeded(ctx context.Context, c *store.PINCredential, pin string) {
	if !s.cfg.Hasher.NeedsRehash(c.PINHash) {
		return
	}
	hash, err := s.cfg.Hasher.Hash(pin)
	if err != nil {
		return
	}
	c.PINHash = hash
	c.UpdatedAt = time.Now()
	_ = s.stores.PINs.SetPINCredential(ctx, c)
}

func (s *Service) dummy() string {
	s.dummyOnce.Do(func() {
		s.dummyHash, _ = s.cfg.Hasher.Hash(strings.Repeat("0", s.cfg.PINLength))
	})
	return s.dummyHash
}

func userKey(userID string) string { return "pin:user:" + userID }

func loginKey(normalized string) string { return "pin:login:" + normalized }

// ValidateDevice resolves a device token to its user and device, and
// records the use (at most once per Config.LastUsedInterval).
//
// An unknown, revoked or expired token, or one whose user is gone, is
// ErrInvalidToken; a user an operator has locked is ErrAccountLocked. A
// store failure is returned as itself, so a caller can answer it with a 500
// rather than signing the device out.
func (s *Service) ValidateDevice(ctx context.Context, token string) (store.User, store.BoundDevice, error) {
	if token == "" {
		return store.User{}, store.BoundDevice{}, ErrInvalidToken
	}
	d, err := s.stores.Devices.GetBoundDeviceByTokenHash(ctx, authitcrypto.HashToken(token))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.User{}, store.BoundDevice{}, ErrInvalidToken
		}
		return store.User{}, store.BoundDevice{}, err
	}
	now := time.Now()
	if d.RevokedAt != nil || (d.ExpiresAt != nil && !now.Before(*d.ExpiresAt)) {
		return store.User{}, store.BoundDevice{}, ErrInvalidToken
	}
	u, err := s.stores.Users.GetUserByID(ctx, d.UserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.User{}, store.BoundDevice{}, ErrInvalidToken
		}
		return store.User{}, store.BoundDevice{}, err
	}
	locked, err := s.stores.Lockouts.IsAccountLocked(ctx, u.ID)
	if err != nil {
		return store.User{}, store.BoundDevice{}, err
	}
	if locked {
		return store.User{}, store.BoundDevice{}, ErrAccountLocked
	}
	if d.LastUsedAt == nil || s.cfg.LastUsedInterval < 0 || now.Sub(*d.LastUsedAt) >= s.cfg.LastUsedInterval {
		if err := s.stores.Devices.TouchBoundDevice(ctx, d.ID, now); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				// Revoked between the read above and now.
				return store.User{}, store.BoundDevice{}, ErrInvalidToken
			}
			return store.User{}, store.BoundDevice{}, err
		}
		d.LastUsedAt = &now
	}
	return *u, *d, nil
}

// ListDevices lists every device userID has signed in on, revoked ones
// included so an office can see what was revoked; filter on RevokedAt and
// ExpiresAt as needed.
func (s *Service) ListDevices(ctx context.Context, userID string) ([]store.BoundDevice, error) {
	devices, err := s.stores.Devices.ListBoundDevicesByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]store.BoundDevice, len(devices))
	for i, d := range devices {
		out[i] = *d
	}
	return out, nil
}

// RevokeDevice signs the device deviceID out at once: a lost phone. actorID
// is who revoked it, for the audit trail; whether they may is the caller's
// decision. Revoking a revoked device is not an error; an unknown one is
// store.ErrNotFound.
func (s *Service) RevokeDevice(ctx context.Context, actorID, deviceID string) error {
	d, err := s.stores.Devices.GetBoundDevice(ctx, deviceID)
	if err != nil {
		return err
	}
	if err := s.stores.Devices.RevokeBoundDevice(ctx, d.ID, time.Now()); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventPINDeviceRevoked, Result: audit.ResultSuccess, ActorID: actorID, TargetID: d.ID,
		Metadata: map[string]any{"user_id": d.UserID},
	})
	return nil
}

// RevokeDeviceByToken is the device signing itself out. It is idempotent:
// an unknown or already revoked token is not an error.
func (s *Service) RevokeDeviceByToken(ctx context.Context, token string) error {
	d, err := s.stores.Devices.GetBoundDeviceByTokenHash(ctx, authitcrypto.HashToken(token))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	}
	if d.RevokedAt != nil {
		return nil
	}
	if err := s.stores.Devices.RevokeBoundDevice(ctx, d.ID, time.Now()); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventPINDeviceRevoked, Result: audit.ResultSuccess, ActorID: d.UserID, TargetID: d.ID,
		Metadata: map[string]any{"user_id": d.UserID, "by": "device"},
	})
	return nil
}

// RevokeAllDevices signs every device of userID out, and reports how many
// were still signed in.
func (s *Service) RevokeAllDevices(ctx context.Context, actorID, userID string) (int, error) {
	n, err := s.stores.Devices.RevokeAllBoundDevices(ctx, userID, time.Now())
	if err != nil {
		return 0, err
	}
	if n > 0 {
		s.audit.Log(ctx, audit.Event{
			Type: audit.EventPINDeviceRevoked, Result: audit.ResultSuccess, ActorID: actorID, TargetID: userID,
			Metadata: map[string]any{"user_id": userID, "count": n},
		})
	}
	return n, nil
}

// ImportDevice carries over a device bound by another implementation that
// stored hex(SHA-256(token)), so the device keeps its token and stays
// signed in. The hash is checked for that shape and stored lower-case,
// which is what crypto.HashToken produces when ValidateDevice looks it up.
func (s *Service) ImportDevice(ctx context.Context, in ImportedDevice) (store.BoundDevice, error) {
	hash := strings.ToLower(strings.TrimSpace(in.TokenHash))
	if b, err := hex.DecodeString(hash); err != nil || len(b) != 32 {
		return store.BoundDevice{}, ErrInvalidImport
	}
	if _, err := s.stores.Users.GetUserByID(ctx, in.UserID); err != nil {
		return store.BoundDevice{}, err
	}
	id, err := authitcrypto.NewID()
	if err != nil {
		return store.BoundDevice{}, err
	}
	created := in.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "Device"
	}
	d := &store.BoundDevice{
		ID: id, UserID: in.UserID, Name: name, TokenHash: hash, UserAgent: in.UserAgent, IPAddress: in.IPAddress,
		ExpiresAt: in.ExpiresAt, LastUsedAt: in.LastUsedAt, RevokedAt: in.RevokedAt, CreatedAt: created,
	}
	if err := s.stores.Devices.CreateBoundDevice(ctx, d); err != nil {
		return store.BoundDevice{}, err
	}
	s.audit.Log(ctx, audit.Event{
		Type: audit.EventPINDeviceImported, Result: audit.ResultSuccess, ActorID: in.UserID, TargetID: d.ID,
	})
	return *d, nil
}
