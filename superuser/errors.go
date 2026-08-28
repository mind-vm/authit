package superuser

import (
	"errors"

	authitcrypto "github.com/mind-vm/authit/crypto"
)

// ErrWeakPassword is returned by Bootstrap and CreateSuperuser when
// Config.PasswordValidator rejects the password. Alias for
// crypto.ErrWeakPassword so errors.Is matches either.
var ErrWeakPassword = authitcrypto.ErrWeakPassword

var (
	ErrInvalidCredentials   = errors.New("authit/superuser: invalid credentials")
	ErrAccountLocked        = errors.New("authit/superuser: account locked")
	ErrInactive             = errors.New("authit/superuser: account is not active")
	ErrInvalidToken         = errors.New("authit/superuser: invalid or expired token")
	ErrCannotDeactivateSelf = errors.New("authit/superuser: cannot deactivate your own account")
	ErrAlreadyBootstrapped  = errors.New("authit/superuser: at least one superuser already exists")
)
