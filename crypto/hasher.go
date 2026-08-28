package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// ErrUnknownHashFormat is returned when a stored hash matches no algorithm
// this package understands.
var ErrUnknownHashFormat = errors.New("authit/crypto: unrecognised password hash format")

// Hasher turns a plaintext password into a string safe to store, and checks
// a candidate against one. A host application selects an implementation via
// user.Config.PasswordHasher / superuser.Config.PasswordHasher; the default
// is Argon2id with OWASP-recommended parameters.
//
// Implementations MUST be able to Verify any hash format authit has ever
// written, not only their own -- otherwise switching hashers logs every
// existing user out permanently. Both implementations here dispatch on the
// hash's self-describing prefix, so an application can move from bcrypt to
// argon2id (or back) with no migration: NeedsRehash reports which stored
// hashes are not in the current hasher's preferred form, and the service
// packages re-hash them on the next successful login.
type Hasher interface {
	// Hash returns a self-describing hash of password.
	Hash(password string) (string, error)
	// Verify reports whether password produced hash. It must return false,
	// not an error, for any malformed or unrecognised hash.
	Verify(password, hash string) bool
	// NeedsRehash reports whether hash was produced by a weaker algorithm
	// or weaker parameters than this Hasher would use now.
	NeedsRehash(hash string) bool
}

// DefaultHasher returns the Hasher used when a Config leaves PasswordHasher
// nil: Argon2id at OWASP's recommended minimum parameters.
func DefaultHasher() Hasher { return NewArgon2idHasher() }

// verifyAny checks password against hash by dispatching on the hash's own
// prefix. This is what makes migration between algorithms transparent.
func verifyAny(password, hash string) bool {
	switch {
	case strings.HasPrefix(hash, "$argon2id$"):
		return verifyArgon2id(password, hash)
	case strings.HasPrefix(hash, "$2"): // $2a$, $2b$, $2y$ -- bcrypt
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// bcrypt
// ---------------------------------------------------------------------------

// BcryptHasher hashes with bcrypt. It is no longer the default: bcrypt is
// not memory-hard, and it silently ignores everything past the 72nd byte of
// a password (x/crypto returns bcrypt.ErrPasswordTooLong rather than
// truncating, so Hash surfaces that as an error). It remains available for
// applications that must stay compatible with an existing corpus of bcrypt
// hashes they cannot re-hash.
type BcryptHasher struct {
	// Cost is the bcrypt work factor. Zero means DefaultBcryptCost.
	Cost int
}

func (h BcryptHasher) cost() int {
	if h.Cost <= 0 {
		return DefaultBcryptCost
	}
	return h.Cost
}

func (h BcryptHasher) Hash(password string) (string, error) {
	return HashPasswordWithCost(password, h.cost())
}

func (h BcryptHasher) Verify(password, hash string) bool { return verifyAny(password, hash) }

// NeedsRehash reports true for any hash that is not bcrypt, and for bcrypt
// hashes stored at a lower cost than this hasher would use now.
func (h BcryptHasher) NeedsRehash(hash string) bool {
	if !strings.HasPrefix(hash, "$2") {
		return true
	}
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return true
	}
	return cost < h.cost()
}

// ---------------------------------------------------------------------------
// argon2id
// ---------------------------------------------------------------------------

// Argon2id parameter defaults, from OWASP's Password Storage Cheat Sheet
// minimum for Argon2id: 19 MiB of memory, 2 iterations, 1 degree of
// parallelism.
//
// Memory is per concurrent hash, which is the parameter to think about
// before raising: at the default, a burst of 100 simultaneous logins wants
// roughly 1.9 GiB. Raise DefaultArgon2Memory only alongside a limit on
// concurrent authentication.
const (
	DefaultArgon2Memory  uint32 = 19 * 1024 // KiB
	DefaultArgon2Time    uint32 = 2
	DefaultArgon2Threads uint8  = 1
	DefaultArgon2KeyLen  uint32 = 32
	DefaultArgon2SaltLen uint32 = 16
)

// Argon2idHasher hashes with Argon2id and encodes the result in the PHC
// string format used by the reference implementation:
//
//	$argon2id$v=19$m=19456,t=2,p=1$<salt>$<key>
//
// The parameters travel with the hash, so changing them does not invalidate
// existing rows -- Verify reads each hash's own parameters, and NeedsRehash
// flags rows that are weaker than the current settings.
type Argon2idHasher struct {
	Memory  uint32 // KiB
	Time    uint32
	Threads uint8
	KeyLen  uint32
	SaltLen uint32
}

// NewArgon2idHasher returns an Argon2idHasher with the default parameters.
func NewArgon2idHasher() Argon2idHasher {
	return Argon2idHasher{
		Memory:  DefaultArgon2Memory,
		Time:    DefaultArgon2Time,
		Threads: DefaultArgon2Threads,
		KeyLen:  DefaultArgon2KeyLen,
		SaltLen: DefaultArgon2SaltLen,
	}
}

// withDefaults fills zero-valued fields, so a caller can set only the one
// parameter they care about.
func (h Argon2idHasher) withDefaults() Argon2idHasher {
	d := NewArgon2idHasher()
	if h.Memory == 0 {
		h.Memory = d.Memory
	}
	if h.Time == 0 {
		h.Time = d.Time
	}
	if h.Threads == 0 {
		h.Threads = d.Threads
	}
	if h.KeyLen == 0 {
		h.KeyLen = d.KeyLen
	}
	if h.SaltLen == 0 {
		h.SaltLen = d.SaltLen
	}
	return h
}

func (h Argon2idHasher) Hash(password string) (string, error) {
	h = h.withDefaults()
	salt := make([]byte, h.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, h.Time, h.Memory, h.Threads, h.KeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.Memory, h.Time, h.Threads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

func (h Argon2idHasher) Verify(password, hash string) bool { return verifyAny(password, hash) }

// NeedsRehash reports true for any hash that is not argon2id -- notably
// every bcrypt hash, which is how an existing corpus migrates -- and for
// argon2id hashes whose stored parameters are weaker than this hasher's.
func (h Argon2idHasher) NeedsRehash(hash string) bool {
	h = h.withDefaults()
	p, _, _, err := parseArgon2id(hash)
	if err != nil {
		return true
	}
	return p.Memory < h.Memory || p.Time < h.Time || p.KeyLen < h.KeyLen
}

// argon2Params are the cost parameters recovered from an encoded hash.
type argon2Params struct {
	Memory  uint32
	Time    uint32
	Threads uint8
	KeyLen  uint32
}

// parseArgon2id decodes the PHC string, returning the parameters, salt and
// derived key. It is deliberately strict: anything it cannot parse exactly
// is an error rather than a best guess.
func parseArgon2id(hash string) (p argon2Params, salt, key []byte, err error) {
	parts := strings.Split(hash, "$")
	// "", "argon2id", "v=19", "m=...,t=...,p=...", salt, key
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return p, nil, nil, ErrUnknownHashFormat
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return p, nil, nil, ErrUnknownHashFormat
	}
	if version != argon2.Version {
		return p, nil, nil, fmt.Errorf("%w: argon2 version %d", ErrUnknownHashFormat, version)
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads); err != nil {
		return p, nil, nil, ErrUnknownHashFormat
	}
	b64 := base64.RawStdEncoding
	if salt, err = b64.DecodeString(parts[4]); err != nil {
		return p, nil, nil, ErrUnknownHashFormat
	}
	if key, err = b64.DecodeString(parts[5]); err != nil {
		return p, nil, nil, ErrUnknownHashFormat
	}
	p.KeyLen = uint32(len(key))
	return p, salt, key, nil
}

func verifyArgon2id(password, hash string) bool {
	p, salt, key, err := parseArgon2id(hash)
	if err != nil {
		return false
	}
	candidate := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return subtle.ConstantTimeCompare(candidate, key) == 1
}
