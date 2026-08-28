package crypto

import "crypto/rand"

// userCodeAlphabet is RFC 8628's own example alphabet: base-20, no vowels
// and no visually-confusable characters (0/O, 1/I/l are absent), so a user
// reading a code off one screen and typing it into another rarely
// mistypes it.
const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

// GenerateUserCode returns an 8-character device-flow user code formatted
// as "XXXX-XXXX" (RFC 8628 §6.1's recommended shape), e.g. "WDJB-MJHT".
// At ~34.5 bits of entropy it is deliberately low relative to the
// device_code — the security property comes from rate-limiting guesses, not
// from the code's entropy alone (RFC 8628 §5.2).
//
// authit supplies half of that limit itself: device.Config.RateLimiter
// bounds failed user-code lookups, which is the part a host cannot
// implement from outside because the lookup happens inside the device
// package. Set it. The other half — per-IP limiting on whatever route you
// expose the verification form at — is still yours, and this comment used
// to name a requirement without saying where either half came from.
func GenerateUserCode() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, 9)
	for i, b := range buf {
		pos := i
		if i >= 4 {
			pos++ // leave room for the dash
		}
		out[pos] = userCodeAlphabet[int(b)%len(userCodeAlphabet)]
	}
	out[4] = '-'
	return string(out), nil
}
