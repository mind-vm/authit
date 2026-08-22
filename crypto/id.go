package crypto

import "crypto/rand"

// NewID returns a random UUIDv4 string.
//
// authit's own tables no longer use it: their primary keys default to
// gen_random_uuid() and the database assigns them, so a row comes back
// carrying the id it was actually stored under. It stays exported because it
// is a correct, dependency-free UUIDv4 and a host that wants one for its own
// records may as well not add a module for it.
func NewID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	buf[6] = (buf[6] & 0x0f) | 0x40 // version 4
	buf[8] = (buf[8] & 0x3f) | 0x80 // variant 10

	const hex = "0123456789abcdef"
	out := make([]byte, 36)
	dashes := map[int]bool{8: true, 13: true, 18: true, 23: true}
	j := 0
	for i := range 16 {
		if dashes[j] {
			out[j] = '-'
			j++
		}
		out[j] = hex[buf[i]>>4]
		out[j+1] = hex[buf[i]&0x0f]
		j += 2
	}
	return string(out), nil
}
