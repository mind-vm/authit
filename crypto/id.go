package crypto

import "crypto/rand"

// NewID returns a random UUIDv4 string. authit's service packages use this
// to assign IDs before handing records to a Store, so stores never need to
// generate identifiers themselves.
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
