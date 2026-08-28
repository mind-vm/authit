package crypto_test

import (
	"math"
	"testing"

	authitcrypto "github.com/mind-vm/authit/crypto"
)

// TestNumericCodeIsUnbiased checks that every digit is equally likely.
//
// The obvious implementation -- read a byte, take it modulo 10 -- is
// biased, because 256 is not a multiple of 10: digits 0 to 5 get 26 of the
// 256 byte values and 6 to 9 get 25, so the first six appear about 4% more
// often. That is not a break by itself, but it shrinks the space an
// attacker has to search, and rejection sampling removes it for the cost
// of a loop.
//
// The sample size is chosen so the test can actually see that. With a
// million digits each is expected 100,000 times with a standard deviation
// near 300, while the modulo bias shifts the common digits by about 2,000
// -- some six standard deviations, so a threshold of 1% separates the two
// implementations reliably without tripping on sampling noise. A smaller
// sample would pass for both, which is worse than having no test.
func TestNumericCodeIsUnbiased(t *testing.T) {
	const (
		codeLen   = 10
		codes     = 100_000
		total     = codeLen * codes
		expected  = total / 10
		tolerance = 0.01
	)
	counts := make([]int, 10)
	for range codes {
		code, err := authitcrypto.GenerateNumericCode(codeLen)
		if err != nil {
			t.Fatalf("GenerateNumericCode: %v", err)
		}
		if len(code) != codeLen {
			t.Fatalf("code %q is %d digits, want %d", code, len(code), codeLen)
		}
		for _, r := range code {
			if r < '0' || r > '9' {
				t.Fatalf("code %q contains a non-digit", code)
			}
			counts[r-'0']++
		}
	}
	for d, got := range counts {
		if drift := math.Abs(float64(got)-expected) / expected; drift > tolerance {
			t.Fatalf("digit %d appeared %d times, want within %.0f%% of %d (drift %.2f%%) -- modulo bias?",
				d, got, tolerance*100, expected, drift*100)
		}
	}
}

func TestNumericCodeEdgeCases(t *testing.T) {
	for _, n := range []int{0, -1} {
		got, err := authitcrypto.GenerateNumericCode(n)
		if err != nil || got != "" {
			t.Fatalf("GenerateNumericCode(%d) = %q, %v; want empty", n, got, err)
		}
	}
	// Leading zeros are digits, not something to trim: a code of "007" is
	// three digits, and a caller that stored it as a number would be
	// comparing "7".
	sawLeadingZero := false
	for range 500 {
		c, err := authitcrypto.GenerateNumericCode(3)
		if err != nil {
			t.Fatalf("GenerateNumericCode: %v", err)
		}
		if len(c) != 3 {
			t.Fatalf("code %q is not 3 digits", c)
		}
		if c[0] == '0' {
			sawLeadingZero = true
		}
	}
	if !sawLeadingZero {
		t.Fatal("expected some codes to begin with zero in 500 draws")
	}
}
