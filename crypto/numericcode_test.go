package crypto_test

import (
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
// near 300, while the modulo bias shifts each digit by some 2,000 -- six to
// ten standard deviations. A smaller sample would pass for both, which is
// worse than having no test.
//
// The comparison is chi-squared over all ten digits rather than a per-digit
// tolerance, because a per-digit tolerance cannot be set well here. The
// previous version failed when any digit drifted 1%, which is 3.3 standard
// deviations -- and across ten digits that trips on honest randomness
// roughly once in 115 runs. It did, which is how this was found. Widening
// it to where noise is safe leaves almost no gap below the 2% the bias
// produces.
//
// Chi-squared uses every digit at once and separates the two cases by a
// factor of ten instead: an unbiased generator scores about 9, the biased
// one several hundred. The threshold below is p ≈ 1e-6 for 9 degrees of
// freedom, so a false failure is a once-in-a-million-runs event rather
// than a weekly annoyance -- and a flaky security test is one people learn
// to re-run.
func TestNumericCodeIsUnbiased(t *testing.T) {
	const (
		codeLen  = 10
		codes    = 100_000
		total    = codeLen * codes
		expected = float64(total) / 10
		// Chi-squared critical value, 9 degrees of freedom, p = 1e-6.
		// The biased implementation scores in the hundreds.
		maxChiSquared = 45.0
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

	var chiSquared float64
	for _, got := range counts {
		d := float64(got) - expected
		chiSquared += d * d / expected
	}
	if chiSquared > maxChiSquared {
		t.Fatalf("digit distribution %v scores chi-squared %.1f over %d digits, want under %.0f "+
			"-- modulo bias? (expected %.0f of each)", counts, chiSquared, total, maxChiSquared, expected)
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
