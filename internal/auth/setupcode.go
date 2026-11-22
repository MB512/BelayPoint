package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"strings"
)

// setupAlphabet avoids characters that are easy to confuse (0/O, 1/I/L).
const setupAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

// NewSetupCode returns a one-time code for the first-start setup, e.g.
// "K7QM-2XRA-PH9C-4TWE" (16 characters, about 79 bits). It is printed to
// the container log only, so creating the vault needs access to that log
// and not just network access to the page.
func NewSetupCode() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating setup code: %w", err)
	}
	var sb strings.Builder
	for i, c := range b {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		// 256 % 31 != 0, so this is very slightly biased; irrelevant for
		// a one-time code behind the login limiter.
		sb.WriteByte(setupAlphabet[int(c)%len(setupAlphabet)])
	}
	return sb.String(), nil
}

// SetupCodeMatches compares a typed code with the expected one, ignoring
// case, spaces and dashes, in constant time.
func SetupCodeMatches(expected, typed string) bool {
	if expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(normalizeCode(expected)), []byte(normalizeCode(typed))) == 1
}

func normalizeCode(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '-' || r == ' ' || r == '\t':
			return -1 // drop
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		}
		return r
	}, s)
}
