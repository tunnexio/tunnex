package mfa

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

// RecoveryCodeCount is how many single-use recovery codes issue on TOTP confirm (D4).
const RecoveryCodeCount = 10

var recoveryEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateRecoveryCodes returns RecoveryCodeCount fresh codes, formatted for display
// (XXXXX-XXXXX). The plaintext is shown ONCE; only HashCode(code) is stored.
func GenerateRecoveryCodes() ([]string, error) {
	out := make([]string, 0, RecoveryCodeCount)
	for i := 0; i < RecoveryCodeCount; i++ {
		b := make([]byte, 7) // 7 bytes -> ~11 base32 chars; take 10
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		s := recoveryEnc.EncodeToString(b)[:10]
		out = append(out, s[:5]+"-"+s[5:])
	}
	return out, nil
}

// normalizeCode strips display separators/whitespace and upper-cases, so "abcde-fghij",
// "ABCDE FGHIJ" and "abcdefghij" all hash identically.
func normalizeCode(code string) string {
	code = strings.ReplaceAll(code, "-", "")
	code = strings.ReplaceAll(code, " ", "")
	return strings.ToUpper(strings.TrimSpace(code))
}

// HashCode is the at-rest hash of a recovery code (sha256, cliauth hygiene).
func HashCode(code string) []byte {
	h := sha256.Sum256([]byte(normalizeCode(code)))
	return h[:]
}
