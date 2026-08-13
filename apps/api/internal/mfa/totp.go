// Package mfa implements TOTP (RFC-6238) enrollment + a login-time second-step challenge
// for S7.5.5. Enrollment is OPEN (all editions); org-level ENFORCE is enterprise (app layer).
package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
)

const (
	totpDigits = 6
	totpPeriod = 30 // seconds per timestep
	totpWindow = 1  // accept ±1 timestep (clock skew); replay guard prevents reuse within it
	issuer     = "Tunnex"
)

// base32NoPad is the authenticator-app secret encoding (uppercase, no padding).
var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret returns a fresh base32-encoded TOTP secret (160-bit, RFC-6238 §5.1).
func GenerateSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32NoPad.EncodeToString(b), nil
}

// OtpauthURI builds the otpauth:// provisioning URI a QR code encodes.
func OtpauthURI(secret, account string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", totpDigits))
	q.Set("period", fmt.Sprintf("%d", totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// Timestep is the current RFC-6238 counter for a unix time.
func Timestep(unix int64) int64 { return unix / totpPeriod }

// Validate checks code against secret across the ±window, HONORING the replay guard:
// only a timestep STRICTLY GREATER than lastUsed can match (a code — or its window
// neighbour — accepted before must never be accepted again). Returns the matched
// timestep and true on success; 0,false otherwise. lastUsed<0 means "never used".
func Validate(secret, code string, nowUnix, lastUsed int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}
	key, err := base32NoPad.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return 0, false
	}
	cur := Timestep(nowUnix)
	for ts := cur - totpWindow; ts <= cur+totpWindow; ts++ {
		if ts <= lastUsed {
			continue // replay guard: this timestep already yielded a successful code
		}
		if subtle.ConstantTimeCompare([]byte(hotp(key, ts)), []byte(code)) == 1 {
			return ts, true
		}
	}
	return 0, false
}

// hotp is HMAC-SHA1 HOTP (RFC-4226 §5.3) with dynamic truncation.
func hotp(key []byte, counter int64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	return fmt.Sprintf("%0*d", totpDigits, bin%pow10(totpDigits))
}

func pow10(n int) uint32 {
	p := uint32(1)
	for i := 0; i < n; i++ {
		p *= 10
	}
	return p
}
