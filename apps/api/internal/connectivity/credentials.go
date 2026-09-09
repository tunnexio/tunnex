package connectivity

import (
	"crypto/hmac"
	"crypto/sha1" // coturn REST authentication requires HMAC-SHA1.
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"
	"time"
)

const RelayCredentialTTL = 5 * time.Minute

var ErrRelaySecret = errors.New("invalid relay secret configuration")

// RelayCredentials are bearer secrets. Never log them or persist them in status.
// They authorize TURN allocation, not application access or peer destinations.
type RelayCredentials struct {
	Username  string
	Password  string
	ExpiresAt time.Time
}

// IssueRelayCredentials requires a fresh authoritative snapshot. The eventual
// service must load that snapshot and session in its authorization transaction;
// this function is not a substitute for authentication or durable revocation.
// secret is the configured profile's random coturn shared secret, never caller
// input. Expiry prevents new credentials from outliving a session, but does not
// terminate an existing TURN allocation.
func (s Session) IssueRelayCredentials(p Principal, current Snapshot, now time.Time, secret []byte) (RelayCredentials, error) {
	if err := s.Authorize(p, current, now); err != nil {
		return RelayCredentials{}, err
	}
	if len(secret) < 32 || len(secret) > 4096 {
		return RelayCredentials{}, ErrRelaySecret
	}
	// Stable per-minute credentials prevent each mailbox read minting another
	// coturn username. Always <= five minutes; session expiry remains final.
	expires := now.Truncate(time.Minute).Add(RelayCredentialTTL)
	if s.ExpiresAt.Before(expires) {
		expires = s.ExpiresAt
	}
	expires = expires.UTC().Truncate(time.Second)
	if expires.Unix() <= 0 || expires.Sub(now) < time.Second {
		return RelayCredentials{}, ErrDenied
	}

	// Fixed-width fields and a domain separator avoid ambiguous concatenation.
	// Keyed scope hides raw identity metadata even on customer relay logs.
	scope := hmac.New(sha256.New, secret)
	scope.Write([]byte("tunnex/relay-credential/v1\x00"))
	b := s.Binding
	for _, id := range [][16]byte{b.SessionID, b.OrgID, b.OwnerID, b.DeviceID, b.GatewayID} {
		scope.Write(id[:])
	}
	var generation [8]byte
	binary.BigEndian.PutUint64(generation[:], b.Generation)
	scope.Write(generation[:])
	scope.Write([]byte{byte(p.Side)})
	username := strconv.FormatInt(expires.Unix(), 10) + ":" + base64.RawURLEncoding.EncodeToString(scope.Sum(nil))
	mac := hmac.New(sha1.New, secret)
	mac.Write([]byte(username))
	return RelayCredentials{
		Username: username, Password: base64.StdEncoding.EncodeToString(mac.Sum(nil)), ExpiresAt: expires,
	}, nil
}
