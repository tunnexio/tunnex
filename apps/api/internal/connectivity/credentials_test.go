package connectivity

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRelayCredentialsProtocolAndLifetime(t *testing.T) {
	s, c, p, now := fixture()
	secret := []byte(strings.Repeat("test-only-secret", 3))
	for _, lifetime := range []time.Duration{time.Minute, time.Hour} {
		s.ExpiresAt = now.Add(lifetime)
		got, err := s.IssueRelayCredentials(p, c, now, secret)
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(got.Username, ":")
		if len(parts) != 2 {
			t.Fatal("invalid coturn username shape")
		}
		ts, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil || ts != got.ExpiresAt.Unix() {
			t.Fatal("expiry prefix mismatch")
		}
		want := now.Truncate(time.Minute).Add(RelayCredentialTTL)
		if s.ExpiresAt.Before(want) {
			want = s.ExpiresAt
		}
		if !got.ExpiresAt.Equal(want) {
			t.Fatal("credential lifetime escaped bound")
		}
		mac := hmac.New(sha1.New, secret)
		mac.Write([]byte(got.Username))
		if got.Password != base64.StdEncoding.EncodeToString(mac.Sum(nil)) {
			t.Fatal("coturn password mismatch")
		}
		for _, id := range []string{s.Binding.OrgID.String(), s.Binding.OwnerID.String(), s.Binding.DeviceID.String()} {
			if strings.Contains(got.Username, id) {
				t.Fatal("raw identity leaked")
			}
		}
	}
}

func TestRelayCredentialsScopeAndRotation(t *testing.T) {
	s, c, p, now := fixture()
	secret := []byte(strings.Repeat("a", 32))
	first, err := s.IssueRelayCredentials(p, c, now, secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"side", "generation", "secret"} {
		t.Run(change, func(t *testing.T) {
			ss, cc, pp, key := s, c, p, secret
			switch change {
			case "side":
				pp.Side, pp.SubjectID = GatewaySide, s.Binding.GatewayID
			case "generation":
				ss.Binding.Generation++
				cc.Current = ss.Binding
			case "secret":
				key = []byte(strings.Repeat("b", 32))
			}
			got, err := ss.IssueRelayCredentials(pp, cc, now, key)
			if err != nil {
				t.Fatal(err)
			}
			if got.Username == first.Username || got.Password == first.Password {
				t.Fatal("credential scope reused")
			}
		})
	}
}

func TestRelayCredentialsStableWithinIssuanceMinute(t *testing.T) {
	s, c, p, now := fixture()
	now = now.Truncate(time.Minute).Add(time.Second)
	s.CreatedAt = now
	s.ExpiresAt = now.Add(time.Hour)
	secret := []byte(strings.Repeat("a", 32))
	first, err := s.IssueRelayCredentials(p, c, now, secret)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := s.IssueRelayCredentials(p, c, now.Add(57*time.Second), secret)
	if err != nil || repeated != first {
		t.Fatal("same-minute read minted different credentials")
	}
	next, err := s.IssueRelayCredentials(p, c, now.Add(time.Minute), secret)
	if err != nil || next.Username == first.Username || next.Password == first.Password {
		t.Fatal("next issuance minute did not rotate credentials")
	}
}

func TestRelayCredentialsFailClosed(t *testing.T) {
	for _, name := range []string{"disabled", "revoked", "owner", "expired", "subsecond", "short secret", "large secret"} {
		t.Run(name, func(t *testing.T) {
			s, c, p, now := fixture()
			key := []byte(strings.Repeat("a", 32))
			want := ErrDenied
			switch name {
			case "disabled":
				c.OptedIn = false
			case "revoked":
				s.Revoked = true
			case "owner":
				p.SubjectID = s.Binding.GatewayID
			case "expired":
				now = s.ExpiresAt
			case "subsecond":
				s.ExpiresAt = now.Add(999 * time.Millisecond)
			case "short secret":
				key = key[:31]
				want = ErrRelaySecret
			case "large secret":
				key = make([]byte, 4097)
				want = ErrRelaySecret
			}
			got, err := s.IssueRelayCredentials(p, c, now, key)
			if err != want || got != (RelayCredentials{}) {
				t.Fatal("invalid request issued credentials or wrong error")
			}
		})
	}
}
