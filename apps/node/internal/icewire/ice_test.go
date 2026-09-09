package icewire

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeBindsKeyAndRejectsUnsafeCandidates(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, tc := range []struct {
		name, address string
		allowed       bool
	}{
		{"private", "10.245.1.20", true},
		{"public", "8.8.8.8", true},
		{"loopback", "127.0.0.1", false},
		{"metadata", "169.254.169.254", false},
		{"unspecified", "0.0.0.0", false},
		{"multicast", "224.0.0.1", false},
		{"hostname", "localhost", false},
		{"ipv6", "2001:db8::1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := Signal{Version: 1, PublicKey: key, User: "abcd", Password: strings.Repeat("p", 22), Candidates: []string{"1 1 udp 2130706431 " + tc.address + " 51820 typ host"}}
			b, _ := json.Marshal(s)
			if _, err := Decode(string(b), key); (err == nil) != tc.allowed {
				t.Fatalf("candidate allowed=%v, error=%v", tc.allowed, err)
			}
			if _, err := Decode(string(b), base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))); err == nil {
				t.Fatal("accepted wrong WG identity")
			}
		})
	}
}

func TestDecodeBounds(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, raw := range []string{`{}`, `not-json`, strings.Repeat("x", 16385)} {
		if _, err := Decode(raw, key); err == nil {
			t.Fatal("accepted malformed or oversized offer")
		}
	}
}
