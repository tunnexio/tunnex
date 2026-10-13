package ipsec

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestRuntimeFQDNLeaseCannotOutliveSelectedAnswer(t *testing.T) {
	now := time.Date(2026, 10, 11, 1, 0, 0, 0, time.UTC)
	p := RuntimePolicy{FQDNGrants: []RuntimeFQDNGrant{{}}, FQDNValidUntil: now.Add(2250 * time.Millisecond)}
	for _, tc := range []struct {
		name    string
		elapsed time.Duration
		want    int64
	}{{"short TTL", 0, 2250}, {"commit elapsed", 250 * time.Millisecond, 2000}, {"floor milliseconds", time.Nanosecond, 2249}, {"expired during commit", 2250 * time.Millisecond, 0}, {"negative elapsed", -time.Nanosecond, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := runtimePolicyLeaseTTL(p, now, tc.elapsed)
			if got != tc.want || (err != nil) != (tc.want == 0) {
				t.Fatalf("got %d %v want %d", got, err, tc.want)
			}
		})
	}
	p.FQDNValidUntil = time.Time{}
	if _, err := runtimePolicyLeaseTTL(p, now, 0); err == nil {
		t.Fatal("missing expiry accepted")
	}
	p.FQDNValidUntil = now.Add(5 * time.Minute)
	if got, err := runtimePolicyLeaseTTL(p, now, 0); err != nil || got != 60000 {
		t.Fatal(got, err)
	}
	raw, _ := json.Marshal(p)
	if bytes.Contains(raw, []byte("ValidUntil")) || bytes.Contains(raw, []byte("2026")) {
		t.Fatal("expiry leaked to wire")
	}
	p.FQDNGrants = nil
	if got, err := runtimePolicyLeaseTTL(p, now, time.Minute); err != nil || got != 60000 {
		t.Fatal("ordinary lease changed", got, err)
	}
}
