package ipsec

import (
	"testing"
	"time"
)

func TestDesktopGrantExpiryBoundsWholeLease(t *testing.T) {
	now := time.Now()
	end := now.Add(4 * time.Second)
	p := RuntimePolicy{DesktopGrants: []RuntimeDesktopGrant{{ExpiresAt: &end}}}
	ttl, err := runtimeFQDNWholeLeaseTTL(p, now, 500*time.Millisecond)
	if err != nil || ttl != 3500 {
		t.Fatalf("unbounded desktop lease %d %v", ttl, err)
	}
	if _, err = runtimeFQDNWholeLeaseTTL(p, now, 4*time.Second); err == nil {
		t.Fatal("expired desktop lease renewed")
	}
}
