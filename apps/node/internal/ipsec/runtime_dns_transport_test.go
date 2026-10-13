package ipsec

import (
	"context"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
)

func TestDNSControllerLockHonorsDeadline(t *testing.T) {
	c := &RuntimeController{}
	c.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	if c.lockDNSController(ctx) {
		t.Fatal("DNS acquired busy owner despite expired deadline")
	}
	if time.Since(start) > time.Second {
		t.Fatal("DNS waited unbounded behind runtime owner")
	}
	c.mu.Unlock()
	if !c.lockDNSController(context.Background()) {
		t.Fatal("available owner refused")
	}
	c.mu.Unlock()
}

func TestDNSRuntimeBridgeUnsupportedOrInactiveRefuses(t *testing.T) {
	config := fqdnrpc.ResolverConfig{}
	endpoint := fqdnrpc.ResolverEndpoint{Address: "10.85.2.24", Port: 53, Transport: "udp"}
	bridge := &DNSRuntimeTransport{}
	for _, controller := range []*RuntimeController{nil, {}} {
		bridge.Attach(controller)
		if _, err := bridge.ExchangeDNS(context.Background(), config, endpoint, nil); err == nil {
			t.Fatal("inactive runtime exchanged private DNS")
		}
		if err := bridge.ValidateDNSPath(context.Background(), config, endpoint); err == nil {
			t.Fatal("inactive runtime authorized cached DNS")
		}
	}
}
