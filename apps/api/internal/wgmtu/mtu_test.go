package wgmtu

import (
	"testing"
	"time"
)

func TestFreshAppliedMTUAndLegacyFallback(t *testing.T) {
	now := time.Now()
	for _, x := range []struct {
		caps string
		age  time.Duration
		want int
	}{{`{"wireguard_applied_mtu":1380}`, time.Second, 1380}, {`{"wireguard_applied_mtu":1420}`, time.Second, 1420}, {`{}`, time.Second, 1420}, {`{"wireguard_applied_mtu":true}`, time.Second, 1420}, {`{"wireguard_applied_mtu":1199}`, time.Second, 1420}, {`{"wireguard_applied_mtu":1500}`, time.Second, 1420}, {`{"wireguard_applied_mtu":1380}`, 91 * time.Second, 1420}, {`{"wireguard_applied_mtu":1380}`, -time.Second, 1420}} {
		if got := Applied([]byte(x.caps), now.Add(-x.age), now); got != x.want {
			t.Fatalf("%+v got%d", x, got)
		}
	}
}
