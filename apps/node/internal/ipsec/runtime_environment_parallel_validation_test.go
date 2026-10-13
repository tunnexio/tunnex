package ipsec

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEnvironmentSnapshotValidationPrecedesSecondReads(t *testing.T) {
	for _, kind := range []string{"valid", "malformed_rules", "malformed_links", "malformed_routes", "malformed_addresses", "malformed_peer", "changed_peer", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			e := journalFixture()
			e.Engines[1].RemoteAddress = netip.MustParseAddr("192.0.2.3")
			for i := range e.Engines {
				e.Engines[i].LocalPrefixes = []netip.Prefix{netip.MustParsePrefix("10.10.0.0/16")}
			}
			var mu sync.Mutex
			counts := map[string]int{}
			inspector := &runtimeEnvironmentInspector{namespace: func() (string, error) { return e.Allocation.Namespace, nil }, nft: func(context.Context, ...string) ([]byte, error) {
				mu.Lock()
				counts["nft"]++
				mu.Unlock()
				return []byte(`{"nftables":[]}`), nil
			}, ip: func(c context.Context, args ...string) ([]byte, error) {
				key := strings.Join(args, " ")
				mu.Lock()
				counts[key]++
				n := counts[key]
				mu.Unlock()
				if kind == "deadline" {
					<-c.Done()
					return nil, c.Err()
				}
				var raw string
				switch key {
				case "-j -4 rule show":
					raw = `[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`
					if kind == "malformed_rules" {
						raw = `[]`
					}
				case "-j -d link show":
					raw = `[{"ifindex":2,"ifname":"eth0","link_type":"ether","mtu":1500,"flags":["UP"]},{"ifindex":3,"ifname":"lan0","link_type":"ether","mtu":1500,"flags":["UP"]}]`
					if kind == "malformed_links" {
						raw = `[{"ifindex":0}]`
					}
				case "-j -4 route show table main":
					raw = `[{"dst":"10.10.0.0/16","dev":"lan0"}]`
					if kind == "malformed_routes" {
						raw = `[]`
					}
				case "-j -4 address show":
					raw = `[{"ifname":"eth0","addr_info":[{"local":"172.18.0.2"}]}]`
					if kind == "malformed_addresses" {
						raw = `[]`
					}
				default:
					raw = `[{"dst":"` + args[len(args)-1] + `","dev":"eth0","prefsrc":"172.18.0.2"}]`
					if kind == "malformed_peer" || (kind == "changed_peer" && n == 2) {
						raw = `[]`
					}
				}
				return []byte(raw), nil
			}}
			ctx := context.Background()
			if kind == "deadline" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 20*time.Millisecond)
				defer cancel()
			}
			out, err := inspector.Observe(ctx, e.Allocation, e.Engines)
			if kind == "valid" {
				if err != nil || out.Namespace == "" {
					t.Fatal("valid failed", err)
				}
			} else if err == nil || out.Namespace != "" {
				t.Fatal("invalid snapshot produced facts")
			}
			if strings.HasPrefix(kind, "malformed_") {
				for _, n := range counts {
					if n != 1 {
						t.Fatal("second snapshot began before first validation", counts)
					}
				}
				if len(counts) != 7 {
					t.Fatal("first snapshot was not drained", counts)
				}
			}
			if kind == "valid" || kind == "changed_peer" {
				for _, n := range counts {
					if n != 2 {
						t.Fatal("incomplete independent snapshots", counts)
					}
				}
			}
		})
	}
}
