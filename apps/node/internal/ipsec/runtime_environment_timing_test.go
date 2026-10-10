package ipsec

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEnvironmentTimingPreservesEighteenCommands(t *testing.T) {
	nft, err := os.ReadFile("testdata/runtime-docker-dns-nft.json")
	if err != nil {
		t.Fatal(err)
	}
	listing, err := os.ReadFile("testdata/runtime-docker-dns-save.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"success", "nft_error", "hook_error", "cancel", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			var before RuntimeEnvironment
			var beforeErr error
			var beforeOrder []string
			for _, enabled := range []bool{false, true} {
				e := journalFixture()
				for i := range e.Engines {
					e.Engines[i].LocalPrefixes = []netip.Prefix{netip.MustParsePrefix("10.10.0.0/16")}
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if kind == "deadline" {
					var expired context.CancelFunc
					ctx, expired = context.WithDeadline(ctx, time.Now().Add(-time.Second))
					defer expired()
				}
				var order []string
				var orderMu sync.Mutex
				record := func(v string) { orderMu.Lock(); order = append(order, v); orderMu.Unlock() }
				inspector := &runtimeEnvironmentInspector{nftPath: "/qualified/nft", namespace: func() (string, error) { return e.Allocation.Namespace, nil }, nft: func(context.Context, ...string) ([]byte, error) {
					record("nft")
					if kind == "nft_error" {
						return nil, errors.New("private")
					}
					if kind == "cancel" {
						cancel()
					}
					return nft, nil
				}, ip: func(_ context.Context, args ...string) ([]byte, error) {
					command := strings.Join(args, " ")
					record(command)
					switch command {
					case "-j -4 rule show":
						return []byte(`[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`), nil
					case "-j -d link show":
						return []byte(`[{"ifindex":2,"ifname":"eth0","link_type":"ether","mtu":1500,"flags":["UP"]},{"ifindex":3,"ifname":"lan0","link_type":"ether","mtu":1500,"flags":["UP"]}]`), nil
					case "-j -4 route show table main":
						return []byte(`[{"dst":"10.10.0.0/16","dev":"lan0"}]`), nil
					case "-j -4 address show":
						return []byte(`[{"ifname":"eth0","addr_info":[{"local":"172.18.0.2"}]}]`), nil
					default:
						return []byte(`[{"dst":"` + args[len(args)-1] + `","dev":"eth0","prefsrc":"172.18.0.2"}]`), nil
					}
				}}
				hook := func(ctx context.Context, _ string, args ...string) ([]byte, error) {
					record("hook " + strings.Join(args, " "))
					if ctx.Err() != nil {
						return nil, ctx.Err()
					}
					if kind == "hook_error" {
						return nil, errors.New("private")
					}
					time.Sleep(time.Millisecond)
					if len(args) == 1 {
						return []byte("iptables-nft-save v1.8.7 (nf_tables)"), nil
					}
					return listing, nil
				}
				var measured runtimeEnvironmentTiming
				calls := 0
				var observe func(runtimeEnvironmentTiming)
				if enabled {
					observe = func(v runtimeEnvironmentTiming) { calls++; measured = v }
				}
				got, err := inspector.observeWithCommands(ctx, e.Allocation, e.Engines, observe, hook)
				if kind == "success" {
					nftPhase := 0
					for _, command := range order {
						switch command {
						case "nft":
							if nftPhase%3 != 0 {
								t.Fatal("nft snapshots overlapped")
							}
							nftPhase++
						case "hook -V":
							if nftPhase%3 != 1 {
								t.Fatal("version read out of order")
							}
							nftPhase++
						case "hook -t nat":
							if nftPhase%3 != 2 {
								t.Fatal("NAT read out of order")
							}
							nftPhase++
						}
					}
					if nftPhase != 6 {
						t.Fatal("missing census reads")
					}
				}
				sort.Strings(order)
				if !enabled {
					before, beforeErr, beforeOrder = got, err, order
				} else {
					if !reflect.DeepEqual(got, before) || !errors.Is(err, beforeErr) || (kind == "success" && !reflect.DeepEqual(order, beforeOrder)) {
						t.Fatal("timing changed result/error/order")
					}
					if calls != 1 || measured.CommandCount != len(order) || measured.CommandMillis < 0 || measured.VerificationMillis < 0 {
						t.Fatal("invalid timing", measured)
					}
				}
				if kind == "success" {
					expected := []string{"nft", "hook -V", "hook -t nat", "-j -4 rule show", "-j -d link show", "-j -4 route show table main", "-j -4 address show", "-j -4 route get " + e.Engines[0].RemoteAddress.String(), "-j -4 route get " + e.Engines[1].RemoteAddress.String(), "-j -d link show", "-j -4 rule show", "nft", "hook -V", "hook -t nat", "-j -4 route show table main", "-j -4 address show", "-j -4 route get " + e.Engines[0].RemoteAddress.String(), "-j -4 route get " + e.Engines[1].RemoteAddress.String()}
					sort.Strings(expected)
					if err != nil || !reflect.DeepEqual(order, expected) {
						t.Fatal("full eighteen-command bracket failed", err, order)
					}
				} else if err == nil {
					t.Fatal("failure accepted")
				}
			}
		})
	}
}
func TestEnvironmentTimingBounds(t *testing.T) {
	for _, v := range []runtimeEnvironmentTiming{{CommandMillis: -1}, {CommandMillis: 60001}, {VerificationMillis: -1}, {VerificationMillis: 60001}, {CommandCount: -1}, {CommandCount: 19}} {
		if validDNSReadTiming(runtimeDNSReadTiming{Native: runtimeNativePhaseTiming{Environment: v}}) {
			t.Fatal("invalid scalar accepted")
		}
	}
}
