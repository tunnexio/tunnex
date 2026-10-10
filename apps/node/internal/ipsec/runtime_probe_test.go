package ipsec

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestRuntimePlatformProbeRequiresEveryObservation(t *testing.T) {
	names := []string{"package", "daemon", "kernel", "xfrm", "environment", "nft", "privilege"}
	for _, broken := range append([]string{""}, names...) {
		t.Run(broken, func(t *testing.T) {
			calls := map[string]int{}
			p := runtimePlatformProbe{namespace: func() (string, error) { return "net:[1234]", nil }, clock: func() (runtimeClock, error) { return runtimeClock{Boot: time.Hour, Monotonic: time.Hour}, nil }, alive: func() bool { return true }}
			mk := func(name string) func(context.Context) error {
				return func(context.Context) error {
					calls[name]++
					if name == broken {
						return errors.New("synthetic secret")
					}
					return nil
				}
			}
			p.packaged = mk("package")
			p.daemon = mk("daemon")
			p.kernel = mk("kernel")
			p.xfrm = mk("xfrm")
			p.environment = mk("environment")
			p.nft = mk("nft")
			p.privilege = mk("privilege")
			receipt, e := p.probe(context.Background())
			if broken != "" {
				if e != ErrRuntimeProbe || receipt != nil {
					t.Fatal("failed probe qualified")
				}
				return
			}
			if e != nil || !receipt.current() {
				t.Fatal("complete observations refused", e)
			}
			for _, name := range names {
				if calls[name] != 1 {
					t.Fatal("probe omitted", name)
				}
			}
		})
	}
}
func TestRuntimePlatformProbeResumeInvalidatesReceipt(t *testing.T) {
	reading := runtimeClock{Boot: time.Hour, Monotonic: time.Hour}
	q := &RuntimePlatformQualification{namespace: "net:[1234]", readNamespace: func() (string, error) { return "net:[1234]", nil }, readClock: func() (runtimeClock, error) { return reading, nil }, baseline: reading, alive: func() bool { return true }}
	if !q.current() {
		t.Fatal("live receipt refused")
	}
	reading.Boot += time.Minute
	if q.current() {
		t.Fatal("resume retained authority")
	}
	reading.Boot -= time.Minute
	if q.current() {
		t.Fatal("invalidated receipt resurrected")
	}
}

func TestRuntimePlatformReceiptDetectsLaterClockRegression(t *testing.T) {
	reading := runtimeClock{Boot: time.Hour, Monotonic: time.Hour}
	q := &RuntimePlatformQualification{namespace: "net:[1234]", readNamespace: func() (string, error) { return "net:[1234]", nil }, readClock: func() (runtimeClock, error) { return reading, nil }, baseline: reading, alive: func() bool { return true }}
	reading.Boot += time.Minute
	reading.Monotonic += time.Minute
	if !q.current() {
		t.Fatal("forward clock rejected")
	}
	reading.Boot -= time.Second
	reading.Monotonic -= time.Second
	if q.current() {
		t.Fatal("later clock regression accepted")
	}
}

func TestRuntimePlatformNativePluginInventory(t *testing.T) {
	actual := []string{"charon", "random", "nonce", "openssl", "kdf", "kernel-netlink", "socket-default", "vici"}
	if !runtimeProbePlugins(actual) {
		t.Fatal("native builtin charon and seven shared plugins rejected")
	}
	if runtimeProbePlugins(actual[1:]) || runtimeProbePlugins(append(append([]string{}, actual...), "updown")) {
		t.Fatal("incomplete or expanded plugin profile accepted")
	}
	duplicate := append([]string{}, actual...)
	duplicate[7] = "charon"
	if runtimeProbePlugins(duplicate) {
		t.Fatal("duplicate plugin accepted")
	}
}

// This checks the real check-only bootstrap manifest, not a parallel render
// fixture: qualification must exercise every newly required nft expression.
func TestRuntimeProbeManifestExercisesMSSAndRelatedParentGrammar(t *testing.T) {
	m, err := runtimeProbeManifest("net:[1234]")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`"mangle"`, `"related"`, `"proto-dst"`, `"right":443`, `"destination-unreachable"`} {
		if !strings.Contains(m.NFTJSON, required) {
			t.Fatal("bootstrap omitted grammar", required)
		}
	}
	if !strings.Contains(m.NFT, "ip daddr 10.250.1.1/32") || !strings.Contains(m.NFT, "ct original proto-dst 443") {
		t.Fatal("probe parent receiver/port not exact")
	}
	i := guardFixture()
	c := &i.Connections[0]
	c.Grants[0].Source = netip.MustParsePrefix("10.10.0.1/32")
	c.ReplyIngressIndices = []int{10}
	c.TunnelMTUs = []GuardTunnelMTU{{10, 1422}}
	c.PermitFor = 0
	denied, err := RenderGuard(i)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(denied.NFTJSON, `"mangle"`) || strings.Contains(denied.NFTJSON, `"related"`) {
		t.Fatal("expired guard manufactured authority from probe grammar")
	}
}
