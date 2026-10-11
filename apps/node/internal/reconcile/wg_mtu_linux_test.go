//go:build linux

package reconcile

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestUnderlayUsesDefaultRouteLinksNotSmallXFRM(t *testing.T) {
	b := &wgctrlBackend{iface: "wg0"}
	b.runFn = func(_ context.Context, _ string, args ...string) (string, error) {
		s := strings.Join(args, " ")
		switch s {
		case "-j -4 route show default":
			return `[{"dst":"default","dev":"ens4"}]`, nil
		case "-j -6 route show default":
			return `[]`, nil
		case "-j -d link show dev ens4":
			return `[{"ifname":"ens4","ifindex":2,"mtu":1460,"flags":["UP"]}]`, nil
		}
		return "", fmt.Errorf("unexpected command %s", s)
	}
	got, err := b.underlayMTU(context.Background())
	if err != nil || got != 1460 {
		t.Fatalf("%d %v", got, err)
	}
	b.runFn = func(_ context.Context, _ string, args ...string) (string, error) {
		return `[{"dst":"default","dev":"wg0"}]`, nil
	}
	if _, err := b.underlayMTU(context.Background()); err == nil {
		t.Fatal("own tunnel accepted as underlay")
	}
}
func TestAppliedMTURequiresSuccessfulReadback(t *testing.T) {
	b := &wgctrlBackend{iface: "wg0"}
	b.runFn = func(context.Context, string, ...string) (string, error) {
		return `[{"ifname":"wg0","mtu":1420,"flags":["UP"]}]`, nil
	}
	if err := b.verifyAppliedMTU(context.Background(), 1380); err == nil || b.AppliedMTU() != 0 {
		t.Fatal("computed ceiling advertised without readback")
	}
	b.runFn = func(context.Context, string, ...string) (string, error) {
		return `[{"ifname":"wg0","mtu":1380,"flags":["UP"]}]`, nil
	}
	if err := b.verifyAppliedMTU(context.Background(), 1380); err != nil || b.AppliedMTU() != 1380 {
		t.Fatalf("readback %v", err)
	}
}

func TestConfigureAppliesAndReportsFreshEffectiveMTU(t *testing.T) {
	underlay, current := 1460, 1420
	underlayReads := 0
	drift, wrongReadback := false, false
	b := &wgctrlBackend{iface: "wg0"}
	b.runFn = func(_ context.Context, name string, args ...string) (string, error) {
		s := strings.Join(args, " ")
		switch {
		case name == "wg" && s == "show wg0 dump":
			return "private\tpublic\t51820\toff", nil
		case name == "ip" && s == "-j -4 route show default":
			return `[{"dst":"default","dev":"ens4"}]`, nil
		case name == "ip" && s == "-j -6 route show default":
			return `[]`, nil
		case name == "ip" && s == "-j -d link show dev ens4":
			underlayReads++
			observed := underlay
			if drift && underlayReads%2 == 0 {
				observed--
			}
			return fmt.Sprintf(`[{"ifname":"ens4","ifindex":2,"mtu":%d,"flags":["UP"]}]`, observed), nil
		case name == "ip" && s == "link show wg0":
			return fmt.Sprintf("wg0: <UP> mtu %d state UNKNOWN", current), nil
		case name == "ip" && strings.HasPrefix(s, "link set dev wg0 mtu "):
			if _, err := fmt.Sscanf(s, "link set dev wg0 mtu %d up", &current); err != nil {
				return "", err
			}
			return "", nil
		case name == "ip" && s == "-j link show dev wg0":
			observed := current
			if wrongReadback {
				observed--
			}
			return fmt.Sprintf(`[{"ifname":"wg0","mtu":%d,"flags":["UP"]}]`, observed), nil
		}
		return "", fmt.Errorf("unexpected %s %s", name, s)
	}
	for _, x := range []struct{ physical, want int }{{1460, 1380}, {1500, 1420}} {
		underlay = x.physical
		if err := b.Configure(context.Background(), InterfaceConfig{MTU: 1420}); err != nil {
			t.Fatal(err)
		}
		if current != x.want || b.AppliedMTU() != x.want {
			t.Fatalf("physical%d current%d reported%d", underlay, current, b.AppliedMTU())
		}
	}
	drift = true
	underlayReads = 0
	if err := b.Configure(context.Background(), InterfaceConfig{MTU: 1420}); err == nil || b.AppliedMTU() != 0 {
		t.Fatal("late underlay drift retained report")
	}
	drift = false
	wrongReadback = true
	if err := b.Configure(context.Background(), InterfaceConfig{MTU: 1420}); err == nil || b.AppliedMTU() != 0 {
		t.Fatal("late WG readback refusal retained report")
	}
	b.runFn = func(context.Context, string, ...string) (string, error) { return "", fmt.Errorf("read failed") }
	if err := b.Configure(context.Background(), InterfaceConfig{MTU: 1420}); err == nil || b.AppliedMTU() != 0 {
		t.Fatal("failed configure retained report")
	}
}
