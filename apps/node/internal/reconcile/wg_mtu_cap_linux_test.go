//go:build linux

package reconcile

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestConfigureGatewayMTUCapUsesNormalOwnerAndReadback(t *testing.T) {
	for _, tc := range []struct {
		name                           string
		cap, requested, physical, want int
		refuseWrite, wrongReadback     bool
	}{
		{name: "default unchanged", requested: 1420, physical: 1500, want: 1420},
		{name: "explicit cap", cap: 1380, requested: 1420, physical: 1500, want: 1380},
		{name: "minimum cap", cap: 1280, requested: 1420, physical: 1500, want: 1280},
		{name: "maximum cap", cap: 1420, requested: 1420, physical: 1500, want: 1420},
		{name: "physical remains stricter", cap: 1380, requested: 1420, physical: 1400, want: 1320},
		{name: "desired remains stricter", cap: 1380, requested: 1360, physical: 1500, want: 1360},
		{name: "zero desired remains unowned", cap: 1380, physical: 1500, want: 1420},
		{name: "write refusal clears report", cap: 1380, requested: 1420, physical: 1500, refuseWrite: true},
		{name: "readback refusal clears report", cap: 1380, requested: 1420, physical: 1500, wrongReadback: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend, err := SelectBackendWithOptions("wgctrl", "wg0", nil, BackendOptions{WireGuardMTUCap: tc.cap})
			if err != nil {
				t.Fatal(err)
			}
			b := backend.(*wgctrlBackend)
			current, writes := 1420, 0
			b.appliedMTU.Store(1420)
			b.runFn = func(_ context.Context, name string, args ...string) (string, error) {
				command := strings.Join(args, " ")
				switch {
				case name == "wg" && command == "show wg0 dump":
					return "private\tpublic\t51820\toff", nil
				case name == "ip" && command == "link show wg0":
					return fmt.Sprintf("wg0: <UP> mtu %d state UNKNOWN", current), nil
				case name == "ip" && command == "-j -4 route show default":
					return `[{"dst":"default","dev":"ens4"}]`, nil
				case name == "ip" && command == "-j -6 route show default":
					return `[]`, nil
				case name == "ip" && command == "-j -d link show dev ens4":
					return fmt.Sprintf(`[{"ifname":"ens4","ifindex":2,"mtu":%d,"flags":["UP"]}]`, tc.physical), nil
				case name == "ip" && strings.HasPrefix(command, "link set dev wg0 mtu "):
					writes++
					if tc.refuseWrite {
						return "", fmt.Errorf("write refused")
					}
					_, err := fmt.Sscanf(command, "link set dev wg0 mtu %d up", &current)
					return "", err
				case name == "ip" && command == "-j link show dev wg0":
					observed := current
					if tc.wrongReadback {
						observed--
					}
					return fmt.Sprintf(`[{"ifname":"wg0","mtu":%d,"flags":["UP"]}]`, observed), nil
				}
				return "", fmt.Errorf("unexpected command %s %s", name, command)
			}
			report := (&Reconciler{backend: b}).AppliedWireGuardMTU
			err = b.Configure(context.Background(), InterfaceConfig{MTU: tc.requested})
			if tc.refuseWrite || tc.wrongReadback {
				if err == nil || report() != 0 {
					t.Fatalf("failed apply reported MTU: %d %v", report(), err)
				}
				return
			}
			wantReport := tc.want
			if tc.requested == 0 {
				wantReport = 0
			}
			if err != nil || current != tc.want || report() != wantReport {
				t.Fatalf("current%d reported%d want%d/%d err%v", current, report(), tc.want, wantReport, err)
			}
			before := writes
			if err = b.Configure(context.Background(), InterfaceConfig{MTU: tc.requested}); err != nil || writes != before {
				t.Fatalf("steady cap rewrote interface: writes%d->%d err%v", before, writes, err)
			}
		})
	}
}
