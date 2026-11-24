//go:build linux

package egress

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/hostposture"
)

// releasedStopRuleset is hostPostureMarkerOnlyRuleset as released in v0.1.44 and on origin/main
// (60aae74f), byte for byte. K8N-5: `flush table` keeps every chain, so this left `forward` hooked
// with policy drop and no rules. Kept here so the kernel witness can show what it did.
const releasedStopRuleset = `add table ip tunnex
flush table ip tunnex
table ip tunnex {
  chain tunnex_posture_owner {
    counter comment "tunnex_host_posture_v1"
  }
}
add table ip6 tunnex
flush table ip6 tunnex
table ip6 tunnex {
  chain tunnex_posture_owner {
    counter comment "tunnex_host_posture_v1"
  }
}
`

func TestStoppedRulesetLeavesNoDropPolicyAndClosesOnlyTheTunnel(t *testing.T) {
	got, err := hostPostureStoppedRuleset([]string{"wg0"})
	if err != nil {
		t.Fatal(err)
	}
	want := `flush table ip tunnex
add chain ip tunnex prerouting
delete chain ip tunnex prerouting
add chain ip tunnex postrouting
delete chain ip tunnex postrouting
add chain ip tunnex forward
delete chain ip tunnex forward
add chain ip tunnex input
delete chain ip tunnex input
add chain ip tunnex forward { type filter hook forward priority filter; policy accept; }
add rule ip tunnex forward iifname "wg0" counter drop comment "tunnex_stopped_tunnel_drop"
add rule ip tunnex forward oifname "wg0" counter drop comment "tunnex_stopped_tunnel_drop"
add chain ip tunnex input { type filter hook input priority filter; policy accept; }
add rule ip tunnex input iifname "wg0" counter drop comment "tunnex_stopped_tunnel_drop"
add chain ip tunnex tunnex_posture_owner
add rule ip tunnex tunnex_posture_owner counter comment "tunnex_host_posture_v1"
flush table ip6 tunnex
add chain ip6 tunnex prerouting
delete chain ip6 tunnex prerouting
add chain ip6 tunnex postrouting
delete chain ip6 tunnex postrouting
add chain ip6 tunnex forward
delete chain ip6 tunnex forward
add chain ip6 tunnex input
delete chain ip6 tunnex input
add chain ip6 tunnex forward { type filter hook forward priority filter; policy accept; }
add rule ip6 tunnex forward iifname "wg0" counter drop comment "tunnex_stopped_tunnel_drop"
add rule ip6 tunnex forward oifname "wg0" counter drop comment "tunnex_stopped_tunnel_drop"
add chain ip6 tunnex input { type filter hook input priority filter; policy accept; }
add rule ip6 tunnex input iifname "wg0" counter drop comment "tunnex_stopped_tunnel_drop"
add chain ip6 tunnex tunnex_posture_owner
add rule ip6 tunnex tunnex_posture_owner counter comment "tunnex_host_posture_v1"
`
	if got != want {
		t.Fatalf("stopped ruleset changed:\n%s", got)
	}
	// Each statement on its own: what the stop may and may not leave.
	for _, line := range strings.Split(strings.TrimSpace(got), "\n") {
		switch {
		case strings.HasPrefix(line, "add table"), strings.HasPrefix(line, "delete table"):
			t.Fatalf("the stop must neither recreate nor delete the manager's table: %q", line)
		case strings.Contains(line, "policy drop"):
			t.Fatalf("the stop leaves a drop policy: %q", line)
		case strings.Contains(line, " drop") && !strings.Contains(line, `ifname "wg0" counter drop`):
			t.Fatalf("a stop drop rule is not limited to the tunnel interface: %q", line)
		case strings.Contains(line, "hook") && !strings.Contains(line, "hook forward priority filter; policy accept;") && !strings.Contains(line, "hook input priority filter; policy accept;"):
			t.Fatalf("the stop leaves a hooked chain other than the tunnel guards: %q", line)
		case strings.HasPrefix(line, "add rule") && strings.Contains(line, " input ") && line != "add rule "+strings.Fields(line)[2]+` tunnex input iifname "wg0" counter drop comment "tunnex_stopped_tunnel_drop"`:
			t.Fatalf("the stopped input chain holds more than the tunnel drop (K8N-7): %q", line)
		}
	}
	for _, family := range []string{"ip", "ip6"} {
		if !strings.Contains(got, "flush table "+family+" tunnex\n") {
			t.Fatalf("%s: no flush", family)
		}
		if !strings.Contains(got, "add rule "+family+" tunnex tunnex_posture_owner counter comment \""+hostposture.NFTMarkerComment+"\"\n") {
			t.Fatalf("%s: the ownership marker is not written back", family)
		}
	}
}

func TestStoppedRulesetClosesTheOpenVPNTunnelToo(t *testing.T) {
	got, err := hostPostureStoppedRuleset([]string{"wg0", "tun0"})
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"ip", "ip6"} {
		for _, field := range []string{"iifname", "oifname"} {
			want := "add rule " + family + ` tunnex forward ` + field + ` { "wg0", "tun0" } counter drop comment "tunnex_stopped_tunnel_drop"` + "\n"
			if !strings.Contains(got, want) {
				t.Fatalf("missing %q in:\n%s", want, got)
			}
		}
		// K8N-7: the node stays closed to both tunnels after the stop.
		want := "add rule " + family + ` tunnex input iifname { "wg0", "tun0" } counter drop comment "tunnex_stopped_tunnel_drop"` + "\n"
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
}

func TestStoppedRulesetRefusesUnsafeInterfaceNames(t *testing.T) {
	for _, tun := range [][]string{nil, {""}, {"wg0", `x" accept #`}, {"wg0", "a b"}} {
		if got, err := hostPostureStoppedRuleset(tun); err == nil {
			t.Fatalf("interfaces %q rendered:\n%s", tun, got)
		}
	}
}

func TestKubernetesGatewayStopWithOpenVPNClosesBothTunnels(t *testing.T) {
	m := New("wg0")
	m.SetKubernetesMode(true)
	m.k8sNetPrep = &fakeK8sNetPrep{}
	m.SetOVPNTun("tun0")
	m.nftRun = func(_ context.Context, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), "tunnex_posture_owner") {
			return "table ip tunnex {\n chain tunnex_posture_owner { # handle 1\n  counter packets 0 bytes 0 comment \"tunnex_host_posture_v1\" # handle 2\n }\n}\n", nil
		}
		return "", errors.New("DOCKER-USER absent")
	}
	var applied string
	m.apply = func(_ context.Context, ruleset string) error { applied = ruleset; return nil }
	m.Teardown(t.Context())
	want, _ := hostPostureStoppedRuleset([]string{"wg0", "tun0"})
	if applied != want {
		t.Fatalf("stop with OpenVPN applied:\n%s\nwant:\n%s", applied, want)
	}
}
