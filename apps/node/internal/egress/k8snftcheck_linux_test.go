//go:build linux

package egress

import (
	"context"
	"net/netip"
	"os/exec"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// TestRenderedRulesetIsValidNft (WF-K5 L11) proves the rendered ruleset is one `nft` ACCEPTS — the
// artifact-WORKS probe applied to the render itself, so the multi-endpoint jhash LB map + the `ct original`
// grant match + the DNAT syntax are proven valid here rather than deferred to the wire. Runs `nft -c -f -`
// (CHECK only — parses + semantically validates against a transaction, commits nothing, needs no privilege).
// Skips if nft is absent (the CI test-node image installs nftables).
func TestRenderedRulesetIsValidNft(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed — the render-valid probe needs nftables (CI installs it)")
	}
	m := New("wg0")
	m.localIPs = func() map[netip.Addr]struct{} { return nil }
	m.SetEndpointSource(&fakeSource{m: map[string]fakeEntry{
		"prod/api": {ok: true, targets: []k8sTarget{{ip: "10.42.0.14", port: 8080}}},                             // single → plain dnat to ip:port
		"prod/web": {ok: true, targets: []k8sTarget{{ip: "10.42.0.15", port: 80}, {ip: "10.42.0.16", port: 80}}}, // N → jhash LB map
	}})
	m.SetPolicy(&nodepolicy.Compiled{
		Version: 7, Mode: nodepolicy.ModeEnforcing,
		Allow: []nodepolicy.AllowEntry{ // exercises the `ct original ip daddr` grant match too
			{SrcIP: "10.99.0.10", DstCIDR: "10.0.5.0/24", Protocol: "tcp", PortLow: 5432, PortHigh: 5432},
		},
		VIPMappings: []nodepolicy.VIPMapping{
			{VIP: "100.64.0.5", Namespace: "prod", Service: "api", Protocol: "tcp", PortLow: 80, PortHigh: 80},
			{VIP: "100.64.0.6", Namespace: "prod", Service: "web", Protocol: "tcp", PortLow: 8080, PortHigh: 8080},
		},
	})
	m.ResolveK8sVIPs(context.Background())
	rs := m.ruleset("10.99.0.1/24")
	// Sanity: the shapes we care about are actually present (so a future refactor that drops them still
	// exercises nft on the real forms).
	for _, want := range []string{"dnat to 10.42.0.14:8080", "jhash ip saddr . ip daddr mod 2 map {", "ct original ip daddr"} {
		if !strings.Contains(rs, want) {
			t.Fatalf("ruleset missing %q (probe would not exercise it):\n%s", want, rs)
		}
	}
	cmd := exec.Command("nft", "-c", "-f", "-")
	cmd.Stdin = strings.NewReader(rs)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// `nft -c` opens netlink to init its cache even in check-only mode; without NET_ADMIN that fails with
		// "Operation not permitted" BEFORE any syntax check. That is an environment (capability) limit, not a
		// render defect — SKIP rather than false-fail. The Makefile test-node target adds --cap-add=NET_ADMIN
		// so CI actually runs the check; a capless local `go test` skips here.
		if strings.Contains(string(out), "Operation not permitted") || strings.Contains(string(out), "cache initialization") {
			t.Skipf("nft cannot init netlink here (needs NET_ADMIN) — render-valid check skipped:\n%s", out)
		}
		t.Fatalf("nft rejected the rendered ruleset (%v):\n%s\n--- RULESET ---\n%s", err, out, rs)
	}
}
