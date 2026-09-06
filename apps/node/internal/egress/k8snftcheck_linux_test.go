//go:build linux

package egress

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// Explicit opt-in: unshare creates a fresh network namespace before any nft
// mutation. Failure to isolate or apply is a failure, never a silent skip.
func TestK8sDNATKernelPrinterRoundTrip(t *testing.T) {
	if os.Getenv("TUNNEX_TEST_NFT_ROUNDTRIP") != "1" {
		t.Skip("set TUNNEX_TEST_NFT_ROUNDTRIP=1 in an isolated Linux test container")
	}
	fixtures := []resolvedVIP{
		{vip: "100.96.0.3", proto: "tcp", svcPort: 8080, targets: []k8sTarget{{ip: "10.240.10.149", port: 8080}}},
		{vip: "100.96.0.4", proto: "tcp", svcPort: 8080, targets: []k8sTarget{{ip: "10.240.10.98", port: 8080}, {ip: "10.240.10.149", port: 8080}}},
	}
	m := New("wg0")
	m.resolvedVIPs.Store(&fixtures)
	var rendered, want []string
	for _, fixture := range fixtures {
		rendered = append(rendered, dnatRule(fixture))
	}
	for _, receipt := range m.RequestedK8sDNATReceipts() {
		want = append(want, receipt.Digest)
	}
	if len(want) != len(fixtures) {
		t.Fatalf("requested receipt count=%d want=%d", len(want), len(fixtures))
	}
	input := "table ip tunnex {\nchain prerouting {\ntype nat hook prerouting priority dstnat; policy accept;\n" + strings.Join(rendered, "\n") + "\n}\n}\n"
	cmd := exec.Command("unshare", "--net", "sh", "-c", "nft -f - && nft list table ip tunnex")
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated nft apply/list failed: %v\n%s", err, out)
	}
	got, err := parseK8sDNATReceipts(string(out))
	sort.Strings(want)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("kernel receipts=%v want=%v err=%v\n%s", got, want, err, out)
	}
	t.Logf("kernel apply/list/receipt proof:\n%s", out)
}

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
