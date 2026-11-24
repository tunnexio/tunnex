//go:build linux

package egress

import (
	"bytes"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// K8N-5 item 4. An in-cluster gateway on a site with `lan_egress = gateway_address`: a remote site host
// (10.50.0.5, behind the site link on wg0) reaches pod 10.70.0.9, whose node has no route back to the
// remote range. The gateway's own tunnel address is 100.65.0.2, as in the K8N-3 inputs.
const (
	siteLANTunnel = "100.65.0.2/32"
	siteLANRemote = "10.50.0.0/24"
	siteLANPod    = "10.70.0.9"
	siteLANRule   = `ip saddr 10.50.0.0/24 oifname != "wg0" masquerade comment "tunnex_site_lan_masquerade"`
)

func siteLANPolicy() *nodepolicy.Compiled {
	return &nodepolicy.Compiled{
		Version: 15, Mode: nodepolicy.ModeEnforcing,
		Allow: []nodepolicy.AllowEntry{
			{SrcIP: siteLANRemote, DstCIDR: siteLANPod + "/32", Protocol: "tcp", PortLow: 80, PortHigh: 80},
		},
		Routes:            []nodepolicy.Route{{DstCIDR: siteLANRemote}},
		SiteLANMasquerade: true,
	}
}

func siteLANManager() *Manager {
	m := New("wg0")
	m.localIPs = func() map[netip.Addr]struct{} { return nil }
	m.SetKubernetesMode(true)
	m.SetPolicy(siteLANPolicy())
	return m
}

func TestSiteLANMasqueradeRendersUnderTheMarkerTheOwnershipCheckAccepts(t *testing.T) {
	if k8snetprep.SiteLANMasqueradeRuleComment != "tunnex_site_lan_masquerade" {
		t.Fatalf("the marker changed: %q", k8snetprep.SiteLANMasqueradeRuleComment)
	}
	m := siteLANManager()
	assertNATChain(t, m.ruleset(siteLANTunnel), `ip saddr 100.65.0.2/32 oifname != "wg0" masquerade`, siteLANRule)
	m.SetOVPNTun("tun0")
	assertNATChain(t, m.ruleset(siteLANTunnel),
		`ip saddr 100.65.0.2/32 oifname != { "wg0", "tun0" } masquerade`,
		`ip saddr 10.50.0.0/24 oifname != { "wg0", "tun0" } masquerade comment "tunnex_site_lan_masquerade"`)
}

// The ownership check's fixture (k8snetprep/testdata/k8n5-site-lan.nft-ruleset.json) is what a real
// kernel listed after loading this renderer's output. If the NAT chain is rendered differently, the check
// must be proved against the new shape (TestSiteLANMasqueradeKernel regenerates both files).
func TestSiteLANRenderingIsTheOneTheOwnershipCheckWasProvedOn(t *testing.T) {
	captured, err := os.ReadFile("../k8snetprep/testdata/k8n5-site-lan.rendered.nft")
	if err != nil {
		t.Fatal(err)
	}
	got, want := natChain(t, siteLANManager().ruleset(siteLANTunnel)), natChain(t, string(captured))
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("ip tunnex postrouting is rendered as:\n%s\nthe ownership check was proved on a kernel that loaded:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestSiteLANRulesetIsValidNft(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	m := siteLANManager()
	for _, tun := range []string{"", "tun0"} {
		m.SetOVPNTun(tun)
		rs := m.ruleset(siteLANTunnel)
		cmd := exec.Command("nft", "-c", "-f", "-")
		cmd.Stdin = strings.NewReader(rs)
		if out, err := cmd.CombinedOutput(); err != nil {
			if strings.Contains(string(out), "Operation not permitted") || strings.Contains(string(out), "cache initialization") {
				t.Skipf("nft cannot init netlink here (needs NET_ADMIN):\n%s", out)
			}
			t.Fatalf("nft rejected the rendered ruleset (%v):\n%s\n--- RULESET ---\n%s", err, out, rs)
		}
	}
}

// K8N-5 item 4, (b): the IPsec desktop exemption is withheld in Kubernetes mode, with the reason logged
// once per change of the withheld set. Outside Kubernetes mode it is rendered exactly as before
// (TestDesktopNoSNATIsExactBeforeMasqueradeAndWithdraws).
func TestIPsecDesktopExemptionIsWithheldOnAnInClusterGateway(t *testing.T) {
	var logs bytes.Buffer
	m := New("wg0")
	m.log = slog.New(slog.NewTextHandler(&logs, nil))
	m.SetKubernetesMode(true)
	source := &ipsec.DesktopNATSource{}
	m.SetIPsecDesktopNATSource(source)
	baseline := m.rulesetWith("10.99.0.0/24", nil)
	id := uuid.New()
	source.Set(id, []ipsec.DesktopNATExemption{
		{Source: netip.MustParsePrefix("10.99.0.2/32"), Destination: netip.MustParsePrefix("10.180.0.0/16")},
	})
	for pass := 0; pass < 3; pass++ {
		if got := m.rulesetWith("10.99.0.0/24", nil); got != baseline {
			t.Fatalf("pass %d: the exemption changed the in-cluster ruleset:\n%s", pass, got)
		}
	}
	if n := strings.Count(logs.String(), "k8s_ipsec_desktop_nat_withheld"); n != 1 {
		t.Fatalf("the reason was logged %d times over three passes, want once:\n%s", n, logs.String())
	}
	if !strings.Contains(logs.String(), "IPsec is not supported on an in-cluster gateway") {
		t.Fatalf("the reason is not stated:\n%s", logs.String())
	}
	// A different withheld set is a change: logged again. Withdrawn: nothing to log.
	source.Set(id, []ipsec.DesktopNATExemption{
		{Source: netip.MustParsePrefix("10.99.0.3/32"), Destination: netip.MustParsePrefix("10.180.0.0/16")},
	})
	_ = m.rulesetWith("10.99.0.0/24", nil)
	source.Set(id, nil)
	_ = m.rulesetWith("10.99.0.0/24", nil)
	if n := strings.Count(logs.String(), "k8s_ipsec_desktop_nat_withheld"); n != 2 {
		t.Fatalf("logged %d times, want twice (one per non-empty change):\n%s", n, logs.String())
	}

	vm := New("wg0")
	vm.SetIPsecDesktopNATSource(source)
	source.Set(id, []ipsec.DesktopNATExemption{
		{Source: netip.MustParsePrefix("10.99.0.2/32"), Destination: netip.MustParsePrefix("10.180.0.0/16")},
	})
	if !strings.Contains(vm.rulesetWith("10.99.0.0/24", nil), "tunnex_ipsec_desktop_no_snat") {
		t.Fatal("a VM gateway must still render the exemption")
	}
}
