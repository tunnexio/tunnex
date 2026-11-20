//go:build linux

package egress

import (
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

const siteMasq = `ip saddr 10.70.0.0/24 oifname != "wg0" masquerade comment "tunnex_site_lan_masquerade"`

// TestSiteLANMasqueradeIsOptIn — SSI-8. Without the flag the ruleset is byte-identical to before: a site
// link preserves the remote source and TestSiteToSiteNotMasqueraded's invariant holds. With it, traffic
// from each remote site range is masqueraded as it leaves a non-tunnel interface.
func TestSiteLANMasqueradeIsOptIn(t *testing.T) {
	routes := []nodepolicy.Route{{DstCIDR: "10.70.0.0/24"}, {DstCIDR: "10.71.5.9/24"}, {DstCIDR: "10.70.0.0/24"}}
	off := New("wg0")
	off.SetPolicy(&nodepolicy.Compiled{Mode: nodepolicy.ModeEnforcing, Routes: routes})
	plain := off.ruleset("10.99.0.1/24")
	if strings.Contains(plain, "tunnex_site_lan_masquerade") {
		t.Fatalf("no flag, no site masquerade; got:\n%s", plain)
	}

	on := New("wg0")
	on.SetPolicy(&nodepolicy.Compiled{Mode: nodepolicy.ModeEnforcing, Routes: routes, SiteLANMasquerade: true})
	rs := on.ruleset("10.99.0.1/24")
	if !strings.Contains(rs, siteMasq) {
		t.Fatalf("the remote site range must be masqueraded out of non-tunnel interfaces; got:\n%s", rs)
	}
	// Host bits are masked and a repeated range renders once.
	if !strings.Contains(rs, `ip saddr 10.71.5.0/24 oifname != "wg0" masquerade`) {
		t.Fatalf("a range is rendered in canonical masked form; got:\n%s", rs)
	}
	if n := strings.Count(rs, "tunnex_site_lan_masquerade"); n != 2 {
		t.Fatalf("two distinct remote ranges render two rules, got %d", n)
	}
	// The flag adds lines and changes nothing else: removing them gives back the plain ruleset.
	stripped := rs
	for _, line := range strings.Split(rs, "\n") {
		if strings.Contains(line, "tunnex_site_lan_masquerade") {
			stripped = strings.Replace(stripped, line+"\n", "", 1)
		}
	}
	if stripped != plain {
		t.Fatal("the flag must only ADD masquerade lines; the rest of the ruleset changed")
	}
}

// TestSiteLANMasqueradeNeverTranslatesTransit — a hub forwards spoke-to-spoke traffic tunnel to tunnel. The
// rule is scoped `oifname != <tunnel set>`, so that traffic keeps its source and the destination gateway's
// own forward chain still adjudicates the original address.
func TestSiteLANMasqueradeNeverTranslatesTransit(t *testing.T) {
	m := New("wg0")
	m.SetPolicy(&nodepolicy.Compiled{Mode: nodepolicy.ModeEnforcing, Routes: []nodepolicy.Route{{DstCIDR: "10.70.0.0/24"}}, SiteLANMasquerade: true})
	for _, line := range strings.Split(m.ruleset("10.99.0.1/24"), "\n") {
		if strings.Contains(line, "tunnex_site_lan_masquerade") && !strings.Contains(line, `oifname != "wg0"`) {
			t.Fatalf("a site masquerade rule not scoped away from the tunnel would translate transit: %s", line)
		}
	}
}

// TestSiteLANMasqueradeNeedsRoutes — the flag alone renders nothing: with no remote range there is no
// remote-sourced traffic to translate, and nothing wider is ever emitted in its place.
func TestSiteLANMasqueradeNeedsRoutes(t *testing.T) {
	m := New("wg0")
	m.SetPolicy(&nodepolicy.Compiled{Mode: nodepolicy.ModeEnforcing, SiteLANMasquerade: true})
	if rs := m.ruleset("10.99.0.1/24"); strings.Contains(rs, "tunnex_site_lan_masquerade") {
		t.Fatalf("no remote range, no rule; got:\n%s", rs)
	}
}
