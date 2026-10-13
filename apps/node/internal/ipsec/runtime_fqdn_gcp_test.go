package ipsec

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRuntimeFQDNGCPCardinalityAndFullGuard(t *testing.T) {
	for name, material := range map[string]RuntimeMaterial{"classic": classicMaterialFixture(), "ha": gcpMaterialFixture()} {
		t.Run(name, func(t *testing.T) {
			original, _, _ := fqdnRuntimeFixture(t)
			f := original.Policy.FQDNGrants[0]
			f.SelectedSiteID = material.Manifest.SiteID.String()
			f.SelectedGatewayID = material.Manifest.NodeID.String()
			f.ConnectionID = material.Manifest.ConnectionID.String()
			f.ConfigurationRevision = material.Manifest.ConfigurationRevision
			material.Policy.FQDNPolicyVersion = 1
			material.Policy.FQDNGrants = []RuntimeFQDNGrant{f}
			runtimeReseal(&material)
			entry, grants, err := runtimeMaterialEntry(material, material.Manifest.OrgID, material.Manifest.NodeID, "net:[4026531992]")
			if err != nil || len(grants) != 1 {
				t.Fatal("GCP provenance material", err)
			}
			count := 2
			if name == "classic" {
				count = 1
			}
			if entry.Allocation.activeTunnelCount() != count {
				t.Fatal("GCP cardinality changed")
			}
			input := guardFixture()
			input.OwnerID = material.Manifest.NodeID
			input.Connections[0].ID = material.Manifest.ConnectionID
			input.Connections[0].Grants = grants
			if name == "classic" {
				input.Connections[0].TunnelCount = 1
				input.Connections[0].Tunnels[1] = Ownership{}
				input.Connections[0].TunnelMTUs = nil
			}
			rendered, err := RenderGuard(input)
			if err != nil {
				t.Fatal(err)
			}
			if err = VerifyGuardReadback([]byte(rendered.ExpectedJSON), []byte(rendered.ExpectedJSON)); err != nil {
				t.Fatal("full production readback", err)
			}
			if !strings.Contains(rendered.NFT, "ct mark set") || !strings.Contains(rendered.NFT, "ct mark &") {
				t.Fatal("exact original/reply marks missing")
			}
			input.Connections[0].PermitFor = 0
			denied, err := RenderGuard(input)
			if err != nil || strings.Contains(denied.NFT, "counter accept") {
				t.Fatal("expired FQDN GCP lease allowed", err)
			}
		})
	}
}

func TestRuntimeFQDNLeaseSelectorRemainsSingle(t *testing.T) {
	for _, marked := range []bool{false, true} {
		input := guardFixture()
		if marked {
			_, g, _ := fqdnRuntimeFixture(t)
			input.OwnerID = g.FQDN.SelectedGatewayID
			input.Connections[0].ID = g.FQDN.ConnectionID
			input.Connections[0].Grants = []GuardGrant{g}
		}
		rendered, err := RenderGuard(input)
		if err != nil {
			t.Fatal(err)
		}
		var root struct {
			NFTables []map[string]json.RawMessage `json:"nftables"`
		}
		if json.Unmarshal([]byte(rendered.ExpectedJSON), &root) != nil {
			t.Fatal("guard json")
		}
		for _, raw := range root.NFTables {
			var rule struct {
				Expr []map[string]json.RawMessage `json:"expr"`
			}
			if json.Unmarshal(raw["rule"], &rule) != nil {
				continue
			}
			accepted := false
			selectors := 0
			for _, expr := range rule.Expr {
				if _, ok := expr["accept"]; ok {
					accepted = true
				}
				var match struct {
					Right any `json:"right"`
				}
				if json.Unmarshal(expr["match"], &match) == nil {
					if s, ok := match.Right.(string); ok && (strings.HasPrefix(s, "@lease_") || strings.HasPrefix(s, "@reply_lease_")) {
						selectors++
					}
				}
			}
			if accepted && selectors != 1 {
				t.Fatalf("marked=%t accept lease selector count=%d", marked, selectors)
			}
		}
	}
}

func TestRuntimeFQDNProducerConsumerClosedScopes(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		t.Run(protocol+"-zero-port", func(t *testing.T) {
			m, _, _ := fqdnRuntimeFixture(t)
			m.Policy.FQDNGrants[0].Protocol = protocol
			m.Policy.FQDNGrants[0].PortLow, m.Policy.FQDNGrants[0].PortHigh = 0, 0
			if _, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]"); err == nil {
				t.Fatal("zero transport port admitted")
			}
		})
	}
	t.Run("empty-suffix", func(t *testing.T) {
		m, _, _ := fqdnRuntimeFixture(t)
		m.Policy.FQDNGrants[0].ResolverMatchSuffix = ""
		if _, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]"); err == nil {
			t.Fatal("unbound suffix admitted")
		}
	})
}

func TestRuntimeFQDNShortLeaseChargesTransitAndExpires(t *testing.T) {
	a, now, identity := leaseFixture()
	request, err := a.Begin(identity)
	if err != nil {
		t.Fatal(err)
	}
	*now = time.Second
	if err = a.Accept(PermitLeaseResponse{PermitLeaseRequest: request, TTLMillis: 5000}); err != nil {
		t.Fatal(err)
	}
	remaining, err := a.RemainingForApply(identity, time.Second)
	if err != nil || remaining != 3*time.Second {
		t.Fatal("response transit extended answer authority", remaining, err)
	}
	*now = 5 * time.Second
	if _, err = a.RemainingForApply(identity, time.Millisecond); err == nil {
		t.Fatal("expired answer lease remained usable")
	}
	request, err = a.Begin(identity)
	if err != nil {
		t.Fatal(err)
	}
	*now += 500 * time.Millisecond
	if err = a.Accept(PermitLeaseResponse{PermitLeaseRequest: request, TTLMillis: 500}); err == nil {
		t.Fatal("late short-lease response extended authority")
	}
}
