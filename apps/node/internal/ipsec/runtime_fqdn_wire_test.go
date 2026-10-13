package ipsec

import (
	"bytes"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

func TestRuntimeFQDNConsumesActualCompilerWire(t *testing.T) {
	path := os.Getenv("TUNNEX_FQDN_TEST_WIRE_PATH")
	if path == "" {
		t.Skip("run paired compiler-to-node qualification")
	}
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 65536 {
		t.Fatal("missing or unbounded compiler fixture")
	}
	var wire struct {
		Policy                              RuntimePolicy       `json:"policy"`
		Compiled                            nodepolicy.Compiled `json:"compiled"`
		CanonicalHash                       string              `json:"canonical_hash"`
		OrgID, NodeID, SiteID, ConnectionID uuid.UUID
		Local, Remote                       []string
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&wire); err != nil {
		t.Fatal(err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		t.Fatal("trailing compiler fixture")
	}
	m := RuntimeMaterial{RuntimeDelivery: RuntimeDelivery{Manifest: RuntimeManifest{OrgID: wire.OrgID, NodeID: wire.NodeID, SiteID: wire.SiteID, ConnectionID: wire.ConnectionID, ConfigurationRevision: 1}}, Policy: wire.Policy}
	parse := func(raw []string) []netip.Prefix {
		out := make([]netip.Prefix, len(raw))
		for i, s := range raw {
			out[i] = netip.MustParsePrefix(s)
		}
		return out
	}
	g, err := runtimeFQDNGrants(m, parse(wire.Local), parse(wire.Remote))
	if err != nil || len(g) != 1 || g[0].Destination.String() != "10.85.1.10/32" || g[0].Source.String() != "10.84.2.10/32" || g[0].FQDN.ConnectionID != wire.ConnectionID || g[0].FQDN.SelectedGatewayID != wire.NodeID || !g[0].FQDNManaged {
		t.Fatal("actual compiler scope/provenance did not survive node wire", err)
	}
	if len(m.Policy.Grants) != 1 || m.Policy.Grants[0].Destination != "10.85.1.20/32" {
		t.Fatal("ordinary grant changed")
	}
	if nodepolicy.CanonicalHash(&wire.Compiled) != wire.CanonicalHash {
		t.Fatal("canonical API/node hash changed")
	}
	s := &RuntimeFQDNPolicySource{}
	if s.view.Load().matches(g[0]) {
		t.Fatal("uncommitted compiler wire granted")
	}
	s.CommittedPolicy(&wire.Compiled)
	if !s.view.Load().matches(g[0]) {
		t.Fatal("actual compiled canonical host prefix refused")
	}
	for _, answer := range []string{"10.85.1.10", "10.85.1.0/24", "2001:db8::1/128", "10.85.1.11/32"} {
		wire.Compiled.FQDNGenerations[0].Answers[0] = answer
		s.CommittedPolicy(&wire.Compiled)
		if s.view.Load().matches(g[0]) {
			t.Fatalf("noncanonical or different answer %q granted", answer)
		}
	}
	for _, destination := range []string{"10.85.1.10", "10.85.1.0/24", "2001:db8::1/128", "10.86.1.10/32"} {
		m.Policy.FQDNGrants[0].Destination = destination
		if _, err := runtimeFQDNGrants(m, parse(wire.Local), parse(wire.Remote)); err == nil {
			t.Fatalf("invalid or unapproved destination %q accepted", destination)
		}
	}
}

func TestRuntimeFQDNCommittedAnswerRequiresCanonicalCompilerPrefix(t *testing.T) {
	_, g, p := fqdnRuntimeFixture(t)
	s := &RuntimeFQDNPolicySource{}
	s.CommittedPolicy(p)
	if !s.view.Load().matches(g) {
		t.Fatal("canonical compiler host prefix refused")
	}
	p.FQDNGenerations[0].Answers[0] = g.Destination.Addr().String()
	s.CommittedPolicy(p)
	if s.view.Load().matches(g) {
		t.Fatal("bare answer alias accepted as committed compiler authority")
	}
}
