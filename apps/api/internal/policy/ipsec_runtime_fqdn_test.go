package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdnresolver"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

func runtimeFQDNFixture(t *testing.T) (Snapshot, ipsec.RuntimePolicyInput) {
	t.Helper()
	org, site, node, conn, resource, config, profile, ordinary := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	input := ipsec.RuntimePolicyInput{OrgID: org, SiteID: site, NodeID: node, ConnectionID: conn, ConfigurationRevision: 1, FQDNPolicyVersion: 1, Config: ipsec.StaticConfig{LocalPrefixes: []string{"10.84.2.0/24"}, RemotePrefixes: []string{"10.85.0.0/16"}}}
	port := int32(8081)
	generation := fqdnresolver.ActiveGeneration{OrgID: org, ResourceID: resource, Hostname: "app.corp.example", Protocol: "tcp", PortLow: &port, PortHigh: &port, Context: fqdnresolver.Context{ResolverID: site.String(), GatewayID: node.String()}, ResolverConfig: fqdnresolver.ResolverConfig{ID: config.String(), Version: 3, ProfileID: profile.String(), MatchedSuffix: "corp.example", IPsecPath: &fqdnresolver.ResolverIPsecPath{ConnectionID: conn.String(), ConfigurationRevision: 1, SourceAddress: "10.84.2.254"}, Endpoints: []fqdnresolver.ResolverEndpoint{{Address: netip.MustParseAddr("10.85.0.53"), Port: 53, Transport: "udp"}}}, Addresses: []netip.Addr{netip.MustParseAddr("10.85.1.10")}}
	fqdnResource, err := fqdnResourceFromActiveGeneration(generation, []netip.Prefix{netip.MustParsePrefix("10.85.0.0/16")})
	if err != nil {
		t.Fatal(err)
	}
	rule := uuid.New()
	return Snapshot{Mode: ModeEnforcing, FQDNResourcesLicensed: true, FQDNResourcesEnabled: true, SiteNodes: []SiteNode{{SiteID: site, NodeID: node}}, SiteSubnets: []SiteSubnet{{SiteID: site, CIDR: "10.84.2.0/24"}}, FQDNResources: []FQDNResource{fqdnResource}, FQDNRuleReferences: []FQDNRuleReference{{PolicyRuleID: rule, FQDNResourceID: resource}}, Resources: []Resource{{ID: ordinary, CIDR: "10.85.1.20/32", Protocol: "tcp", PortLow: 443, PortHigh: 443}}, Rules: []Rule{{ID: rule, SrcKind: "cidr", SrcCIDR: "10.84.2.10/32", DstKind: "fqdn_resource"}, {ID: uuid.New(), SrcKind: "site", SrcSiteID: site, DstKind: "resource", DstResourceID: ordinary}}}, input
}

func TestIPsecFQDNRuntimeCurrentExactOutboundProvenance(t *testing.T) {
	snapshot, input := runtimeFQDNFixture(t)
	result, err := compileIPsecRuntimePolicy(snapshot, input)
	if err != nil || len(result.FQDNGrants) != 1 || result.FQDNPolicyVersion != 1 {
		t.Fatalf("active FQDN not lowered: %+v %v", result, err)
	}
	if len(result.Grants) != 1 || result.Grants[0].Destination != "10.85.1.20/32" {
		t.Fatalf("answer/resolver copied into ordinary grants: %+v", result.Grants)
	}
	g := result.FQDNGrants[0]
	resource := snapshot.FQDNResources[0]
	expected, _, _, _ := activeFQDNGeneration(resource)
	if !g.FQDNManaged || g.Source != "10.84.2.10/32" || g.Destination != "10.85.1.10/32" || g.Protocol != "tcp" || g.PortLow != 8081 || g.PortHigh != 8081 || g.RuleID != snapshot.Rules[0].ID.String() || g.Name != expected.Name || g.Generation != expected.Generation || g.ResourceID != resource.ID.String() || g.ResolverConfigID != resource.Active.ResolverConfigID.String() || g.ResolverConfigVersion != 3 || g.ResolverProfileID != resource.Active.ResolverProfileID.String() || g.ResolverMatchSuffix != "corp.example" || g.SelectedSiteID != input.SiteID.String() || g.SelectedGatewayID != input.NodeID.String() || g.ConnectionID != input.ConnectionID.String() || g.ConfigurationRevision != 1 {
		t.Fatalf("provenance or tuple widened/lost: %+v", g)
	}
	raw, _ := json.Marshal(result)
	var wire map[string]json.RawMessage
	if json.Unmarshal(raw, &wire) != nil || len(wire["fqdn_grants"]) == 0 {
		t.Fatal("additive typed field missing")
	}
	snapshot.Rules[0].SrcKind = "site"
	snapshot.Rules[0].SrcSiteID = input.SiteID
	site, err := compileIPsecRuntimePolicy(snapshot, input)
	if err != nil || len(site.FQDNGrants) != 1 || site.FQDNGrants[0].Source != "10.84.2.0/24" {
		t.Fatal("exact local Site grant lost", err)
	}
}

func TestIPsecFQDNRuntimeRefusesUnsupportedAndForeignScope(t *testing.T) {
	cases := map[string]func(*Snapshot, *ipsec.RuntimePolicyInput){
		"missing capability": func(_ *Snapshot, in *ipsec.RuntimePolicyInput) { in.FQDNPolicyVersion = 0 },
		"unknown capability": func(_ *Snapshot, in *ipsec.RuntimePolicyInput) { in.FQDNPolicyVersion = 2 },
		"unlicensed":         func(s *Snapshot, _ *ipsec.RuntimePolicyInput) { s.FQDNResourcesLicensed = false },
		"opt out":            func(s *Snapshot, _ *ipsec.RuntimePolicyInput) { s.FQDNResourcesEnabled = false },
		"foreign Site":       func(s *Snapshot, _ *ipsec.RuntimePolicyInput) { s.FQDNResources[0].Active.SelectedSiteID = uuid.New() },
		"foreign gateway": func(s *Snapshot, _ *ipsec.RuntimePolicyInput) {
			s.FQDNResources[0].Active.SelectedGatewayID = uuid.New()
		},
		"foreign connection": func(s *Snapshot, _ *ipsec.RuntimePolicyInput) {
			s.FQDNResources[0].Active.IPsecConnectionID = uuid.New()
		},
		"stale IPsec revision": func(s *Snapshot, _ *ipsec.RuntimePolicyInput) {
			s.FQDNResources[0].Active.IPsecConfigurationRevision = 2
		},
		"invalid active config revision": func(s *Snapshot, _ *ipsec.RuntimePolicyInput) { s.FQDNResources[0].Active.ResolverConfigVersion = 0 },
		"missing active profile":         func(s *Snapshot, _ *ipsec.RuntimePolicyInput) { s.FQDNResources[0].Active.ResolverProfileID = uuid.Nil },
		"outside local WG CIDR":          func(s *Snapshot, _ *ipsec.RuntimePolicyInput) { s.Rules[0].SrcCIDR = "10.99.0.2/32" },
		"WG user source": func(s *Snapshot, _ *ipsec.RuntimePolicyInput) {
			s.Rules[0].SrcKind = "user"
			s.Rules[0].SrcUserID = uuid.New()
		},
		"foreign source Site": func(s *Snapshot, _ *ipsec.RuntimePolicyInput) {
			s.Rules[0].SrcKind = "site"
			s.Rules[0].SrcSiteID = uuid.New()
		},
		"broader local source": func(s *Snapshot, _ *ipsec.RuntimePolicyInput) { s.Rules[0].SrcCIDR = "10.84.0.0/16" },
		"outside remote": func(s *Snapshot, _ *ipsec.RuntimePolicyInput) {
			s.FQDNResources[0].Active.Answers = []string{"10.86.1.10"}
		},
		"IPv6 answer": func(s *Snapshot, _ *ipsec.RuntimePolicyInput) {
			s.FQDNResources[0].Active.Answers = []string{"2606:4700:4700::1111"}
		},
		"protected metadata": func(s *Snapshot, in *ipsec.RuntimePolicyInput) {
			s.FQDNResources[0].Active.Answers = []string{"169.254.169.254"}
			in.Config.RemotePrefixes = []string{"169.254.0.0/16"}
		},
		"protected loopback": func(s *Snapshot, in *ipsec.RuntimePolicyInput) {
			s.FQDNResources[0].Active.Answers = []string{"127.0.0.1"}
			in.Config.RemotePrefixes = []string{"127.0.0.0/8"}
		},
		"documentation answer": func(s *Snapshot, in *ipsec.RuntimePolicyInput) {
			s.FQDNResources[0].Active.Answers = []string{"192.0.2.2"}
			in.Config.RemotePrefixes = []string{"192.0.2.0/24"}
		},
		"no current active generation": func(s *Snapshot, _ *ipsec.RuntimePolicyInput) { s.FQDNResources[0].Active = nil },
		"disabled rule":                func(s *Snapshot, _ *ipsec.RuntimePolicyInput) { s.Rules[0].Disabled = true },
		"removed rule":                 func(s *Snapshot, _ *ipsec.RuntimePolicyInput) { s.Rules = s.Rules[1:] },
		"missing reference":            func(s *Snapshot, _ *ipsec.RuntimePolicyInput) { s.FQDNRuleReferences = nil },
		"ambiguous reference": func(s *Snapshot, _ *ipsec.RuntimePolicyInput) {
			s.FQDNRuleReferences = append(s.FQDNRuleReferences, s.FQDNRuleReferences[0])
		},
		"outside local resolver source": func(s *Snapshot, _ *ipsec.RuntimePolicyInput) {
			s.FQDNResources[0].Active.IPsecSourceAddress = "10.99.0.2"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			snapshot, input := runtimeFQDNFixture(t)
			mutate(&snapshot, &input)
			result, err := compileIPsecRuntimePolicy(snapshot, input)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.FQDNGrants) != 0 || result.FQDNPolicyVersion != 0 {
				t.Fatalf("refused scope minted FQDN authority: %+v", result)
			}
		})
	}
}

func TestIPsecFQDNRuntimeGenerationChangeAndOrdinaryHashPreserved(t *testing.T) {
	snapshot, input := runtimeFQDNFixture(t)
	before, err := compileIPsecRuntimePolicy(snapshot, input)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Snapshot){func(s *Snapshot) { s.FQDNResources[0].Active.Answers = []string{"10.85.1.11"} }, func(s *Snapshot) { s.FQDNResources[0].Active.ResolverConfigID = uuid.New() }, func(s *Snapshot) { s.FQDNResources[0].Active.ResolverConfigVersion++ }, func(s *Snapshot) { s.FQDNResources[0].Active.ResolverProfileID = uuid.New() }} {
		s, in := runtimeFQDNFixture(t)
		// Preserve exact IDs so changes cannot be attributed to a new fixture.
		s = snapshot
		copyResource := snapshot.FQDNResources[0]
		copyActive := *copyResource.Active
		copyResource.Active = &copyActive
		s.FQDNResources = []FQDNResource{copyResource}
		in = input
		change(&s)
		after, err := compileIPsecRuntimePolicy(s, in)
		if err != nil || len(after.FQDNGrants) != 1 || after.Hash == before.Hash || after.FQDNGrants[0].Generation == before.FQDNGrants[0].Generation {
			t.Fatal("current generation change not hash significant", err)
		}
		if !reflect.DeepEqual(before.Grants, after.Grants) {
			t.Fatal("FQDN provenance altered ordinary grants")
		}
	}
	snapshot.FQDNResourcesLicensed = false
	ordinary, err := compileIPsecRuntimePolicy(snapshot, input)
	if err != nil {
		t.Fatal(err)
	}
	oldRaw, _ := json.Marshal(struct {
		Org, Node, Site, Connection uuid.UUID
		Grants                      []ipsec.RuntimeGrant
		DNSResolverGrants           []ipsec.RuntimeDNSResolverGrant `json:"dns_resolver_grants,omitempty"`
		DNSResolverProfiles         []policyspec.DNSResolverProfile `json:"dns_resolver_profiles,omitempty"`
	}{input.OrgID, input.NodeID, input.SiteID, input.ConnectionID, ordinary.Grants, ordinary.DNSResolverGrants, ordinary.DNSResolverProfiles})
	digest := sha256.Sum256(oldRaw)
	if ordinary.Hash != hex.EncodeToString(digest[:]) {
		t.Fatal("legacy ordinary hash changed")
	}
	wire, _ := json.Marshal(ordinary)
	if strings.Contains(string(wire), "fqdn_") {
		t.Fatal("empty FQDN policy fields not omitted")
	}
}

type runtimeFQDNFailQuery struct {
	sqlc.DBTX
	calls int
}

func (q *runtimeFQDNFailQuery) Query(context.Context, string, ...any) (pgx.Rows, error) {
	q.calls++
	return nil, errors.New("transaction query refused")
}
func TestIPsecFQDNRuntimeUsesTransactionReaderAndEntitlement(t *testing.T) {
	for _, c := range []struct {
		name                      string
		cap                       int
		licensed, enabled, reader bool
		calls                     int
		refused                   bool
	}{{"missing reader", 1, true, true, false, 0, false}, {"low capability", 0, true, true, true, 0, false}, {"unknown capability", 3, true, true, true, 0, false}, {"unlicensed", 1, false, true, true, 0, false}, {"optout", 1, true, false, true, 0, false}, {"current Tx query failure", 1, true, true, true, 1, true}} {
		t.Run(c.name, func(t *testing.T) {
			query := &runtimeFQDNFailQuery{}
			s := Snapshot{FQDNResourcesEnabled: c.enabled}
			in := ipsec.RuntimePolicyInput{OrgID: uuid.New(), FQDNPolicyVersion: c.cap}
			if c.reader {
				in.Transaction = query
			}
			err := appendRuntimeFQDNGenerations(context.Background(), &s, in, c.licensed)
			if (err != nil) != c.refused || query.calls != c.calls || len(s.FQDNResources) != 0 {
				t.Fatalf("reader/entitlement bypass calls=%d err=%v", query.calls, err)
			}
		})
	}
}
