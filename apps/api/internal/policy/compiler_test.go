package policy_test

import (
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

// Fixed IDs so tests read clearly and output is stable.
var (
	nodeA = uuid.MustParse("00000000-0000-0000-0000-0000000000a1")
	nodeB = uuid.MustParse("00000000-0000-0000-0000-0000000000b1")

	uAlice = uuid.MustParse("00000000-0000-0000-0000-00000000a11c")
	uBob   = uuid.MustParse("00000000-0000-0000-0000-00000000b0b0")
	uCarol = uuid.MustParse("00000000-0000-0000-0000-0000000ca401")

	gAdmins  = uuid.MustParse("00000000-0000-0000-0000-00000000ad00")
	gServers = uuid.MustParse("00000000-0000-0000-0000-0000005e4e40")

	rDB = uuid.MustParse("00000000-0000-0000-0000-0000000db000")
)

// allowsFor returns node A's allow entries (nil if the node is absent).
func allowsFor(m map[uuid.UUID]policyspec.Compiled, n uuid.UUID) []policyspec.AllowEntry {
	return m[n].Allow
}

func hasAllow(entries []policyspec.AllowEntry, src, dst string) bool {
	for _, e := range entries {
		if e.SrcIP == src && e.DstCIDR == dst {
			return true
		}
	}
	return false
}

func activeFQDN(resourceID, siteID, gatewayID, configID uuid.UUID, answers ...string) *policy.FQDNGeneration {
	return &policy.FQDNGeneration{
		ResourceID: resourceID, SelectedSiteID: siteID, SelectedGatewayID: gatewayID,
		ResolverConfigID: configID, ResolverProfileID: configID, ResolverMatchSuffix: "example.com", ResolverConfigVersion: 1,
		Answers: answers, ResolverAddresses: []string{"10.53.0.53/32"},
	}
}

// B1 (deliberate-red): enforcing + ZERO grants proves the BASE, not a rule —
// the compiled allow-set is EMPTY, and empty must not read as permissive
// (Mesh=false). If this ever compiles to a non-empty or mesh output, default-deny
// is broken.
func TestEnforcingZeroGrantsIsEmptyNotPermissive(t *testing.T) {
	agentID := uuid.New()
	revision := int64(9)
	snap := policy.Snapshot{
		Mode: policy.ModeEnforcing,
		Devices: []policy.Device{
			{ID: uuid.New(), UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10", Kind: "human"},
			{ID: agentID, UserID: uBob, NodeID: nodeA, AssignedIP: "10.99.0.11", Kind: "agent", ConfigRevision: &revision},
		},
		// no groups, no memberships, no rules
	}
	out := policy.Compile(snap)
	c, ok := out[nodeA]
	if !ok {
		t.Fatal("node with active devices must appear in output even under deny-all")
	}
	if c.Mesh {
		t.Fatal("enforcing mode must NEVER set Mesh=true (that is the blanket mesh)")
	}
	if len(c.Allow) != 0 {
		t.Fatalf("zero grants must compile to an EMPTY allow-set, got %d entries: %+v", len(c.Allow), c.Allow)
	}
	if c.Mode != policy.ModeEnforcing {
		t.Fatalf("mode = %q, want enforcing", c.Mode)
	}
	if len(c.Subjects) != 2 {
		t.Fatalf("deny-all artifact must retain every active subject, got %+v", c.Subjects)
	}
	if got := c.Subjects[1]; got.DeviceID != agentID.String() || got.Kind != "agent" || got.ConfigRevision == nil || *got.ConfigRevision != revision {
		t.Fatalf("agent subject attribution missing from zero-grant artifact: %+v", got)
	}
}

func TestSubjectAttributionIsHashBlind(t *testing.T) {
	base := policyspec.Compiled{Version: 1, Mode: policy.ModeEnforcing}
	with := base
	with.Subjects = []policyspec.SubjectAttribution{{SrcIP: "10.99.0.9", DeviceID: uuid.NewString(), Kind: "agent"}}
	if policyspec.CanonicalHash(base) != policyspec.CanonicalHash(with) {
		t.Fatal("subject attribution must not perturb the enforcement hash")
	}
}

func TestFQDNResourceExpandsActiveGenerationWithExactL4Scope(t *testing.T) {
	resourceID := uuid.New()
	ruleID := uuid.New()
	siteID, gatewayID, configID := uuid.New(), uuid.New(), uuid.New()
	snap := policy.Snapshot{
		Mode: policy.ModeEnforcing, FQDNResourcesLicensed: true, FQDNResourcesEnabled: true,
		Devices:     []policy.Device{{ID: uuid.New(), UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"}},
		Memberships: []policy.Membership{{GroupID: gAdmins, UserID: uAlice}},
		FQDNResources: []policy.FQDNResource{{ID: resourceID, FQDN: "api.example.com", Protocol: "tcp", PortLow: 443, PortHigh: 443,
			Active: activeFQDN(resourceID, siteID, gatewayID, configID, "2001:4860:4860::8888", "8.8.8.8", "8.8.8.8")}},
		FQDNRuleReferences: []policy.FQDNRuleReference{{PolicyRuleID: ruleID, FQDNResourceID: resourceID}},
		Rules:              []policy.Rule{{ID: ruleID, SrcGroupID: gAdmins, DstKind: "fqdn_resource"}},
		SiteNodes:          []policy.SiteNode{{SiteID: siteID, NodeID: gatewayID}},
		SiteSubnets:        []policy.SiteSubnet{{SiteID: siteID, CIDR: "10.53.0.0/24"}},
	}
	c := policy.Compile(snap)[nodeA]
	if c.Mesh || c.Version != 9 {
		t.Fatalf("FQDN artifact must be enforcing v9, got mesh=%v version=%d", c.Mesh, c.Version)
	}
	if len(c.Allow) != 4 || !hasAllow(c.Allow, "10.99.0.10", "8.8.8.8/32") || !hasAllow(c.Allow, "10.99.0.10", "2001:4860:4860::8888/128") {
		t.Fatalf("active answers must expand to exact hosts, got %+v", c.Allow)
	}
	for _, allow := range c.Allow {
		if allow.RuleID != ruleID.String() {
			t.Fatalf("derived tuple lost parent provenance: %+v", allow)
		}
		if allow.DstCIDR == "10.53.0.53/32" {
			if allow.FQDNManaged || (allow.Protocol != policyspec.ProtoUDP && allow.Protocol != policyspec.ProtoTCP) || allow.PortLow != 53 || allow.PortHigh != 53 {
				t.Fatalf("resolver tuple lost standard DNS scope: %+v", allow)
			}
		} else if !allow.FQDNManaged || allow.Protocol != policyspec.ProtoTCP || allow.PortLow != 443 || allow.PortHigh != 443 {
			t.Fatalf("answer lost resource L4 scope: %+v", allow)
		}
	}
	wantIdentity := policy.FQDNGenerationIdentityWithResolverConfig(resourceID, "api.example.com", siteID, gatewayID, configID, configID, "example.com", 1, []string{"2001:4860:4860::8888", "8.8.8.8"})
	if got := c.FQDNGenerations; len(got) != 1 || got[0].Generation != wantIdentity || !reflect.DeepEqual(got[0].Answers, []string{"2001:4860:4860::8888/128", "8.8.8.8/32"}) {
		t.Fatalf("generation identity must be canonical and present in artifact: %+v", got)
	}
}

func TestFQDNProvenanceSurvivesOrdinaryTupleDeduplication(t *testing.T) {
	resourceID, ruleID, ordinaryRuleID := uuid.New(), uuid.New(), uuid.New()
	siteID, gatewayID, configID := uuid.New(), uuid.New(), uuid.New()
	snap := policy.Snapshot{
		Mode: policy.ModeEnforcing, FQDNResourcesLicensed: true, FQDNResourcesEnabled: true,
		Devices:     []policy.Device{{ID: uuid.New(), UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"}},
		Memberships: []policy.Membership{{GroupID: gAdmins, UserID: uAlice}},
		Resources:   []policy.Resource{{ID: uuid.New(), CIDR: "8.8.8.8/32", Protocol: "tcp", PortLow: 443, PortHigh: 443}},
		FQDNResources: []policy.FQDNResource{{ID: resourceID, FQDN: "api.example.com", Protocol: "tcp", PortLow: 443, PortHigh: 443,
			Active: activeFQDN(resourceID, siteID, gatewayID, configID, "8.8.8.8")}},
		Rules: []policy.Rule{
			{ID: ordinaryRuleID, SrcGroupID: gAdmins, DstKind: "resource"},
			{ID: ruleID, SrcGroupID: gAdmins, DstKind: "fqdn_resource"},
		},
		FQDNRuleReferences: []policy.FQDNRuleReference{{PolicyRuleID: ruleID, FQDNResourceID: resourceID}},
		SiteNodes:          []policy.SiteNode{{SiteID: siteID, NodeID: gatewayID}},
		SiteSubnets:        []policy.SiteSubnet{{SiteID: siteID, CIDR: "10.53.0.0/24"}},
	}
	snap.Rules[0].DstResourceID = snap.Resources[0].ID
	compiled := policy.Compile(snap)[nodeA]
	if len(compiled.Allow) != 3 || compiled.Version != 9 {
		t.Fatalf("shared ordinary/FQDN tuple must retain FQDN ownership provenance: %+v", compiled)
	}
	for _, allow := range compiled.Allow {
		if allow.RuleID != ruleID.String() {
			t.Fatalf("FQDN parent must own deduplicated derived provenance: %+v", allow)
		}
		if allow.DstCIDR == "8.8.8.8/32" && !allow.FQDNManaged {
			t.Fatalf("concrete answer must retain S21 ownership: %+v", allow)
		}
		if allow.DstCIDR == "10.53.0.53/32" && allow.FQDNManaged {
			t.Fatalf("resolver carriage is ordinary policy, not answer-owned conntrack state: %+v", allow)
		}
	}
}

func TestFQDNResolverCarriageDeduplicatesManualRulesAndCleansUp(t *testing.T) {
	resourceID, parentRuleID := uuid.New(), uuid.New()
	udpResourceID, tcpResourceID := uuid.New(), uuid.New()
	udpRuleID, tcpRuleID := uuid.New(), uuid.New()
	siteID, gatewayID, configID := uuid.New(), uuid.New(), uuid.New()
	base := policy.Snapshot{
		Mode: policy.ModeEnforcing, FQDNResourcesLicensed: true, FQDNResourcesEnabled: true,
		Devices:     []policy.Device{{ID: uuid.New(), UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"}},
		Memberships: []policy.Membership{{GroupID: gAdmins, UserID: uAlice}},
		Resources: []policy.Resource{
			{ID: udpResourceID, CIDR: "10.53.0.53/32", Protocol: "udp", PortLow: 53, PortHigh: 53},
			{ID: tcpResourceID, CIDR: "10.53.0.53/32", Protocol: "tcp", PortLow: 53, PortHigh: 53},
		},
		FQDNResources: []policy.FQDNResource{{ID: resourceID, FQDN: "api.example.com", Protocol: "tcp", PortLow: 443, PortHigh: 443,
			Active: activeFQDN(resourceID, siteID, gatewayID, configID, "8.8.8.8")}},
		Rules: []policy.Rule{
			{ID: udpRuleID, SrcGroupID: gAdmins, DstKind: "resource", DstResourceID: udpResourceID},
			{ID: tcpRuleID, SrcGroupID: gAdmins, DstKind: "resource", DstResourceID: tcpResourceID},
			{ID: parentRuleID, SrcGroupID: gAdmins, DstKind: "fqdn_resource"},
		},
		FQDNRuleReferences: []policy.FQDNRuleReference{{PolicyRuleID: parentRuleID, FQDNResourceID: resourceID}},
		SiteNodes:          []policy.SiteNode{{SiteID: siteID, NodeID: gatewayID}},
		// Routed reachability is deliberately owned by an unbound site so the
		// explicit manual resources remain source-edge-only. The selected gateway
		// therefore receives DNS tuples solely from the FQDN parent.
		SiteSubnets: []policy.SiteSubnet{{SiteID: uuid.New(), CIDR: "10.53.0.0/24"}},
	}

	active := policy.Compile(base)
	for _, node := range []uuid.UUID{nodeA, gatewayID} {
		artifact := active[node]
		if len(artifact.Allow) != 3 || len(artifact.FQDNGenerations) != 1 {
			t.Fatalf("node %s: active parent must emit one answer plus deduped DNS transports: %+v", node, artifact)
		}
		for _, allow := range artifact.Allow {
			if allow.DstCIDR == "10.53.0.53/32" {
				if allow.FQDNManaged || allow.RuleID != parentRuleID.String() {
					t.Fatalf("node %s: resolver carriage must cite parent without S21 ownership: %+v", node, allow)
				}
			}
		}
	}

	assertManualOnly := func(t *testing.T, snapshot policy.Snapshot) {
		t.Helper()
		compiled := policy.Compile(snapshot)
		atSource := compiled[nodeA]
		if len(atSource.Allow) != 2 || len(atSource.FQDNGenerations) != 0 || atSource.Version == 9 {
			t.Fatalf("source must retain only explicit manual DNS grants: %+v", atSource)
		}
		wantRule := map[policyspec.Protocol]string{policyspec.ProtoUDP: udpRuleID.String(), policyspec.ProtoTCP: tcpRuleID.String()}
		for _, allow := range atSource.Allow {
			if allow.DstCIDR != "10.53.0.53/32" || allow.FQDNManaged || allow.RuleID != wantRule[allow.Protocol] {
				t.Fatalf("manual provenance was not restored after parent cleanup: %+v", allow)
			}
		}
		if atGateway := compiled[gatewayID]; len(atGateway.Allow) != 0 || len(atGateway.FQDNGenerations) != 0 {
			t.Fatalf("selected gateway must lose all parent-derived state: %+v", atGateway)
		}
	}

	disabled := base
	disabled.Rules = append([]policy.Rule(nil), base.Rules...)
	disabled.Rules[2].Disabled = true
	assertManualOnly(t, disabled)

	withdrawn := base
	withdrawn.FQDNResources = append([]policy.FQDNResource(nil), base.FQDNResources...)
	withdrawn.FQDNResources[0].Active = nil
	assertManualOnly(t, withdrawn)
}

func TestFQDNSelectedGatewayPlacementUsesExactSiteMembership(t *testing.T) {
	resourceID, ruleID := uuid.New(), uuid.New()
	siteID, selectedGateway, otherGateway, hub, configID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	snapshot := policy.Snapshot{
		Mode: policy.ModeEnforcing, FQDNResourcesLicensed: true, FQDNResourcesEnabled: true,
		Devices:     []policy.Device{{ID: uuid.New(), UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"}},
		Memberships: []policy.Membership{{GroupID: gAdmins, UserID: uAlice}},
		FQDNResources: []policy.FQDNResource{{ID: resourceID, FQDN: "api.example.com", Protocol: "tcp", PortLow: 443, PortHigh: 443,
			Active: activeFQDN(resourceID, siteID, selectedGateway, configID, "8.8.8.8")}},
		Rules:              []policy.Rule{{ID: ruleID, SrcGroupID: gAdmins, DstKind: "fqdn_resource"}},
		FQDNRuleReferences: []policy.FQDNRuleReference{{PolicyRuleID: ruleID, FQDNResourceID: resourceID}},
		// Put the unselected gateway last: a last-write-wins site map would reject
		// or misplace this generation. Exact pair membership must not.
		SiteNodes:   []policy.SiteNode{{SiteID: siteID, NodeID: selectedGateway}, {SiteID: siteID, NodeID: otherGateway}},
		SiteSubnets: []policy.SiteSubnet{{SiteID: siteID, CIDR: "10.53.0.0/24"}},
		ActiveHub:   hub,
	}
	compiled := policy.Compile(snapshot)
	for _, node := range []uuid.UUID{nodeA, selectedGateway, hub} {
		if got := compiled[node]; len(got.Allow) != 3 || len(got.FQDNGenerations) != 1 {
			t.Fatalf("node %s must enforce the exact selected path: %+v", node, got)
		}
	}
	if got := compiled[otherGateway]; len(got.Allow) != 0 || len(got.FQDNGenerations) != 0 {
		t.Fatalf("unselected gateway must remain deny-all: %+v", got)
	}
}

func TestFQDNSiteSourceResolverDerivationAndOptionalEndpoint(t *testing.T) {
	resourceID, ruleID := uuid.New(), uuid.New()
	sourceSite, selectedSite, routedResolverSite := uuid.New(), uuid.New(), uuid.New()
	sourceGateway, selectedGateway, hub, configID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	generation := activeFQDN(resourceID, selectedSite, selectedGateway, configID, "8.8.8.8")
	snapshot := policy.Snapshot{
		Mode: policy.ModeEnforcing, FQDNResourcesLicensed: true, FQDNResourcesEnabled: true,
		SiteSubnets: []policy.SiteSubnet{
			{SiteID: sourceSite, CIDR: "10.1.0.0/24"},
			{SiteID: routedResolverSite, CIDR: "10.53.0.0/24"},
		},
		SiteNodes: []policy.SiteNode{
			{SiteID: sourceSite, NodeID: sourceGateway},
			{SiteID: selectedSite, NodeID: selectedGateway},
		},
		FQDNResources:      []policy.FQDNResource{{ID: resourceID, FQDN: "api.example.com", Protocol: "tcp", PortLow: 443, PortHigh: 443, Active: generation}},
		Rules:              []policy.Rule{{ID: ruleID, SrcKind: "site", SrcSiteID: sourceSite, DstKind: "fqdn_resource"}},
		FQDNRuleReferences: []policy.FQDNRuleReference{{PolicyRuleID: ruleID, FQDNResourceID: resourceID}},
		ActiveHub:          hub,
	}
	compiled := policy.Compile(snapshot)
	for _, node := range []uuid.UUID{sourceGateway, selectedGateway, hub} {
		artifact := compiled[node]
		if len(artifact.Allow) != 3 || len(artifact.FQDNGenerations) != 1 {
			t.Fatalf("node %s: site source must derive answer plus DNS transports: %+v", node, artifact)
		}
		for _, allow := range artifact.Allow {
			if allow.SrcIP != "10.1.0.0/24" || allow.RuleID != ruleID.String() {
				t.Fatalf("node %s: site-source tuple lost placement/provenance: %+v", node, allow)
			}
			if allow.DstCIDR == "8.8.8.8/32" && !allow.FQDNManaged {
				t.Fatalf("node %s: concrete answer lost S21 ownership: %+v", node, allow)
			}
			if allow.DstCIDR == "10.53.0.53/32" && allow.FQDNManaged {
				t.Fatalf("node %s: resolver carriage must remain ordinary policy: %+v", node, allow)
			}
		}
	}

	withoutResolver := snapshot
	withoutResolver.FQDNResources = append([]policy.FQDNResource(nil), snapshot.FQDNResources...)
	withoutGeneration := *generation
	withoutGeneration.ResolverAddresses = nil
	withoutResolver.FQDNResources[0].Active = &withoutGeneration
	compiled = policy.Compile(withoutResolver)
	for _, node := range []uuid.UUID{sourceGateway, selectedGateway, hub} {
		artifact := compiled[node]
		if len(artifact.Allow) != 1 || len(artifact.FQDNGenerations) != 1 || artifact.Allow[0].DstCIDR != "8.8.8.8/32" {
			t.Fatalf("node %s: answer generation remains valid without client-usable UDP/53: %+v", node, artifact)
		}
	}
}

func TestFQDNWithdrawalAndUnsafeAnswersFailClosed(t *testing.T) {
	resourceID := uuid.New()
	base := policy.Snapshot{Mode: policy.ModeEnforcing, FQDNResourcesLicensed: true, FQDNResourcesEnabled: true,
		Devices:     []policy.Device{{ID: uuid.New(), UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"}},
		Memberships: []policy.Membership{{GroupID: gAdmins, UserID: uAlice}},
		Rules:       []policy.Rule{{ID: uuid.New(), SrcGroupID: gAdmins, DstKind: "fqdn_resource"}},
	}
	base.FQDNRuleReferences = []policy.FQDNRuleReference{{PolicyRuleID: base.Rules[0].ID, FQDNResourceID: resourceID}}
	siteID, gatewayID, configID := uuid.New(), uuid.New(), uuid.New()
	base.SiteNodes = []policy.SiteNode{{SiteID: siteID, NodeID: gatewayID}}
	base.SiteSubnets = []policy.SiteSubnet{{SiteID: siteID, CIDR: "10.53.0.0/24"}}
	for name, resource := range map[string]policy.FQDNResource{
		"withdrawn":          {ID: resourceID, FQDN: "api.example.com"},
		"metadata":           {ID: resourceID, FQDN: "api.example.com", Active: activeFQDN(resourceID, siteID, gatewayID, configID, "169.254.169.254")},
		"documentation":      {ID: resourceID, FQDN: "api.example.com", Active: activeFQDN(resourceID, siteID, gatewayID, configID, "192.0.2.1")},
		"invalid-port-scope": {ID: resourceID, FQDN: "api.example.com", Protocol: "tcp", PortLow: 443, Active: activeFQDN(resourceID, siteID, gatewayID, configID, "8.8.8.8")},
		"invalid-protocol":   {ID: resourceID, FQDN: "api.example.com", Protocol: "sctp", Active: activeFQDN(resourceID, siteID, gatewayID, configID, "8.8.8.8")},
	} {
		s := base
		s.FQDNResources = []policy.FQDNResource{resource}
		c := policy.Compile(s)[nodeA]
		if len(c.Allow) != 0 || len(c.FQDNGenerations) != 0 || c.Mesh {
			t.Fatalf("%s must withdraw to default deny, got %+v", name, c)
		}
	}
}

func TestFQDNGenerationChangesCanonicalHashDeterministically(t *testing.T) {
	resourceID := uuid.New()
	siteID, gatewayID, configID, profileID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	makeArtifact := func(answers []string, selectedGateway uuid.UUID, resolver string, selectedProfile uuid.UUID, suffix string) policyspec.Compiled {
		ruleID := uuid.New()
		generation := activeFQDN(resourceID, siteID, selectedGateway, configID, answers...)
		generation.ResolverProfileID = selectedProfile
		generation.ResolverMatchSuffix = suffix
		generation.ResolverAddresses = []string{resolver}
		s := policy.Snapshot{Mode: policy.ModeEnforcing, FQDNResourcesLicensed: true, FQDNResourcesEnabled: true,
			Devices:     []policy.Device{{ID: uuid.New(), UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"}},
			Memberships: []policy.Membership{{GroupID: gAdmins, UserID: uAlice}},
			FQDNResources: []policy.FQDNResource{{ID: resourceID, FQDN: "api.example.com", Protocol: "udp", PortLow: 53, PortHigh: 53,
				Active: generation}},
			FQDNRuleReferences: []policy.FQDNRuleReference{{PolicyRuleID: ruleID, FQDNResourceID: resourceID}},
			Rules:              []policy.Rule{{ID: ruleID, SrcGroupID: gAdmins, DstKind: "fqdn_resource"}},
			SiteNodes:          []policy.SiteNode{{SiteID: siteID, NodeID: selectedGateway}},
			SiteSubnets:        []policy.SiteSubnet{{SiteID: siteID, CIDR: "10.53.0.0/24"}},
		}
		return policy.Compile(s)[nodeA]
	}
	a := makeArtifact([]string{"8.8.4.4", "8.8.8.8"}, gatewayID, "10.53.0.53/32", profileID, "example.com")
	b := makeArtifact([]string{"8.8.8.8", "8.8.4.4"}, gatewayID, "10.53.0.53/32", profileID, "example.com")
	if policyspec.CanonicalHash(a) != policyspec.CanonicalHash(b) {
		t.Fatal("answer ordering must not perturb the canonical hash")
	}
	if policyspec.CanonicalHash(a) == policyspec.CanonicalHash(makeArtifact([]string{"8.8.4.4", "8.8.8.8"}, uuid.New(), "10.53.0.53/32", profileID, "example.com")) {
		t.Fatal("a generation selected by a different gateway must change the enforcement hash")
	}
	if policyspec.CanonicalHash(a) == policyspec.CanonicalHash(makeArtifact([]string{"1.1.1.1"}, gatewayID, "10.53.0.53/32", profileID, "example.com")) {
		t.Fatal("a changed answer set must change the enforcement hash")
	}
	if policyspec.CanonicalHash(a) == policyspec.CanonicalHash(makeArtifact([]string{"8.8.4.4", "8.8.8.8"}, gatewayID, "10.53.0.54/32", profileID, "example.com")) {
		t.Fatal("a changed selected resolver address must change the enforcement hash")
	}
	if policyspec.CanonicalHash(a) == policyspec.CanonicalHash(makeArtifact([]string{"8.8.4.4", "8.8.8.8"}, gatewayID, "10.53.0.53/32", uuid.New(), "example.com")) {
		t.Fatal("a changed selected resolver profile must change the generation identity")
	}
	if policyspec.CanonicalHash(a) == policyspec.CanonicalHash(makeArtifact([]string{"8.8.4.4", "8.8.8.8"}, gatewayID, "10.53.0.53/32", profileID, "api.example.com")) {
		t.Fatal("a changed matched suffix must change the generation identity")
	}
	configChanged := a
	configChanged.FQDNGenerations = append([]policyspec.FQDNGeneration(nil), a.FQDNGenerations...)
	configChanged.FQDNGenerations[0].ResolverConfigVersion++
	if policyspec.CanonicalHash(a) == policyspec.CanonicalHash(configChanged) {
		t.Fatal("a resolver configuration revision must change the enforcing FQDN artifact hash")
	}
}

func TestFQDNReferenceAndSnapshotGatesFailClosed(t *testing.T) {
	resourceID, ruleID := uuid.New(), uuid.New()
	siteID, gatewayID, configID := uuid.New(), uuid.New(), uuid.New()
	base := policy.Snapshot{
		Mode: policy.ModeEnforcing, FQDNResourcesLicensed: true, FQDNResourcesEnabled: true,
		Devices:     []policy.Device{{ID: uuid.New(), UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"}},
		Memberships: []policy.Membership{{GroupID: gAdmins, UserID: uAlice}},
		Rules:       []policy.Rule{{ID: ruleID, SrcGroupID: gAdmins, DstKind: "fqdn_resource"}},
		FQDNResources: []policy.FQDNResource{{ID: resourceID, FQDN: "api.example.com", Protocol: "tcp", PortLow: 443, PortHigh: 443,
			Active: activeFQDN(resourceID, siteID, gatewayID, configID, "8.8.8.8")}},
		FQDNRuleReferences: []policy.FQDNRuleReference{{PolicyRuleID: ruleID, FQDNResourceID: resourceID}},
		SiteNodes:          []policy.SiteNode{{SiteID: siteID, NodeID: gatewayID}},
		SiteSubnets:        []policy.SiteSubnet{{SiteID: siteID, CIDR: "10.53.0.0/24"}},
	}
	if got := policy.Compile(base)[nodeA]; len(got.Allow) != 3 || got.Version != 9 {
		t.Fatalf("complete licensed+opted-in FQDN snapshot must compile, got %+v", got)
	}

	mutations := map[string]func(*policy.Snapshot){
		"licence absent":    func(s *policy.Snapshot) { s.FQDNResourcesLicensed = false },
		"org opt-in absent": func(s *policy.Snapshot) { s.FQDNResourcesEnabled = false },
		"parent disabled":   func(s *policy.Snapshot) { s.Rules[0].Disabled = true },
		"reference absent":  func(s *policy.Snapshot) { s.FQDNRuleReferences = nil },
		"reference ambiguous": func(s *policy.Snapshot) {
			s.FQDNRuleReferences = append(s.FQDNRuleReferences, policy.FQDNRuleReference{PolicyRuleID: ruleID, FQDNResourceID: resourceID})
		},
		"reference points elsewhere":    func(s *policy.Snapshot) { s.FQDNRuleReferences[0].FQDNResourceID = uuid.New() },
		"resource identity ambiguous":   func(s *policy.Snapshot) { s.FQDNResources = append(s.FQDNResources, s.FQDNResources[0]) },
		"generation belongs elsewhere":  func(s *policy.Snapshot) { s.FQDNResources[0].Active.ResourceID = uuid.New() },
		"resolver configuration absent": func(s *policy.Snapshot) { s.FQDNResources[0].Active.ResolverConfigID = uuid.Nil },
		"resolver profile absent":       func(s *policy.Snapshot) { s.FQDNResources[0].Active.ResolverProfileID = uuid.Nil },
		"resolver suffix mismatch":      func(s *policy.Snapshot) { s.FQDNResources[0].Active.ResolverMatchSuffix = "elsewhere.example" },
		"selected context pair absent": func(s *policy.Snapshot) {
			s.SiteNodes = []policy.SiteNode{{SiteID: siteID, NodeID: uuid.New()}, {SiteID: uuid.New(), NodeID: gatewayID}}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			s := base
			s.FQDNResources = append([]policy.FQDNResource(nil), base.FQDNResources...)
			generation := *base.FQDNResources[0].Active
			s.FQDNResources[0].Active = &generation
			s.FQDNRuleReferences = append([]policy.FQDNRuleReference(nil), base.FQDNRuleReferences...)
			s.SiteNodes = append([]policy.SiteNode(nil), base.SiteNodes...)
			mutate(&s)
			got := policy.Compile(s)[nodeA]
			if len(got.Allow) != 0 || len(got.FQDNGenerations) != 0 || got.Version == 9 {
				t.Fatalf("%s must withdraw FQDN enforcement, got %+v", name, got)
			}
		})
	}
}

// B2 (structural guard): the enforcing path can NEVER emit Mesh=true, no matter
// the inputs. Drive a rich enforcing snapshot and assert every node is Mesh=false.
func TestEnforcingNeverEmitsBlanketMesh(t *testing.T) {
	out := policy.Compile(richSnapshot(policy.ModeEnforcing))
	if len(out) == 0 {
		t.Fatal("expected node output")
	}
	for id, c := range out {
		if c.Mesh {
			t.Fatalf("node %s: enforcing must not emit Mesh=true", id)
		}
	}
}

// C4: off mode is the legacy blanket mesh (Mesh=true, no allows); flipping to
// enforcing recompiles to a grant set. Same devices, different mode => different
// output (proves mode is a compiler input, and the transition recompiles).
func TestModeOffIsMeshEnforcingIsGrants(t *testing.T) {
	off := policy.Compile(richSnapshot(policy.ModeOff))
	if c := off[nodeA]; !c.Mesh || len(c.Allow) != 0 || c.Mode != policy.ModeOff {
		t.Fatalf("off mode: want mesh+no-allows+off, got %+v", c)
	}
	enf := policy.Compile(richSnapshot(policy.ModeEnforcing))
	if c := enf[nodeA]; c.Mesh || c.Mode != policy.ModeEnforcing {
		t.Fatalf("enforcing mode: want !mesh+enforcing, got %+v", c)
	}
	if len(enf[nodeA].Allow) == 0 {
		t.Fatal("enforcing rich snapshot should yield grants on node A")
	}
}

// C4 fail-closed: an UNKNOWN mode must be treated as enforcing (deny), never as
// the permissive mesh.
func TestUnknownModeFailsClosed(t *testing.T) {
	snap := richSnapshot("garbage")
	out := policy.Compile(snap)
	for id, c := range out {
		if c.Mesh {
			t.Fatalf("node %s: unknown mode must fail closed (no mesh)", id)
		}
	}
}

// A2 (deliberate-red): revoking a group-member device removes its /32 from the
// compiled output as BOTH a source (no allows keyed on it) and a destination (no
// peer may reach it) — so a reused address can't inherit the old device's grants.
func TestRevokedDeviceLeavesCompiledOutput(t *testing.T) {
	// Admins may reach the servers group (device-to-device). Alice is an admin,
	// Bob + Carol are servers, all on node A.
	base := policy.Snapshot{
		Mode: policy.ModeEnforcing,
		Rules: []policy.Rule{
			{SrcGroupID: gAdmins, DstKind: "group", DstGroupID: gServers},
		},
		Memberships: []policy.Membership{
			{GroupID: gAdmins, UserID: uAlice},
			{GroupID: gServers, UserID: uBob},
			{GroupID: gServers, UserID: uCarol},
		},
		Devices: []policy.Device{
			{UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"},
			{UserID: uBob, NodeID: nodeA, AssignedIP: "10.99.0.20"},
			{UserID: uCarol, NodeID: nodeA, AssignedIP: "10.99.0.21"},
		},
	}
	before := allowsFor(policy.Compile(base), nodeA)
	if !hasAllow(before, "10.99.0.10", "10.99.0.20/32") {
		t.Fatalf("baseline: admin should reach Bob's server, got %+v", before)
	}

	// Revoke Bob's device == remove it from the active-device snapshot.
	revoked := base
	revoked.Devices = []policy.Device{
		{UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"},
		{UserID: uCarol, NodeID: nodeA, AssignedIP: "10.99.0.21"},
	}
	after := allowsFor(policy.Compile(revoked), nodeA)

	// Bob's /32 must be gone as a DESTINATION...
	if hasAllow(after, "10.99.0.10", "10.99.0.20/32") {
		t.Fatal("revoked device's /32 still present as a destination — inherited grant on IP reuse")
	}
	// ...and nowhere at all (also not as a source, though Bob was never a source here).
	for _, e := range after {
		if e.SrcIP == "10.99.0.20" || e.DstCIDR == "10.99.0.20/32" {
			t.Fatalf("revoked /32 10.99.0.20 still referenced: %+v", e)
		}
	}
	// Carol's server is still reachable — revocation was surgical.
	if !hasAllow(after, "10.99.0.10", "10.99.0.21/32") {
		t.Fatal("Carol's server should still be reachable after Bob's revoke")
	}
}

func TestAgentGroupSourceExpandsOnlyCurrentMembers(t *testing.T) {
	group := uuid.New()
	agentA, agentB, outsider := uuid.New(), uuid.New(), uuid.New()
	node := uuid.New()
	res := uuid.New()
	snap := policy.Snapshot{
		Mode: policy.ModeEnforcing,
		Rules: []policy.Rule{{
			ID: uuid.New(), SrcKind: "agent_group", SrcAgentGroupID: group,
			DstKind: "resource", DstResourceID: res,
		}},
		Resources: []policy.Resource{{ID: res, CIDR: "10.80.0.0/24", Protocol: "tcp", PortLow: 443, PortHigh: 443}},
		Devices: []policy.Device{
			{ID: agentA, NodeID: node, AssignedIP: "10.99.0.10", Kind: "agent"},
			{ID: agentB, NodeID: node, AssignedIP: "10.99.0.11", Kind: "agent"},
			{ID: outsider, NodeID: node, AssignedIP: "10.99.0.12", Kind: "agent"},
		},
		AgentGroupMemberships: []policy.AgentGroupMembership{
			{GroupID: group, DeviceID: agentA},
			{GroupID: group, DeviceID: agentB},
		},
	}

	compiled := policy.Compile(snap)[node]
	if len(compiled.Allow) != 2 {
		t.Fatalf("agent-group allow count=%d want=2: %#v", len(compiled.Allow), compiled.Allow)
	}
	got := map[string]bool{}
	for _, allow := range compiled.Allow {
		got[allow.SrcDeviceID] = true
	}
	if !got[agentA.String()] || !got[agentB.String()] || got[outsider.String()] {
		t.Fatalf("agent-group expansion=%v", got)
	}
}

// Identity binding: access derives ONLY from the owner's group memberships. A
// device whose owner is in no group gets no grants even when rules exist.
func TestNoGrantsWithoutOwnerMembership(t *testing.T) {
	snap := policy.Snapshot{
		Mode: policy.ModeEnforcing,
		Resources: []policy.Resource{
			{ID: rDB, CIDR: "10.0.5.0/24", Protocol: "tcp", PortLow: 5432, PortHigh: 5432},
		},
		Rules: []policy.Rule{
			{SrcGroupID: gAdmins, DstKind: "resource", DstResourceID: rDB},
		},
		// Alice is NOT a member of gAdmins (no memberships at all).
		Devices: []policy.Device{
			{UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"},
		},
	}
	if a := allowsFor(policy.Compile(snap), nodeA); len(a) != 0 {
		t.Fatalf("no membership => no grants, got %+v", a)
	}
}

// Resource destination compiles to src /32 -> cidr with the L4 scope.
func TestResourceDestinationScope(t *testing.T) {
	snap := policy.Snapshot{
		Mode: policy.ModeEnforcing,
		Resources: []policy.Resource{
			{ID: rDB, CIDR: "10.0.5.0/24", Protocol: "tcp", PortLow: 5432, PortHigh: 5432},
		},
		Rules:       []policy.Rule{{SrcGroupID: gAdmins, DstKind: "resource", DstResourceID: rDB}},
		Memberships: []policy.Membership{{GroupID: gAdmins, UserID: uAlice}},
		Devices:     []policy.Device{{UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"}},
	}
	a := allowsFor(policy.Compile(snap), nodeA)
	if len(a) != 1 {
		t.Fatalf("want 1 entry, got %+v", a)
	}
	e := a[0]
	if e.SrcIP != "10.99.0.10" || e.DstCIDR != "10.0.5.0/24" || e.Protocol != policyspec.ProtoTCP || e.PortLow != 5432 || e.PortHigh != 5432 {
		t.Fatalf("resource scope wrong: %+v", e)
	}
}

// S7.5.4 — a per-USER rule (src_kind=user) resolves to exactly that user's device
// /32s, and ONLY that user's — a groupless user still gets their direct grant, and a
// different user in the same org gets nothing from it.
func TestPerUserSubjectResolvesToThatUserOnly(t *testing.T) {
	snap := policy.Snapshot{
		Mode:      policy.ModeEnforcing,
		Resources: []policy.Resource{{ID: rDB, CIDR: "10.0.5.0/24", Protocol: "any"}},
		// A per-user grant for Alice — NOTE: no group memberships at all.
		Rules: []policy.Rule{{SrcKind: "user", SrcUserID: uAlice, DstKind: "resource", DstResourceID: rDB}},
		Devices: []policy.Device{
			{UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"},
			{UserID: uBob, NodeID: nodeA, AssignedIP: "10.99.0.11"}, // Bob: no grant
		},
	}
	a := allowsFor(policy.Compile(snap), nodeA)
	if len(a) != 1 {
		t.Fatalf("per-user grant must emit exactly Alice's /32, got %+v", a)
	}
	if a[0].SrcIP != "10.99.0.10" || a[0].DstCIDR != "10.0.5.0/24" {
		t.Fatalf("wrong src: %+v (Bob must get nothing; a groupless user still gets a direct grant)", a[0])
	}
}

// S7.5.4 — a per-user grant and a group grant COMPOSE: the compiler is additive, and
// a user with both a group membership and a direct grant gets both destinations.
func TestPerUserAndGroupGrantsCompose(t *testing.T) {
	snap := policy.Snapshot{
		Mode: policy.ModeEnforcing,
		Resources: []policy.Resource{
			{ID: rDB, CIDR: "10.0.5.0/24", Protocol: "any"},
			{ID: gServers, CIDR: "10.0.6.0/24", Protocol: "any"}, // reuse a distinct uuid as a resource id
		},
		Rules: []policy.Rule{
			{SrcKind: "group", SrcGroupID: gAdmins, DstKind: "resource", DstResourceID: rDB},
			{SrcKind: "user", SrcUserID: uAlice, DstKind: "resource", DstResourceID: gServers},
		},
		Memberships: []policy.Membership{{GroupID: gAdmins, UserID: uAlice}},
		Devices:     []policy.Device{{UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"}},
	}
	a := allowsFor(policy.Compile(snap), nodeA)
	if len(a) != 2 {
		t.Fatalf("group + per-user grants must compose to 2 entries, got %+v", a)
	}
}

// Duplicate grants (two rules resolving to the same entry) collapse to one.
func TestDuplicateGrantsDeduped(t *testing.T) {
	snap := policy.Snapshot{
		Mode: policy.ModeEnforcing,
		Resources: []policy.Resource{
			{ID: rDB, CIDR: "10.0.5.0/24", Protocol: "any"},
		},
		Rules: []policy.Rule{
			{SrcGroupID: gAdmins, DstKind: "resource", DstResourceID: rDB},
			{SrcGroupID: gServers, DstKind: "resource", DstResourceID: rDB},
		},
		Memberships: []policy.Membership{
			{GroupID: gAdmins, UserID: uAlice},
			{GroupID: gServers, UserID: uAlice}, // Alice in both groups => same entry twice
		},
		Devices: []policy.Device{{UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"}},
	}
	if a := allowsFor(policy.Compile(snap), nodeA); len(a) != 1 {
		t.Fatalf("duplicate grants must dedup to 1, got %d: %+v", len(a), a)
	}
}

// A rule deleted and recreated with a NEW uuid but the SAME grant yields the SAME
// compiled hash — rule_id is STAMPED (for S7.5.1 flow-log attribution) yet hash-
// EXCLUDED, so the delete+recreate desync flap (the S7.4b trackDesync path) is dead by
// construction: the CP sees no content change, so no stamp fires.
func TestRuleRecreateHashStableStampVaries(t *testing.T) {
	build := func(ruleID uuid.UUID) policyspec.Compiled {
		snap := policy.Snapshot{
			Mode:        policy.ModeEnforcing,
			Resources:   []policy.Resource{{ID: rDB, CIDR: "10.0.5.0/24", Protocol: "tcp", PortLow: 5432, PortHigh: 5432}},
			Rules:       []policy.Rule{{ID: ruleID, SrcGroupID: gAdmins, DstKind: "resource", DstResourceID: rDB}},
			Memberships: []policy.Membership{{GroupID: gAdmins, UserID: uAlice}},
			Devices:     []policy.Device{{UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"}},
		}
		return policy.Compile(snap)[nodeA]
	}
	r1, r2 := uuid.New(), uuid.New() // r2 = the "recreated" rule: new uuid, identical grant
	c1, c2 := build(r1), build(r2)
	// The stamp VARIES — proves rule_id is actually populated from the CP rule uuid.
	if c1.Allow[0].RuleID != r1.String() || c2.Allow[0].RuleID != r2.String() {
		t.Fatalf("rule_id must be stamped from the CP rule uuid: %q / %q", c1.Allow[0].RuleID, c2.Allow[0].RuleID)
	}
	// ...yet the HASH is stable — no content change, so no desync flap.
	if policyspec.CanonicalHash(c1) != policyspec.CanonicalHash(c2) {
		t.Fatal("delete+recreate of an identical grant must NOT change the hash (S7.4b flap dead)")
	}
}

// S7.5.4 v3 — each AllowEntry carries the SOURCE device's id (src_device_id), so the
// agent can stamp flow events with device identity from the artifact. Observability: it
// varies with the device but must not perturb the enforcement hash.
func TestSrcDeviceIDStampedFromSourceDevice(t *testing.T) {
	devA := uuid.New()
	snap := policy.Snapshot{
		Mode:      policy.ModeEnforcing,
		Resources: []policy.Resource{{ID: rDB, CIDR: "10.0.5.0/24", Protocol: "any"}},
		Rules:     []policy.Rule{{SrcKind: "user", SrcUserID: uAlice, DstKind: "resource", DstResourceID: rDB}},
		Devices:   []policy.Device{{ID: devA, UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"}},
	}
	a := allowsFor(policy.Compile(snap), nodeA)
	if len(a) != 1 || a[0].SrcDeviceID != devA.String() {
		t.Fatalf("src_device_id must be the source device's id, got %+v", a)
	}
	// Hash-blind: a different device id (same grant/IP) must not change the enforcement hash.
	snap.Devices[0].ID = uuid.New()
	b := policy.Compile(snap)[nodeA]
	first := policy.Compile(policy.Snapshot{
		Mode: policy.ModeEnforcing, Resources: snap.Resources, Rules: snap.Rules,
		Devices: []policy.Device{{ID: devA, UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"}},
	})[nodeA]
	if policyspec.CanonicalHash(first) != policyspec.CanonicalHash(b) {
		t.Fatal("src_device_id must not perturb the enforcement hash")
	}
}

// Determinism: equal input compiles to byte-identical output (the reconcile
// no-op contract). Compile the same rich snapshot twice and compare JSON.
func TestCompileDeterministic(t *testing.T) {
	a := policy.Compile(richSnapshot(policy.ModeEnforcing))
	b := policy.Compile(richSnapshot(policy.ModeEnforcing))
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Fatalf("non-deterministic output:\n a=%s\n b=%s", ja, jb)
	}
	// And the per-node allow slices are internally sorted.
	for _, c := range a {
		for i := 1; i < len(c.Allow); i++ {
			if !leAllow(c.Allow[i-1], c.Allow[i]) {
				t.Fatalf("allow entries not sorted: %+v", c.Allow)
			}
		}
	}
}

// Per-node isolation: a grant only lands on the node the SOURCE device lives on.
func TestGrantsPartitionedByNode(t *testing.T) {
	snap := policy.Snapshot{
		Mode:      policy.ModeEnforcing,
		Resources: []policy.Resource{{ID: rDB, CIDR: "0.0.0.0/0", Protocol: "any"}},
		Rules:     []policy.Rule{{SrcGroupID: gAdmins, DstKind: "resource", DstResourceID: rDB}},
		Memberships: []policy.Membership{
			{GroupID: gAdmins, UserID: uAlice},
			{GroupID: gAdmins, UserID: uBob},
		},
		Devices: []policy.Device{
			{UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"},
			{UserID: uBob, NodeID: nodeB, AssignedIP: "10.99.0.11"},
		},
	}
	out := policy.Compile(snap)
	if !hasAllow(out[nodeA].Allow, "10.99.0.10", "0.0.0.0/0") {
		t.Fatal("node A should carry Alice's egress grant")
	}
	if !hasAllow(out[nodeB].Allow, "10.99.0.11", "0.0.0.0/0") {
		t.Fatal("node B should carry Bob's egress grant")
	}
	if hasAllow(out[nodeA].Allow, "10.99.0.11", "0.0.0.0/0") {
		t.Fatal("Bob's grant leaked onto node A")
	}
}

// Recompile-invalidation (D4), model layer: the compiled output is a pure function
// of the device set — ADDING a device changes it, so a device-create must trigger a
// recompile (the push is S7.2). New device for an admin gains the admin's grants.
func TestDeviceAddChangesOutput(t *testing.T) {
	base := policy.Snapshot{
		Mode:        policy.ModeEnforcing,
		Resources:   []policy.Resource{{ID: rDB, CIDR: "10.0.5.0/24", Protocol: "any"}},
		Rules:       []policy.Rule{{SrcGroupID: gAdmins, DstKind: "resource", DstResourceID: rDB}},
		Memberships: []policy.Membership{{GroupID: gAdmins, UserID: uAlice}},
		Devices:     []policy.Device{{UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"}},
	}
	before := allowsFor(policy.Compile(base), nodeA)
	withNew := base
	withNew.Devices = append([]policy.Device{}, base.Devices...)
	withNew.Devices = append(withNew.Devices, policy.Device{UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.99"})
	after := allowsFor(policy.Compile(withNew), nodeA)
	if len(after) <= len(before) || !hasAllow(after, "10.99.0.99", "10.0.5.0/24") {
		t.Fatalf("adding a device must add its grants (recompile needed): before=%d after=%+v", len(before), after)
	}
}

// Recompile-invalidation (D4), model layer: the output depends on group MEMBERSHIP,
// so a membership change must trigger a recompile. Granting Alice the admins group
// gives her device the DB grant it did not have before.
func TestMembershipChangeChangesOutput(t *testing.T) {
	base := policy.Snapshot{
		Mode:      policy.ModeEnforcing,
		Resources: []policy.Resource{{ID: rDB, CIDR: "10.0.5.0/24", Protocol: "any"}},
		Rules:     []policy.Rule{{SrcGroupID: gAdmins, DstKind: "resource", DstResourceID: rDB}},
		Devices:   []policy.Device{{UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"}},
		// no memberships yet
	}
	if a := allowsFor(policy.Compile(base), nodeA); len(a) != 0 {
		t.Fatalf("no membership => no grants, got %+v", a)
	}
	withMember := base
	withMember.Memberships = []policy.Membership{{GroupID: gAdmins, UserID: uAlice}}
	after := allowsFor(policy.Compile(withMember), nodeA)
	if !hasAllow(after, "10.99.0.10", "10.0.5.0/24") {
		t.Fatalf("adding a membership must grant access (recompile needed), got %+v", after)
	}
}

func leAllow(a, b policyspec.AllowEntry) bool {
	if a.SrcIP != b.SrcIP {
		return a.SrcIP <= b.SrcIP
	}
	return a.DstCIDR <= b.DstCIDR
}

// richSnapshot: a non-trivial org with a resource grant + a device-to-device grant
// across two nodes, parameterized by mode.
func richSnapshot(mode string) policy.Snapshot {
	return policy.Snapshot{
		Mode: mode,
		Resources: []policy.Resource{
			{ID: rDB, CIDR: "10.0.5.0/24", Protocol: "tcp", PortLow: 5432, PortHigh: 5432},
		},
		Rules: []policy.Rule{
			{SrcGroupID: gAdmins, DstKind: "resource", DstResourceID: rDB},
			{SrcGroupID: gAdmins, DstKind: "group", DstGroupID: gServers},
		},
		Memberships: []policy.Membership{
			{GroupID: gAdmins, UserID: uAlice},
			{GroupID: gServers, UserID: uBob},
		},
		Devices: []policy.Device{
			{UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"},
			{UserID: uBob, NodeID: nodeA, AssignedIP: "10.99.0.20"},
		},
	}
}

// TestSiteSubnetDestinationResolution — S8.1 Slice-3 enforcing-gates + resolution-edge reds (D3,
// Option A). A dst_kind='site' rule compiles to one same-shape AllowEntry per the target site's
// subnet; enforcing GATES it (only the GRANTED device reaches the subnet). Ruled edges: zero subnets
// → no grant (not an error); N subnets → N grants.
func TestSiteSubnetDestinationResolution(t *testing.T) {
	siteHQ := uuid.MustParse("00000000-0000-0000-0000-00000051e001")
	base := func(subnets []policy.SiteSubnet) policy.Snapshot {
		return policy.Snapshot{
			Mode: policy.ModeEnforcing,
			Devices: []policy.Device{
				{ID: uuid.New(), UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"}, // granted (in gAdmins)
				{ID: uuid.New(), UserID: uBob, NodeID: nodeA, AssignedIP: "10.99.0.11"},   // NOT in gAdmins
			},
			Memberships: []policy.Membership{{GroupID: gAdmins, UserID: uAlice}},
			Rules:       []policy.Rule{{ID: uuid.New(), SrcKind: "group", SrcGroupID: gAdmins, DstKind: "site", DstSiteID: siteHQ}},
			SiteSubnets: subnets,
		}
	}

	// Edge 1: a subnetless site -> NO grant (compiles to nothing, not an error).
	if none := allowsFor(policy.Compile(base(nil)), nodeA); len(none) != 0 {
		t.Fatalf("a dst=site rule against a SUBNETLESS site must compile to nothing, got %+v", none)
	}

	one := allowsFor(policy.Compile(base([]policy.SiteSubnet{{SiteID: siteHQ, CIDR: "10.20.0.0/24"}})), nodeA)
	// Enforcing GATES: the granted device reaches the subnet...
	if !hasAllow(one, "10.99.0.10", "10.20.0.0/24") {
		t.Fatalf("enforcing must GRANT the granted device to the site subnet, got %+v", one)
	}
	// ...and the NON-granted device does NOT (default-deny holds for site subnets too).
	if hasAllow(one, "10.99.0.11", "10.20.0.0/24") {
		t.Fatalf("a non-granted device must NOT reach the site subnet, got %+v", one)
	}

	// Edge 2: N subnets -> N grants (one AllowEntry per subnet), granted device only.
	multi := allowsFor(policy.Compile(base([]policy.SiteSubnet{
		{SiteID: siteHQ, CIDR: "10.20.0.0/24"}, {SiteID: siteHQ, CIDR: "10.21.0.0/24"},
	})), nodeA)
	if !hasAllow(multi, "10.99.0.10", "10.20.0.0/24") || !hasAllow(multi, "10.99.0.10", "10.21.0.0/24") {
		t.Fatalf("a site with 2 subnets must compile to 2 grants, got %+v", multi)
	}
	if len(multi) != 2 {
		t.Fatalf("want exactly 2 grants (one per subnet, granted device only), got %d: %+v", len(multi), multi)
	}
}

// TestSiteSubnetDowngradeToMesh — S8.1 D11 downgrade-to-mesh red. The SAME site-dst snapshot under
// off-mode compiles to the legacy MESH (Mesh=true, no grant-gating): enterprise->open releases the
// enforcing gate on the site subnet to the off-mode mesh. Enforcing gates it; off reaches it ungated.
func TestSiteSubnetDowngradeToMesh(t *testing.T) {
	siteHQ := uuid.MustParse("00000000-0000-0000-0000-00000051e002")
	snap := func(mode string) policy.Snapshot {
		return policy.Snapshot{
			Mode:        mode,
			Devices:     []policy.Device{{ID: uuid.New(), UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"}},
			Memberships: []policy.Membership{{GroupID: gAdmins, UserID: uAlice}},
			Rules:       []policy.Rule{{ID: uuid.New(), SrcKind: "group", SrcGroupID: gAdmins, DstKind: "site", DstSiteID: siteHQ}},
			SiteSubnets: []policy.SiteSubnet{{SiteID: siteHQ, CIDR: "10.20.0.0/24"}},
		}
	}
	// Enforcing: GATED (the grant is the only reason the subnet is reachable).
	if enf := policy.Compile(snap(policy.ModeEnforcing))[nodeA]; enf.Mesh || !hasAllow(enf.Allow, "10.99.0.10", "10.20.0.0/24") {
		t.Fatalf("enforcing must gate the site subnet via the grant, got mesh=%v allow=%+v", enf.Mesh, enf.Allow)
	}
	// Off (downgrade): MESH — the subnet is reachable via the blanket, no grant-gating.
	if off := policy.Compile(snap(policy.ModeOff))[nodeA]; !off.Mesh || len(off.Allow) != 0 {
		t.Fatalf("off-mode must be the legacy mesh (no site-subnet grant-gating), got mesh=%v allow=%+v", off.Mesh, off.Allow)
	}
}

// TestSiteSourceResolution — S8.2 Slice-1: a src_kind='site' rule makes a site's LAN the SOURCE. The
// compiler resolves it to the source site's subnet CIDR(s), emits AllowEntry{Src: site-CIDR, Dst}, and
// places the grant on the gateway nodes bound to the involved sites (src site + a site destination — the
// transit endpoints whose forward chain the LAN traffic crosses). Ruled edges: a subnetless source site
// grants nothing; an UNBOUND source site (no gateway) has no node to enforce on. Version is content-
// derived (D1b): a CIDR source flips the artifact to v5.
func TestSiteSourceResolution(t *testing.T) {
	siteA := uuid.MustParse("00000000-0000-0000-0000-00000051e0a1")
	siteB := uuid.MustParse("00000000-0000-0000-0000-00000051e0b1")
	base := func(bindA bool, subs []policy.SiteSubnet) policy.Snapshot {
		nodes := []policy.SiteNode{{SiteID: siteB, NodeID: nodeB}}
		if bindA {
			nodes = append(nodes, policy.SiteNode{SiteID: siteA, NodeID: nodeA})
		}
		return policy.Snapshot{
			Mode:        policy.ModeEnforcing,
			Rules:       []policy.Rule{{ID: uuid.New(), SrcKind: "site", SrcSiteID: siteA, DstKind: "site", DstSiteID: siteB}},
			SiteSubnets: subs,
			SiteNodes:   nodes,
		}
	}
	subs := []policy.SiteSubnet{{SiteID: siteA, CIDR: "10.1.0.0/24"}, {SiteID: siteB, CIDR: "10.2.0.0/24"}}

	out := policy.Compile(base(true, subs))
	// The site→site grant lands on BOTH involved gateways (transit endpoints).
	for _, n := range []uuid.UUID{nodeA, nodeB} {
		if !hasAllow(allowsFor(out, n), "10.1.0.0/24", "10.2.0.0/24") {
			t.Fatalf("site→site grant must be on node %v's forward chain, got %+v", n, allowsFor(out, n))
		}
	}
	// Content-derived version: a CIDR source flips the artifact to v5 (D1b).
	if v := out[nodeA].Version; v != 5 {
		t.Fatalf("a CIDR-source artifact must be v5 (content-derived), got %d", v)
	}

	// Edge: a subnetless SOURCE site → nothing (even though the dst has subnets).
	noneSrc := base(true, []policy.SiteSubnet{{SiteID: siteB, CIDR: "10.2.0.0/24"}})
	if got := allowsFor(policy.Compile(noneSrc), nodeA); len(got) != 0 {
		t.Fatalf("a subnetless SOURCE site must grant nothing, got %+v", got)
	}

	// Edge: an UNBOUND source site (no gateway node) → nodeA gets no artifact at all.
	if _, ok := policy.Compile(base(false, subs))[nodeA]; ok {
		t.Fatalf("an unbound source site's node must not appear in the output")
	}
}

// TestSiteSourceTransitHubGrant — S8.2 B1: a site→site grant is placed on the transit HUB (a third
// site's gateway, hub ∉ {src,dst}), not just src+dst, so the hub's default-deny forward chain accepts
// the transited A-LAN→B-LAN pair. Without this a 3-site hub-and-spoke silently blackholes spoke↔spoke
// at the hub (the paper's packet-walk step 4). Inverse: hub ∈ {src,dst} emits no duplicate.
func TestSiteSourceTransitHubGrant(t *testing.T) {
	siteA := uuid.MustParse("00000000-0000-0000-0000-00000051ed01")
	siteB := uuid.MustParse("00000000-0000-0000-0000-00000051ed02")
	siteH := uuid.MustParse("00000000-0000-0000-0000-00000051ed03")
	nodeH := uuid.MustParse("00000000-0000-0000-0000-0000000000c1")
	snap := policy.Snapshot{
		Mode:  policy.ModeEnforcing,
		Rules: []policy.Rule{{ID: uuid.New(), SrcKind: "site", SrcSiteID: siteA, DstKind: "site", DstSiteID: siteB}},
		SiteSubnets: []policy.SiteSubnet{
			{SiteID: siteA, CIDR: "10.1.0.0/24"}, {SiteID: siteB, CIDR: "10.2.0.0/24"}, {SiteID: siteH, CIDR: "10.3.0.0/24"},
		},
		SiteNodes: []policy.SiteNode{
			{SiteID: siteA, NodeID: nodeA},
			{SiteID: siteB, NodeID: nodeB},
			{SiteID: siteH, NodeID: nodeH, Endpoint: "hub.example:51820"}, // the HUB — a THIRD site, neither src nor dst
		},
		ActiveHub: nodeH, // S8.6 REDUCE #1: the derived active hub is THREADED IN (the compiler never elects)
	}
	out := policy.Compile(snap)
	if !hasAllow(allowsFor(out, nodeH), "10.1.0.0/24", "10.2.0.0/24") {
		t.Fatalf("the transit HUB (hub ∉ {src,dst}) must carry the site→site grant, got %+v", allowsFor(out, nodeH))
	}
	if !hasAllow(allowsFor(out, nodeA), "10.1.0.0/24", "10.2.0.0/24") || !hasAllow(allowsFor(out, nodeB), "10.1.0.0/24", "10.2.0.0/24") {
		t.Fatal("src + dst gateways must carry the grant too")
	}
	// Inverse: A is BOTH the hub (the threaded active hub) AND the src → no duplicate emission on nodeA.
	snap.SiteNodes = []policy.SiteNode{
		{SiteID: siteA, NodeID: nodeA, Endpoint: "a.example:51820"},
		{SiteID: siteB, NodeID: nodeB},
	}
	snap.ActiveHub = nodeA
	snap.SiteSubnets = []policy.SiteSubnet{{SiteID: siteA, CIDR: "10.1.0.0/24"}, {SiteID: siteB, CIDR: "10.2.0.0/24"}}
	if a2 := allowsFor(policy.Compile(snap), nodeA); len(a2) != 1 {
		t.Fatalf("hub==src must not duplicate the grant, got %d: %+v", len(a2), a2)
	}
}

// TestSiteTransitGrantHonorsThreadedActiveHub — S8.6 REDUCE #1 (the enterprise-enforcing cross-site
// BLACKHOLE): the transit grant lands on the THREADED ActiveHub, NEVER on the lowest-id gateway. Under HA a
// pinned/promoted non-lowest-id gateway IS the active hub; the pre-reduce lowest-id election put the grant on
// the WRONG gateway, so the enforcing forward chain of the ACTUAL hub dropped every cross-site packet. With
// the election deleted and the hub threaded in, the grant follows the derived active hub — the two compile
// paths (data-plane routing + policy transit) can no longer cite different hubs.
func TestSiteTransitGrantHonorsThreadedActiveHub(t *testing.T) {
	siteA := uuid.MustParse("00000000-0000-0000-0000-00000051ed01")
	siteB := uuid.MustParse("00000000-0000-0000-0000-00000051ed02")
	siteH := uuid.MustParse("00000000-0000-0000-0000-00000051ed03")
	// Two endpoint-bearing gateways on the hub site: nodeLow sorts BEFORE nodeHigh by id, so the pre-reduce
	// lowest-id election would have picked nodeLow. The DERIVED active hub is nodeHigh (a pin/failover).
	nodeLow := uuid.MustParse("00000000-0000-0000-0000-0000000000c1")
	nodeHigh := uuid.MustParse("00000000-0000-0000-0000-0000000000f9")
	snap := policy.Snapshot{
		Mode:  policy.ModeEnforcing,
		Rules: []policy.Rule{{ID: uuid.New(), SrcKind: "site", SrcSiteID: siteA, DstKind: "site", DstSiteID: siteB}},
		SiteSubnets: []policy.SiteSubnet{
			{SiteID: siteA, CIDR: "10.1.0.0/24"}, {SiteID: siteB, CIDR: "10.2.0.0/24"},
		},
		SiteNodes: []policy.SiteNode{
			{SiteID: siteA, NodeID: nodeA},
			{SiteID: siteB, NodeID: nodeB},
			{SiteID: siteH, NodeID: nodeLow, Endpoint: "low.example:51820"},   // the lowest-id temptation
			{SiteID: siteH, NodeID: nodeHigh, Endpoint: "high.example:51820"}, // the DERIVED active hub
		},
		ActiveHub: nodeHigh,
	}
	out := policy.Compile(snap)
	if !hasAllow(allowsFor(out, nodeHigh), "10.1.0.0/24", "10.2.0.0/24") {
		t.Fatalf("the transit grant must land on the DERIVED active hub (nodeHigh), got %+v", allowsFor(out, nodeHigh))
	}
	if a := allowsFor(out, nodeLow); hasAllow(a, "10.1.0.0/24", "10.2.0.0/24") {
		t.Fatalf("the transit grant must NOT land on the lowest-id gateway (the pre-reduce blackhole bug), got %+v", a)
	}
}

// TestSiteSourceDowngradeToMesh — S8.2 D11 downgrade-release: a src_kind='site' grant is GATED under
// enforcing (the LAN-source AllowEntry is the sole reason the traffic is permitted) and RELEASES to the
// legacy MESH under off-mode (enterprise→open downgrade → routed-but-ungated). Symmetric to the S8.1 dst
// downgrade red — the mode-as-compiler-input revert.
func TestSiteSourceDowngradeToMesh(t *testing.T) {
	siteA := uuid.MustParse("00000000-0000-0000-0000-00000051e0c1")
	siteB := uuid.MustParse("00000000-0000-0000-0000-00000051e0c2")
	snap := func(mode string) policy.Snapshot {
		return policy.Snapshot{
			Mode:        mode,
			Rules:       []policy.Rule{{ID: uuid.New(), SrcKind: "site", SrcSiteID: siteA, DstKind: "site", DstSiteID: siteB}},
			SiteSubnets: []policy.SiteSubnet{{SiteID: siteA, CIDR: "10.1.0.0/24"}, {SiteID: siteB, CIDR: "10.2.0.0/24"}},
			SiteNodes:   []policy.SiteNode{{SiteID: siteA, NodeID: nodeA}, {SiteID: siteB, NodeID: nodeB}},
		}
	}
	if enf := policy.Compile(snap(policy.ModeEnforcing))[nodeA]; enf.Mesh || !hasAllow(enf.Allow, "10.1.0.0/24", "10.2.0.0/24") {
		t.Fatalf("enforcing must gate the site-source grant, got mesh=%v allow=%+v", enf.Mesh, enf.Allow)
	}
	if off := policy.Compile(snap(policy.ModeOff))[nodeA]; !off.Mesh || len(off.Allow) != 0 {
		t.Fatalf("off-mode must release to the legacy mesh (no site-source grant-gating), got mesh=%v allow=%+v", off.Mesh, off.Allow)
	}
}

// TestContentDerivedVersion — S8.2 D1b: the emitted Version is the MINIMUM the artifact's content
// requires. A device-only org (no CIDR source) stays v4 — byte-identical, old gated agents keep working,
// no fleet re-converge. Only an artifact carrying a site-LAN (CIDR) source is v5.
func TestContentDerivedVersion(t *testing.T) {
	dev := policy.Compile(policy.Snapshot{
		Mode:        policy.ModeEnforcing,
		Rules:       []policy.Rule{{SrcGroupID: gAdmins, DstKind: "resource", DstResourceID: rDB}},
		Resources:   []policy.Resource{{ID: rDB, CIDR: "10.0.5.0/24"}},
		Memberships: []policy.Membership{{GroupID: gAdmins, UserID: uAlice}},
		Devices:     []policy.Device{{ID: uuid.New(), UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"}},
	})
	if v := dev[nodeA].Version; v != 4 {
		t.Fatalf("a device-only artifact must stay v4 (content-derived), got %d", v)
	}
	off := policy.Compile(policy.Snapshot{
		Mode:    policy.ModeOff,
		Devices: []policy.Device{{ID: uuid.New(), UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"}},
	})
	if v := off[nodeA].Version; v != 4 {
		t.Fatalf("an off-mode mesh artifact must be v4, got %d", v)
	}
}

// TestDeviceSiteGrantFarPlacement — A3b D-A3b-2 (founder-ruled BOTH-ENFORCE): a device→site grant lands
// on EVERY chain the transited packet crosses — the device's own node (entry), the transit HUB, and the
// DESTINATION site's gateway. Forward-blind far gateways would hang their security off every hub's
// integrity (wrong trust direction for customer-operated hubs); the far counter is the attribution point,
// the hub counter the transit witness.
func TestDeviceSiteGrantFarPlacement(t *testing.T) {
	siteFar := uuid.MustParse("00000000-0000-0000-0000-00000051efa1")
	nodeHub := uuid.MustParse("00000000-0000-0000-0000-0000000000b1")
	nodeFar := uuid.MustParse("00000000-0000-0000-0000-0000000000c1")
	snap := policy.Snapshot{
		Mode:        policy.ModeEnforcing,
		Devices:     []policy.Device{{ID: uuid.New(), UserID: uAlice, NodeID: nodeHub, AssignedIP: "10.99.0.10"}},
		Memberships: []policy.Membership{{GroupID: gAdmins, UserID: uAlice}},
		Rules:       []policy.Rule{{ID: uuid.New(), SrcKind: "group", SrcGroupID: gAdmins, DstKind: "site", DstSiteID: siteFar}},
		SiteSubnets: []policy.SiteSubnet{{SiteID: siteFar, CIDR: "10.2.0.0/24"}},
		SiteNodes:   []policy.SiteNode{{SiteID: siteFar, NodeID: nodeFar}},
		ActiveHub:   nodeHub,
	}
	out := policy.Compile(snap)
	// Entry (device node == hub here) and the FAR gateway both carry the grant; map-dedup means the
	// hub==device-node overlap emits ONCE per node, never twice.
	for _, n := range []uuid.UUID{nodeHub, nodeFar} {
		entries := allowsFor(out, n)
		if !hasAllow(entries, "10.99.0.10", "10.2.0.0/24") {
			t.Fatalf("device→site grant must land on node %s (both-enforce), got %+v", n, entries)
		}
		if len(entries) != 1 {
			t.Fatalf("exactly ONE deduped entry per node, got %d: %+v", len(entries), entries)
		}
	}
}

// TestDeviceResourceInSiteFarPlacement — A3b: a device→resource grant whose CIDR lives INSIDE a site's
// approved subnet is site-fronted — same 3-way placement (entry + hub + far). A resource in NO site
// subnet keeps the pre-A3b device-node-only placement (the siteOwning Nil edge).
func TestDeviceResourceInSiteFarPlacement(t *testing.T) {
	siteFar := uuid.MustParse("00000000-0000-0000-0000-00000051efa2")
	nodeDev := uuid.MustParse("00000000-0000-0000-0000-0000000000d1")
	nodeHub := uuid.MustParse("00000000-0000-0000-0000-0000000000b2")
	nodeFar := uuid.MustParse("00000000-0000-0000-0000-0000000000c2")
	resIn := uuid.New()  // inside the far site's subnet
	resOut := uuid.New() // in no site subnet
	snap := policy.Snapshot{
		Mode:        policy.ModeEnforcing,
		Devices:     []policy.Device{{ID: uuid.New(), UserID: uAlice, NodeID: nodeDev, AssignedIP: "10.99.0.10"}},
		Memberships: []policy.Membership{{GroupID: gAdmins, UserID: uAlice}},
		Resources: []policy.Resource{
			{ID: resIn, CIDR: "10.2.0.8/32", Protocol: "tcp", PortLow: 443, PortHigh: 443},
			{ID: resOut, CIDR: "192.0.2.0/24", Protocol: "any"},
		},
		Rules: []policy.Rule{
			{ID: uuid.New(), SrcKind: "group", SrcGroupID: gAdmins, DstKind: "resource", DstResourceID: resIn},
			{ID: uuid.New(), SrcKind: "group", SrcGroupID: gAdmins, DstKind: "resource", DstResourceID: resOut},
		},
		SiteSubnets: []policy.SiteSubnet{{SiteID: siteFar, CIDR: "10.2.0.0/24"}},
		SiteNodes:   []policy.SiteNode{{SiteID: siteFar, NodeID: nodeFar}},
		ActiveHub:   nodeHub,
	}
	out := policy.Compile(snap)
	// The in-site resource: entry + hub + far all adjudicate.
	for _, n := range []uuid.UUID{nodeDev, nodeHub, nodeFar} {
		if !hasAllow(allowsFor(out, n), "10.99.0.10", "10.2.0.8/32") {
			t.Fatalf("in-site resource grant must land on node %s (both-enforce), got %+v", n, allowsFor(out, n))
		}
	}
	// The non-site resource: device node ONLY — the hub/far chains never learn it.
	if !hasAllow(allowsFor(out, nodeDev), "10.99.0.10", "192.0.2.0/24") {
		t.Fatalf("non-site resource must still land on the device's node, got %+v", allowsFor(out, nodeDev))
	}
	for _, n := range []uuid.UUID{nodeHub, nodeFar} {
		if hasAllow(allowsFor(out, n), "10.99.0.10", "192.0.2.0/24") {
			t.Fatalf("a resource in NO site subnet must NOT land on node %s, got %+v", n, allowsFor(out, n))
		}
	}
}

// TestNodeSetSeedCensus — the F1 fold's one-truth check (census-style grep-proof): nodeSet is written at
// EXACTLY four seed sites — devices, SiteNodes, selected Kubernetes connectors, and the threaded ActiveHub
// — and nowhere else. No lazy
// admit path exists: every grant-placement target is in nodeSet by construction, so a cross-org node
// reaching the compiled output is STRUCTURALLY impossible (construction-over-convention, 3rd instance —
// the uapi field omission and allowedIPsFor's ranges-free signature are its siblings). A fourth write
// site appearing here without its paper entry is the drift this red exists to catch.
func TestNodeSetSeedCensus(t *testing.T) {
	src, err := os.ReadFile("compiler.go")
	if err != nil {
		t.Fatalf("read compiler.go: %v", err)
	}
	writes := regexp.MustCompile(`nodeSet\[[^\]]+\] = true`).FindAll(src, -1)
	if len(writes) != 4 {
		t.Fatalf("nodeSet must have EXACTLY 4 seed writes (devices, SiteNodes, K8s connectors, ActiveHub) — got %d: %s",
			len(writes), writes)
	}
}

// TestCIDRSourceGrantIsPrecise — S8.7 Slice 1: a src_kind='cidr' grant places the LITERAL CIDR (a /32) on
// its CONTAINING site's gateway — the /32 reaches the dst, the REST of the site does NOT (the founder's
// 172.31.17.64 → 10.0.0.4, "prove the rest of the site still drops"). A CIDR in NO site subnet compiles to
// nothing (the warn-not-refuse case — no placement).
func TestCIDRSourceGrantIsPrecise(t *testing.T) {
	siteA := uuid.MustParse("00000000-0000-0000-0000-0000005c1d01")
	gwA := uuid.MustParse("00000000-0000-0000-0000-0000000000d1")
	res := uuid.MustParse("00000000-0000-0000-0000-0000000000d2")
	snap := policy.Snapshot{
		Mode:        policy.ModeEnforcing,
		Rules:       []policy.Rule{{ID: uuid.New(), SrcKind: "cidr", SrcCIDR: "172.31.17.64/32", DstKind: "resource", DstResourceID: res}},
		Resources:   []policy.Resource{{ID: res, CIDR: "10.0.0.4/32", Protocol: "any"}},
		SiteSubnets: []policy.SiteSubnet{{SiteID: siteA, CIDR: "172.31.0.0/16"}},
		SiteNodes:   []policy.SiteNode{{SiteID: siteA, NodeID: gwA, Endpoint: "a:51820"}},
	}
	a := allowsFor(policy.Compile(snap), gwA)
	if !hasAllow(a, "172.31.17.64/32", "10.0.0.4/32") {
		t.Fatalf("the /32 source must reach the dst, placed on the containing site's gateway, got %+v", a)
	}
	if hasAllow(a, "172.31.0.0/16", "10.0.0.4/32") {
		t.Fatalf("the WHOLE site must NOT get the grant — /32 precision (the rest of the site drops), got %+v", a)
	}

	// A CIDR in NO site subnet → resolves to no containing site → compiles to nothing (warn-not-refuse).
	orphan := policy.Snapshot{
		Mode:        policy.ModeEnforcing,
		Rules:       []policy.Rule{{ID: uuid.New(), SrcKind: "cidr", SrcCIDR: "192.0.2.5/32", DstKind: "resource", DstResourceID: res}},
		Resources:   []policy.Resource{{ID: res, CIDR: "10.0.0.4/32", Protocol: "any"}},
		SiteSubnets: []policy.SiteSubnet{{SiteID: siteA, CIDR: "172.31.0.0/16"}},
		SiteNodes:   []policy.SiteNode{{SiteID: siteA, NodeID: gwA, Endpoint: "a:51820"}},
	}
	if a := allowsFor(policy.Compile(orphan), gwA); hasAllow(a, "192.0.2.5/32", "10.0.0.4/32") {
		t.Fatalf("an out-of-world CIDR (in no site subnet) must compile to nothing, got %+v", a)
	}
}

// TestCIDRSourcePlacementBiconditional — S8.7 [0]+[9]: the compiler side of warn⟺won't-place. A cidr PLACES
// iff its containing approved site subnet has a bound gateway; otherwise it places NOTHING — never the [0]
// dst-site ACCEPT bypass, never the [9] node-less silent no-op.
func TestCIDRSourcePlacementBiconditional(t *testing.T) {
	siteA := uuid.MustParse("00000000-0000-0000-0000-00000051cb01")
	siteB := uuid.MustParse("00000000-0000-0000-0000-00000051cb02")
	siteC := uuid.MustParse("00000000-0000-0000-0000-00000051cb03")
	gwA := uuid.MustParse("00000000-0000-0000-0000-0000000000e1")
	gwB := uuid.MustParse("00000000-0000-0000-0000-0000000000e2")
	res := uuid.MustParse("00000000-0000-0000-0000-0000000000e9")
	resource := []policy.Resource{{ID: res, CIDR: "10.0.0.4/32", Protocol: "any"}}

	// PLACES: a cidr inside siteA's subnet AND siteA has a bound gateway.
	placed := policy.Snapshot{
		Mode: policy.ModeEnforcing, Resources: resource,
		Rules:       []policy.Rule{{ID: uuid.New(), SrcKind: "cidr", SrcCIDR: "172.31.17.64/32", DstKind: "resource", DstResourceID: res}},
		SiteSubnets: []policy.SiteSubnet{{SiteID: siteA, CIDR: "172.31.0.0/16"}},
		SiteNodes:   []policy.SiteNode{{SiteID: siteA, NodeID: gwA, Endpoint: "a:51820"}},
	}
	if !hasAllow(allowsFor(policy.Compile(placed), gwA), "172.31.17.64/32", "10.0.0.4/32") {
		t.Fatal("in-world cidr with a bound gateway must PLACE")
	}

	// [0] DST-SITE BYPASS: an OUT-OF-WORLD cidr (in no site subnet) → dst=site. The warned-inert rule must
	// emit NOTHING on the dst gateway or the hub — NOT an ACCEPT the operator was told matches nothing.
	bypass := policy.Snapshot{
		Mode:        policy.ModeEnforcing,
		Rules:       []policy.Rule{{ID: uuid.New(), SrcKind: "cidr", SrcCIDR: "203.0.113.9/32", DstKind: "site", DstSiteID: siteB}},
		SiteSubnets: []policy.SiteSubnet{{SiteID: siteA, CIDR: "172.31.0.0/16"}, {SiteID: siteB, CIDR: "10.2.0.0/24"}},
		SiteNodes:   []policy.SiteNode{{SiteID: siteA, NodeID: gwA, Endpoint: "a:51820"}, {SiteID: siteB, NodeID: gwB, Endpoint: "b:51820"}},
		ActiveHub:   gwA,
	}
	out := policy.Compile(bypass)
	for _, n := range []uuid.UUID{gwA, gwB} {
		if hasAllow(allowsFor(out, n), "203.0.113.9/32", "10.2.0.0/24") {
			t.Fatalf("[0] an out-of-world cidr → dst-site must emit NO ACCEPT (default-deny bypass) on %v, got %+v", n, allowsFor(out, n))
		}
	}

	// [9] NODE-LESS SITE: a cidr inside siteC's subnet but siteC has NO bound gateway → places NOTHING.
	nodeless := policy.Snapshot{
		Mode: policy.ModeEnforcing, Resources: resource,
		Rules:       []policy.Rule{{ID: uuid.New(), SrcKind: "cidr", SrcCIDR: "192.168.5.5/32", DstKind: "resource", DstResourceID: res}},
		SiteSubnets: []policy.SiteSubnet{{SiteID: siteC, CIDR: "192.168.0.0/16"}}, // siteC has NO SiteNode
	}
	for _, c := range policy.Compile(nodeless) {
		if hasAllow(c.Allow, "192.168.5.5/32", "10.0.0.4/32") {
			t.Fatal("[9] a cidr in a NODE-LESS site must place NOTHING (compiles to nothing)")
		}
	}
}

// F3 — a DISABLED rule compiles to NOTHING: its allow is withdrawn (as-if-absent under default-deny),
// re-enabling restores it, and the toggle MOVES the CanonicalHash (a real, in-hash policy change) but NEVER
// bumps RequiredVersion (only WHICH entries exist changes, not the AllowEntry shape).
func TestDisabledRuleCompilesToNothing(t *testing.T) {
	base := func(disabled bool) policy.Snapshot {
		return policy.Snapshot{
			Mode:        policy.ModeEnforcing,
			Resources:   []policy.Resource{{ID: rDB, CIDR: "10.0.5.0/24", Protocol: "any"}},
			Rules:       []policy.Rule{{SrcGroupID: gAdmins, DstKind: "resource", DstResourceID: rDB, Disabled: disabled}},
			Memberships: []policy.Membership{{GroupID: gAdmins, UserID: uAlice}},
			Devices:     []policy.Device{{UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"}},
		}
	}
	enabled := policy.Compile(base(false))
	disabled := policy.Compile(base(true))
	// the same snapshot with the rule REMOVED entirely (the as-if-absent oracle).
	removed := policy.Compile(policy.Snapshot{Mode: policy.ModeEnforcing,
		Resources:   []policy.Resource{{ID: rDB, CIDR: "10.0.5.0/24", Protocol: "any"}},
		Memberships: []policy.Membership{{GroupID: gAdmins, UserID: uAlice}},
		Devices:     []policy.Device{{UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"}}})

	if len(allowsFor(enabled, nodeA)) != 1 {
		t.Fatalf("enabled rule must grant, got %+v", allowsFor(enabled, nodeA))
	}
	if len(allowsFor(disabled, nodeA)) != 0 {
		t.Fatalf("DISABLED rule must grant NOTHING (withdrawn allow), got %+v", allowsFor(disabled, nodeA))
	}
	// AS-IF-ABSENT: disabled compiles byte-identically to the rule not existing.
	if policyspec.CanonicalHash(disabled[nodeA]) != policyspec.CanonicalHash(removed[nodeA]) {
		t.Fatal("a disabled rule must compile IDENTICALLY to the rule not existing (as-if-absent)")
	}
	// HASH MOVES: an in-hash policy change (disabled differs from enabled) → ordinary push, NOT out-of-hash.
	if policyspec.CanonicalHash(enabled[nodeA]) == policyspec.CanonicalHash(disabled[nodeA]) {
		t.Fatal("disabling must MOVE the CanonicalHash (in-hash policy change)")
	}
	// NO VERSION BUMP: only which entries exist changed, not the artifact shape.
	if policyspec.RequiredVersion(enabled[nodeA]) != policyspec.RequiredVersion(disabled[nodeA]) {
		t.Fatalf("disabling must NOT bump RequiredVersion, got %d vs %d",
			policyspec.RequiredVersion(enabled[nodeA]), policyspec.RequiredVersion(disabled[nodeA]))
	}
}

// TestB1DeviceGrantIsTransportAgnostic (S9.1, Slice 1) LOCKS the epic's load-bearing finding:
// "an OVPN device is just a Device row with a /32." The compiler keys a device subject by its
// AssignedIP, and the ENFORCEMENT output (AllowEntry) carries NO transport dimension — so a
// WireGuard device and an OpenVPN device at the same /32/owner/node compile byte-identically.
// This is what makes B1 (ZT-coverage for OpenVPN) FREE: there is no transport fork in the
// compiler, so grants are transport-agnostic BY CONSTRUCTION, not by a second code path.
//
// Two locks: (1) the device grant is keyed by the bare /32 (no transport qualifier on the source
// match); (2) a checkpoint over AllowEntry's fields — if a future OVPN slice adds a field here,
// this trips and forces a conscious proof that the enforcement path stays transport-blind (an
// AllowEntry field that could encode transport would let an OVPN grant diverge from a WG grant at
// the same /32 — the two-door risk B1 forbids). See docs/S9.1-decisions.md (B1, D-S9.1-4).
//
// SUBSTITUTES != SATISFIES: this is the in-code half of the B1 boundary proof; the wire form (a
// real OpenVPN Connect client, enforcing + zero grants, DROPPED byte-for-byte) is OWED, trigger =
// the S9.1 box-walk after Slices 2-3.
func TestB1DeviceGrantIsTransportAgnostic(t *testing.T) {
	snap := policy.Snapshot{
		Mode:  policy.ModeEnforcing,
		Rules: []policy.Rule{{SrcGroupID: gAdmins, DstKind: "group", DstGroupID: gServers}},
		Memberships: []policy.Membership{
			{GroupID: gAdmins, UserID: uAlice},
			{GroupID: gServers, UserID: uBob},
		},
		Devices: []policy.Device{
			{UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"},
			{UserID: uBob, NodeID: nodeA, AssignedIP: "10.99.0.20"},
		},
	}
	got := allowsFor(policy.Compile(snap), nodeA)

	// (1) keyed by the bare /32 — the source match IS the assigned address, nothing else.
	if !hasAllow(got, "10.99.0.10", "10.99.0.20/32") {
		t.Fatalf("device grant must be keyed by the bare /32 (transport-blind); got %+v", got)
	}

	// (2) checkpoint: the AllowEntry field set is a conscious B1 boundary. A new field here is a
	// deliberate decision — if it can encode transport, an OVPN grant could diverge from a WG grant
	// at the same /32. FQDNManaged is the S21 tuple-provenance interlock, not a
	// transport discriminator: it is false for this ordinary device grant and is
	// consumed only by the gateway's selective hostname-tuple recovery. Observability
	// fields (RuleID, SrcDeviceID) are hash-EXCLUDED and listed so the guard is exact.
	want := map[string]bool{
		"SrcIP": true, "DstCIDR": true, "Protocol": true, "PortLow": true, "PortHigh": true,
		"RuleID": true, "SrcDeviceID": true, "FQDNManaged": true,
	}
	rt := reflect.TypeOf(policyspec.AllowEntry{})
	for i := 0; i < rt.NumField(); i++ {
		if name := rt.Field(i).Name; !want[name] {
			t.Fatalf("AllowEntry gained field %q — B1 requires the enforcement output stay "+
				"transport-blind. If this field can encode transport, prove the compiler AND the "+
				"egress renderer ignore it, then update this guard (docs/S9.1-decisions.md B1).", name)
		}
	}
}
