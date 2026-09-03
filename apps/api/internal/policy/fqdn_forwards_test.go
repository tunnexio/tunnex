package policy

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

func TestSelectFirstReachableResolverAddressPreservesProfileOrder(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}
	got, ok := selectFirstReachableResolverAddress([]string{
		"10.30.0.53", // valid, but not routed
		"not-an-ip",  // malformed candidates are fail-closed, not fatal
		"10.20.0.54",
		"10.20.0.53", // lower address must not win over profile order
	}, prefixes)
	if !ok || got != "10.20.0.54/32" {
		t.Fatalf("selected resolver = %q, %v; want 10.20.0.54/32, true", got, ok)
	}
}

func TestSelectFirstReachableResolverAddressFailsClosed(t *testing.T) {
	for name, candidates := range map[string][]string{
		"none":      nil,
		"unrouted":  {"10.30.0.53"},
		"loopback":  {"127.0.0.53"},
		"multicast": {"224.0.0.53"},
	} {
		t.Run(name, func(t *testing.T) {
			if got, ok := selectFirstReachableResolverAddress(candidates, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}); ok || got != "" {
				t.Fatalf("selected resolver = %q, %v; want empty, false", got, ok)
			}
		})
	}
}

func TestDeviceFQDNForwardsDerivesOnlyMatchingParentRules(t *testing.T) {
	deviceID, otherDeviceID := uuid.New(), uuid.New()
	ownerID, otherOwnerID := uuid.New(), uuid.New()
	nodeID, siteID, gatewayID := uuid.New(), uuid.New(), uuid.New()
	groupID, agentGroupID := uuid.New(), uuid.New()
	userRule, groupRule, agentRule, agentGroupRule, foreignRule := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()

	resources := []FQDNResource{
		fqdnForwardResource("user.internal.example", "internal.example", "10.20.0.53", siteID, gatewayID),
		fqdnForwardResource("group.internal.example", "internal.example", "10.20.0.53", siteID, gatewayID),
		fqdnForwardResource("agent.dev.internal.example", "dev.internal.example", "10.20.0.54", siteID, gatewayID),
		fqdnForwardResource("agent-group.ops.internal.example", "ops.internal.example", "10.20.0.55", siteID, gatewayID),
		fqdnForwardResource("foreign.internal.example", "foreign.internal.example", "10.20.0.99", siteID, gatewayID),
	}
	rules := []Rule{
		{ID: userRule, SrcKind: "user", SrcUserID: ownerID, DstKind: "fqdn_resource"},
		{ID: groupRule, SrcKind: "group", SrcGroupID: groupID, DstKind: "fqdn_resource"},
		{ID: agentRule, SrcKind: "agent", SrcDeviceID: deviceID, DstKind: "fqdn_resource"},
		{ID: agentGroupRule, SrcKind: "agent_group", SrcAgentGroupID: agentGroupID, DstKind: "fqdn_resource"},
		{ID: foreignRule, SrcKind: "user", SrcUserID: otherOwnerID, DstKind: "fqdn_resource"},
	}
	refs := make([]FQDNRuleReference, 0, len(rules))
	for i, rule := range rules {
		refs = append(refs, FQDNRuleReference{PolicyRuleID: rule.ID, FQDNResourceID: resources[i].ID})
	}
	snapshot := Snapshot{
		Mode: ModeEnforcing, FQDNResourcesLicensed: true, FQDNResourcesEnabled: true,
		Devices: []Device{
			{ID: deviceID, UserID: ownerID, NodeID: nodeID, AssignedIP: "10.99.0.5"},
			{ID: otherDeviceID, UserID: otherOwnerID, NodeID: nodeID, AssignedIP: "10.99.0.6"},
		},
		Memberships:           []Membership{{GroupID: groupID, UserID: ownerID}},
		AgentGroupMemberships: []AgentGroupMembership{{GroupID: agentGroupID, DeviceID: deviceID}},
		SiteNodes:             []SiteNode{{SiteID: siteID, NodeID: gatewayID}},
		Rules:                 rules,
		FQDNResources:         resources,
		FQDNRuleReferences:    refs,
	}

	want := []policyspec.DNSForward{
		{Domain: "dev.internal.example", ResolverIP: "10.20.0.54"},
		{Domain: "internal.example", ResolverIP: "10.20.0.53"},
		{Domain: "ops.internal.example", ResolverIP: "10.20.0.55"},
	}
	got := deviceFQDNForwardsFromSnapshot(snapshot, deviceID, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("device forwards: got %+v want %+v", got, want)
	}

	foreign := deviceFQDNForwardsFromSnapshot(snapshot, otherDeviceID, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")})
	if wantForeign := []policyspec.DNSForward{{Domain: "foreign.internal.example", ResolverIP: "10.20.0.99"}}; !reflect.DeepEqual(foreign, wantForeign) {
		t.Fatalf("foreign device forwards: got %+v want %+v", foreign, wantForeign)
	}
}

func TestDeviceFQDNForwardsWithholdsConflictsAndUnreachableResolvers(t *testing.T) {
	deviceID, ownerID, nodeID := uuid.New(), uuid.New(), uuid.New()
	siteID, gatewayID := uuid.New(), uuid.New()
	first := fqdnForwardResource("one.internal.example", "internal.example", "10.20.0.53", siteID, gatewayID)
	conflict := fqdnForwardResource("two.internal.example", "internal.example", "10.20.0.54", siteID, gatewayID)
	unreachable := fqdnForwardResource("hidden.private.example", "private.example", "10.30.0.53", siteID, gatewayID)
	rules := []Rule{
		{ID: uuid.New(), SrcKind: "user", SrcUserID: ownerID, DstKind: "fqdn_resource"},
		{ID: uuid.New(), SrcKind: "user", SrcUserID: ownerID, DstKind: "fqdn_resource"},
		{ID: uuid.New(), SrcKind: "user", SrcUserID: ownerID, DstKind: "fqdn_resource"},
	}
	snapshot := Snapshot{
		Mode: ModeEnforcing, FQDNResourcesLicensed: true, FQDNResourcesEnabled: true,
		Devices:       []Device{{ID: deviceID, UserID: ownerID, NodeID: nodeID, AssignedIP: "10.99.0.5"}},
		SiteNodes:     []SiteNode{{SiteID: siteID, NodeID: gatewayID}},
		Rules:         rules,
		FQDNResources: []FQDNResource{first, conflict, unreachable},
		FQDNRuleReferences: []FQDNRuleReference{
			{PolicyRuleID: rules[0].ID, FQDNResourceID: first.ID},
			{PolicyRuleID: rules[1].ID, FQDNResourceID: conflict.ID},
			{PolicyRuleID: rules[2].ID, FQDNResourceID: unreachable.ID},
		},
	}
	got := deviceFQDNForwardsFromSnapshot(snapshot, deviceID, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")})
	if got == nil || len(got) != 0 {
		t.Fatalf("conflicted/unreachable forwards must be non-nil empty, got %+v", got)
	}
}

func TestDeviceFQDNForwardsFailsClosedOutsideEnforcement(t *testing.T) {
	deviceID := uuid.New()
	for name, snapshot := range map[string]Snapshot{
		"off":        {Mode: ModeOff, FQDNResourcesLicensed: true, FQDNResourcesEnabled: true},
		"unlicensed": {Mode: ModeEnforcing, FQDNResourcesEnabled: true},
		"opted out":  {Mode: ModeEnforcing, FQDNResourcesLicensed: true},
	} {
		t.Run(name, func(t *testing.T) {
			got := deviceFQDNForwardsFromSnapshot(snapshot, deviceID, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")})
			if got == nil || len(got) != 0 {
				t.Fatalf("forward projection = %+v, want non-nil empty", got)
			}
		})
	}
}

func fqdnForwardResource(hostname, suffix, resolver string, siteID, gatewayID uuid.UUID) FQDNResource {
	resourceID := uuid.New()
	return FQDNResource{
		ID: resourceID, FQDN: hostname, Protocol: "tcp", PortLow: 443, PortHigh: 443,
		Active: &FQDNGeneration{
			ResourceID: resourceID, SelectedSiteID: siteID, SelectedGatewayID: gatewayID,
			ResolverConfigID: uuid.New(), ResolverProfileID: uuid.New(), ResolverMatchSuffix: suffix,
			ResolverConfigVersion: 1, Answers: []string{"172.16.0.4"},
			ResolverAddresses: []string{netip.PrefixFrom(netip.MustParseAddr(resolver), 32).String()},
		},
	}
}
