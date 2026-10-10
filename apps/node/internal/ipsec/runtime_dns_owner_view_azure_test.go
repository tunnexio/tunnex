package ipsec

import (
	"context"
	"net/netip"
	"reflect"
	"testing"
)

func TestAzureDNSOwnerViewPreservesProfileCardinalityAndFreshProof(t *testing.T) {
	for _, profile := range []string{AzureActiveActiveBGPProfile, AzureActiveActiveStaticProfile, AzureActiveStandbyBGPProfile, AzureActiveStandbyStaticProfile} {
		t.Run(profile, func(t *testing.T) {
			m := azureMaterialFixture(profile)
			grants := dnsMaterialFixture().Policy.DNSResolverGrants
			grants[0].ConnectionID, grants[0].ConfigurationRevision = m.Manifest.ConnectionID, m.Manifest.ConfigurationRevision
			m.Policy.DNSResolverGrants = grants
			runtimeReseal(&m)
			f := newDNSOwnerViewMaterialFixture(t, m, nil)
			owner := f.c.dnsView.Load().entries[m.Manifest.ConnectionID]
			original := f.c.active[m.Manifest.ConnectionID]
			if !sameDNSOwnerInputs(owner.active, original) || owner.active.Entry.Allocation.ProfileID != profile || owner.active.Entry.Allocation.activeTunnelCount() != map[bool]int{true: 1, false: 2}[IsSingleTunnelProfile(profile)] {
				t.Fatal("Azure cloned owner inputs changed transport contract")
			}
			if IsSingleTunnelProfile(profile) && (owner.active.Entry.Observed[1] != (Ownership{}) || !reflect.DeepEqual(owner.active.Entry.Engines[1], EngineTunnel{}) || !reflect.DeepEqual(owner.active.Entry.Allocation.Tunnels[1], KernelTunnelAllocation{})) {
				t.Fatal("inactive Azure slot gained cloned authority")
			}
			if IsAzureBGPProfile(profile) && (owner.active.Entry.Allocation.Tunnels[0].InsideAddress.Bits() != 32 || !validJournalBGP(owner.active.Entry) || !validBGPRoutes(owner.active.Entry)) {
				t.Fatal("Azure APIPA/BGP contract lost")
			}
			f.c.mu.Lock() // An unrelated serial owner wait must not consume DNS budget.
			before, err := f.prove(context.Background())
			f.c.mu.Unlock()
			if err != nil || before.Slot != 1 || before.InterfaceIndex != 10 || f.nativeProofs.Load() != 1 || f.guardReads.Load() != 1 || f.sourceReads.Load() != 2 || f.routeReads.Load() != 1 {
				t.Fatal("fresh Azure DNS proof missing", err)
			}
			after, err := f.prove(context.Background())
			if err != nil || !sameResolverDNSProof(before, after) {
				t.Fatal("Azure before/after exchange provenance changed", err)
			}
			original.Entry.Engines[0].RemotePrefixes[0] = netip.MustParsePrefix("10.21.0.0/24")
			if owner.active.Entry.Engines[0].RemotePrefixes[0].String() != "10.20.0.0/24" {
				t.Fatal("Azure clone aliases mutable owner prefix")
			}
			f.c.mu.Lock()
			f.c.withdrawDNSOwnerView(m.Manifest.ConnectionID)
			f.c.mu.Unlock()
			if sameResolverDNSProof(before, after) {
				t.Fatal("Azure withdrawn epoch survived final proof")
			}
		})
	}
}
