package ipsec

import (
	"context"
	"github.com/google/uuid"
	"reflect"
	"testing"
)

func azureMaintenanceRig(t *testing.T, profile string) (*renewalCycleRig, RuntimeMaterial) {
	t.Helper()
	var m RuntimeMaterial
	r := newRenewalCycleRigTransformed(t, true, func(c *RuntimeController, entries []RuntimeJournalEntry, materials []RuntimeMaterial) {
		index := -1
		for i, e := range entries {
			if e.ContractVersion == 3 {
				index = i
				break
			}
		}
		if index < 0 {
			t.Fatal("BGP fixture missing")
		}
		m = materials[index]
		m.Manifest.ProfileID = profile
		v := 3
		m.Manifest.BGPVersion = &v
		m.Manifest.BGP.RemoteASN = 65515
		for i := range m.Manifest.Tunnels {
			m.Manifest.Tunnels[i].InsideCIDR = "169.254.10.1/32"
			m.Manifest.Tunnels[i].CustomerInsideAddress = "169.254.10.1"
			m.Manifest.Tunnels[i].CloudInsideAddress = []string{"169.254.21.2", "169.254.22.2"}[i]
		}
		m.Secrets[1].PSK = m.Secrets[0].PSK
		if IsSingleTunnelProfile(profile) {
			v, n := 1, 1
			m.Manifest.TransportVersion = &v
			m.Manifest.TunnelCount = &n
			m.Manifest.Tunnels[1] = RuntimeTunnel{}
			m.Secrets[1] = RuntimeSecret{}
		}
		runtimeReseal(&m)
		old := c.active[m.Manifest.ConnectionID]
		e, grants, err := runtimeMaterialEntry(m, c.config.OrgID, c.config.GatewayID, old.Entry.Allocation.Namespace)
		if err != nil {
			t.Fatal(err)
		}
		e.Phase, e.Observed, e.Restoration = old.Entry.Phase, old.Entry.Observed, old.Entry.Restoration
		e.BGPProcess, e.BGPRoutes, e.BGPProcessHistory = old.Entry.BGPProcess, old.Entry.BGPRoutes, old.Entry.BGPProcessHistory
		e.Allocation.Generation = old.Entry.Allocation.Generation
		for i := range e.Engines[:e.Allocation.activeTunnelCount()] {
			e.Engines[i].LocalAddress = old.Environment.Underlays[i].LocalAddress
			e.Allocation.Tunnels[i].Alias = old.Entry.Allocation.Tunnels[i].Alias
		}
		if IsSingleTunnelProfile(profile) {
			e.Observed[1] = Ownership{}
			old.Environment.Underlays[1] = RuntimeUnderlay{}
		}
		old.Entry = e
		old.Grants = grants
		old.Identity = PermitLeaseIdentity{DeliveryID: m.ID, Binding: e.Engines[0].Binding, PolicyHash: m.Policy.Hash}
		old.Authority = NewPermitLeaseAuthority()
		req, err := old.Authority.Begin(old.Identity)
		if err != nil {
			t.Fatal(err)
		}
		if old.Authority.Accept(PermitLeaseResponse{PermitLeaseRequest: req, TTLMillis: 60000}) != nil {
			t.Fatal("initial lease")
		}
		c.active[m.Manifest.ConnectionID] = old
		entries[index] = e
		materials[index] = m
	})
	r.c.recoveryObserve = func(_ context.Context, e RuntimeJournalEntry) [2]string {
		if e.Allocation.activeTunnelCount() == 1 {
			return [2]string{"up", "unknown"}
		}
		return [2]string{"up", "up"}
	}
	if err := r.c.installActive(context.Background(), r.entries); err != nil {
		t.Fatal(err)
	}
	return r, m
}

func TestAzureMaintainedBGPCardinalityAndChangedInputs(t *testing.T) {
	for _, profile := range []string{AzureActiveActiveBGPProfile, AzureActiveStandbyBGPProfile} {
		for _, changed := range []bool{false, true} {
			t.Run(profile+map[bool]string{false: "/unchanged", true: "/changed-grants"}[changed], func(t *testing.T) {
				r, m := azureMaintenanceRig(t, profile)
				before, _ := r.c.journal.Entries()
				old := r.c.active[m.Manifest.ConnectionID]
				if changed {
					m.Policy.Grants = []RuntimeGrant{{Source: m.Manifest.LocalPrefixes[0], Destination: m.Manifest.RemotePrefixes[0], Protocol: "tcp", PortLow: 53, PortHigh: 53}}
					runtimeReseal(&m)
				}
				results, err := r.c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{m}, maintenanceAuthority(r), func() bool { return true })
				if err != nil {
					t.Fatal(err)
				}
				if changed {
					if len(results) != 0 {
						t.Fatal("changed input maintained")
					}
					if _, ok := r.c.active[m.Manifest.ConnectionID]; ok {
						t.Fatal("changed owner retained")
					}
				} else {
					if len(results) != 1 || results[0].Acknowledgement.DeliveryID != m.ID {
						t.Fatal("unchanged Azure not maintained")
					}
					count, _ := runtimeTransportContract(m.Manifest)
					for i := 0; i < count; i++ {
						if results[0].Report.Tunnels[i].ID != m.Manifest.Tunnels[i].ID {
							t.Fatal("slot identity lost")
						}
					}
					if count == 1 && (results[0].Report.Tunnels[1].ID != uuid.Nil || results[0].Report.TunnelCount == nil || *results[0].Report.TunnelCount != 1) {
						t.Fatal("standby fabricated slot")
					}
					if r.c.active[m.Manifest.ConnectionID].Authority == old.Authority {
						t.Fatal("fresh CP nonce authority missing")
					}
				}
				after, _ := r.c.journal.Entries()
				if !reflect.DeepEqual(before, after) {
					t.Fatal("maintenance changed retained journal duties")
				}
			})
		}
	}
}

func TestAzureMaintainedObservationCardinalityAndAuthority(t *testing.T) {
	for _, profile := range []string{AzureActiveActiveBGPProfile, AzureActiveStandbyBGPProfile} {
		for _, scenario := range []string{"unchanged", "changed-grants", "canceled"} {
			t.Run(profile+"/"+scenario, func(t *testing.T) {
				r, m := azureMaintenanceRig(t, profile)
				old := r.c.active[m.Manifest.ConnectionID]
				deadline := old.Authority.deadline
				if scenario == "changed-grants" {
					m.Policy.Grants = []RuntimeGrant{{Source: m.Manifest.LocalPrefixes[0], Destination: m.Manifest.RemotePrefixes[0], Protocol: "tcp", PortLow: 53, PortHigh: 53}}
					runtimeReseal(&m)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				calls := 0
				var published RuntimeStatusReport
				results, err := r.c.maintainIPsecRuntimeObserved(ctx, []RuntimeMaterial{m}, maintenanceAuthority(r), func() bool { return true }, func(_ context.Context, d RuntimeDelivery, report RuntimeStatusReport) error {
					calls++
					if !reflect.DeepEqual(d, m.RuntimeDelivery) || report.DeliveryID != m.ID || report.DesiredRevision != m.DesiredRevision {
						t.Fatal("unbound callback")
					}
					current := r.c.active[m.Manifest.ConnectionID]
					if current.Authority == nil || current.Authority == old.Authority {
						t.Fatal("callback before replacement native commit")
					}
					count, _ := runtimeTransportContract(m.Manifest)
					for i := 0; i < count; i++ {
						if report.Tunnels[i].ID != m.Manifest.Tunnels[i].ID || report.Tunnels[i].Slot != i+1 || report.Tunnels[i].Status != "unknown" {
							t.Fatal("cached Up or wrong Azure slot")
						}
					}
					if count == 1 && (report.Tunnels[1] != (RuntimeTunnelStatus{}) || report.TransportVersion == nil || *report.TransportVersion != 1 || report.TunnelCount == nil || *report.TunnelCount != 1) {
						t.Fatal("fabricated standby slot")
					}
					if count == 2 && (report.TransportVersion != nil || report.TunnelCount != nil) {
						t.Fatal("active-active wire changed")
					}
					published = report
					if scenario == "canceled" {
						cancel()
					}
					return nil
				})
				if old.Authority.deadline != deadline {
					t.Fatal("original authority extended")
				}
				switch scenario {
				case "changed-grants":
					if err != nil || len(results) != 0 || calls != 0 {
						t.Fatal("changed intent streamed or acknowledged", err, calls)
					}
				case "canceled":
					if err == nil || len(results) != 0 || calls != 1 || len(r.c.active) != 0 {
						t.Fatal("callback cancellation escaped whole-result gate")
					}
				default:
					if err != nil || len(results) != 1 || calls != 1 || !reflect.DeepEqual(results[0].Report, published) {
						t.Fatal("completed report/result mismatch", err, calls)
					}
				}
			})
		}
	}
}
