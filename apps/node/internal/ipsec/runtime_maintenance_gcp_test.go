package ipsec

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Provider material is validated before modeled native/clock seams; not cloud proof.
func gcpMaintenancePair(t *testing.T, c *RuntimeController, entries []RuntimeJournalEntry, materials []RuntimeMaterial) ([]RuntimeJournalEntry, []RuntimeMaterial) {
	t.Helper()
	outE := []RuntimeJournalEntry{}
	outM := []RuntimeMaterial{}
	keep := map[uuid.UUID]bool{}
	for _, n := range []int{0, 3} {
		old, m := entries[n], materials[n]
		if n == 0 {
			v := 2
			m.Manifest.ProfileID = GCPHABGPProfile
			m.Manifest.BGPVersion = &v
			b := *m.Manifest.BGP
			b.RemoteASN = 65001
			m.Manifest.BGP = &b
		} else {
			v, count := 1, 1
			m.Manifest.ProfileID = GCPClassicStaticProfile
			m.Manifest.TransportVersion = &v
			m.Manifest.TunnelCount = &count
			m.Manifest.RecoveryVersion = nil
			m.Manifest.Tunnels[1] = RuntimeTunnel{}
			m.Secrets[1] = RuntimeSecret{}
			m.Manifest.Tunnels[0].InsideCIDR = ""
			m.Manifest.Tunnels[0].CustomerInsideAddress = ""
			m.Manifest.Tunnels[0].CloudInsideAddress = ""
		}
		m.Policy.Grants = []RuntimeGrant{{Source: m.Manifest.LocalPrefixes[0], Destination: m.Manifest.RemotePrefixes[0], Protocol: "tcp", PortLow: 8080, PortHigh: 8080}, {Source: m.Manifest.LocalPrefixes[0], Destination: m.Manifest.RemotePrefixes[0], Protocol: "udp", PortLow: 9000, PortHigh: 9000}}
		runtimeReseal(&m)
		e, grants, err := runtimeMaterialEntry(m, c.config.OrgID, c.config.GatewayID, old.Allocation.Namespace)
		if err != nil {
			t.Fatal("real GCP contract", err)
		}
		a := c.active[old.Allocation.ConnectionID]
		a.Environment.LocalIngressIndices = []int{2}
		e.Phase = RuntimeApplied
		for i := 0; i < e.Allocation.activeTunnelCount(); i++ {
			e.Engines[i].LocalAddress = a.Environment.Underlays[i].LocalAddress
			e.Observed[i] = Ownership{Namespace: e.Allocation.Namespace, InterfaceName: e.Allocation.Tunnels[i].Name, InterfaceIndex: old.Observed[i].InterfaceIndex, XFRMID: e.Allocation.Tunnels[i].XFRMID}
		}
		if n == 0 {
			e.BGPRoutes = old.BGPRoutes
			e.BGPProcess = old.BGPProcess
			a.Delivery = RuntimeDelivery{}
		} else {
			a.Environment.Underlays[1] = RuntimeUnderlay{}
			a.Delivery = m.RuntimeDelivery
		}
		a.Entry, a.Grants = e, grants
		a.Identity = PermitLeaseIdentity{DeliveryID: m.ID, Binding: e.Engines[0].Binding, PolicyHash: m.Policy.Hash}
		c.active[e.Allocation.ConnectionID] = a
		keep[e.Allocation.ConnectionID] = true
		outE = append(outE, e)
		outM = append(outM, m)
	}
	for id := range c.active {
		if !keep[id] {
			delete(c.active, id)
		}
	}

	// Model complete current owned link/address/route inventory through the real
	// KernelApplier parser, including single-slot unnumbered Classic.
	c.kernel = &KernelApplier{namespace: c.namespace, run: func(ctx context.Context, args ...string) ([]byte, error) {
		objects := []map[string]any{}
		for _, entry := range outE {
			f := newRecoveryKernelFixture()
			f.p = entry.Allocation
			f.owned = entry.Observed
			f.mtu = [2]uint64{1382, 1382}
			f.routes = [2]map[string]bool{{}, {}}
			for i := 0; i < entry.Allocation.activeTunnelCount(); i++ {
				if entry.ContractVersion == 3 {
					f.routes[i][entry.Allocation.Tunnels[i].BGP.Peer.String()+"/32"] = true
				} else if i == 0 {
					for _, p := range entry.Allocation.Tunnels[i].RemotePrefixes {
						f.routes[i][p.String()] = true
					}
				}
			}
			if entry.ContractVersion == 3 {
				for _, r := range entry.BGPRoutes.Owned {
					f.routes[int(r.Slot)-1][r.Prefix.String()] = true
				}
			}
			raw, err := f.run(ctx, args...)
			if err != nil {
				return nil, err
			}
			part := []map[string]any{}
			if err = json.Unmarshal(raw, &part); err != nil {
				return nil, err
			}
			for _, o := range part {
				if o["ifname"] == "" {
					continue
				}
				if entry.ContractVersion == 4 && strings.Contains(strings.Join(args, " "), "addr show") {
					continue
				}
				objects = append(objects, o)
			}
		}
		return json.Marshal(objects)
	}}
	return outE, outM
}
func gcpMaintenanceRestoredClassic(t *testing.T, c *RuntimeController, entries []RuntimeJournalEntry, materials []RuntimeMaterial) ([]RuntimeJournalEntry, []RuntimeMaterial) {
	entries, materials = gcpMaintenancePair(t, c, entries, materials)
	old := entries[1]
	next := old
	next.Allocation.Generation = uuid.New()
	next.Allocation.Tunnels[0].Alias = KernelTunnelAlias(next.Allocation.Generation, next.Allocation.Tunnels[0].TunnelID)
	boot := uuid.NewString()
	next.Restoration = &RuntimeRestoration{BootID: boot, Epoch: 1, Retired: []RuntimeRetiredEpoch{{Entry: flattenedRestorationEntry(old), NewBootID: boot, NewNamespace: next.Allocation.Namespace, NewGeneration: next.Allocation.Generation, Termination: "supervisor-confirmed-runtime-stop", EvidenceDigest: stringDigest([]byte("modeled consumed receipt, no host authority"))}}}
	if !validRestoration(next) {
		t.Fatal("restored Classic fixture invalid")
	}
	entries[1] = next
	a := c.active[next.Allocation.ConnectionID]
	a.Entry = next
	c.active[next.Allocation.ConnectionID] = a
	return entries, materials
}
func TestGCPMaintainedRestoredClassic(t *testing.T) {
	r := newRenewalCycleRigInput(t, true, gcpMaintenanceRestoredClassic)
	old := r.entries[1]
	r.phase = "maintenance"
	results, err := r.c.maintainIPsecRuntime(context.Background(), r.materials, maintenanceAuthority(r), func() bool { return true })
	if err != nil || len(results) != 2 {
		t.Fatalf("results%d err%v", len(results), err)
	}
	got := r.c.active[old.Allocation.ConnectionID].Entry
	if !reflect.DeepEqual(got, old) || got.Allocation.Generation == r.materials[1].ID || !validRestoration(got) {
		t.Fatal("restored Classic generation/history replaced")
	}
}
func TestGCPMaintainedHAClassicPair(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(map[bool]string{false: "HA_first", true: "Classic_first"}[reverse], func(t *testing.T) {
			r := newRenewalCycleRigInput(t, true, gcpMaintenancePair)
			r.target = r.entries[1].Allocation.ConnectionID
			mats := append([]RuntimeMaterial{}, r.materials...)
			if reverse {
				mats[0], mats[1] = mats[1], mats[0]
			}
			old := map[uuid.UUID]runtimeActive{}
			deadlines := map[uuid.UUID]time.Duration{}
			for id, a := range r.c.active {
				old[id] = a
				deadlines[id] = a.Authority.deadline
			}
			commits := 0
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) { commits++; return replace(ctx, in) }
			r.phase = "maintenance"
			results, err := r.c.maintainIPsecRuntime(context.Background(), mats, maintenanceAuthority(r), func() bool { return true })
			if err != nil || len(results) != 2 || len(r.c.active) != 2 {
				t.Fatalf("results=%d active=%d err=%v", len(results), len(r.c.active), err)
			}
			r.charge("report_ack", time.Duration(len(results))*600*time.Millisecond)
			if commits != 1 || r.firstLapse != 0 || r.expiryEmpty || r.applicationDenied[r.target] || *r.now >= 55*time.Second {
				t.Fatalf("budget elapsed=%s commits=%d lapse=%s", *r.now, commits, r.firstLapse)
			}
			for i, m := range mats {
				a := r.c.active[m.Manifest.ConnectionID]
				if a.Authority == old[m.Manifest.ConnectionID].Authority || !reflect.DeepEqual(a.Entry, old[m.Manifest.ConnectionID].Entry) {
					t.Fatal("changed intent or unrenewed authority")
				}
				if old[m.Manifest.ConnectionID].Authority.deadline != deadlines[m.Manifest.ConnectionID] {
					t.Fatal("maintenance extended original authority")
				}
				report := results[i].Report
				if m.Manifest.ProfileID == GCPClassicStaticProfile {
					if report.TransportVersion == nil || *report.TransportVersion != 1 || report.TunnelCount == nil || *report.TunnelCount != 1 || report.Tunnels[1] != (RuntimeTunnelStatus{}) {
						t.Fatal("Classic report lost exact inactive zero")
					}
				}
			}
			t.Logf("modeled two-profile elapsed=%s freshCP=%d commits=%d", *r.now, r.leases, commits)
		})
	}
}

func TestGCPMaintainedStrictRefusal(t *testing.T) {
	for _, mode := range []string{"inactive_slot", "wrong_profile", "policy", "expired", "native", "wrong_nonce", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			r := newRenewalCycleRigInput(t, true, gcpMaintenancePair)
			mats := append([]RuntimeMaterial{}, r.materials...)
			target := mats[1].Manifest.ConnectionID
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "inactive_slot":
				mats[1].Manifest.Tunnels[1].Slot = 2
				runtimeReseal(&mats[1])
			case "wrong_profile":
				mats[1].Manifest.ProfileID = GCPHABGPProfile
				runtimeReseal(&mats[1])
			case "policy":
				mats[1].Policy.Grants = []RuntimeGrant{{Source: mats[1].Manifest.LocalPrefixes[0], Destination: mats[1].Manifest.RemotePrefixes[0], Protocol: "tcp", PortLow: 53, PortHigh: 53}}
				runtimeReseal(&mats[1])
			case "expired":
				r.c.active[target].Authority.Invalidate()
			case "native":
				old := r.c.prove
				r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
					if e.Allocation.ConnectionID == target {
						return ErrRuntimeController
					}
					return old(ctx, e, env)
				}
			case "wrong_nonce":
				old := r.c.client
				r.c.client = maintenanceLeaseFunc(func(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
					out, err := old.RenewIPsecLease(ctx, id, q)
					out.Nonce = "wrong"
					return out, err
				})
			case "cancel":
				cancel()
			}
			r.phase = "maintenance"
			out, err := r.c.maintainIPsecRuntime(ctx, mats, maintenanceAuthority(r), func() bool { return true })
			for _, got := range out {
				if got.Report.DeliveryID == mats[1].ID {
					t.Fatal("unsafe Classic maintenance result")
				}
			}
			if mode == "inactive_slot" || mode == "wrong_profile" || mode == "wrong_nonce" || mode == "cancel" {
				if err == nil || len(out) != 0 {
					t.Fatal("invalid batch accepted")
				}
			}
			if a, ok := r.c.active[target]; ok && a.Authority != nil && mode != "cancel" {
				if mode == "policy" || mode == "expired" || mode == "native" {
					t.Fatal("refused Classic authority retained")
				}
			}
		})
	}
}
