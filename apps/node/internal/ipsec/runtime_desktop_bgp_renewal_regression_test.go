package ipsec

import (
	"context"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
)

// Use the real retained owner, finite permit, journal and guard machinery. Only
// native WireGuard/FRR/kernel observations are synthetic.
func desktopBGPRenewalRig(t *testing.T, installed bool) (*renewalCycleRig, uuid.UUID, *bgpSessionFixture, *recoveryKernelFixture) {
	t.Helper()
	r := newRenewalCycleRigInput(t, true)
	var id uuid.UUID
	for i := range r.materials {
		m := &r.materials[i]
		if m.Manifest.ProfileID != "aws-bgp-ipv4-v1" {
			continue
		}
		id = m.Manifest.ConnectionID
		d := desktopGrantFixture()
		d.Destination = netip.PrefixFrom(netip.MustParsePrefix(m.Manifest.RemotePrefixes[0]).Addr().Next(), 32).String()
		m.Policy.DesktopGrants = []RuntimeDesktopGrant{d}
		a := r.c.active[id]
		_, grants, err := runtimeMaterialEntry(*m, r.c.config.OrgID, r.c.config.GatewayID, a.Environment.Namespace)
		if err != nil {
			t.Fatal(err)
		}
		for j := range grants {
			if grants[j].DesktopDeviceID != uuid.Nil {
				grants[j].DesktopIngressIndex = 7777
			}
		}
		a.Grants = grants
		r.c.active[id] = a
		break
	}
	if id == uuid.Nil {
		t.Fatal("missing AWS BGP fixture")
	}
	a := r.c.active[id]
	kernel := newRecoveryKernelFixture()
	kernel.p, kernel.owned = a.Entry.Allocation, a.Entry.Observed
	for i, tunnel := range kernel.p.Tunnels {
		kernel.routes[i] = map[string]bool{netip.PrefixFrom(tunnel.BGP.Peer, 32).String(): true}
	}
	for _, route := range a.Entry.BGPRoutes.Owned {
		kernel.routes[int(route.Slot)-1][route.Prefix.String()] = true
	}
	r.c.kernel = kernel.applier()
	if !installed {
		if err := ReconcileBGPRoutes(context.Background(), r.c.journal, r.c.kernel, a.Entry.DeliveryID.String(), nil); err != nil {
			t.Fatal("initial empty AWS RIB", err)
		}
		var err error
		r.entries, err = r.c.journal.Entries()
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range r.entries {
			if entry.Allocation.ConnectionID == id {
				a.Entry = entry
			}
		}
		r.c.active[id] = a
	}
	r.c.desktopObserve = func(_ context.Context, in []GuardGrant) ([]GuardGrant, error) {
		out := append([]GuardGrant(nil), in...)
		for i := range out {
			if out[i].DesktopDeviceID != uuid.Nil {
				out[i].DesktopIngressIndex = 7777
			}
		}
		return out, nil
	}
	interfaces := r.c.guard.reader.interfaces
	r.c.guard.reader.interfaces = func() ([]GuardInterface, error) {
		out, err := interfaces()
		return append(out, GuardInterface{Name: "wg0", Index: 7777}), err
	}
	r.c.bgpDesktopExports = map[uuid.UUID][]netip.Prefix{a.Entry.DeliveryID: {netip.MustParsePrefix("10.99.0.7/32")}}
	if err := r.c.installActive(context.Background(), r.entries); err != nil {
		t.Fatal("initial desktop guard", err)
	}
	r.phase = "maintenance"
	return r, id, r.c.bgpProcesses[a.Entry.DeliveryID].(*bgpSessionFixture), kernel
}

func TestDesktopPriorityRenewalReconcilesLearnedBGPBeforeLease(t *testing.T) {
	for _, installed := range []bool{false, true} {
		name := "first_aws_route"
		if installed {
			name = "best_path_changes_slot"
		}
		t.Run(name, func(t *testing.T) {
			r, id, process, kernel := desktopBGPRenewalRig(t, installed)
			old := r.c.active[id]
			deadline := old.Authority.deadline
			target := routeTupleFixture(old.Entry, 2)
			process.routes = []bgpengine.LearnedRoute{{Prefix: target.Prefix, Slot: 2}}
			if err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil); err != nil {
				t.Fatalf("healthy learned route blocked priority renewal: %v", err)
			}
			current, ok := r.c.active[id]
			if process.closed || r.c.bgpProcesses[old.Entry.DeliveryID] != process || !ok {
				t.Fatal("normal AWS route convergence closed the healthy desktop-export session")
			}
			if !reflect.DeepEqual(current.Entry.BGPRoutes.Owned, []RuntimeBGPRouteTuple{target}) || !kernel.routes[1][target.Prefix.String()] || kernel.routes[0][target.Prefix.String()] {
				t.Fatal("renewal did not reconcile and bind the exact selected AWS route")
			}
			if old.Authority.deadline != deadline || current.Authority == old.Authority || r.applicationDenied[id] || !reflect.DeepEqual(current.Grants, old.Grants) {
				t.Fatal("renewal changed original authority or lost the authorized desktop grants")
			}
		})
	}
}

func TestDesktopPriorityRenewalRouteChangeStillClosesLostAuthority(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		name := "expired_original_lease"
		if revoked {
			name = "revoked_desktop_identity"
		}
		t.Run(name, func(t *testing.T) {
			r, id, process, _ := desktopBGPRenewalRig(t, false)
			old := r.c.active[id]
			deadline := old.Authority.deadline
			target := routeTupleFixture(old.Entry, 2)
			process.routes = []bgpengine.LearnedRoute{{Prefix: target.Prefix, Slot: 2}}
			if revoked {
				r.c.desktopObserve = func(context.Context, []GuardGrant) ([]GuardGrant, error) { return nil, ErrRuntimeController }
			} else {
				*r.now = deadline + time.Second
			}
			_ = r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil)
			if _, ok := r.c.active[id]; ok || !process.closed || r.c.bgpProcesses[old.Entry.DeliveryID] != nil || !r.applicationDenied[id] {
				t.Fatal("lost authority kept desktop application access or BGP exports")
			}
			if old.Authority.deadline != deadline {
				t.Fatal("original permit deadline extended")
			}
		})
	}
}

func TestDesktopPriorityRenewalReconciledRouteStillRequiresFreshCPProof(t *testing.T) {
	for _, routeChangesAgain := range []bool{false, true} {
		name := "cp_revoked_permission"
		if routeChangesAgain {
			name = "route_changes_after_cp_reply"
		}
		t.Run(name, func(t *testing.T) {
			r, id, process, kernel := desktopBGPRenewalRig(t, false)
			old := r.c.active[id]
			deadline := old.Authority.deadline
			target := routeTupleFixture(old.Entry, 2)
			process.routes = []bgpengine.LearnedRoute{{Prefix: target.Prefix, Slot: 2}}
			base, calls := r.c.client, 0
			r.c.client = maintenanceLeaseFunc(func(ctx context.Context, connection uuid.UUID, req RuntimeLeaseRequest) (RuntimeLease, error) {
				if connection != id {
					return base.RenewIPsecLease(ctx, connection, req)
				}
				calls++
				if !kernel.routes[1][target.Prefix.String()] || !r.applicationDenied[id] || old.Authority.deadline != deadline {
					t.Fatal("route change restored app access or extended authority before CP renewal")
				}
				if !routeChangesAgain {
					return RuntimeLease{}, ErrRuntimeController
				}
				process.routes = []bgpengine.LearnedRoute{{Prefix: target.Prefix, Slot: 1}}
				return base.RenewIPsecLease(ctx, connection, req)
			})
			err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil)
			if err == nil || calls != 1 {
				t.Fatal("changed/revoked CP proof was accepted or retried", err, calls)
			}
			if _, ok := r.c.active[id]; ok || !process.closed || r.c.bgpProcesses[old.Entry.DeliveryID] != nil || !r.applicationDenied[id] {
				t.Fatal("CP revocation or post-CP route drift retained desktop forwarding/exports")
			}
			if old.Authority.deadline != deadline {
				t.Fatal("original permit deadline extended")
			}
		})
	}
}

func TestDesktopBGPReconcileDiagnosticStageIsClosed(t *testing.T) {
	if !validRuntimeDiagnostic("maintenance", "maintenance_retained_bgp_reconcile") || validRuntimeDiagnostic("maintenance", "maintenance_retained_bgp_reconcile untrusted") {
		t.Fatal("retained BGP reconciliation diagnostic vocabulary is not exact")
	}
}
