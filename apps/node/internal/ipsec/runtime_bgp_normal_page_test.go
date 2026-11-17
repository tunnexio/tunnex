package ipsec

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
)

func TestNormalPageDesktopBGPConvergencePreservesSession(t *testing.T) {
	for _, installed := range []bool{false, true} {
		name := "first_learned_route"
		if installed {
			name = "selected_slot_changes"
		}
		t.Run(name, func(t *testing.T) {
			r, id, process, kernel := desktopBGPRenewalRig(t, installed)
			old := r.c.active[id]
			deadline := old.Authority.deadline
			var material RuntimeMaterial
			for _, m := range r.materials {
				if m.Manifest.ConnectionID == id {
					material = m
				}
			}
			target := routeTupleFixture(old.Entry, 2)
			process.routes = []bgpengine.LearnedRoute{{Prefix: target.Prefix, Slot: 2}}
			ordinaryBefore := map[string]time.Duration{}
			for _, name := range []string{guardLeaseName(id), guardReplyLeaseName(id), guardSALeaseName(id)} {
				ordinaryBefore[name] = r.installed[name]
				if ordinaryBefore[name] <= *r.now {
					t.Fatal("fixture did not begin with finite live ordinary permit")
				}
			}
			lease := r.c.client
			calls := 0
			r.c.client = maintenanceLeaseFunc(func(ctx context.Context, connection uuid.UUID, req RuntimeLeaseRequest) (RuntimeLease, error) {
				if connection == id {
					calls++
					if !kernel.routes[1][target.Prefix.String()] || !r.applicationDenied[id] {
						t.Fatal("route change was not reconciled with applications denied before fresh lease")
					}
				}
				return lease.RenewIPsecLease(ctx, connection, req)
			})
			result, err := r.c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{material}, maintenanceAuthority(r), func() bool { return true })
			current, ok := r.c.active[id]
			t.Logf("result err=%v results=%d retained=%t processClosed=%t leaseCalls=%d appDenied=%t oldDeadline=%v now=%v", err, len(result), ok, process.closed, calls, r.applicationDenied[id], deadline, *r.now)
			if err != nil || len(result) != 1 || !ok || process.closed || r.c.bgpProcesses[old.Entry.DeliveryID] != process {
				t.Fatal("normal-page route convergence retired a healthy authorized desktop BGP owner")
			}
			if calls != 1 || old.Authority.deadline != deadline || current.Authority == old.Authority || r.applicationDenied[id] || !reflect.DeepEqual(current.Grants, old.Grants) {
				t.Fatal("normal-page route reconciliation did not require a fresh permit or preserve original finite authority")
			}
			if !reflect.DeepEqual(current.Entry.BGPRoutes.Owned, []RuntimeBGPRouteTuple{target}) || !kernel.routes[1][target.Prefix.String()] || kernel.routes[0][target.Prefix.String()] {
				t.Fatal("normal page did not bind selected route exactly")
			}
			for name := range ordinaryBefore {
				if r.installed[name] <= *r.now {
					t.Fatal("fresh ordinary permit not installed", name)
				}
			}
		})
	}
}

// Keep the real FQDN policy/lease identity path in the normal-page convergence
// regression; route repair alone is never permission to reuse a DNS generation.
func TestNormalPageFQDNBGPConvergencePreservesSession(t *testing.T) {
	r, client := fqdnExpiryTurnoverRig(t)
	old := r.c.active[r.target]
	deadline := old.Authority.deadline
	oldFQDNDeadline := old.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(old.FQDNLeaseDescriptors[0])]
	page := staleFQDNPage(r, client)
	process := r.c.bgpProcesses[old.Entry.DeliveryID].(*bgpSessionFixture)
	target := routeTupleFixture(old.Entry, 2)
	process.routes = []bgpengine.LearnedRoute{{Prefix: target.Prefix, Slot: 2}}
	result, err := r.c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{page}, maintenanceAuthority(r), func() bool { return true })
	current, ok := r.c.active[r.target]
	t.Logf("result err=%v results=%d retained=%t processClosed=%t fetches=%d leases=%d", err, len(result), ok, process.closed, client.fetched, len(client.requests))
	if err != nil || len(result) != 1 || !ok || process.closed || r.c.bgpProcesses[old.Entry.DeliveryID] != process {
		t.Fatal("FQDN normal-page convergence retired healthy BGP owner")
	}
	if old.Authority.deadline != deadline || old.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(old.FQDNLeaseDescriptors[0])] != oldFQDNDeadline || current.Authority == old.Authority || current.Identity.PolicyHash != client.material.Policy.Hash || client.fetched != 1 || len(client.requests) != 2 || client.requests[0].Nonce == client.requests[1].Nonce || !reflect.DeepEqual(current.FQDNLeaseDescriptors, client.material.Policy.FQDNGrants) {
		t.Fatal("convergence bypassed exact independent FQDN authorization")
	}
	if !reflect.DeepEqual(current.Entry.BGPRoutes.Owned, []RuntimeBGPRouteTuple{target}) {
		t.Fatal("wrong selected route")
	}
	for _, g := range current.Grants {
		if g.FQDNManaged {
			if _, e := current.Authority.RemainingFQDNForApply(current.Identity, guardFQDNGrantDigest(g), time.Millisecond); e != nil || r.installed[guardFQDNSetName(g)] <= *r.now || r.installed[guardFQDNSetName(g)] > current.Authority.fqdnDeadlines[guardFQDNGrantDigest(g)] {
				t.Fatal("fresh exact FQDN native member missing", e)
			}
		}
	}
}

func TestNormalPageBGPConvergenceRejectsLostProof(t *testing.T) {
	for _, mode := range []string{"original_lease_expired", "desktop_revoked", "process_dead", "qualification_lost", "rib_read_refused", "health_unknown", "material_policy_changed", "second_route_change", "cp_revoked", "post_cp_route_change", "fresh_nonce_mismatch"} {
		t.Run(mode, func(t *testing.T) {
			r, id, process, kernel := desktopBGPRenewalRig(t, true)
			old := r.c.active[id]
			deadline := old.Authority.deadline
			var material RuntimeMaterial
			for _, m := range r.materials {
				if m.Manifest.ConnectionID == id {
					material = m
				}
			}
			target := routeTupleFixture(old.Entry, 2)
			process.routes = []bgpengine.LearnedRoute{{Prefix: target.Prefix, Slot: 2}}
			calls, reconciles, retryRefusals := 0, 0, 0
			r.c.config.Diagnostic = func(d RuntimeDiagnostic) {
				if d.Operation == "maintenance_bgp_route_change" && d.ConnectionID == id {
					if d.Stage == "route_change_reconcile_once" {
						reconciles++
					}
					if d.Stage == "route_change_ineligible" {
						retryRefusals++
					}
				}
			}
			current := true
			baseObserve := r.c.recoveryObserve
			r.c.recoveryObserve = func(ctx context.Context, e RuntimeJournalEntry) [2]string {
				health := baseObserve(ctx, e)
				if e.Allocation.ConnectionID == id {
					switch mode {
					case "qualification_lost":
						current = false
					case "health_unknown":
						health[0] = "unknown"
					}
				}
				return health
			}
			switch mode {
			case "original_lease_expired":
				*r.now = deadline + time.Second
			case "desktop_revoked":
				r.c.desktopObserve = func(context.Context, []GuardGrant) ([]GuardGrant, error) { return nil, ErrRuntimeController }
			case "process_dead":
				process.closed = true
			case "rib_read_refused":
				process.routesError = true
			case "material_policy_changed":
				material.Policy.Hash = strings.Repeat("f", 64)
			case "second_route_change":
				// Change the next RIB before it is read, after the first selected
				// route was durably reconciled. This exercises the retry guard,
				// not the separate post-CP drift fence.
				process.alive = func() bool {
					if kernel.routes[1][target.Prefix.String()] {
						process.routes = []bgpengine.LearnedRoute{{Prefix: target.Prefix, Slot: 1}}
					}
					return !process.closed
				}
			}
			base := r.c.client
			r.c.client = maintenanceLeaseFunc(func(ctx context.Context, connection uuid.UUID, req RuntimeLeaseRequest) (RuntimeLease, error) {
				if connection == id {
					calls++
					if !kernel.routes[1][target.Prefix.String()] || !r.applicationDenied[id] {
						t.Fatal("fresh lease attempted before deny-first exact route reconciliation")
					}
					if mode == "cp_revoked" {
						return RuntimeLease{}, ErrRuntimeController
					}
					if mode == "post_cp_route_change" {
						process.routes = []bgpengine.LearnedRoute{{Prefix: target.Prefix, Slot: 1}}
					}
				}
				lease, err := base.RenewIPsecLease(ctx, connection, req)
				if connection == id && mode == "fresh_nonce_mismatch" {
					lease.Nonce = uuid.NewString()
				}
				return lease, err
			})
			results, err := r.c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{material}, maintenanceAuthority(r), func() bool { return current })
			if len(results) != 0 {
				t.Fatal("unsafe target returned applied result", err)
			}
			if _, ok := r.c.active[id]; ok || !process.closed || r.c.bgpProcesses[old.Entry.DeliveryID] != nil || !r.applicationDenied[id] {
				t.Fatalf("unsafe current/CP proof retained owner or desktop exports: mode=%s err=%v active=%t closed=%t denied=%t", mode, err, ok, process.closed, r.applicationDenied[id])
			}
			for _, name := range []string{guardLeaseName(id), guardReplyLeaseName(id), guardSALeaseName(id)} {
				if r.installed[name] > *r.now {
					t.Fatal("unsafe proof retained native authority", name)
				}
			}
			if old.Authority.deadline != deadline {
				t.Fatal("old permit deadline changed")
			}
			wantReconciles, wantCalls := 0, 0
			switch mode {
			case "second_route_change":
				wantReconciles = 1
			case "cp_revoked", "post_cp_route_change", "fresh_nonce_mismatch":
				wantReconciles, wantCalls = 1, 1
			}
			if reconciles != wantReconciles || calls != wantCalls {
				t.Fatalf("reconcile or lease retried unexpectedly: reconcile=%d/%d lease=%d/%d", reconciles, wantReconciles, calls, wantCalls)
			}
			if mode == "second_route_change" && retryRefusals != 1 {
				t.Fatalf("second route change did not refuse the bounded retry: %d", retryRefusals)
			}
		})
	}
}

func TestMaintenanceCurrentBGPDiagnosticPreservesPredicateOrder(t *testing.T) {
	for _, mode := range []string{"process_after", "qualification_after", "route_changed"} {
		t.Run(mode, func(t *testing.T) {
			r, id, process, _ := desktopBGPRenewalRig(t, true)
			old := r.c.active[id]
			deadline := old.Authority.deadline
			nativeBefore := map[string]time.Duration{}
			for k, v := range r.installed {
				nativeBefore[k] = v
			}
			journalBefore, err := r.c.journal.Entries()
			if err != nil {
				t.Fatal(err)
			}
			after, aliveCalls, currentCalls := false, 0, 0
			baseObserve := r.c.recoveryObserve
			r.c.recoveryObserve = func(ctx context.Context, e RuntimeJournalEntry) [2]string {
				health := baseObserve(ctx, e)
				after = true
				return health
			}
			process.alive = func() bool { aliveCalls++; return !(after && mode == "process_after") }
			current := func() bool { currentCalls++; return !(after && mode == "qualification_after") }
			if mode == "route_changed" {
				target := routeTupleFixture(old.Entry, 2)
				process.routes = []bgpengine.LearnedRoute{{Prefix: target.Prefix, Slot: 2}}
			}
			var diagnostic []RuntimeDiagnostic
			r.c.config.Diagnostic = func(d RuntimeDiagnostic) {
				if d.Operation == "maintenance_current" {
					diagnostic = append(diagnostic, d)
				}
			}
			err = r.c.maintenanceCurrent(context.Background(), old, current)
			if err == nil || errors.Is(err, errMaintenanceBGPRouteChanged) != (mode == "route_changed") {
				t.Fatal("diagnostic changed typed refusal", err)
			}
			wantStage := "maintenance_current_bgp_" + mode
			if len(diagnostic) != 1 || diagnostic[0].Stage != wantStage || !diagnostic[0].Refused {
				t.Fatalf("wrong branch diagnostic: %+v want %s", diagnostic, wantStage)
			}
			wantCurrent := 2
			if mode == "process_after" {
				wantCurrent = 1
			}
			if aliveCalls != 2 || currentCalls != wantCurrent {
				t.Fatalf("predicate order/count changed: process=%d qualification=%d/%d", aliveCalls, currentCalls, wantCurrent)
			}
			journalAfter, err := r.c.journal.Entries()
			if err != nil {
				t.Fatal(err)
			}
			if old.Authority.deadline != deadline || !reflect.DeepEqual(r.c.active[id], old) || !reflect.DeepEqual(r.installed, nativeBefore) || !reflect.DeepEqual(journalBefore, journalAfter) {
				t.Fatal("read-only diagnostic changed authority/native/journal state")
			}
		})
	}
}

func TestMaintenanceBGPDiagnosticVocabularyIsClosed(t *testing.T) {
	for _, stage := range []string{"maintenance_current_bgp_process_after", "maintenance_current_bgp_qualification_after", "maintenance_current_bgp_route_changed"} {
		if !validRuntimeDiagnostic("maintenance_current", stage) || validRuntimeDiagnostic("maintenance_current", stage+" untrusted") {
			t.Fatal("diagnostic is not fixed", stage)
		}
	}
	for _, stage := range []string{"route_change_reconcile_once", "route_change_ineligible"} {
		if !validRuntimeDiagnostic("maintenance_bgp_route_change", stage) || validRuntimeDiagnostic("maintenance_bgp_route_change", stage+" untrusted") || validRuntimeDiagnostic("maintenance", stage) {
			t.Fatal("decision diagnostic is not operation-scoped", stage)
		}
	}
}
