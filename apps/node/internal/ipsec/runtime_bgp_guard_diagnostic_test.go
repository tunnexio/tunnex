package ipsec

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
)

func bgpLeafDiagnostic(t *testing.T, events []RuntimeDiagnostic, operation, stage string, id uuid.UUID, refused bool) RuntimeDiagnostic {
	t.Helper()
	var found []RuntimeDiagnostic
	for _, event := range events {
		if event.Operation == operation && event.Stage == stage {
			found = append(found, event)
		}
		if !validRuntimeDiagnostic(event.Operation, event.Stage) || event.ElapsedMillis < 0 {
			t.Fatal("invalid diagnostic", event)
		}
	}
	if len(found) != 1 || found[0].ConnectionID != id || found[0].Refused != refused {
		t.Fatalf("missing distinct leaf %s/%s refused=%t: %+v", operation, stage, refused, events)
	}
	return found[0]
}

// The same previously opaque installer stage can mean a recoverable RIB
// change or a refused native/FRR/current-authority proof. These cases use the
// real guard implementation and keep all authority, journal and routes intact.
func TestBGPGuardDiagnosticCandidateLeaves(t *testing.T) {
	for _, mode := range []string{"healthy", "prior_current", "prior_permit", "process", "peer_summary", "routes", "native_health", "current_after_observation", "context_after_observation", "permit_after_observation", "route_change_required", "native_guard"} {
		t.Run(mode, func(t *testing.T) {
			r, _, id, process, kernel := exactPageBGPConvergenceRig(t, true)
			a := r.c.active[id]
			old := cloneMaintenanceActive(a)
			current := func() bool { return true }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			health := [2]string{"up", "up"}
			observe := func() [2]string { return health }
			switch mode {
			case "prior_current":
				current = func() bool { return false }
			case "prior_permit":
				*r.now = old.Authority.deadline + time.Second
			case "process":
				process.closed = true
			case "peer_summary":
				process.observationError = true
			case "routes":
				process.routesError = true
			case "native_health":
				health[0] = "unknown"
			case "current_after_observation":
				calls := 0
				current = func() bool { calls++; return calls == 1 }
			case "context_after_observation":
				observe = func() [2]string { cancel(); return health }
			case "permit_after_observation":
				observe = func() [2]string { *r.now = old.Authority.deadline + time.Second; return health }
			case "route_change_required":
				target := routeTupleFixture(a.Entry, 2)
				process.routes = []bgpengine.LearnedRoute{{Prefix: target.Prefix, Slot: 2}}
			case "native_guard":
				kernel.badMetric = true
			}
			before := assemblyClone(r.c.active)
			journalBefore, _ := r.c.journal.Entries()
			deadline := old.Authority.deadline
			mutations := kernel.mutations
			var events []RuntimeDiagnostic
			r.c.config.Diagnostic = func(d RuntimeDiagnostic) { events = append(events, d) }
			_, err := r.c.maintenanceBGPGuardObserved(ctx, a, old, 40*time.Second, current, observe)
			if mode == "healthy" {
				if err != nil || len(events) != 0 {
					t.Fatal("healthy guard changed", err, events)
				}
			} else {
				if err == nil {
					t.Fatal("refused proof accepted")
				}
				recoverable := mode == "route_change_required"
				if errors.Is(err, errMaintenanceBGPRouteChanged) != recoverable {
					t.Fatal("error class changed", err)
				}
				event := bgpLeafDiagnostic(t, events, "bgp_candidate_guard", mode, id, !recoverable)
				if mode == "context_after_observation" && event.ContextState != "canceled" {
					t.Fatal("child context hidden", event)
				}
				if mode == "native_guard" {
					bgpLeafDiagnostic(t, events, "bgp_native_guard", "tunnel_mtu", id, true)
				}
			}
			journalAfter, _ := r.c.journal.Entries()
			if !reflect.DeepEqual(before, r.c.active) || r.c.active[id].Authority != old.Authority || old.Authority.deadline != deadline || !reflect.DeepEqual(journalBefore, journalAfter) || kernel.mutations != mutations {
				t.Fatal("diagnostic changed native owner, finite authority or journal")
			}
		})
	}
}

func TestBGPGuardDiagnosticRetainedLeaves(t *testing.T) {
	for _, mode := range []string{"desktop_ownership", "native_health", "healthy_tunnel", "tunnel_mtu"} {
		t.Run(mode, func(t *testing.T) {
			r, _, id, _, kernel := exactPageBGPConvergenceRig(t, true)
			a := r.c.active[id]
			health := [2]string{"up", "up"}
			switch mode {
			case "desktop_ownership":
				r.c.desktopObserve = func(context.Context, []GuardGrant) ([]GuardGrant, error) { return nil, ErrRuntimeController }
			case "native_health":
				health[1] = "unknown"
			case "healthy_tunnel":
				health = [2]string{"down", "down"}
			case "tunnel_mtu":
				kernel.badMetric = true
			}
			before := assemblyClone(r.c.active)
			journalBefore, _ := r.c.journal.Entries()
			mutations := kernel.mutations
			var events []RuntimeDiagnostic
			r.c.config.Diagnostic = func(d RuntimeDiagnostic) { events = append(events, d) }
			if _, err := r.c.bgpGuardWithStatuses(context.Background(), a, 40*time.Second, health); err == nil {
				t.Fatal("lost native proof accepted")
			}
			bgpLeafDiagnostic(t, events, "bgp_native_guard", mode, id, true)
			if len(events) != 1 {
				t.Fatal("retained owner confused with required candidate", events)
			}
			journalAfter, _ := r.c.journal.Entries()
			if !reflect.DeepEqual(before, r.c.active) || r.c.active[id].Authority != a.Authority || !reflect.DeepEqual(journalBefore, journalAfter) || kernel.mutations != mutations {
				t.Fatal("diagnostic mutated retained owner")
			}
		})
	}
}

func TestBGPGuardDiagnosticExactRetryOutcome(t *testing.T) {
	for _, mode := range []string{"ready_for_retry", "material_fetch", "material_binding", "input"} {
		t.Run(mode, func(t *testing.T) {
			r, client, id, process, kernel := exactPageBGPConvergenceRig(t, true)
			old := r.c.active[id]
			original := assemblyClone(r.c.active)
			target := routeTupleFixture(old.Entry, 2)
			process.routes = []bgpengine.LearnedRoute{{Prefix: target.Prefix, Slot: 2}}
			base := r.c.client
			r.c.client = exactPageConvergenceClient{lease: base.RenewIPsecLease, material: func(ctx context.Context, owner uuid.UUID, revision int64) (RuntimeMaterial, error) {
				if mode == "material_fetch" {
					return RuntimeMaterial{}, ErrRuntimeController
				}
				m, err := client.IPsecMaterial(ctx, owner, revision)
				if mode == "material_binding" {
					m.DesiredRevision++
				}
				return m, err
			}}
			refreshed := map[uuid.UUID]maintenanceItem{id: {}}
			var events []RuntimeDiagnostic
			r.c.config.Diagnostic = func(d RuntimeDiagnostic) { events = append(events, d) }
			current := func() bool { return mode != "input" }
			out, err := r.c.reconcileExactRefreshBGP(context.Background(), r.entries, original, refreshed, current)
			connection := id
			if mode == "ready_for_retry" || mode == "input" {
				connection = uuid.Nil
			}
			bgpLeafDiagnostic(t, events, "bgp_exact_refresh", mode, connection, mode != "ready_for_retry")
			if mode == "ready_for_retry" {
				if err != nil || len(out) != len(original) || !kernel.routes[1][target.Prefix.String()] || process.closed || r.c.active[id].Authority != old.Authority {
					t.Fatal("retry preparation changed", err)
				}
			} else if err == nil || len(out) != 0 {
				t.Fatal("refused retry accepted")
			}
			for owner, prior := range original {
				if current, ok := r.c.active[owner]; ok && (current.Authority != prior.Authority || current.Authority.deadline != prior.Authority.deadline) {
					t.Fatal("retry diagnostics renewed authority")
				}
			}
		})
	}
}

func TestBGPGuardDiagnosticClosedLabels(t *testing.T) {
	for _, operation := range []string{"bgp_candidate_guard", "bgp_native_guard", "bgp_exact_refresh"} {
		for _, stage := range []string{"peer_summary secret", "routes=10.0.0.0/8", "private_key", "ready_for_retry_extra", "password=secret", ""} {
			if validRuntimeDiagnostic(operation, stage) {
				t.Fatal("dynamic diagnostic label admitted", operation, stage)
			}
		}
	}
	if validRuntimeDiagnostic("bgp_native_guard", "route_change_required") || validRuntimeDiagnostic("bgp_candidate_guard", "material_fetch") || validRuntimeDiagnostic("bgp_exact_refresh", "tunnel_mtu") {
		t.Fatal("cross-operation label admitted")
	}
}
