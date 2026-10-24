package ipsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
)

// Preserve real journal/permit/guard and FRR RIB handling for the exact-page
// three-owner path. Only the host inventory readers and kernel commands are
// synthetic; route writes remain stateful and must pass their normal readback.
func exactPageBGPConvergenceRig(t *testing.T, installed bool) (*renewalCycleRig, *fqdnCadenceSubsetClient, uuid.UUID, *bgpSessionFixture, *recoveryKernelFixture) {
	t.Helper()
	r, client := fqdnMultiOwnerCadenceRig(t, "live")
	kernels := map[uuid.UUID]*recoveryKernelFixture{}
	var id uuid.UUID
	for _, e := range r.entries {
		k := newRecoveryKernelFixture()
		k.p, k.owned = e.Allocation, e.Observed
		k.routes = [2]map[string]bool{{}, {}}
		for slot, tunnel := range e.Allocation.Tunnels {
			if e.ContractVersion == 3 {
				id = e.Allocation.ConnectionID
				k.routes[slot][netip.PrefixFrom(tunnel.BGP.Peer, 32).String()] = true
			} else if slot == 0 {
				for _, prefix := range tunnel.RemotePrefixes {
					k.routes[slot][prefix.String()] = true
				}
			}
		}
		if e.BGPRoutes != nil {
			for _, route := range e.BGPRoutes.Owned {
				k.routes[route.Slot-1][route.Prefix.String()] = true
			}
		}
		kernels[e.Allocation.ConnectionID] = k
	}
	if id == uuid.Nil {
		t.Fatal("missing BGP owner")
	}
	r.c.kernel = &KernelApplier{namespace: r.c.namespace, run: func(ctx context.Context, args ...string) ([]byte, error) {
		if len(args) == 12 && args[0] == "-4" && args[1] == "route" {
			for _, k := range kernels {
				for _, tunnel := range k.p.Tunnels {
					if args[5] == tunnel.Name {
						return k.run(ctx, args...)
					}
				}
			}
			return nil, fmt.Errorf("unknown route owner")
		}
		if !strings.HasPrefix(strings.Join(args, " "), "-j") {
			return nil, fmt.Errorf("unexpected non-read command")
		}
		rows := []json.RawMessage{}
		for _, k := range kernels {
			raw, err := k.run(ctx, args...)
			if err != nil {
				return nil, err
			}
			var part []json.RawMessage
			if err = json.Unmarshal(raw, &part); err != nil {
				return nil, err
			}
			rows = append(rows, part...)
		}
		return json.Marshal(rows)
	}}
	old := r.c.active[id]
	process := r.c.bgpProcesses[old.Entry.DeliveryID].(*bgpSessionFixture)
	if !installed {
		if err := ReconcileBGPRoutes(context.Background(), r.c.journal, r.c.kernel, old.Entry.DeliveryID.String(), nil); err != nil {
			t.Fatal("clear initially absent learned route", err)
		}
		var err error
		r.entries, err = r.c.journal.Entries()
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range r.entries {
			if e.Allocation.ConnectionID == id {
				old.Entry = e
			}
		}
		r.c.active[id] = old
		process.routes = nil
	}
	// Re-render the empty/previous RIB before FRR learns its new best route.
	if err := r.c.installActive(context.Background(), r.entries); err != nil {
		t.Fatal("seed exact current guard", err)
	}
	installFQDNCadenceStatusReaders(t, r, nil)
	process.status = &bgpengine.Status{Peers: [2]bgpengine.PeerStatus{{Slot: 1, State: "established", AcceptedPrefixes: 1}, {Slot: 2, State: "established", AcceptedPrefixes: 1}}}
	if !r.c.exactPageRefreshScope() {
		t.Fatal("fixture did not enter exact multiowner scope")
	}
	for _, a := range r.c.active {
		if len(a.FQDNLeaseDescriptors) != 4 {
			t.Fatal("fixture must retain two desktop identities and two answers per owner")
		}
	}
	r.phase = "maintenance"
	return r, client, id, process, kernels[id]
}

type exactPageConvergenceClient struct {
	lease    func(context.Context, uuid.UUID, RuntimeLeaseRequest) (RuntimeLease, error)
	material func(context.Context, uuid.UUID, int64) (RuntimeMaterial, error)
}

func (c exactPageConvergenceClient) RenewIPsecLease(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
	return c.lease(ctx, id, q)
}
func (c exactPageConvergenceClient) IPsecMaterial(ctx context.Context, id uuid.UUID, rev int64) (RuntimeMaterial, error) {
	return c.material(ctx, id, rev)
}

func TestExactPageFQDNBGPConvergencePreservesSession(t *testing.T) {
	for _, installed := range []bool{false, true} {
		t.Run(map[bool]string{false: "first_learned_route", true: "changed_selected_slot"}[installed], func(t *testing.T) {
			r, client, id, process, kernel := exactPageBGPConvergenceRig(t, installed)
			originals := assemblyClone(r.c.active)
			originalDeadlines := map[uuid.UUID]time.Duration{}
			originalFQDNDeadlines := map[uuid.UUID]map[string]time.Duration{}
			for owner, a := range originals {
				originalDeadlines[owner] = a.Authority.deadline
				originalFQDNDeadlines[owner] = map[string]time.Duration{}
				for digest, end := range a.Authority.fqdnDeadlines {
					originalFQDNDeadlines[owner][digest] = end
				}
			}
			old := originals[id]
			generation := old.Entry.BGPProcess
			deadline := old.Authority.deadline
			target := routeTupleFixture(old.Entry, 2)
			process.routes = []bgpengine.LearnedRoute{{Prefix: target.Prefix, Slot: 2}}
			client.publishAt = *r.now
			page := exactPageTestMaterials(t, r, client, false)
			for i := range page {
				if page[i].Manifest.ConnectionID == id {
					page[i] = client.materialAt(id, 1)
				}
			}
			leases := map[uuid.UUID]int{}
			adoptedLeaseBeforeRouteProof := false
			nonces := []string{}
			refetches := 0
			base := r.c.client
			r.c.client = exactPageConvergenceClient{material: func(ctx context.Context, owner uuid.UUID, rev int64) (RuntimeMaterial, error) {
				if owner == id {
					refetches++
				}
				m, err := client.IPsecMaterial(ctx, owner, rev)
				// This isolated RIB case leaves sibling DNS metadata unchanged.
				// The separate split-publication regression covers fresh joiners.
				if owner != id && err == nil {
					m = client.old[owner]
				}
				return m, err
			}, lease: func(ctx context.Context, connection uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
				leases[connection]++
				if connection == id {
					nonces = append(nonces, q.Nonce)
					if leases[id] > 1 && (!kernel.routes[1][target.Prefix.String()] || (!installed && !r.applicationDenied[id])) {
						adoptedLeaseBeforeRouteProof = true
					}
				}
				return base.RenewIPsecLease(ctx, connection, q)
			}}
			reports := map[uuid.UUID]RuntimeStatusReport{}
			results, handled, err := r.c.tryMaintainExactRuntimePage(context.Background(), page, maintenanceAuthority(r), func() bool { return true }, func(_ context.Context, d RuntimeDelivery, report RuntimeStatusReport) error {
				if !kernel.routes[1][target.Prefix.String()] || r.applicationDenied[id] {
					t.Fatal("status/ACK preceded final adopted route and finite authority")
				}
				reports[d.Manifest.ConnectionID] = report
				return nil
			})
			current, ok := r.c.active[id]
			t.Logf("handled=%t err=%v results=%d retained=%t process_closed=%t leases=%v old_owned=%v current_owned=%v", handled, err, len(results), ok, process.closed, leases, old.Entry.BGPRoutes.Owned, current.Entry.BGPRoutes)
			if !handled || err != nil || len(results) != 3 || !ok || process.closed || r.c.bgpProcesses[old.Entry.DeliveryID] != process {
				t.Fatal("exact refresh discarded healthy learned BGP session")
			}
			if !reflect.DeepEqual(current.Entry.BGPProcess, generation) || !reflect.DeepEqual(current.Entry.BGPRoutes.Owned, []RuntimeBGPRouteTuple{target}) || !kernel.routes[1][target.Prefix.String()] || kernel.routes[0][target.Prefix.String()] {
				t.Fatal("exact route convergence replaced process generation or failed owned route adoption")
			}
			persisted, readErr := r.c.journal.Entries()
			if readErr != nil {
				t.Fatal(readErr)
			}
			durableMatches := 0
			for _, e := range persisted {
				if e.DeliveryID == old.Delivery.ID {
					if !reflect.DeepEqual(e, current.Entry) {
						t.Fatal("adopted BGP route was not durably journaled")
					}
					durableMatches++
				}
			}
			if durableMatches != 1 {
				t.Fatal("missing unique durable route owner")
			}
			if adoptedLeaseBeforeRouteProof {
				t.Fatal("fresh BGP permit preceded deny-first exact kernel route readback")
			}
			if leases[id] != 2 || len(nonces) != 2 || nonces[0] == nonces[1] || refetches == 0 || current.Authority == old.Authority || current.Identity.PolicyHash != pagePolicyHash(page, id) || r.applicationDenied[id] {
				t.Fatal("convergence bypassed independent current permit")
			}
			if len(reports) != 1 || reports[id].DeliveryID != old.Delivery.ID || reports[id].BGP == nil {
				t.Fatal("candidate lacks actual BGP status publication")
			}
			for _, result := range results {
				if result.Retained != nil {
					sibling := result.Retained.Manifest.ConnectionID
					if sibling == id || leases[sibling] != 0 || !reflect.DeepEqual(r.c.active[sibling], originals[sibling]) {
						t.Fatal("unchanged sibling was renewed or mutated")
					}
				} else if result.Report.DeliveryID != old.Delivery.ID || result.Acknowledgement.DeliveryID != old.Delivery.ID {
					t.Fatal("unexpected candidate ACK")
				}
			}
			for owner, before := range originals {
				active := r.c.active[owner]
				if _, e := active.Authority.RemainingForApply(active.Identity, time.Millisecond); e != nil {
					t.Fatal("current original/candidate authority expired", e)
				}
				for _, name := range []string{guardLeaseName(owner), guardReplyLeaseName(owner), guardSALeaseName(owner)} {
					if r.installed[name] <= *r.now || r.installed[name] > active.Authority.deadline {
						t.Fatal("ordinary native permit not finite", name)
					}
				}
				if before.Authority.deadline != originalDeadlines[owner] || !reflect.DeepEqual(before.Authority.fqdnDeadlines, originalFQDNDeadlines[owner]) {
					t.Fatal("original finite authority mutated")
				}
				if owner != id && (r.c.active[owner].Authority.deadline != originalDeadlines[owner] || !reflect.DeepEqual(r.c.active[owner].Authority.fqdnDeadlines, originalFQDNDeadlines[owner])) {
					t.Fatal("sibling finite deadline extended")
				}
				for _, g := range r.c.active[owner].Grants {
					if g.FQDNManaged {
						a := r.c.active[owner]
						d := a.Authority.fqdnDeadlines[guardFQDNGrantDigest(g)]
						if r.installed[guardFQDNSetName(g)] <= *r.now || r.installed[guardFQDNSetName(g)] > d {
							t.Fatal("current application guard not finite")
						}
					}
				}
			}
			if old.Authority.deadline != deadline {
				t.Fatal("original authority changed")
			}
		})
	}
}

func pagePolicyHash(page []RuntimeMaterial, id uuid.UUID) string {
	for _, m := range page {
		if m.Manifest.ConnectionID == id {
			return m.Policy.Hash
		}
	}
	return ""
}

func TestExactPageFQDNBGPConvergenceRejectsLostProof(t *testing.T) {
	for _, mode := range []string{"original_lease_expired", "unknown_native", "rib_read_refused", "kernel_route_mismatch", "second_route_change", "cp_refetch_refused", "retry_nonce_mismatch", "post_retry_route_change"} {
		t.Run(mode, func(t *testing.T) {
			r, client, id, process, kernel := exactPageBGPConvergenceRig(t, false)
			old := r.c.active[id]
			deadline := old.Authority.deadline
			target := routeTupleFixture(old.Entry, 2)
			process.routes = []bgpengine.LearnedRoute{{Prefix: target.Prefix, Slot: 2}}
			client.publishAt = *r.now
			page := exactPageTestMaterials(t, r, client, false)
			for i := range page {
				if page[i].Manifest.ConnectionID == id {
					page[i] = client.materialAt(id, 1)
				}
			}
			switch mode {
			case "original_lease_expired":
				*r.now = deadline + time.Millisecond
			case "unknown_native":
				r.c.statusReaders.xfrm = func(context.Context) (XFRMInventory, error) {
					return XFRMInventory{Namespace: old.Environment.Namespace}, nil
				}
				r.c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { return [2]string{"unknown", "unknown"} }
			case "rib_read_refused":
				process.routesError = true
			case "kernel_route_mismatch":
				kernel.badMetric = true
			case "second_route_change":
				process.alive = func() bool {
					if kernel.routes[1][target.Prefix.String()] {
						process.routes = []bgpengine.LearnedRoute{{Prefix: target.Prefix, Slot: 1}}
					}
					return !process.closed
				}
			}
			calls, fetches, publishes := 0, 0, 0
			r.c.client = exactPageConvergenceClient{
				material: func(ctx context.Context, owner uuid.UUID, rev int64) (RuntimeMaterial, error) {
					if owner == id {
						fetches++
						if mode == "cp_refetch_refused" {
							return RuntimeMaterial{}, ErrRuntimeController
						}
					}
					return client.IPsecMaterial(ctx, owner, rev)
				},
				lease: func(ctx context.Context, owner uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
					if owner == id {
						calls++
					}
					out, err := client.RenewIPsecLease(ctx, owner, q)
					if owner == id && calls > 1 {
						if mode == "retry_nonce_mismatch" {
							out.Nonce = uuid.NewString()
						}
						if mode == "post_retry_route_change" {
							process.routes = []bgpengine.LearnedRoute{{Prefix: target.Prefix, Slot: 1}}
						}
					}
					return out, err
				},
			}
			results, handled, err := r.c.tryMaintainExactRuntimePage(context.Background(), page, maintenanceAuthority(r), func() bool { return true }, func(context.Context, RuntimeDelivery, RuntimeStatusReport) error { publishes++; return nil })
			t.Logf("mode=%s handled=%t err=%v results=%d leases=%d refetches=%d active=%d", mode, handled, err, len(results), calls, fetches, len(r.c.active))
			if !handled || err == nil || len(results) != 0 || publishes != 0 {
				t.Fatal("unsafe convergence returned ACK, retained result or publication")
			}
			if old.Authority.deadline != deadline || calls > 2 || fetches > 1 {
				t.Fatal("unsafe route convergence extended authority or retried without bound")
			}
			if _, ok := r.c.active[id]; ok {
				t.Fatal("unsafe convergence retained active BGP authority")
			}
			if mode == "original_lease_expired" && calls != 0 {
				t.Fatal("expired original owner obtained candidate lease")
			}
			if mode == "cp_refetch_refused" && (fetches != 1 || calls != 1) {
				t.Fatal("refused current material did not terminate before second nonce")
			}
			if mode == "retry_nonce_mismatch" && calls != 2 {
				t.Fatal("test did not exercise retry nonce binding")
			}
		})
	}
}

// A known RIB change discovered before any candidate work can use the normal
// canonical maintenance path. Unknown native evidence must still abort closed.
func TestExactPageFQDNBGPZeroCandidateRouteFallback(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(map[bool]string{false: "known_route_change_read_only_fallback", true: "unknown_native_aborts"}[unknown], func(t *testing.T) {
			r, client, id, process, kernel := exactPageBGPConvergenceRig(t, false)
			old := r.c.active[id]
			target := routeTupleFixture(old.Entry, 2)
			process.routes = []bgpengine.LearnedRoute{{Prefix: target.Prefix, Slot: 2}}
			page := exactPageTestMaterials(t, r, client, false)
			for _, a := range r.c.active {
				if r.c.maintenanceRenewalDue(a) {
					t.Fatal("fixture unexpectedly has due candidate")
				}
			}
			before := assemblyClone(r.c.active)
			nativeBefore := map[string]time.Duration{}
			authorityBefore := map[uuid.UUID]time.Duration{}
			for k, v := range r.installed {
				nativeBefore[k] = v
			}
			for owner, a := range before {
				authorityBefore[owner] = a.Authority.deadline
			}
			journalPath := filepath.Join(r.c.journal.dir, "journal.json")
			journalBefore, err := os.ReadFile(journalPath)
			if err != nil {
				t.Fatal(err)
			}
			mutations := kernel.mutations
			prove := r.c.prove
			r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
				if err := prove(ctx, e, env); err != nil {
					return err
				}
				if runtimeObservedStatuses(ctx, e, *r.c.statusReaders) != [2]string{"up", "up"} {
					return ErrRuntimeController
				}
				return nil
			}
			if unknown {
				r.c.statusReaders.xfrm = func(context.Context) (XFRMInventory, error) {
					return XFRMInventory{Namespace: old.Environment.Namespace}, nil
				}
			}
			published, writes := 0, 0
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) { writes++; return replace(ctx, in) }
			result, handled, err := r.c.tryMaintainExactRuntimePage(context.Background(), page, maintenanceAuthority(r), func() bool { return true }, func(context.Context, RuntimeDelivery, RuntimeStatusReport) error { published++; return nil })
			if client.requests != 0 || published != 0 || len(result) != 0 {
				t.Fatal("prework branch minted a nonce, report or ACK")
			}
			if unknown {
				if !handled || err == nil || len(r.c.active) != 0 {
					t.Fatal("unknown proof escaped canonical refusal", handled, err)
				}
				return
			}
			journalAfter, readErr := os.ReadFile(journalPath)
			if handled || err != nil || writes != 0 || kernel.mutations != mutations || !reflect.DeepEqual(before, r.c.active) || !reflect.DeepEqual(nativeBefore, r.installed) || readErr != nil || !reflect.DeepEqual(journalBefore, journalAfter) || process.closed {
				t.Fatal("known typed mismatch did not fall through read-only", handled, err, writes)
			}
			for owner, a := range before {
				if a.Authority.deadline != authorityBefore[owner] {
					t.Fatal("fallback changed original finite permit")
				}
			}
		})
	}
}
