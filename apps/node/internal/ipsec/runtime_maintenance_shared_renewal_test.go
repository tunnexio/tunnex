package ipsec

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"testing"
	"time"
)

// Focused shared-renewal regressions reuse the current GCP five-owner rig.
// No AWS active-pulse production or history code is imported.

func TestMaintenanceCombinedPriorReserveRepeatedNativeCostSharedProfile(t *testing.T) {
	r := newRenewalCycleRigInput(t, true)
	materials := []RuntimeMaterial{}
	for _, index := range []int{0, 3, 1, 4, 2} {
		materials = append(materials, r.materials[index])
	}
	r.target = materials[1].Manifest.ConnectionID
	r.c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error {
		r.charge("native_proof", 450*time.Millisecond)
		return nil
	}
	r.c.config.Daemon = &DaemonClient{request: func(context.Context, string, string, viciMessage) (viciMessage, []viciMessage, error) {
		return viciMessage{}, nil, errors.New("honest status unknown")
	}}
	r.c.config.IPPath = "/usr/bin/true"
	// Virtual time only advances at charged IO and kernel deadlines change only
	// at replacement. Checking every old trio immediately before replacement
	// detects an interval lapse before it can be hidden by renewed elements.
	assertAllNative := func() {
		for index, m := range materials {
			id := m.Manifest.ConnectionID
			for _, name := range []string{guardLeaseName(id), guardReplyLeaseName(id), guardSALeaseName(id)} {
				if end, ok := r.installed[name]; !ok || end <= *r.now {
					a := r.c.active[id]
					t.Fatalf("owned native permit interval lapsed owner=%s index=%d kind=%d set=%s rendered=%s now=%s authority=%s phase=%s costs=%v", id, index, a.Entry.ContractVersion, name, end, *r.now, a.Authority.deadline, r.phase, r.charged)
				}
			}
			if r.c.maintenanceGuard(context.Background(), r.c.active[id].Entry) != nil {
				t.Fatal("full owned native trio readback refused", id)
			}
		}
	}
	replace := r.c.replace
	r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
		positive := false
		for _, g := range in.Connections {
			positive = positive || !g.PrefixOnly
		}
		if positive {
			assertAllNative()
		}
		return replace(ctx, in)
	}
	var events []RuntimeDiagnostic
	r.c.config.Diagnostic = func(e RuntimeDiagnostic) { events = append(events, e) }
	for page := 1; page <= 4; page++ {
		old := map[uuid.UUID]*PermitLeaseAuthority{}
		deadlines := map[uuid.UUID]time.Duration{}
		for id, a := range r.c.active {
			old[id], deadlines[id] = a.Authority, a.Authority.deadline
		}
		if len(old) != 5 {
			t.Fatal("page must begin with all five owners", page)
		}
		r.charge("loop_start_due", time.Second)
		r.heartbeat(t)
		started := *r.now
		r.phase = "maintenance"
		results, err := r.c.maintainIPsecRuntimeObserved(context.Background(), materials, maintenanceAuthority(r), func() bool { return true }, func(context.Context, RuntimeDelivery, RuntimeStatusReport) error { return nil })
		r.phase = ""
		r.charge("observe_report_ack", time.Duration(len(results))*600*time.Millisecond)
		t.Logf("page=%d started=%s elapsed=%s results=%d active=%d firstLapse=%s costs=%v events=%v", page, started, *r.now-started, len(results), len(r.c.active), r.firstLapse, r.charged, events)
		if err != nil || len(results) != 5 || len(r.c.active) != 5 {
			t.Fatalf("finite five-owner renewal failed page%d: results=%d active=%d err=%v", page, len(results), len(r.c.active), err)
		}
		if r.firstLapse != 0 || r.expiryEmpty {
			t.Fatal("native permit expired across unchanged consecutive pages", page, r.firstLapse)
		}
		assertAllNative()
		for id, authority := range old {
			if authority.deadline != deadlines[id] || r.c.active[id].Authority == authority {
				t.Fatal("original deadline extended or fresh authority not published", page, id)
			}
			if r.c.maintenanceGuard(context.Background(), r.c.active[id].Entry) != nil {
				t.Fatal("committed native guard missing", page, id)
			}
		}
	}
}

func TestMaintenanceAfterCPProofCostMoveStillRefusesUnsafeOwnerSharedProfile(t *testing.T) {
	for _, scenario := range []string{"native_invalid", "bgp_routes_changed", "guard_missing", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			r := newRenewalCycleRigInput(t, true)
			materials := maintenanceMaterials(r)
			id := materials[0].Manifest.ConnectionID
			original := r.c.active[id]
			originalDeadline := original.Authority.deadline
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var events []RuntimeDiagnostic
			r.c.config.Diagnostic = func(e RuntimeDiagnostic) { events = append(events, e) }
			candidates := []*PermitLeaseAuthority{}
			constructor := func() *PermitLeaseAuthority {
				a := &PermitLeaseAuthority{elapsed: func() time.Duration { return *r.now }}
				candidates = append(candidates, a)
				return a
			}
			changed, nativeInvalid := false, false
			prove := r.c.prove
			r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
				if nativeInvalid && e.Allocation.ConnectionID == id {
					return ErrRuntimeController
				}
				return prove(ctx, e, env)
			}
			client := r.c.client
			r.c.client = maintenanceLeaseFunc(func(ctx context.Context, connection uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
				out, err := client.RenewIPsecLease(ctx, connection, q)
				candidateRequest := false
				for _, a := range candidates {
					candidateRequest = candidateRequest || (a.pending != nil && a.pending.Nonce == q.Nonce)
				}
				if connection == id && candidateRequest && !changed {
					changed = true
					switch scenario {
					case "native_invalid":
						nativeInvalid = true
					case "bgp_routes_changed":
						r.c.bgpProcesses[original.Entry.DeliveryID].(*bgpSessionFixture).routes = nil
					case "guard_missing":
						delete(r.installed, guardLeaseName(id))
					case "canceled":
						cancel()
					}
				}
				return out, err
			})
			positiveTargetCommits := 0
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				for _, g := range in.Connections {
					if g.ID == id && !g.PrefixOnly && len(g.Grants) > 0 {
						positiveTargetCommits++
					}
				}
				return replace(ctx, in)
			}
			r.phase = "maintenance"
			results, err := r.c.maintainIPsecRuntime(ctx, materials, constructor, func() bool { return true })
			r.phase = ""
			if !changed || positiveTargetCommits != 0 || original.Authority.deadline != originalDeadline {
				t.Fatal("post-CP unsafe owner published or original deadline mutated", changed, positiveTargetCommits)
			}
			for _, out := range results {
				if out.Acknowledgement.DeliveryID == original.Entry.DeliveryID {
					t.Fatal("unsafe owner acknowledged")
				}
			}
			if scenario == "native_invalid" {
				installerRefused := false
				for _, event := range events {
					installerRefused = installerRefused || (event.Operation == "install_active" && event.Stage == "entry_current_proof" && event.ConnectionID == id && event.Refused)
				}
				if !installerRefused || err == nil || len(results) != 0 || len(r.c.active) != 0 {
					t.Fatal("mandatory after-CP installer proof did not reject changed native owner", installerRefused, err, len(results), len(r.c.active))
				}
			}
			if scenario == "bgp_routes_changed" && (err == nil || len(results) != 0 || len(r.c.active) != 0) {
				t.Fatal("required post-CP BGP route failure did not refuse the whole renewal", err, len(results), len(r.c.active))
			}
		})
	}
}

func TestMaintenanceRequiredBGPRouteProofWithoutAppGrantsSharedProfile(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "healthy", true: "changed_routes"}[changed], func(t *testing.T) {
			r := newRenewalCycleRigInput(t, true)
			id := r.materials[0].Manifest.ConnectionID
			old := r.c.active[id]
			if old.Entry.ContractVersion != 3 {
				t.Fatal("BGP fixture required")
			}
			fresh := maintenanceAuthority(r)()
			request, err := fresh.Begin(old.Identity)
			if err != nil {
				t.Fatal(err)
			}
			lease, err := r.c.client.RenewIPsecLease(context.Background(), id, RuntimeLeaseRequest{DeliveryID: old.Identity.DeliveryID, DesiredRevision: old.Identity.Binding.DesiredRevision, PolicyHash: old.Identity.PolicyHash, Nonce: request.Nonce})
			if err != nil || fresh.Accept(PermitLeaseResponse{PermitLeaseRequest: request, TTLMillis: lease.TTLMS}) != nil {
				t.Fatal("genuine fresh CP authority unavailable", err)
			}
			candidate := old
			candidate.Authority, candidate.Grants = fresh, nil
			staged := map[uuid.UUID]runtimeActive{}
			for owner, a := range r.c.active {
				staged[owner] = a
			}
			staged[id] = candidate
			if changed {
				r.c.bgpProcesses[old.Entry.DeliveryID].(*bgpSessionFixture).routes = nil
			}
			commits := 0
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				for _, g := range in.Connections {
					if g.ID == id && !g.PrefixOnly {
						commits++
					}
				}
				return replace(ctx, in)
			}
			err = r.c.installActiveCandidates(context.Background(), r.entries, staged, map[uuid.UUID]runtimeActive{id: candidate}, map[uuid.UUID]runtimeActive{id: old}, func() bool { return true })
			if changed && (err == nil || commits != 0) {
				t.Fatal("zero-grant required candidate bypassed its fresh BGP route proof", err, commits)
			}
			if !changed && (err != nil || commits != 1) {
				t.Fatal("healthy zero-grant required candidate refused", err, commits)
			}
		})
	}
}

func TestMaintenanceOrdinaryCurrentStillRequiresNativeProofSharedProfile(t *testing.T) {
	r := newRenewalCycleRigInput(t, true)
	a := r.c.active[r.target]
	r.c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error { return ErrRuntimeController }
	if r.c.maintenanceCurrent(context.Background(), a, func() bool { return true }) == nil {
		t.Fatal("ordinary current proof accepted invalid native ownership")
	}
}

func TestTwoPhaseCandidateBeginsAfterAllEligibleOwnerProofsSharedProfile(t *testing.T) {
	r := newRenewalCycleRigInput(t, true)
	mats := maintenanceMaterials(r)
	proven := map[uuid.UUID]bool{}
	before := r.c.prove
	r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
		err := before(ctx, e, env)
		if err == nil {
			proven[e.Allocation.ConnectionID] = true
		}
		return err
	}
	constructors := 0
	constructor := func() *PermitLeaseAuthority {
		constructors++
		for _, m := range mats {
			if !proven[m.Manifest.ConnectionID] {
				t.Fatal("candidate factory precedes another owner eligibility proof", m.Manifest.ConnectionID)
			}
		}
		return &PermitLeaseAuthority{elapsed: func() time.Duration { return *r.now }}
	}
	r.phase = "maintenance"
	out, err := r.c.maintainIPsecRuntime(context.Background(), mats, constructor, func() bool { return true })
	if err != nil || len(out) != 5 || constructors != 5 {
		t.Fatal("complete genuine eligibility/candidate sequence", len(out), constructors, err)
	}
}

func TestTwoPhaseCapturedOwnerCannotReappearSharedProfile(t *testing.T) {
	for _, scenario := range []string{"expired_phase1", "expired_before_begin", "removed_before_begin", "replaced_before_begin", "revoked_before_begin", "reserve_exhausted_before_begin", "removed_during_CP", "replaced_during_CP", "revoked_during_CP", "expired_during_CP", "changed_environment_during_CP", "canceled_before_begin", "qualification_before_begin", "daemon_before_begin", "bgp_qualification_before_begin"} {
		t.Run(scenario, func(t *testing.T) {
			r := newRenewalCycleRigInput(t, true)
			mats := maintenanceMaterials(r)
			id := mats[0].Manifest.ConnectionID
			original := r.c.active[id]
			originalDeadline := original.Authority.deadline
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			daemonCurrent, bgpCurrent := true, true
			r.c.config.DaemonAlive = func() bool { return daemonCurrent }
			candidates := []*PermitLeaseAuthority{}
			freshRequests, targetRequests := 0, 0
			mutate := func() {
				switch scenario {
				case "removed_before_begin", "removed_during_CP":
					delete(r.c.active, id)
				case "replaced_before_begin", "replaced_during_CP":
					a := r.c.active[id]
					a.Authority = &PermitLeaseAuthority{elapsed: func() time.Duration { return *r.now }}
					r.c.active[id] = a
				case "revoked_before_begin", "revoked_during_CP":
					original.Authority.Invalidate()
				case "expired_phase1", "expired_before_begin", "expired_during_CP":
					original.Authority.deadline = *r.now
				case "canceled_before_begin":
					cancel()
				case "qualification_before_begin":
					r.c.qualification.invalid = true
				case "daemon_before_begin":
					daemonCurrent = false
				case "bgp_qualification_before_begin":
					bgpCurrent = false
				case "reserve_exhausted_before_begin":
					r.charge("original_reserve_boundary", originalDeadline-*r.now-4*time.Second)
				case "changed_environment_during_CP":
					a := r.c.active[id]
					a.Environment.Namespace = "net:[4026533999]"
					r.c.active[id] = a
				}
			}
			constructor := func() *PermitLeaseAuthority {
				a := &PermitLeaseAuthority{elapsed: func() time.Duration { return *r.now }}
				candidates = append(candidates, a)
				if len(candidates) == 1 && (scenario == "expired_before_begin" || scenario == "removed_before_begin" || scenario == "replaced_before_begin" || scenario == "revoked_before_begin" || scenario == "reserve_exhausted_before_begin" || scenario == "canceled_before_begin" || scenario == "qualification_before_begin" || scenario == "daemon_before_begin" || scenario == "bgp_qualification_before_begin") {
					mutate()
				}
				return a
			}
			client := r.c.client
			r.c.client = maintenanceLeaseFunc(func(ctx context.Context, connection uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
				candidateRequest := false
				for _, a := range candidates {
					if a.pending != nil && a.pending.Nonce == q.Nonce {
						candidateRequest = true
					}
				}
				out, err := client.RenewIPsecLease(ctx, connection, q)
				if candidateRequest {
					freshRequests++
					if connection == id {
						targetRequests++
					}
					if freshRequests == 1 && (scenario == "removed_during_CP" || scenario == "replaced_during_CP" || scenario == "revoked_during_CP" || scenario == "expired_during_CP" || scenario == "changed_environment_during_CP") {
						mutate()
					}
				}
				return out, err
			})
			positives := 0
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				for _, g := range in.Connections {
					if !g.PrefixOnly {
						positives++
						break
					}
				}
				return replace(ctx, in)
			}
			if scenario == "expired_phase1" {
				mutate()
			}
			r.phase = "maintenance"
			results, err := r.c.maintainIPsecRuntime(ctx, mats, constructor, func() bool { return bgpCurrent })
			if scenario == "expired_phase1" || scenario == "expired_before_begin" || scenario == "revoked_before_begin" || scenario == "revoked_during_CP" || scenario == "expired_during_CP" {
				// Known original-authority expiry/revocation omits only its owner.
				if err != nil || len(results) != 4 || len(r.c.active) != 4 || positives != 1 {
					t.Fatal("healthy siblings lost after known target revocation", err, len(results), len(r.c.active), positives)
				}
				if _, ok := r.c.active[id]; ok {
					t.Fatal("revoked owner restored")
				}
				denied := r.c.recoveryGuardDenied(context.Background(), original.Entry)
				if !denied {
					t.Fatal("known expired owner retains native lease members", denied)
				}
				for sibling, a := range r.c.active {
					if r.c.maintenanceGuard(context.Background(), a.Entry) != nil {
						t.Fatal("healthy sibling loses original native authority", sibling)
					}
				}
				for _, out := range results {
					if out.Acknowledgement.DeliveryID == original.Delivery.ID {
						t.Fatal("revoked owner acknowledged")
					}
				}
			} else if scenario == "reserve_exhausted_before_begin" {
				if len(results) != 0 || len(r.c.active) != 0 || positives != 0 {
					t.Fatal("no owner with exhausted original reserve may remain positive", err, len(results), len(r.c.active), positives)
				}
			} else if err == nil || len(results) != 0 || len(r.c.active) != 0 || positives != 0 {
				t.Fatal("unsafe captured authority restored or acknowledged", err, len(results), len(r.c.active), positives)
			}
			if scenario == "expired_before_begin" || scenario == "removed_before_begin" || scenario == "replaced_before_begin" || scenario == "revoked_before_begin" || scenario == "reserve_exhausted_before_begin" || scenario == "canceled_before_begin" || scenario == "qualification_before_begin" || scenario == "daemon_before_begin" || scenario == "bgp_qualification_before_begin" {
				if targetRequests != 0 {
					t.Fatal("target candidate CP request after known failed binding/reserve", targetRequests)
				}
			}
			if scenario != "expired_phase1" && scenario != "expired_before_begin" && scenario != "expired_during_CP" && scenario != "revoked_before_begin" && scenario != "revoked_during_CP" && original.Authority.deadline != originalDeadline {
				t.Fatal("original finite deadline extended")
			}
		})
	}
}
