package ipsec

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
)

// Reuse the real five-owner AWS model topology and route writer. The public Apply BGP
// qualification is intentionally unforgeable; this rig reaches the extracted
// post-successful-reconcile boundary, with a separately supplied qualification
// classification. Native platform admission remains a distinct Linux/live gate.
func bgpFailureScopeRig(t *testing.T, gcp ...bool) (*RuntimeController, []RuntimeJournalEntry, runtimeActive, *bgpSessionFixture, *[]byte) {
	t.Helper()
	c, entries, _ := mixedBudgetFixture(t)
	if len(gcp) == 1 && gcp[0] {
		for _, index := range []int{0, 3} {
			old := entries[index]
			m := gcpMaterialFixture()
			if index == 3 {
				m = classicMaterialFixture()
			}
			m.Manifest.OrgID = c.config.OrgID
			m.Manifest.NodeID = c.config.GatewayID
			m.Manifest.ConnectionID = old.Allocation.ConnectionID
			m.Manifest.LocalPrefixes = []string{}
			m.Manifest.RemotePrefixes = []string{}
			for _, p := range old.Engines[0].LocalPrefixes {
				m.Manifest.LocalPrefixes = append(m.Manifest.LocalPrefixes, p.String())
			}
			for _, p := range old.Engines[0].RemotePrefixes {
				m.Manifest.RemotePrefixes = append(m.Manifest.RemotePrefixes, p.String())
			}
			runtimeReseal(&m)
			e, _, err := runtimeMaterialEntry(m, c.config.OrgID, c.config.GatewayID, old.Allocation.Namespace)
			if err != nil {
				t.Fatal(err)
			}
			e.Phase = RuntimeApplied
			for slot := 0; slot < e.Allocation.activeTunnelCount(); slot++ {
				e.Observed[slot] = Ownership{Namespace: e.Allocation.Namespace, InterfaceName: e.Allocation.Tunnels[slot].Name, InterfaceIndex: old.Observed[slot].InterfaceIndex, XFRMID: e.Allocation.Tunnels[slot].XFRMID}
			}
			if index == 0 {
				e.BGPRoutes = &RuntimeBGPRoutes{Sequence: 1, Stage: "completed", Owned: []RuntimeBGPRouteTuple{routeTupleFixture(e, 1)}, Target: []RuntimeBGPRouteTuple{routeTupleFixture(e, 1)}}
				c.bgpProcesses[e.DeliveryID] = c.bgpProcesses[old.DeliveryID]
				delete(c.bgpProcesses, old.DeliveryID)
			}
			a := c.active[old.Allocation.ConnectionID]
			a.Entry = e
			a.Identity.DeliveryID = e.DeliveryID
			a.Identity.Binding = e.Engines[0].Binding
			a.Authority = NewPermitLeaseAuthority()
			r, err := a.Authority.Begin(a.Identity)
			if err != nil || a.Authority.Accept(PermitLeaseResponse{PermitLeaseRequest: r, TTLMillis: 60000}) != nil {
				t.Fatal("GCP authority")
			}
			c.active[e.Allocation.ConnectionID] = a
			entries[index] = e
		}
	}

	j, err := OpenRuntimeJournal(journalDir(t), c.config.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	c.journal = j
	desired := cloneRuntimeEntries(entries)
	seed := cloneRuntimeEntries(entries)
	for i := range seed {
		seed[i].BGPRoutes = nil
		seed[i].Phase = RuntimeReserved
	}
	for _, phase := range []RuntimePhase{RuntimeReserved, RuntimeApplying, RuntimeApplied} {
		for i := range seed {
			seed[i].Phase = phase
		}
		if err := j.Save(seed); err != nil {
			t.Fatal("five-provider journal phase", phase, err)
		}
	}
	var badKernel *recoveryKernelFixture
	for i, e := range desired {
		if e.ContractVersion != 3 {
			continue
		}
		f := newRecoveryKernelFixture()
		f.p = e.Allocation
		f.owned = e.Observed
		for slot, tunnel := range e.Allocation.Tunnels {
			f.routes[slot] = map[string]bool{tunnel.BGP.Peer.String() + "/32": true}
		}
		if err := ReconcileBGPRoutes(context.Background(), j, f.applier(), e.DeliveryID.String(), e.BGPRoutes.Owned); err != nil {
			t.Fatal("genuine route commit", err)
		}
		if i == 0 {
			badKernel = f
		}
		p := c.bgpProcesses[e.DeliveryID].(*bgpSessionFixture)
		p.routes = []bgpengine.LearnedRoute{{Prefix: e.BGPRoutes.Owned[0].Prefix, Slot: 1}}
	}
	// The ready process is durably checkpointed through the normal three stages.
	bad := checkpointControllerProcess(t, c)
	entries, err = j.Entries()
	if err != nil || len(entries) != 5 {
		t.Fatal("full current journal", err)
	}
	for _, e := range entries {
		a := c.active[e.Allocation.ConnectionID]
		a.Entry = e
		c.active[e.Allocation.ConnectionID] = a
	}
	c.kernel = badKernel.applier()
	raw := []byte(nil)
	c.replace = func(_ context.Context, in GuardIntent) (GuardManifest, error) {
		m, err := RenderGuard(in)
		if err != nil {
			return m, err
		}
		if err = j.prepareGuard(m); err != nil {
			return m, err
		}
		raw = append([]byte(nil), []byte(m.ExpectedJSON)...)
		if err = j.finishGuard(m); err != nil {
			return m, err
		}
		return m, nil
	}
	if err = c.installActive(context.Background(), entries); err != nil {
		t.Fatal("real combined render", err)
	}
	links := []GuardInterface{}
	for _, e := range entries {
		for _, o := range e.Observed {
			if o.InterfaceIndex == 0 {
				continue
			}
			links = append(links, GuardInterface{Name: o.InterfaceName, Index: o.InterfaceIndex})
		}
	}
	c.guard = &RuntimeGuard{journal: j, reader: &GuardReader{namespace: c.namespace, interfaces: func() ([]GuardInterface, error) { return append([]GuardInterface(nil), links...), nil }, run: func(context.Context, ...string) ([]byte, error) { return append([]byte(nil), raw...), nil }}}
	c.guard.apply = func(_ context.Context, transaction []byte) error {
		var doc map[string]any
		if json.Unmarshal(transaction, &doc) != nil {
			t.Fatal("transaction JSON")
		}
		commands := doc["nftables"].([]any)
		if len(commands) != 3 {
			t.Fatal("target-only command count")
		}
		names := bgpScopeNames(bad.Allocation.ConnectionID)
		seen := map[string]bool{}
		for _, cmd := range commands {
			fields := cmd.(map[string]any)["flush"].(map[string]any)["set"].(map[string]any)
			name := fields["name"].(string)
			if len(fields) != 3 || fields["family"] != "inet" || fields["table"] != "tunnex_ipsec" || !names[name] || seen[name] {
				t.Fatal("foreign withdrawal")
			}
			seen[name] = true
		}
		raw = bgpScopeEdit(t, raw, func(set map[string]any) {
			if seen[set["name"].(string)] {
				delete(set, "elem")
			}
		})
		return nil
	}
	p := c.bgpProcesses[bad.DeliveryID].(*bgpSessionFixture)
	p.close = func() {
		if !bgpScopeEmpty(t, raw, bgpScopeNames(bad.Allocation.ConnectionID)) {
			t.Fatal("session close before actual denial")
		}
	}
	c.bgpRecover = func(identity bgpengine.ProcessIdentity) error {
		if !p.closed || !reflect.DeepEqual(identity, *bad.BGPProcess) {
			t.Fatal("process identity/close ordering")
		}
		return nil
	}
	old := c.active[bad.Allocation.ConnectionID]
	return c, entries, old, p, &raw
}

func bgpScopeNames(id uuid.UUID) map[string]bool {
	return map[string]bool{guardLeaseName(id): true, guardReplyLeaseName(id): true, guardSALeaseName(id): true}
}
func bgpScopeEdit(t *testing.T, raw []byte, edit func(map[string]any)) []byte {
	t.Helper()
	var table map[string]any
	if json.Unmarshal(raw, &table) != nil {
		t.Fatal("native JSON")
	}
	for _, object := range table["nftables"].([]any) {
		if set, ok := object.(map[string]any)["set"].(map[string]any); ok {
			edit(set)
		}
	}
	out, err := json.Marshal(table)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func bgpScopeMembers(t *testing.T, raw []byte, names map[string]bool) map[string]any {
	t.Helper()
	out := map[string]any{}
	_ = bgpScopeEdit(t, raw, func(set map[string]any) {
		if names[set["name"].(string)] {
			out[set["name"].(string)] = set["elem"]
		}
	})
	return out
}
func bgpScopeEmpty(t *testing.T, raw []byte, names map[string]bool) bool {
	members := bgpScopeMembers(t, raw, names)
	if len(members) != 3 {
		return false
	}
	for _, m := range members {
		if m != nil && len(m.([]any)) != 0 {
			return false
		}
	}
	return true
}

func TestBGPExpiredContinuityDoesNotGloballyWithdrawHealthyTGW(t *testing.T) {
	for _, elapsed := range []time.Duration{56 * time.Second, 61 * time.Second} {
		t.Run(elapsed.String(), func(t *testing.T) {
			c, entries, old, p, raw := bgpFailureScopeRig(t)
			fresh := NewPermitLeaseAuthority()
			request, err := fresh.Begin(old.Identity)
			if err != nil || fresh.Accept(PermitLeaseResponse{PermitLeaseRequest: request, TTLMillis: 60000}) != nil {
				t.Fatal("fresh candidate")
			}
			// This is the old continuity authority used by successful BGP reconciliation,
			// not the separately accepted fresh candidate waiting at the publication gate.
			old.Authority.elapsed = func() time.Duration { return elapsed }
			if err = c.reconcileActiveBGP(context.Background(), entries); err != nil {
				t.Fatal("successful expired-owner reconciliation", err)
			}
			latest, err := c.journal.Entries()
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range latest {
				if e.DeliveryID == old.Entry.DeliveryID {
					if e.BGPRoutes.Stage != "completed" || len(e.BGPRoutes.Owned) != 0 || e.BGPProcess.Stage != "cleaned" || !p.closed {
						t.Fatal("exact empty routes/closed process required")
					}
				}
			}
			if c.active[old.Entry.Allocation.ConnectionID].Authority != nil || c.bgpProcesses[old.Entry.DeliveryID] != nil || !bgpScopeEmpty(t, *raw, bgpScopeNames(old.Entry.Allocation.ConnectionID)) {
				t.Fatal("own authority not actually denied")
			}
			before := map[uuid.UUID]runtimeActive{}
			memberBefore := map[uuid.UUID]map[string]any{}
			for id, a := range c.active {
				before[id] = a
				memberBefore[id] = bgpScopeMembers(t, *raw, bgpScopeNames(id))
				if _, err := a.Authority.RemainingForApply(a.Identity, 5*time.Second); err != nil {
					t.Fatal("other authority", err)
				}
			}
			if len(before) != 4 {
				t.Fatal("four independent live owners")
			}
			templates, seq, _ := c.journal.guardTemplates()
			_, err = c.finishBGPApplyContinuity(context.Background(), entries, old, true, fresh, old.Identity, func() bool { return true })
			if err == nil {
				t.Fatal("expired continuity must not acknowledge Apply or publish fresh authority")
			}
			for id, a := range before {
				if !reflect.DeepEqual(memberBefore[id], bgpScopeMembers(t, *raw, bgpScopeNames(id))) {
					t.Fatal("healthy owner globally withdrawn after expired BGP continuity", id)
				}
				current, ok := c.active[id]
				if !ok || current.Authority != a.Authority || !reflect.DeepEqual(current.Entry, a.Entry) || !reflect.DeepEqual(current.Grants, a.Grants) || !reflect.DeepEqual(current.Environment, a.Environment) {
					t.Fatal("unrelated live inputs changed")
				}
				if _, err := a.Authority.RemainingForApply(a.Identity, 5*time.Second); err != nil {
					t.Fatal("unrelated deadline", err)
				}
			}
			after, nextSeq, _ := c.journal.guardTemplates()
			if seq != nextSeq || !reflect.DeepEqual(templates, after) {
				t.Fatal("isolated refusal rewrote journal/template")
			}
			if c.active[old.Entry.Allocation.ConnectionID].Authority != nil || !bgpScopeEmpty(t, *raw, bgpScopeNames(old.Entry.Allocation.ConnectionID)) {
				t.Fatal("expired BGP reactivated")
			}
		})
	}
}

func cloneRuntimeEntries(entries []RuntimeJournalEntry) []RuntimeJournalEntry {
	out := make([]RuntimeJournalEntry, len(entries))
	for i, e := range entries {
		out[i] = copyDNSEntry(e)
	}
	return out
}

func TestBGPExpiredContinuityUnknownStillUsesGlobalRefusal(t *testing.T) {
	cases := []string{"wrong_identity", "revoked_original", "reserve_still_valid", "backwards_clock", "candidate_expired", "candidate_after_withdraw", "route_pending", "route_nonempty", "process_handle", "changed_process_identity", "changed_native_identity", "platform_qualification", "qualification_after_withdraw", "namespace", "daemon", "canceled", "foreign_table", "withdraw_error"}
	for _, kind := range cases {
		t.Run(kind, func(t *testing.T) {
			c, entries, old, p, raw := bgpFailureScopeRig(t)
			originalIdentity := old.Identity
			fresh := NewPermitLeaseAuthority()
			request, err := fresh.Begin(originalIdentity)
			if err != nil || fresh.Accept(PermitLeaseResponse{PermitLeaseRequest: request, TTLMillis: 60000}) != nil {
				t.Fatal("fresh candidate")
			}
			old.Authority.elapsed = func() time.Duration { return 61 * time.Second }
			if err = c.reconcileActiveBGP(context.Background(), entries); err != nil {
				t.Fatal("known initial reconciliation", err)
			}
			ctx := context.Background()
			qualified := true
			switch kind {
			case "wrong_identity":
				old.Identity.PolicyHash = ""
			case "revoked_original":
				old.Authority.Invalidate()
			case "reserve_still_valid":
				a := &PermitLeaseAuthority{elapsed: func() time.Duration { return 0 }}
				r, e := a.Begin(originalIdentity)
				if e != nil || a.Accept(PermitLeaseResponse{PermitLeaseRequest: r, TTLMillis: 60000}) != nil {
					t.Fatal("reserve fixture")
				}
				a.elapsed = func() time.Duration { return 54 * time.Second }
				old.Authority = a
			case "backwards_clock":
				old.Authority.elapsed = func() time.Duration { return time.Second }
			case "candidate_expired":
				fresh.elapsed = func() time.Duration { return 61 * time.Second }
			case "candidate_after_withdraw":
				apply := c.guard.apply
				c.guard.apply = func(ctx context.Context, transaction []byte) error {
					err := apply(ctx, transaction)
					fresh.elapsed = func() time.Duration { return 61 * time.Second }
					return err
				}
			case "route_pending":
				latest, _ := c.journal.Entries()
				for i := range latest {
					if latest[i].DeliveryID == old.Entry.DeliveryID {
						latest[i].BGPRoutes = &RuntimeBGPRoutes{Sequence: latest[i].BGPRoutes.Sequence + 1, Stage: "pending", Owned: []RuntimeBGPRouteTuple{}, Target: append([]RuntimeBGPRouteTuple(nil), old.Entry.BGPRoutes.Owned...)}
					}
				}
				if c.journal.Save(latest) != nil {
					t.Fatal("real pending route obligation")
				}
			case "route_nonempty":
				if ReconcileBGPRoutes(context.Background(), c.journal, c.kernel, old.Entry.DeliveryID.String(), append([]RuntimeBGPRouteTuple(nil), old.Entry.BGPRoutes.Owned...)) != nil {
					t.Fatal("real nonempty route obligation")
				}
			case "process_handle":
				c.bgpProcesses[old.Entry.DeliveryID] = p
			case "changed_process_identity":
				old.Entry = copyDNSEntry(old.Entry)
				old.Entry.BGPProcess.Supervisor.StartTicks++
			case "changed_native_identity":
				old.Entry = copyDNSEntry(old.Entry)
				old.Entry.Observed[0].InterfaceIndex++
			case "platform_qualification":
				qualified = false
			case "qualification_after_withdraw":
				apply := c.guard.apply
				c.guard.apply = func(ctx context.Context, transaction []byte) error {
					err := apply(ctx, transaction)
					qualified = false
					return err
				}
			case "namespace":
				c.namespace = func() (string, error) { return "net:[456]", nil }
			case "daemon":
				c.config.DaemonAlive = func() bool { return false }
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "foreign_table":
				*raw = bgpScopeEdit(t, *raw, func(set map[string]any) {
					if set["name"] == guardLeaseName(entries[4].Allocation.ConnectionID) {
						set["timeout"] = float64(61)
					}
				})
			case "withdraw_error":
				c.guard.apply = func(context.Context, []byte) error { return ErrGuardRead }
			}
			globalCalls := 0
			replace := c.replace
			c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				globalCalls++
				for _, g := range in.Connections {
					if !g.PrefixOnly {
						t.Fatal("global refusal contained positive permit")
					}
				}
				return replace(ctx, in)
			}
			if _, err := c.finishBGPApplyContinuity(ctx, entries, old, true, fresh, originalIdentity, func() bool { return qualified }); err == nil {
				t.Fatal("unknown accepted")
			}
			if globalCalls != 1 || c.active[old.Entry.Allocation.ConnectionID].Authority != nil {
				t.Fatal("unknown was classified as isolated positive/withdrawal", globalCalls)
			}
		})
	}
}

// An unchanged continuing owner retains the existing publication behavior;
// the helper does not itself rewrite the native table or renew sibling owners.
func TestBGPActiveContinuityPublishesOnlyFreshCurrentCandidate(t *testing.T) {
	c, entries, old, _, raw := bgpFailureScopeRig(t)
	fresh := NewPermitLeaseAuthority()
	request, err := fresh.Begin(old.Identity)
	if err != nil || fresh.Accept(PermitLeaseResponse{PermitLeaseRequest: request, TTLMillis: 60000}) != nil {
		t.Fatal("fresh candidate")
	}
	if err := c.reconcileActiveBGP(context.Background(), entries); err != nil {
		t.Fatal("successful current reconciliation", err)
	}
	before := append([]byte(nil), (*raw)...)
	siblings := map[uuid.UUID]runtimeActive{}
	for id, a := range c.active {
		if id != old.Entry.Allocation.ConnectionID {
			siblings[id] = a
		}
	}
	latest, err := c.journal.Entries()
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.finishBGPApplyContinuity(context.Background(), entries, old, true, fresh, old.Identity, func() bool { return true })
	if err != nil || !reflect.DeepEqual(got, latest) || c.active[old.Entry.Allocation.ConnectionID].Authority != fresh || !reflect.DeepEqual(before, *raw) {
		t.Fatal("unchanged current continuity publication", err)
	}
	for id, a := range siblings {
		current := c.active[id]
		if current.Authority != a.Authority || !reflect.DeepEqual(current.Entry, a.Entry) || !reflect.DeepEqual(current.Grants, a.Grants) {
			t.Fatal("sibling changed")
		}
	}
}

func TestGCPHAExpiredContinuityPreservesClassicSibling(t *testing.T) {
	for _, elapsed := range []time.Duration{56 * time.Second, 61 * time.Second} {
		c, entries, old, _, raw := bgpFailureScopeRig(t, true)
		if old.Entry.Allocation.ProfileID != GCPHABGPProfile {
			t.Fatal("target not real HA")
		}
		classic := entries[3]
		if classic.ContractVersion != 4 || !validClassicJournal(classic) || !reflect.DeepEqual(classic.Engines[1], EngineTunnel{}) || classic.Observed[1] != (Ownership{}) {
			t.Fatal("Classic inactive slot")
		}
		fresh := NewPermitLeaseAuthority()
		r, err := fresh.Begin(old.Identity)
		if err != nil || fresh.Accept(PermitLeaseResponse{PermitLeaseRequest: r, TTLMillis: 60000}) != nil {
			t.Fatal("fresh")
		}

		old.Authority.elapsed = func() time.Duration { return elapsed }
		if c.reconcileActiveBGP(context.Background(), entries) != nil {
			t.Fatal("reconcile")
		}
		latest, _ := c.journal.Entries()
		if !c.expiredBGPContinuityDenied(context.Background(), old, latest, fresh, old.Identity, func() bool { return true }) {
			t.Fatalf("classification invalid: journal=%v routes=%v current=%+v old=%+v", validJournalBGP(old.Entry), validBGPRoutes(old.Entry), latest[0].BGPRoutes, old.Entry.BGPRoutes)
		}
		before := bgpScopeMembers(t, *raw, bgpScopeNames(classic.Allocation.ConnectionID))
		sibling := c.active[classic.Allocation.ConnectionID]
		if _, err := c.finishBGPApplyContinuity(context.Background(), entries, old, true, fresh, old.Identity, func() bool { return true }); err == nil {
			t.Fatal("exhausted accepted")
		}
		after := c.active[classic.Allocation.ConnectionID]
		if after.Authority != sibling.Authority || !reflect.DeepEqual(after.Entry, sibling.Entry) || !reflect.DeepEqual(before, bgpScopeMembers(t, *raw, bgpScopeNames(classic.Allocation.ConnectionID))) {
			t.Fatal("Classic sibling altered")
		}
		if !bgpScopeEmpty(t, *raw, bgpScopeNames(old.Entry.Allocation.ConnectionID)) {
			t.Fatal("HA not denied")
		}
	}
}
