package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"net/netip"
	"testing"
)

func TestAzureProfileAbsenceOnlyPublicPlaceholderDomain(t *testing.T) {
	oldm := azureMaterialFixture(AzureActiveActiveBGPProfile)
	// Match the unchanged cleanup path: a delivered apply is built without PSKs
	// or Environment.Observe, then marked cleanup-only and genuinely finalized.
	old, _, err := runtimeBuildEntry(RuntimeMaterial{RuntimeDelivery: oldm.RuntimeDelivery}, oldm.Manifest.OrgID, oldm.Manifest.NodeID, "net:[4026531992]", false)
	if err != nil {
		t.Fatal(err)
	}
	old.AbsenceOnly = true
	old = retainedAzure(old)
	_, next := profileRecreationMaterial(t, AzureActiveActiveStaticProfile, []RuntimeJournalEntry{old})
	for i := range next.Engines {
		next.Engines[i].LocalAddress = netip.MustParseAddr("172.18.0.5")
	}
	if !sameAzureRecreationLocalSocket(next, old, next.Engines[0], old.Engines[0]) || !sameAzureRecreationLocalSocket(old, next, old.Engines[0], next.Engines[0]) {
		t.Fatal("socket comparison asymmetric")
	}
	entries := []RuntimeJournalEntry{old, next}
	before, _ := json.Marshal(entries)
	if !sameHandoffDomain(next, old) || !validRetainedGuardJournal(entries) {
		t.Fatal("legitimate never-observed public placeholder refused")
	}
	if _, _, err := runtimeGuardProjection(entries); err != nil {
		t.Fatal("full guard graph refused")
	}
	after, _ := json.Marshal(entries)
	if !bytes.Equal(before, after) {
		t.Fatal("immutable lineage changed")
	}
	for name, mutate := range map[string]func(*RuntimeJournalEntry){
		"observed_object":          func(e *RuntimeJournalEntry) { e.Observed[0] = Ownership{InterfaceIndex: 1} },
		"routes_observed":          func(e *RuntimeJournalEntry) { e.BGPRoutes = &RuntimeBGPRoutes{} },
		"history_observed":         func(e *RuntimeJournalEntry) { e.BGPProcessHistory = &RuntimeHistoryContinuation{} },
		"zero_covered":             func(e *RuntimeJournalEntry) { e.CoveredDeliveryRevision = 0 },
		"insufficient_covered":     func(e *RuntimeJournalEntry) { e.CoveredDeliveryRevision = e.Engines[0].Binding.DesiredRevision - 1 },
		"foreign_org":              func(e *RuntimeJournalEntry) { e.Engines[0].Binding.OrgID = uuid.New() },
		"foreign_gateway":          func(e *RuntimeJournalEntry) { e.Engines[0].Binding.GatewayID = uuid.New() },
		"foreign_remote_identity":  func(e *RuntimeJournalEntry) { e.Engines[0].RemoteIdentity = netip.MustParseAddr("198.51.100.23") },
		"restoration":              func(e *RuntimeJournalEntry) { e.Restoration = &RuntimeRestoration{} },
		"observed":                 func(e *RuntimeJournalEntry) { e.AbsenceOnly = false },
		"forged_placeholder":       func(e *RuntimeJournalEntry) { e.Engines[0].LocalAddress = netip.MustParseAddr("172.18.0.9") },
		"pending_invalid_coverage": func(e *RuntimeJournalEntry) { e.Phase = RuntimeCleanupPending; e.CoveredDeliveryRevision = 0 },
		"missing_cleanup":          func(e *RuntimeJournalEntry) { e.CleanupID = uuid.Nil },
		"not_covered":              func(e *RuntimeJournalEntry) { e.CleanupDesiredRevision = e.CoveredDeliveryRevision },
		"foreign_identity":         func(e *RuntimeJournalEntry) { e.Engines[0].LocalIdentity = netip.MustParseAddr("198.51.100.20") },
		"foreign_site":             func(e *RuntimeJournalEntry) { e.SiteID = uuid.New() },
		"foreign_remote":           func(e *RuntimeJournalEntry) { e.Engines[0].RemoteAddress = netip.MustParseAddr("198.51.100.21") },
	} {
		t.Run(name, func(t *testing.T) {
			bad := old
			mutate(&bad)
			if sameHandoffDomain(next, bad) {
				t.Fatal("invalid accommodation accepted")
			}
		})
	}
	bad := old
	bad.OwnershipDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if validRetainedGuardJournal([]RuntimeJournalEntry{bad, next}) {
		t.Fatal("foreign digest lineage accepted")
	}
}

func TestAzureProfileAbsenceOnlyMixedAncestorGraph(t *testing.T) {
	m := azureMaterialFixture(AzureActiveActiveBGPProfile)
	first, _, err := runtimeBuildEntry(RuntimeMaterial{RuntimeDelivery: m.RuntimeDelivery}, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]", false)
	if err != nil {
		t.Fatal(err)
	}
	first.AbsenceOnly = true
	first = retainedAzure(first)
	_, second := profileRecreationMaterial(t, AzureActiveActiveStaticProfile, []RuntimeJournalEntry{first})
	second.AbsenceOnly = true
	second = retainedAzure(second)
	_, third := profileRecreationMaterial(t, AzureActiveActiveStaticProfile, []RuntimeJournalEntry{first, second})
	for i := range third.Engines {
		third.Engines[i].LocalAddress = netip.MustParseAddr("172.18.0.5")
	}
	entries := []RuntimeJournalEntry{first, second, third}
	if !validRetainedGuardJournal(entries) {
		t.Fatal("both cleanup-only mixed ancestors refused")
	}
	if _, _, e := runtimeGuardProjection(entries); e != nil {
		t.Fatal(e)
	}
	third.RetainedGuardPredecessors = nil
	if validRetainedGuardJournal([]RuntimeJournalEntry{first, second, third}) {
		t.Fatal("partial ancestor graph accepted")
	}
}

func TestAzureProfileAbsenceOnlyCanonicalCleanupPersistence(t *testing.T) {
	_, prior := profileRecreationMaterial(t, AzureActiveActiveBGPProfile, nil)
	for i := range prior.Engines {
		prior.Engines[i].LocalAddress = netip.MustParseAddr("172.18.0.5")
	}
	prior = retainedAzure(prior)
	prior.BGPRoutes = &RuntimeBGPRoutes{Sequence: 1, Stage: "completed", Withdrawal: true, Owned: []RuntimeBGPRouteTuple{}, Target: []RuntimeBGPRouteTuple{}}
	m, _ := profileRecreationMaterial(t, AzureActiveActiveStaticProfile, []RuntimeJournalEntry{prior})
	never, _, err := runtimeBuildEntry(RuntimeMaterial{RuntimeDelivery: m.RuntimeDelivery}, m.Manifest.OrgID, m.Manifest.NodeID, prior.Allocation.Namespace, false)
	if err != nil {
		t.Fatal(err)
	}
	never.AbsenceOnly = true
	j, err := OpenRuntimeJournal(journalDir(t), m.Manifest.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	seed := prior
	seed.Phase = RuntimeReserved
	seed.CleanupID = uuid.Nil
	seed.CleanupDesiredRevision = 0
	seed.CoveredDeliveryRevision = 0
	seed.BGPRoutes = nil
	if err = j.Save([]RuntimeJournalEntry{seed}); err != nil {
		t.Fatal("seed", err)
	}
	pendingSeed := seed
	pendingSeed.Phase = RuntimeCleanupPending
	pendingSeed.CleanupID = prior.CleanupID
	pendingSeed.CleanupDesiredRevision = prior.CleanupDesiredRevision
	pendingSeed.CoveredDeliveryRevision = prior.CoveredDeliveryRevision
	if err = j.Save([]RuntimeJournalEntry{pendingSeed}); err != nil {
		t.Fatal("pending seed", err)
	}
	prior.BGPRoutes = nil
	if err = j.Save([]RuntimeJournalEntry{prior}); err != nil {
		t.Fatal("retained seed", err)
	}
	c := &RuntimeController{started: true, journal: j, qualification: testRuntimeQualification(prior.Allocation.Namespace), config: RuntimeControllerConfig{OrgID: m.Manifest.OrgID, GatewayID: m.Manifest.NodeID, DaemonAlive: func() bool { return false }}}
	c.namespace = func() (string, error) { return prior.Allocation.Namespace, nil }
	c.replace = func(_ context.Context, in GuardIntent) (GuardManifest, error) {
		for _, v := range in.Connections {
			if len(v.Grants) != 0 {
				t.Fatal("negative cleanup generated permits")
			}
		}
		return RenderGuard(in)
	}
	cleanup := RuntimeCleanup{RuntimeDelivery: m.RuntimeDelivery, RetainGuard: true, Lineage: []RuntimeDelivery{m.RuntimeDelivery}}
	cleanup.ID = uuid.New()
	cleanup.Kind = "cleanup"
	cleanup.DesiredRevision = m.DesiredRevision + 1
	cleanup.CoversDeliveryRevision = m.DesiredRevision
	raw, _ := json.Marshal(cleanup.Lineage)
	cleanup.OwnershipDigest = stringDigest(raw)
	ack, err := c.Cleanup(t.Context(), cleanup)
	// Native proof is deliberately unavailable: persistence must succeed, but
	// no successful cleanup acknowledgement is manufactured by this test.
	if err == nil || ack.GuardRetained {
		t.Fatal("cleanup accepted without native absence")
	}
	entries, err := j.Entries()
	if err != nil || len(entries) != 2 {
		t.Fatal("unknown lineage initial Save failed", err)
	}
	n := entries[1]
	if !n.AbsenceOnly || n.Phase != RuntimeCleanupPending || n.CleanupID != cleanup.ID {
		t.Fatal("controller did not persist genuine pending cleanup")
	}
	// Exercise the exact independently-proved final state through the same
	// immutable journal transition, separately from a controller native ACK.
	n.Phase = RuntimeRetainedRefusal
	entries[1] = n
	if err = j.Save(entries); err != nil {
		t.Fatal("final retained negative-only persistence refused", err)
	}
	for _, phase := range []RuntimePhase{RuntimeReserved, RuntimeCleanupPending, RuntimeRetainedRefusal} {
		v := never
		v.Phase = phase
		if phase != RuntimeReserved {
			v.CleanupID = cleanup.ID
			v.CleanupDesiredRevision = cleanup.DesiredRevision
			v.CoveredDeliveryRevision = cleanup.CoversDeliveryRevision
		}
		if !validRetainedGuardJournal([]RuntimeJournalEntry{prior, v}) {
			t.Fatal("canonical negative-only phase refused", phase)
		}
	}
	// An unfinished predecessor remains forbidden, even if its socket is a
	// legitimate placeholder. The new accommodation changes no handoff phase.
	pending := prior
	pending.AbsenceOnly = true
	pending.Phase = RuntimeCleanupPending
	for i := range pending.Engines {
		pending.Engines[i].LocalAddress = pending.Engines[i].LocalIdentity
	}
	if validRetainedGuardJournal([]RuntimeJournalEntry{pending, never}) {
		t.Fatal("pending predecessor adopted")
	}
	for _, phase := range []RuntimePhase{RuntimeApplying, RuntimeApplied} {
		v := never
		v.Phase = phase
		if validJournalPayload(runtimeJournalPayload{Version: 13, OwnerID: m.Manifest.NodeID, Entries: []RuntimeJournalEntry{prior, v}}) {
			t.Fatal("absence-only positive phase accepted")
		}
	}
}
