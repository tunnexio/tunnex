package ipsec

import (
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func retainedHandoffFixture(t *testing.T) (RuntimeJournalEntry, RuntimeJournalEntry, RuntimeMaterial) {
	t.Helper()
	m := runtimeMaterialFixture()
	old, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil {
		t.Fatal(err)
	}
	old.Phase = RuntimeRetainedRefusal
	old.CleanupID = uuid.New()
	old.CleanupDesiredRevision = m.DesiredRevision + 1
	old.CoveredDeliveryRevision = m.DesiredRevision
	raw, _ := json.Marshal(m)
	var next RuntimeMaterial
	_ = json.Unmarshal(raw, &next)
	next.ID = uuid.New()
	next.Manifest.ConnectionID = uuid.New()
	for i := range next.Manifest.Tunnels {
		id := uuid.New()
		next.Manifest.Tunnels[i].ID = id
		next.Manifest.Tunnels[i].LinkName = KernelTunnelName(id)
		next.Manifest.Tunnels[i].XFRMID = KernelTunnelID(id)
		next.Manifest.Tunnels[i].ReqID = KernelTunnelID(id)
		next.Secrets[i].TunnelID = id
	}
	next.Manifest.RetainedGuardPredecessors = []RuntimeRetainedGuardPredecessor{{ConnectionID: old.Allocation.ConnectionID, DeliveryID: old.DeliveryID, CleanupDeliveryID: old.CleanupID, OwnershipDigest: old.OwnershipDigest}}
	runtimeReseal(&next)
	successor, _, err := runtimeMaterialEntry(next, next.Manifest.OrgID, next.Manifest.NodeID, old.Allocation.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	return old, successor, next
}
func saveRetainedHandoffFixture(t *testing.T, j *RuntimeJournal, old, successor RuntimeJournalEntry) {
	t.Helper()
	reserved := old
	reserved.Phase = RuntimeReserved
	reserved.CleanupID = uuid.Nil
	reserved.CleanupDesiredRevision = 0
	reserved.CoveredDeliveryRevision = 0
	if err := j.Save([]RuntimeJournalEntry{reserved}); err != nil {
		t.Fatal(err)
	}
	pending := old
	pending.Phase = RuntimeCleanupPending
	if err := j.Save([]RuntimeJournalEntry{pending}); err != nil {
		t.Fatal(err)
	}
	if err := j.Save([]RuntimeJournalEntry{old}); err != nil {
		t.Fatal(err)
	}
	if err := j.Save([]RuntimeJournalEntry{old, successor}); err != nil {
		t.Fatal(err)
	}
}
func TestRetainedGuardHandoffJournalRestartAndRefusal(t *testing.T) {
	old, successor, _ := retainedHandoffFixture(t)
	dir := journalDir(t)
	j, err := OpenRuntimeJournal(dir, old.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	saveRetainedHandoffFixture(t, j, old, successor)
	if j.payload.Version != 9 {
		t.Fatal("handoff journal did not explicitly upgrade")
	}
	entries, _ := j.Entries()
	if !reflect.DeepEqual(entries[0], old) {
		t.Fatal("immutable predecessor rewritten")
	}
	changed := entries
	changed[1].RetainedGuardPredecessors[0].CleanupDeliveryID = uuid.New()
	if j.Save(changed) == nil {
		t.Fatal("hand-off binding rewritten")
	}
	j.Close()
	j, err = OpenRuntimeJournal(dir, old.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	calls := 0
	c := &RuntimeController{config: RuntimeControllerConfig{OrgID: old.Engines[0].Binding.OrgID, GatewayID: old.Engines[0].Binding.GatewayID}, journal: j, namespace: func() (string, error) { return old.Allocation.Namespace, nil }, replace: func(_ context.Context, in GuardIntent) (GuardManifest, error) {
		calls++
		if len(in.Connections) != 1 || in.Connections[0].ID != successor.Allocation.ConnectionID || !in.Connections[0].PrefixOnly || len(in.RetainedLeaseIDs) != 1 || in.RetainedLeaseIDs[0] != old.Allocation.ConnectionID {
			t.Fatal("restart did not retain exact successor denial")
		}
		m, err := RenderGuard(in)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(m.NFT, "ip daddr 10.20.0.0/24 counter drop") || strings.Contains(m.NFT, "counter accept") {
			t.Fatal("startup inferred authority")
		}
		return m, nil
	}}
	if c.Start(context.Background()) != nil || calls != 1 {
		t.Fatal("restart refusal failed")
	}
	entries, _ = j.Entries()
	if !reflect.DeepEqual(entries[0], old) {
		t.Fatal("restart changed predecessor history")
	}
}
func TestRetainedGuardHandoffExactBindingsAndWholeLineage(t *testing.T) {
	cases := map[string]func(*RuntimeJournalEntry, *RuntimeJournalEntry){
		"missing predecessor": func(o, n *RuntimeJournalEntry) { n.RetainedGuardPredecessors[0].DeliveryID = uuid.New() },
		"wrong cleanup":       func(o, n *RuntimeJournalEntry) { n.RetainedGuardPredecessors[0].CleanupDeliveryID = uuid.New() },
		"wrong digest": func(o, n *RuntimeJournalEntry) {
			n.RetainedGuardPredecessors[0].OwnershipDigest = strings.Repeat("e", 64)
		},
		"not cleaned":     func(o, n *RuntimeJournalEntry) { o.Phase = RuntimeCleanupPending },
		"foreign org":     func(o, n *RuntimeJournalEntry) { o.Engines[0].Binding.OrgID = uuid.New() },
		"foreign site":    func(o, n *RuntimeJournalEntry) { o.SiteID = uuid.New() },
		"foreign gateway": func(o, n *RuntimeJournalEntry) { o.Engines[0].Binding.GatewayID = uuid.New() },
		"partial remote": func(o, n *RuntimeJournalEntry) {
			n.Engines[0].RemotePrefixes = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/25")}
		},
		"partial local": func(o, n *RuntimeJournalEntry) {
			n.Engines[0].LocalPrefixes = []netip.Prefix{netip.MustParsePrefix("10.10.0.0/25")}
		},
		"BGP": func(o, n *RuntimeJournalEntry) { n.ContractVersion = 3 },
		"second tunnel local": func(o, n *RuntimeJournalEntry) {
			n.Engines[1].LocalPrefixes = []netip.Prefix{netip.MustParsePrefix("10.11.0.0/24")}
		},
		"second tunnel remote": func(o, n *RuntimeJournalEntry) {
			o.Engines[1].RemotePrefixes = []netip.Prefix{netip.MustParsePrefix("10.21.0.0/24")}
		},
		"duplicate": func(o, n *RuntimeJournalEntry) {
			n.RetainedGuardPredecessors = append(n.RetainedGuardPredecessors, n.RetainedGuardPredecessors[0])
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o, n, _ := retainedHandoffFixture(t)
			mutate(&o, &n)
			if _, _, err := runtimeGuardProjection([]RuntimeJournalEntry{o, n}); err == nil {
				t.Fatal("unsafe handoff accepted")
			}
		})
	}
	o, n, _ := retainedHandoffFixture(t)
	extra := o
	extra.DeliveryID = uuid.New()
	if _, _, err := runtimeGuardProjection([]RuntimeJournalEntry{o, extra, n}); err == nil {
		t.Fatal("unreferenced lineage concealed")
	}
	n.RetainedGuardPredecessors = nil
	if _, _, err := runtimeGuardProjection([]RuntimeJournalEntry{o, n}); err == nil {
		t.Fatal("implicit overlap handoff accepted")
	}
}
func TestRetainedGuardHandoffLeaseExpiryAndIndependentSelection(t *testing.T) {
	old, successor, _ := retainedHandoffFixture(t)
	j, err := OpenRuntimeJournal(journalDir(t), old.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	saveRetainedHandoffFixture(t, j, old, successor)
	elapsed := time.Duration(0)
	a := NewPermitLeaseAuthority()
	a.elapsed = func() time.Duration { return elapsed }
	identity := PermitLeaseIdentity{DeliveryID: successor.DeliveryID, Binding: successor.Engines[0].Binding, PolicyHash: strings.Repeat("b", 64)}
	request, err := a.Begin(identity)
	if err != nil {
		t.Fatal(err)
	}
	if a.Accept(PermitLeaseResponse{PermitLeaseRequest: request, TTLMillis: 60000}) != nil {
		t.Fatal("lease fixture")
	}
	for i, tun := range successor.Allocation.Tunnels {
		successor.Observed[i] = Ownership{Namespace: successor.Allocation.Namespace, InterfaceName: tun.Name, InterfaceIndex: 10 + i, XFRMID: tun.XFRMID}
	}
	env := RuntimeEnvironment{Namespace: successor.Allocation.Namespace, Underlays: [2]RuntimeUnderlay{{InterfaceIndex: 2, OuterMTU: 1500, LocalAddress: netip.MustParseAddr("192.0.2.1")}, {InterfaceIndex: 2, OuterMTU: 1500, LocalAddress: netip.MustParseAddr("192.0.2.1")}}}
	var intents []GuardIntent
	c := &RuntimeController{config: RuntimeControllerConfig{OrgID: old.Engines[0].Binding.OrgID, GatewayID: old.Engines[0].Binding.GatewayID, DaemonAlive: func() bool { return true }}, journal: j, namespace: func() (string, error) { return old.Allocation.Namespace, nil }, qualification: testRuntimeQualification(old.Allocation.Namespace), prove: func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error { return nil }, recoveryObserve: func(context.Context, RuntimeJournalEntry) [2]string { return [2]string{"up", "up"} }, active: map[uuid.UUID]runtimeActive{successor.Allocation.ConnectionID: {Entry: successor, Environment: env, Identity: identity, Authority: a}}, replace: func(_ context.Context, in GuardIntent) (GuardManifest, error) {
		intents = append(intents, in)
		return RenderGuard(in)
	}}
	entries, _ := j.Entries()
	if c.installActive(context.Background(), entries) != nil {
		t.Fatal("fresh exact successor guard failed")
	}
	if len(intents[0].Connections) != 1 || intents[0].Connections[0].PrefixOnly || intents[0].Connections[0].ID != successor.Allocation.ConnectionID {
		t.Fatal("old sorted-ID denial eclipsed valid successor")
	}
	m, _ := RenderGuard(intents[0])
	var raw map[string]any
	_ = json.Unmarshal([]byte(m.ExpectedJSON), &raw)
	oldSets := 0
	for _, item := range raw["nftables"].([]any) {
		set, ok := item.(map[string]any)["set"].(map[string]any)
		if !ok {
			continue
		}
		name := set["name"].(string)
		if name == guardLeaseName(old.Allocation.ConnectionID) || name == guardReplyLeaseName(old.Allocation.ConnectionID) || name == guardSALeaseName(old.Allocation.ConnectionID) {
			oldSets++
			if _, ok := set["elem"]; ok {
				t.Fatal("predecessor authority retained")
			}
		}
	}
	if oldSets != 3 {
		t.Fatal("predecessor empty lease objects omitted")
	}
	elapsed = 60 * time.Second
	if c.installActive(context.Background(), entries) != nil {
		t.Fatal("expiry denial failed")
	}
	if !intents[1].Connections[0].PrefixOnly || len(c.active) != 0 {
		t.Fatal("expired successor authority retained")
	}
	if !reflect.DeepEqual(entries[0], old) {
		t.Fatal("guard projection changed cleanup history")
	}
}
func TestRetainedGuardHandoffManifestIdentity(t *testing.T) {
	_, _, m := retainedHandoffFixture(t)
	m.Manifest.RetainedGuardPredecessors[0].CleanupDeliveryID = uuid.New()
	if _, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]"); err == nil {
		t.Fatal("unhashed handoff accepted")
	}
	runtimeReseal(&m)
	if _, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]"); err != nil {
		t.Fatal("authenticated handoff shape rejected", err)
	}
}

func TestRetainedGuardHandoffPreReservationRefusesUnclaimedOverlap(t *testing.T) {
	old, successor, _ := retainedHandoffFixture(t)
	successor.RetainedGuardPredecessors = nil
	c := &RuntimeController{}
	// Refusal must occur before namespace/native APIs; a nil controller dependency
	// would panic if unclaimed overlap reached a mutation/reservation seam.
	if c.admitRetainedGuardHandoff(context.Background(), []RuntimeJournalEntry{old}, successor) == nil {
		t.Fatal("unclaimed overlap reached reservation")
	}
}

func TestRetainedGuardHandoffRepeatedRecreationAndCycleRefusal(t *testing.T) {
	old, first, m := retainedHandoffFixture(t)
	first.Phase = RuntimeRetainedRefusal
	first.CleanupID = uuid.New()
	first.CleanupDesiredRevision = first.Engines[0].Binding.DesiredRevision + 1
	first.CoveredDeliveryRevision = first.Engines[0].Binding.DesiredRevision
	m.ID = uuid.New()
	m.Manifest.ConnectionID = uuid.New()
	for i := range m.Manifest.Tunnels {
		id := uuid.New()
		m.Manifest.Tunnels[i].ID = id
		m.Manifest.Tunnels[i].LinkName = KernelTunnelName(id)
		m.Manifest.Tunnels[i].XFRMID = KernelTunnelID(id)
		m.Manifest.Tunnels[i].ReqID = KernelTunnelID(id)
		m.Secrets[i].TunnelID = id
	}
	m.Manifest.RetainedGuardPredecessors = append(m.Manifest.RetainedGuardPredecessors, RuntimeRetainedGuardPredecessor{ConnectionID: first.Allocation.ConnectionID, DeliveryID: first.DeliveryID, CleanupDeliveryID: first.CleanupID, OwnershipDigest: first.OwnershipDigest})
	sort.Slice(m.Manifest.RetainedGuardPredecessors, func(i, j int) bool {
		return m.Manifest.RetainedGuardPredecessors[i].DeliveryID.String() < m.Manifest.RetainedGuardPredecessors[j].DeliveryID.String()
	})
	runtimeReseal(&m)
	last, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, old.Allocation.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	entries, retired, err := runtimeGuardProjection([]RuntimeJournalEntry{old, first, last})
	if err != nil || len(entries) != 1 || entries[0].DeliveryID != last.DeliveryID || len(retired) != 2 {
		t.Fatal("cumulative repeated handoff refused", err)
	}
	old.RetainedGuardPredecessors = []RuntimeRetainedGuardPredecessor{{ConnectionID: first.Allocation.ConnectionID, DeliveryID: first.DeliveryID, CleanupDeliveryID: first.CleanupID, OwnershipDigest: first.OwnershipDigest}}
	if validRetainedGuardJournal([]RuntimeJournalEntry{old, first}) {
		t.Fatal("hostile cyclic handoff journal accepted")
	}
}
