package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRuntimeTunnelStatusIndependentEvidence(t *testing.T) {
	e, d, k, x := runtimeProofFixture()
	got := runtimeTunnelStatuses(e, d, k, x)
	if got != [2]string{"up", "up"} {
		t.Fatal("valid observed tunnels not up", got)
	}
	d.SAs = d.SAs[1:]
	got = runtimeTunnelStatuses(e, d, k, x)
	if got != [2]string{"down", "up"} {
		t.Fatal("one absent IKE affected other tunnel", got)
	}
	e, d, k, x = runtimeProofFixture()
	d.SAs[0].Children[0].Installed = false
	got = runtimeTunnelStatuses(e, d, k, x)
	if got != [2]string{"down", "up"} {
		t.Fatal("uninstalled CHILD fabricated up", got)
	}
	e, d, k, x = runtimeProofFixture()
	x.States[0].SPI++
	got = runtimeTunnelStatuses(e, d, k, x)
	if got != [2]string{"unknown", "up"} {
		t.Fatal("mismatched independent SPI accepted", got)
	}
	e, d, k, x = runtimeProofFixture()
	d.SAs = append(d.SAs, d.SAs[0])
	got = runtimeTunnelStatuses(e, d, k, x)
	if got[0] != "unknown" {
		t.Fatal("ambiguous rekey accepted", got)
	}
	e, d, k, x = runtimeProofFixture()
	k.Links[0].Up = false
	got = runtimeTunnelStatuses(e, d, k, x)
	if got != [2]string{"down", "up"} {
		t.Fatal("interface down ignored", got)
	}
}
func TestRuntimeTunnelStatusReadFailureIsUnknown(t *testing.T) {
	e, d, k, x := runtimeProofFixture()
	e.Phase = RuntimeApplied
	readers := runtimeStatusReaders{daemon: func(context.Context) (DaemonInventory, error) { return d, nil }, kernel: func(context.Context) (KernelInventory, error) { return k, nil }, xfrm: func(context.Context) (XFRMInventory, error) { return x, errors.New("synthetic private failure") }, alive: func() bool { return true }}
	if got := runtimeObservedStatuses(context.Background(), e, readers); got != [2]string{"unknown", "unknown"} {
		t.Fatal("Applied inferred up after failed read", got)
	}
}

func TestRuntimeTunnelStatusWrongOwnershipAndPartialInventory(t *testing.T) {
	cases := map[string]func(*DaemonInventory, *KernelInventory, *XFRMInventory){
		"foreign reqid":     func(_ *DaemonInventory, _ *KernelInventory, x *XFRMInventory) { x.States[0].ReqID++ },
		"foreign interface": func(_ *DaemonInventory, k *KernelInventory, _ *XFRMInventory) { k.Links[0].Index += 100 },
		"expanded policy": func(_ *DaemonInventory, _ *KernelInventory, x *XFRMInventory) {
			x.Policies[0].Source = netip.MustParsePrefix("0.0.0.0/0")
		},
		"wrong template spi": func(_ *DaemonInventory, _ *KernelInventory, x *XFRMInventory) { x.Policies[0].TemplateSPI = 123456 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e, d, k, x := runtimeProofFixture()
			mutate(&d, &k, &x)
			if got := runtimeTunnelStatuses(e, d, k, x); got != [2]string{"unknown", "up"} {
				t.Fatal("foreign evidence accepted or unrelated tunnel changed", got)
			}
		})
	}
	e, d, k, x := runtimeProofFixture()
	calls := 0
	r := runtimeStatusReaders{daemon: func(context.Context) (DaemonInventory, error) { return d, nil }, kernel: func(context.Context) (KernelInventory, error) { return k, nil }, xfrm: func(context.Context) (XFRMInventory, error) {
		calls++
		if calls == 2 {
			return XFRMInventory{Namespace: x.Namespace}, nil
		}
		return x, nil
	}, alive: func() bool { return true }}
	if got := runtimeObservedStatuses(context.Background(), e, r); got != [2]string{"unknown", "unknown"} {
		t.Fatal("changing inventory reported definite status", got)
	}
}

func TestRuntimeActivePathRequiresLiveAuthorityAndProof(t *testing.T) {
	entry, _, _, _ := runtimeProofFixture()
	entry.ContractVersion = 2
	entry.Phase = RuntimeApplied
	entry.Recovery = &RuntimeRecoveryState{SelectedSlot: 2, Sequence: 1, Stage: "completed"}
	authority := NewPermitLeaseAuthority()
	elapsed := time.Duration(0)
	authority.elapsed = func() time.Duration { return elapsed }
	identity := PermitLeaseIdentity{DeliveryID: entry.DeliveryID, Binding: entry.Engines[0].Binding, PolicyHash: strings.Repeat("b", 64)}
	identity.Binding.PolicyRevision = 0
	req, err := authority.Begin(identity)
	if err != nil {
		t.Fatal(err)
	}
	if err = authority.Accept(PermitLeaseResponse{PermitLeaseRequest: req, TTLMillis: 60000}); err != nil {
		t.Fatal(err)
	}
	proofOK := true
	alive := true
	c := &RuntimeController{started: true, qualification: testRuntimeQualification(entry.Allocation.Namespace), config: RuntimeControllerConfig{DaemonAlive: func() bool { return alive }}, prove: func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error {
		if !proofOK {
			return ErrRuntimeController
		}
		return nil
	}, active: map[uuid.UUID]runtimeActive{entry.Allocation.ConnectionID: {Entry: entry, Authority: authority, Identity: identity}}}
	observedGuard := attachRecoveryStatusGuard(t, c, entry)
	if got := c.observedRecoveryActiveSlot(context.Background(), entry); got == nil || *got != 2 {
		t.Fatal("verified alternate missing", got)
	}
	beforeProof := c.prove
	c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error {
		elapsed = 61 * time.Second
		return nil
	}
	if c.observedRecoveryActiveSlot(context.Background(), entry) != nil {
		t.Fatal("lease expired during proof still reported active")
	}
	elapsed = 0
	c.prove = beforeProof
	savedGuard := c.guard
	c.guard = nil
	if c.observedRecoveryActiveSlot(context.Background(), entry) != nil {
		t.Fatal("missing permit readback still reported active")
	}
	c.guard = savedGuard
	goodJSON := *observedGuard
	var doc map[string][]map[string]any
	if err := json.Unmarshal([]byte(goodJSON), &doc); err != nil {
		t.Fatal(err)
	}
	for _, obj := range doc["nftables"] {
		if set, ok := obj["set"].(map[string]any); ok {
			delete(set, "elem")
		}
	}
	missingJSON, _ := json.Marshal(doc)
	*observedGuard = string(missingJSON)
	if c.observedRecoveryActiveSlot(context.Background(), entry) != nil {
		t.Fatal("expired kernel permit reported active")
	}
	*observedGuard = goodJSON
	cancelCtx, cancel := context.WithCancel(context.Background())
	c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error { cancel(); return nil }
	if c.observedRecoveryActiveSlot(cancelCtx, entry) != nil {
		t.Fatal("canceled proof reported active")
	}
	c.prove = beforeProof
	c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error { alive = false; return nil }
	if c.observedRecoveryActiveSlot(context.Background(), entry) != nil {
		t.Fatal("daemon lost during proof reported active")
	}
	alive = true
	c.prove = beforeProof
	c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error {
		c.qualification.invalid = true
		return nil
	}
	if c.observedRecoveryActiveSlot(context.Background(), entry) != nil {
		t.Fatal("qualification lost during proof reported active")
	}
	c.qualification = testRuntimeQualification(entry.Allocation.Namespace)
	c.prove = beforeProof
	proofOK = false
	if c.observedRecoveryActiveSlot(context.Background(), entry) != nil {
		t.Fatal("failed proof reported active")
	}
	proofOK = true
	elapsed = 61 * time.Second
	if c.observedRecoveryActiveSlot(context.Background(), entry) != nil {
		t.Fatal("expired permit reported active")
	}
	elapsed = 0
	alive = false
	if c.observedRecoveryActiveSlot(context.Background(), entry) != nil {
		t.Fatal("dead daemon reported active")
	}
	alive = true
	pending := entry
	pending.Recovery = &RuntimeRecoveryState{SelectedSlot: 2, Sequence: 2, Stage: "pending", PendingFrom: 2, PendingTo: 1}
	if c.observedRecoveryActiveSlot(context.Background(), pending) != nil {
		t.Fatal("pending switch reported active")
	}
	delete(c.active, entry.Allocation.ConnectionID)
	if c.observedRecoveryActiveSlot(context.Background(), entry) != nil {
		t.Fatal("journal alone reported active")
	}
}

func attachRecoveryStatusGuard(t *testing.T, c *RuntimeController, entry RuntimeJournalEntry) *string {
	t.Helper()
	intent := guardFixture()
	intent.Namespace = entry.Allocation.Namespace
	intent.OwnerID = entry.Engines[0].Binding.GatewayID
	g := &intent.Connections[0]
	g.ID = entry.Allocation.ConnectionID
	g.Tunnels = entry.Observed
	g.Local = entry.Engines[0].LocalPrefixes
	g.Remote = entry.Engines[0].RemotePrefixes
	index := int(entry.Recovery.SelectedSlot) - 1
	g.PermittedInterfaceIndices = []int{entry.Observed[index].InterfaceIndex}
	g.EncryptedEgress = []GuardEncryptedEgress{{TunnelInterfaceIndex: entry.Observed[index].InterfaceIndex, ReqID: entry.Engines[index].ReqID, Peer: entry.Engines[index].RemoteAddress, UnderlayInterfaceIndex: 3}}
	g.Grants = []GuardGrant{{Source: g.Local[0], Destination: g.Remote[0], Protocol: GuardTCP, PortLow: 443, PortHigh: 443}}
	manifest, err := RenderGuard(intent)
	if err != nil {
		t.Fatal(err)
	}
	j, err := OpenRuntimeJournal(journalDir(t), intent.OwnerID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	if j.prepareGuard(manifest) != nil || j.finishGuard(manifest) != nil {
		t.Fatal("guard fixture journal failed")
	}
	observed := manifest.ExpectedJSON
	c.journal = j
	c.guard = &RuntimeGuard{journal: j, reader: &GuardReader{namespace: func() (string, error) { return intent.Namespace, nil }, interfaces: func() ([]GuardInterface, error) {
		return []GuardInterface{{Name: entry.Observed[0].InterfaceName, Index: entry.Observed[0].InterfaceIndex}, {Name: entry.Observed[1].InterfaceName, Index: entry.Observed[1].InterfaceIndex}}, nil
	}, run: func(ctx context.Context, args ...string) ([]byte, error) {
		if !reflect.DeepEqual(args, []string{"-j", "list", "table", "inet", "tunnex_ipsec"}) {
			t.Fatal("status attempted mutation", args)
		}
		return []byte(observed), nil
	}}}
	return &observed
}

func TestRecoveryGuardPermitRequiresCurrentExactMembers(t *testing.T) {
	for _, kind := range []string{"interface", "sa", "ambiguous template", "read failure"} {
		t.Run(kind, func(t *testing.T) {
			entry, _, _, _ := runtimeProofFixture()
			entry.Recovery = &RuntimeRecoveryState{SelectedSlot: 2, Sequence: 1, Stage: "completed"}
			c := &RuntimeController{}
			observed := attachRecoveryStatusGuard(t, c, entry)
			if !c.recoveryGuardPermits(context.Background(), entry) {
				t.Fatal("positive exact readback refused")
			}
			switch kind {
			case "interface", "sa":
				name := guardLeaseName(entry.Allocation.ConnectionID)
				if kind == "sa" {
					name = guardSALeaseName(entry.Allocation.ConnectionID)
				}
				var doc map[string][]map[string]any
				if err := json.Unmarshal([]byte(*observed), &doc); err != nil {
					t.Fatal(err)
				}
				for _, obj := range doc["nftables"] {
					if set, ok := obj["set"].(map[string]any); ok && set["name"] == name {
						delete(set, "elem")
					}
				}
				raw, _ := json.Marshal(doc)
				*observed = string(raw)
				c.journal.payload.Guards[0].ExpectedJSON = string(raw)
			case "ambiguous template":
				c.journal.payload.Guards = append(c.journal.payload.Guards, c.journal.payload.Guards[0])
			case "read failure":
				c.guard.reader.run = func(context.Context, ...string) ([]byte, error) { return nil, ErrGuardRead }
			}
			if c.recoveryGuardPermits(context.Background(), entry) {
				t.Fatal("unverified permit accepted")
			}
		})
	}
}
