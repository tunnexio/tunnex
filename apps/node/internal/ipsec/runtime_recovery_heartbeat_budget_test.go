package ipsec

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

// This uses real controller/journal/guard validation for two independently
// ready static providers. The elapsed clock models nontrivial native read cost;
// each observation is individually well within the existing five-second bound.
func heartbeatBudgetRig(t *testing.T) (*RuntimeController, *time.Duration, map[uuid.UUID]int, *int) {
	t.Helper()
	ns := "net:[4026531992]"
	first := runtimeMaterialFixture()
	j, err := OpenRuntimeJournal(journalDir(t), first.Manifest.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	now := 5 * time.Second
	reads := map[uuid.UUID]int{}
	denials := 0
	env := RuntimeEnvironment{Namespace: ns}
	c := &RuntimeController{started: true, journal: j,
		config:        RuntimeControllerConfig{OrgID: first.Manifest.OrgID, GatewayID: first.Manifest.NodeID, DaemonAlive: func() bool { return true }, Environment: &mtuEnvironmentFixture{env: env}},
		qualification: testRuntimeQualification(ns), namespace: func() (string, error) { return ns, nil }, client: &recoveryTestLease{ttl: 60000},
		active: map[uuid.UUID]runtimeActive{}, recoveryHistory: map[uuid.UUID]*recoveryDecision{},
		recoveryClock: func() time.Duration { return now },
		recoveryObserve: func(_ context.Context, e RuntimeJournalEntry) [2]string {
			reads[e.Allocation.ConnectionID]++
			now += 1100 * time.Millisecond
			return [2]string{"up", "up"}
		},
		prove:   func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error { return nil },
		replace: func(_ context.Context, in GuardIntent) (GuardManifest, error) { denials++; return RenderGuard(in) },
	}
	entries := []RuntimeJournalEntry{}
	connections := []GuardConnection{}
	links := []GuardInterface{}
	for n := 0; n < 2; n++ {
		m := first
		if n > 0 {
			m = runtimeMaterialFixture()
		}
		m.Manifest.OrgID, m.Manifest.NodeID, m.Manifest.SiteID = first.Manifest.OrgID, first.Manifest.NodeID, first.Manifest.SiteID
		m.Manifest.RemotePrefixes = []string{fmt.Sprintf("10.%d.0.0/24", 20+n)}
		for i := range m.Manifest.Tunnels {
			m.Manifest.Tunnels[i].InsideCIDR = fmt.Sprintf("169.254.%d.%d/30", 20+n, 4*i)
			m.Manifest.Tunnels[i].CustomerInsideAddress = fmt.Sprintf("169.254.%d.%d", 20+n, 4*i+1)
			m.Manifest.Tunnels[i].CloudInsideAddress = fmt.Sprintf("169.254.%d.%d", 20+n, 4*i+2)
		}
		one := 1
		m.Manifest.RecoveryVersion = &one
		runtimeReseal(&m)
		e, _, err := runtimeMaterialEntry(m, c.config.OrgID, c.config.GatewayID, ns)
		if err != nil {
			t.Fatal(err)
		}
		for i, a := range e.Allocation.Tunnels {
			e.Observed[i] = Ownership{Namespace: ns, InterfaceName: a.Name, InterfaceIndex: 10 + 2*n + i, XFRMID: a.XFRMID}
			links = append(links, GuardInterface{Name: a.Name, Index: 10 + 2*n + i})
		}
		entries = append(entries, e)
		a := NewPermitLeaseAuthority()
		identity := PermitLeaseIdentity{DeliveryID: e.DeliveryID, Binding: e.Engines[0].Binding, PolicyHash: m.Policy.Hash}
		req, err := a.Begin(identity)
		if err != nil || a.Accept(PermitLeaseResponse{PermitLeaseRequest: req, TTLMillis: 60000}) != nil {
			t.Fatal("authority fixture")
		}
		c.active[e.Allocation.ConnectionID] = runtimeActive{Delivery: m.RuntimeDelivery, Entry: e, Environment: env, Identity: identity, Authority: a}
		ep := recoveryEpoch{Binding: e.Engines[0].Binding, PolicyHash: m.Policy.Hash, DeliveryID: e.DeliveryID, Namespace: ns, Tunnels: [2]uuid.UUID{e.Engines[0].TunnelID, e.Engines[1].TunnelID}}
		h := &recoveryDecision{}
		h.observe(ep, 0, recoveryObservation{Epoch: ep, Current: 1, Status: [2]string{"up", "up"}, Authorized: true, At: 0})
		c.recoveryHistory[e.Allocation.ConnectionID] = h
		connections = append(connections, GuardConnection{ID: e.Allocation.ConnectionID, Local: e.Engines[0].LocalPrefixes, Remote: e.Engines[0].RemotePrefixes, Tunnels: e.Observed, PermitFor: 50 * time.Second, PermittedInterfaceIndices: []int{e.Observed[0].InterfaceIndex}, ReplyIngressIndices: []int{e.Observed[0].InterfaceIndex, e.Observed[1].InterfaceIndex}, EncryptedEgress: []GuardEncryptedEgress{{TunnelInterfaceIndex: e.Observed[0].InterfaceIndex, ReqID: e.Engines[0].ReqID, Peer: e.Engines[0].RemoteAddress, UnderlayInterfaceIndex: 2}}})
	}
	for _, phase := range []RuntimePhase{RuntimeReserved, RuntimeApplying, RuntimeApplied} {
		for i := range entries {
			entries[i].Phase = phase
		}
		if err := j.Save(entries); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range entries {
		a := c.active[e.Allocation.ConnectionID]
		a.Entry = e
		c.active[e.Allocation.ConnectionID] = a
	}
	g, err := RenderGuard(GuardIntent{Namespace: ns, OwnerID: c.config.GatewayID, Revision: 1, Connections: connections})
	if err != nil || j.prepareGuard(g) != nil || j.finishGuard(g) != nil {
		t.Fatal("guard fixture", err)
	}
	c.guard = &RuntimeGuard{journal: j, reader: &GuardReader{namespace: c.namespace, interfaces: func() ([]GuardInterface, error) { return links, nil }, run: func(context.Context, ...string) ([]byte, error) { return []byte(g.ExpectedJSON), nil }}}
	return c, &now, reads, &denials
}

func TestActiveRecoveryHeartbeatNativeCostDoesNotResampleSameConnectionInCallback(t *testing.T) {
	for _, sameSequence := range []bool{false, true} {
		t.Run(fmt.Sprint("same_sequence=", sameSequence), func(t *testing.T) {
			c, now, reads, denials := heartbeatBudgetRig(t)
			before, _ := c.journal.Entries()
			active := map[uuid.UUID]runtimeActive{}
			_, seq, _ := c.journal.guardTemplates()
			for id, a := range c.active {
				active[id] = a
			}
			if sameSequence {
				c.recoveryStatusSequence = map[uuid.UUID]uint64{}
				for _, e := range before {
					c.recoveryStatusSequence[e.DeliveryID] = seq
				}
			}
			reports, err := c.RefreshIPsecActiveRecovery(context.Background())
			total := 0
			for _, n := range reads {
				total += n
			}
			if err != nil {
				t.Fatalf("healthy callback discarded reports: err=%v native_reads=%d elapsed=%s denials=%d", err, total, *now-5*time.Second, *denials)
			}
			want := 2
			if sameSequence {
				want = 0
			}
			if len(reports) != want || total != 2 || len(reads) != 2 || *denials != 0 || *now != 7200*time.Millisecond {
				t.Fatalf("reports=%d reads=%v denials=%d elapsed=%s", len(reports), reads, *denials, *now-5*time.Second)
			}
			for id, n := range reads {
				if n != 1 || c.active[id].Authority != active[id].Authority {
					t.Fatal("resampled provider or authority replacement")
				}
			}
			after, _ := c.journal.Entries()
			_, nextSeq, _ := c.journal.guardTemplates()
			if !reflect.DeepEqual(before, after) || seq != nextSeq {
				t.Fatal("heartbeat wrote journal or changed durable sequence")
			}
		})
	}
}

func TestActiveRecoveryHeartbeatLaterCancellationStillDiscardsReportsAndWithdraws(t *testing.T) {
	c, _, reads, denials := heartbeatBudgetRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observe := c.recoveryObserve
	c.recoveryObserve = func(ctx context.Context, e RuntimeJournalEntry) [2]string {
		status := observe(ctx, e)
		if len(reads) == 2 {
			cancel()
		}
		return status
	}
	reports, err := c.RefreshIPsecActiveRecovery(ctx)
	if err == nil || len(reports) != 0 || *denials != 1 || len(reads) != 2 || len(c.active) != 1 {
		t.Fatalf("late cancellation retained reports/authority: err=%v reports=%d denials=%d targets=%d active=%d", err, len(reports), *denials, len(reads), len(c.active))
	}
}
