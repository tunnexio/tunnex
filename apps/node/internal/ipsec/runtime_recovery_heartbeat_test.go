package ipsec

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func heartbeatRig(t *testing.T) (*recoveryTestRig, *[]byte) {
	t.Helper()
	r := newRecoveryTestRig(t)
	r.status = [2]string{"up", "up"}
	if err := r.apply(); err != nil {
		t.Fatal(err)
	}
	es, _ := r.c.journal.Entries()
	e := es[0]
	a := r.c.active[e.Allocation.ConnectionID]
	g := GuardConnection{ID: e.Allocation.ConnectionID, Local: e.Engines[0].LocalPrefixes, Remote: e.Engines[0].RemotePrefixes, Tunnels: e.Observed, PermitFor: 50 * time.Second, PermittedInterfaceIndices: []int{e.Observed[0].InterfaceIndex}, ReplyIngressIndices: []int{e.Observed[0].InterfaceIndex, e.Observed[1].InterfaceIndex}, EncryptedEgress: []GuardEncryptedEgress{{TunnelInterfaceIndex: e.Observed[0].InterfaceIndex, ReqID: e.Engines[0].ReqID, Peer: e.Engines[0].RemoteAddress, UnderlayInterfaceIndex: a.Environment.Underlays[0].InterfaceIndex}}}
	m, err := RenderGuard(GuardIntent{Namespace: e.Allocation.Namespace, OwnerID: r.c.config.GatewayID, Revision: 1, Connections: []GuardConnection{g}})
	if err != nil {
		t.Fatal(err)
	}
	if r.c.journal.prepareGuard(m) != nil || r.c.journal.finishGuard(m) != nil {
		t.Fatal("guard")
	}
	raw := []byte(m.ExpectedJSON)
	r.c.guard = &RuntimeGuard{journal: r.c.journal, reader: &GuardReader{namespace: r.c.namespace, interfaces: func() ([]GuardInterface, error) {
		return []GuardInterface{{Name: e.Observed[0].InterfaceName, Index: e.Observed[0].InterfaceIndex}, {Name: e.Observed[1].InterfaceName, Index: e.Observed[1].InterfaceIndex}}, nil
	}, run: func(context.Context, ...string) ([]byte, error) { return raw, nil }}}
	return r, &raw
}
func TestActiveRecoveryHeartbeatDiscardsLeaseAndAddsNoJournalWrites(t *testing.T) {
	r, _ := heartbeatRig(t)
	es, _ := r.c.journal.Entries()
	id := es[0].Allocation.ConnectionID
	active := r.c.active[id]
	_, seq, _ := r.c.journal.guardTemplates()
	events, switches := len(r.events), r.switches
	r.now = 5 * time.Second
	lease := &refreshLeaseFixture{}
	r.c.client = lease
	reports, err := r.c.RefreshIPsecActiveRecovery(context.Background())
	if err != nil || len(reports) != 1 {
		t.Fatal(err, len(reports))
	}
	if reports[0].Report.ActiveSlot == nil || *reports[0].Report.ActiveSlot != 1 || reports[0].Report.Tunnels[0].Status != "up" {
		t.Fatal("missing actual current path")
	}
	after, _ := r.c.journal.Entries()
	_, afterSeq, _ := r.c.journal.guardTemplates()
	if !reflect.DeepEqual(es, after) || seq != afterSeq || r.c.active[id].Authority != active.Authority || len(r.events) != events || r.switches != switches || len(lease.requests) != 1 {
		t.Fatal("heartbeat changed native/journal authority")
	}
	// No intervening durable sequence means no fresh publisher receipt, even
	// though a second independently fresh native sample maintains evidence.
	r.now = 10 * time.Second
	reports, err = r.c.RefreshIPsecActiveRecovery(context.Background())
	if err != nil || len(reports) != 0 {
		t.Fatal("same sequence presented as fresh", err)
	}
}
func TestActiveRecoveryHeartbeatDownEvidenceHasNoSelectedPathOrSwitch(t *testing.T) {
	r, _ := heartbeatRig(t)
	es, _ := r.c.journal.Entries()
	id := es[0].Allocation.ConnectionID
	r.status = [2]string{"down", "up"}
	before := r.switches
	for _, at := range []time.Duration{5 * time.Second, 10 * time.Second, 15 * time.Second} {
		r.now = at
		if r.c.journal.Save(es) != nil {
			t.Fatal("normal other-provider commit")
		}
		reports, err := r.c.RefreshIPsecActiveRecovery(context.Background())
		if err != nil || len(reports) != 1 {
			t.Fatal(err)
		}
		if reports[0].Report.ActiveSlot != nil || reports[0].Report.Tunnels[0].Status != "down" {
			t.Fatal("failed primary published active")
		}
	}
	h := r.c.recoveryHistory[id]
	if h.consecutive != 3 || h.lastNow-h.firstDown != 10*time.Second || r.switches != before {
		t.Fatal("hold/route ownership changed")
	}
	r.now = 16 * time.Second
	if err := r.apply(); err != nil || r.switches != before+1 {
		t.Fatal("normal Apply failed to consume fresh exact evidence", err)
	}
}
func TestActiveRecoveryHeartbeatUnsafeEvidenceWithdrawsWithoutPositivePermit(t *testing.T) {
	for _, kind := range []string{"revoked", "nonce", "unknown", "native-expired", "original-expired", "slow", "route", "source", "namespace"} {
		t.Run(kind, func(t *testing.T) {
			r, raw := heartbeatRig(t)
			es, _ := r.c.journal.Entries()
			id := es[0].Allocation.ConnectionID
			r.now = 5 * time.Second
			lease := &refreshLeaseFixture{}
			r.c.client = lease
			events := len(r.events)
			switches := r.switches
			switch kind {
			case "revoked":
				lease.deny = true
			case "nonce":
				lease.mutate = func(v *RuntimeLease) { v.Nonce = "wrong" }
			case "unknown":
				r.status = [2]string{"unknown", "up"}
			case "native-expired":
				var table map[string]any
				if json.Unmarshal(*raw, &table) != nil {
					t.Fatal("fixture")
				}
				for _, object := range table["nftables"].([]any) {
					if set, ok := object.(map[string]any)["set"].(map[string]any); ok {
						delete(set, "elem")
					}
				}
				*raw, _ = json.Marshal(table)
			case "original-expired":
				a := r.c.active[id]
				a.Authority.elapsed = func() time.Duration { return 61 * time.Second }
			case "slow":
				r.c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { r.now += 6 * time.Second; return r.status }
			case "route":
				r.proofErr = true
			case "source":
				r.c.config.Environment = &mtuEnvironmentFixture{env: RuntimeEnvironment{}}
			case "namespace":
				r.c.namespace = func() (string, error) { return "net:[4026532999]", nil }
			}
			reports, err := r.c.RefreshIPsecActiveRecovery(context.Background())
			if err == nil || len(reports) != 0 || r.c.recoveryHistory[id] != nil {
				t.Fatal("unsafe evidence published")
			}
			if _, ok := r.c.active[id]; ok {
				t.Fatal("old target authority kept")
			}
			if r.switches != switches {
				t.Fatal("heartbeat route mutation")
			}
			for _, v := range r.events[events:] {
				if v != "deny" {
					t.Fatal("positive permit issued")
				}
			}
		})
	}
}

func TestActiveRecoveryHeartbeatShortValidateThenSlowProviderDoesNotRoundPastMaximumGap(t *testing.T) {
	r, _ := heartbeatRig(t)
	es, _ := r.c.journal.Entries()
	id := es[0].Allocation.ConnectionID
	// The old5s age gate skips this useful sample after a4s Validate, then a6s
	// indivisible provider job would put the next observation beyond10s.
	r.now = 4 * time.Second
	first, err := r.c.RefreshIPsecActiveRecovery(context.Background())
	if err != nil || len(first) != 1 || r.c.recoveryHistory[id].lastAt != r.now {
		t.Fatal("pre-provider observation skipped", err)
	}
	if r.c.journal.Save(es) != nil {
		t.Fatal("other provider normal durable commit")
	}
	r.now = 10 * time.Second
	second, err := r.c.RefreshIPsecActiveRecovery(context.Background())
	if err != nil || len(second) != 1 {
		t.Fatal("post-provider observation missing", err)
	}
	if r.c.recoveryHistory[id].lastAt != 10*time.Second {
		t.Fatal("sample incorrectly timed")
	}
}
