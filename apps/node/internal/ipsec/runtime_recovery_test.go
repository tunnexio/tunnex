package ipsec

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

type recoveryTestLease struct {
	deny bool
	ttl  int64
}

func (l *recoveryTestLease) RenewIPsecLease(_ context.Context, _ uuid.UUID, r RuntimeLeaseRequest) (RuntimeLease, error) {
	if l.deny {
		return RuntimeLease{}, errors.New("refused")
	}
	return RuntimeLease{RuntimeLeaseRequest: r, TTLMS: l.ttl}, nil
}

type recoveryTestRig struct {
	c                   *RuntimeController
	m                   RuntimeMaterial
	env                 RuntimeEnvironment
	lease               *recoveryTestLease
	now                 time.Duration
	status              [2]string
	events              []string
	switches            int
	switchErr, proofErr bool
	permitErr           bool
	denyGuard           bool
}

func newRecoveryTestRig(t *testing.T) *recoveryTestRig {
	t.Helper()
	r := &recoveryTestRig{status: [2]string{"down", "up"}, lease: &recoveryTestLease{ttl: 60000}}
	r.m = runtimeMaterialFixture()
	version := 1
	r.m.Manifest.RecoveryVersion = &version
	runtimeReseal(&r.m)
	entry, _, err := runtimeMaterialEntry(r.m, r.m.Manifest.OrgID, r.m.Manifest.NodeID, "net:[4026531992]")
	if err != nil {
		t.Fatal(err)
	}
	for i, a := range entry.Allocation.Tunnels {
		entry.Observed[i] = Ownership{Namespace: entry.Allocation.Namespace, InterfaceName: a.Name, InterfaceIndex: 10 + i, XFRMID: a.XFRMID}
	}
	j, err := OpenRuntimeJournal(journalDir(t), r.m.Manifest.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	if err = j.Save([]RuntimeJournalEntry{entry}); err != nil {
		t.Fatal(err)
	}
	entry.Phase = RuntimeApplying
	if err = j.Save([]RuntimeJournalEntry{entry}); err != nil {
		t.Fatal(err)
	}
	entry.Phase = RuntimeApplied
	if err = j.Save([]RuntimeJournalEntry{entry}); err != nil {
		t.Fatal(err)
	}
	r.env = RuntimeEnvironment{Namespace: entry.Allocation.Namespace, Underlays: [2]RuntimeUnderlay{{InterfaceIndex: 2}, {InterfaceIndex: 2}}}
	r.c = &RuntimeController{started: true, journal: j, config: RuntimeControllerConfig{OrgID: r.m.Manifest.OrgID, GatewayID: r.m.Manifest.NodeID}, client: r.lease,
		qualification: testRuntimeQualification(entry.Allocation.Namespace), namespace: func() (string, error) { return entry.Allocation.Namespace, nil },
		recoveryPrepared: map[uuid.UUID]RuntimeEnvironment{entry.DeliveryID: r.env}, recoveryClock: func() time.Duration { return r.now },
		recoveryObserve: func(context.Context, RuntimeJournalEntry) [2]string { return r.status },
		prove: func(_ context.Context, e RuntimeJournalEntry, _ RuntimeEnvironment) error {
			if r.proofErr || r.status[selectedRuntimeSlot(e)-1] != "up" {
				return ErrRuntimeController
			}
			return nil
		},
	}
	r.c.replace = func(_ context.Context, in GuardIntent) (GuardManifest, error) {
		if in.Connections[0].PrefixOnly {
			r.events = append(r.events, "deny")
			if r.denyGuard {
				return GuardManifest{}, ErrGuardReadback
			}
		} else {
			r.events = append(r.events, "permit")
			if r.permitErr {
				return GuardManifest{}, ErrGuardReadback
			}
			expected := 10 + int(selectedRuntimeSlot(r.c.active[entry.Allocation.ConnectionID].Entry)) - 1
			if len(in.Connections[0].PermittedInterfaceIndices) != 1 || in.Connections[0].PermittedInterfaceIndices[0] != expected {
				t.Fatal("wrong permitted slot")
			}
		}
		return GuardManifest{}, nil
	}
	r.c.recoverySwitch = func(_ context.Context, _ KernelAllocation, _ [2]Ownership, target uint8) error {
		r.switches++
		r.events = append(r.events, "switch")
		if len(r.events) < 2 || r.events[len(r.events)-2] != "deny" {
			t.Fatal("route mutation without prior refusal")
		}
		entries, err := j.Entries()
		if err != nil {
			t.Fatal(err)
		}
		if target != entries[0].Recovery.SelectedSlot && (entries[0].Recovery.Stage != "pending" || entries[0].Recovery.PendingTo != target) {
			t.Fatal("route mutation without pending duty")
		}
		if r.switchErr {
			return ErrKernelApply
		}
		return nil
	}
	return r
}
func (r *recoveryTestRig) apply() error {
	entries, err := r.c.journal.Entries()
	if err != nil {
		return err
	}
	_, err = r.c.applyRecovery(context.Background(), r.m, entries, 0, r.env, nil)
	return err
}
func TestRuntimeRecoveryControllerHoldSwitchAndNoFailback(t *testing.T) {
	r := newRecoveryTestRig(t)
	for _, at := range []time.Duration{0, 5 * time.Second} {
		r.now = at
		if r.apply() == nil {
			t.Fatal("hold-down granted traffic")
		}
	}
	if r.switches != 0 {
		t.Fatal("early route mutation")
	}
	r.now = 10 * time.Second
	if err := r.apply(); err != nil {
		t.Fatal(err)
	}
	entries, _ := r.c.journal.Entries()
	if selectedRuntimeSlot(entries[0]) != 2 || entries[0].Recovery.Sequence != 1 {
		t.Fatal("completion missing")
	}
	r.now = 15 * time.Second
	r.status = [2]string{"up", "up"}
	if err := r.apply(); err != nil {
		t.Fatal(err)
	}
	if r.switches != 1 {
		t.Fatal("healthy alternate switched back")
	}
}
func TestRuntimeRecoveryControllerFaultsRetainRefusal(t *testing.T) {
	for _, kind := range []string{"lease", "guard", "route", "proof", "permit", "short-lease", "durability"} {
		t.Run(kind, func(t *testing.T) {
			r := newRecoveryTestRig(t)
			_ = r.apply()
			r.now = 5 * time.Second
			_ = r.apply()
			r.now = 10 * time.Second
			switch kind {
			case "lease":
				r.lease.deny = true
			case "guard":
				r.denyGuard = true
			case "route":
				r.switchErr = true
			case "proof":
				r.proofErr = true
			case "permit":
				r.permitErr = true
			case "short-lease":
				r.lease.ttl = 1
			case "durability":
				r.c.journal.syncDirectory = func() error { return errors.New("failed fsync") }
			}
			if r.apply() == nil {
				t.Fatal("fault acknowledged")
			}
			if len(r.c.active) != 0 {
				t.Fatal("fault retained authority")
			}
			if (kind == "lease" || kind == "guard" || kind == "short-lease" || kind == "durability") && r.switches != 0 {
				t.Fatal("mutation crossed failed gate")
			}
		})
	}
}
func TestRuntimeRecoveryPendingRetryRequiresFreshLease(t *testing.T) {
	r := newRecoveryTestRig(t)
	_ = r.apply()
	r.now = 5 * time.Second
	_ = r.apply()
	r.now = 10 * time.Second
	r.switchErr = true
	_ = r.apply()
	entries, _ := r.c.journal.Entries()
	if entries[0].Recovery.Stage != "pending" {
		t.Fatal("lost partial route duty")
	}
	r.c.active = nil
	r.c.recoveryHistory = nil
	r.switchErr = false
	r.lease.deny = true
	r.now = 15 * time.Second
	previous := r.switches
	if r.apply() == nil || r.switches != previous {
		t.Fatal("pending retry used old authority")
	}
	r.lease.deny = false
	r.now = 20 * time.Second
	if err := r.apply(); err != nil {
		t.Fatal(err)
	}
	entries, _ = r.c.journal.Entries()
	if selectedRuntimeSlot(entries[0]) != 2 {
		t.Fatal("pending retry not completed")
	}
}

func TestRuntimeRecoveryRetriesOnlyAllDownUnderRefusal(t *testing.T) {
	for _, statuses := range [][2]string{{"down", "down"}, {"down", "up"}, {"unknown", "down"}, {"up", "down"}} {
		t.Run(statuses[0]+statuses[1], func(t *testing.T) {
			r := newRecoveryTestRig(t)
			r.status = statuses
			calls := 0
			r.c.recoveryInitiate = func(ctx context.Context, _ EngineTunnel) error {
				calls++
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("unbounded retry")
				}
				if len(r.events) == 0 || r.events[len(r.events)-1] != "deny" {
					t.Fatal("retry without refusal")
				}
				if calls == 2 {
					r.status = [2]string{"up", "up"}
				}
				return nil
			}
			err := r.apply()
			if statuses == ([2]string{"down", "down"}) {
				if calls != 2 || err != nil {
					t.Fatal("corrected peer not retried", calls, err)
				}
			} else if calls != 0 {
				t.Fatal("healthy or unknown path retried")
			}
		})
	}
}

func TestRuntimeRecoveryRetryCannotReusePreRetryLease(t *testing.T) {
	r := newRecoveryTestRig(t)
	r.status = [2]string{"down", "down"}
	r.c.recoveryInitiate = func(context.Context, EngineTunnel) error {
		r.status = [2]string{"up", "up"}
		r.lease.deny = true
		return nil
	}
	if r.apply() == nil || len(r.c.active) != 0 || r.switches != 0 {
		t.Fatal("retry restored forwarding after fresh CP refusal")
	}
}
