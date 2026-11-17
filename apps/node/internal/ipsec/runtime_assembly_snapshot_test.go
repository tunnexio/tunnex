package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

func assemblySnapshotJSONClone[T any](in T) T {
	raw, err := json.Marshal(in)
	if err != nil {
		panic(err)
	}
	var out T
	if err = json.Unmarshal(raw, &out); err != nil {
		panic(err)
	}
	return out
}

type assemblySnapshotRig struct {
	r      *renewalCycleRig
	client *fqdnCadenceSubsetClient
	reads  [3]int
	daemon func(int, *DaemonInventory) error
	kernel func(int, *KernelInventory) error
	xfrm   func(int, *XFRMInventory) error
}

func newAssemblySnapshotRig(t *testing.T) *assemblySnapshotRig {
	t.Helper()
	r, client := fqdnMultiOwnerCadenceRig(t)
	installFQDNCadenceStatusReaders(t, r, nil)
	x := &assemblySnapshotRig{r: r, client: client}
	original := *r.c.statusReaders
	r.c.statusReaders = &runtimeStatusReaders{alive: original.alive,
		daemon: func(ctx context.Context) (DaemonInventory, error) {
			d, err := original.daemon(ctx)
			d = assemblySnapshotJSONClone(d)
			x.reads[0]++
			if err == nil && x.daemon != nil {
				err = x.daemon(x.reads[0], &d)
			}
			return d, err
		},
		kernel: func(ctx context.Context) (KernelInventory, error) {
			k, err := original.kernel(ctx)
			k = assemblySnapshotJSONClone(k)
			x.reads[1]++
			if err == nil && x.kernel != nil {
				err = x.kernel(x.reads[1], &k)
			}
			return k, err
		},
		xfrm: func(ctx context.Context) (XFRMInventory, error) {
			v, err := original.xfrm(ctx)
			v = assemblySnapshotJSONClone(v)
			x.reads[2]++
			if err == nil && x.xfrm != nil {
				err = x.xfrm(x.reads[2], &v)
			}
			return v, err
		}}
	return x
}

// A normal fresh nonce-bound candidate has already been accepted before this
// assembly seam. Its ordinary authority differs from the still-active owner;
// the snapshot itself must never create or renew that authority.
func (x *assemblySnapshotRig) candidates(t *testing.T) map[uuid.UUID]runtimeActive {
	t.Helper()
	active := assemblyClone(x.r.c.active)
	for id, a := range active {
		if a.Entry.ContractVersion != 3 {
			continue
		}
		fresh := maintenanceAuthority(x.r)()
		request, err := fresh.BeginFQDN(a.Identity, runtimeFQDNLeaseKeys(x.client.old[id].Policy))
		if err != nil {
			t.Fatal(err)
		}
		if err = fresh.Accept(PermitLeaseResponse{PermitLeaseRequest: request, TTLMillis: 60000}); err != nil {
			t.Fatal(err)
		}
		a.Authority = fresh
		active[id] = a
		return active
	}
	t.Fatal("missing ordinary candidate for post-nonce assembly")
	return nil
}

func TestAssemblySnapshotSharesOneImmutablePairAndConsumesIt(t *testing.T) {
	x := newAssemblySnapshotRig(t)
	active := x.candidates(t)
	clocks := maps.Clone(x.r.c.recoveryReportClocks)
	before := assemblyClone(x.r.c.active)
	s, err := x.r.c.beginAssemblySnapshot(context.Background(), active)
	if err != nil || s == nil {
		t.Fatal("snapshot scope not exercised", err)
	}
	for _, a := range active {
		got, e := s.statuses(a.Entry)
		if e != nil || got != [2]string{"up", "up"} {
			t.Fatal("owned status classifier failed", got, e)
		}
	}
	if x.reads != [3]int{1, 1, 1} {
		t.Fatal("per-owner status reread whole host", x.reads)
	}
	if err = s.finish(context.Background(), active); err != nil || x.reads != [3]int{2, 2, 2} {
		t.Fatal("complete second snapshot missing", err, x.reads)
	}
	if s.finish(context.Background(), active) == nil {
		t.Fatal("finished snapshot reused across transaction")
	}
	for _, a := range active {
		if _, e := s.statuses(a.Entry); e == nil {
			t.Fatal("finished statuses reused")
		}
	}
	if x.reads != [3]int{2, 2, 2} || x.client.requests != 0 || !reflect.DeepEqual(before, x.r.c.active) || !reflect.DeepEqual(clocks, x.r.c.recoveryReportClocks) {
		t.Fatal("snapshot performed authority/publication work")
	}
}

func TestAssemblySnapshotOnlyServesExactOwnedEntry(t *testing.T) {
	x := newAssemblySnapshotRig(t)
	active := x.candidates(t)
	s, err := x.r.c.beginAssemblySnapshot(context.Background(), active)
	if err != nil || s == nil {
		t.Fatal(err)
	}
	for _, a := range active {
		foreign := cloneMaintenanceActive(a).Entry
		foreign.Allocation.ConnectionID = uuid.New()
		if _, err = s.statuses(foreign); err == nil {
			t.Fatal("foreign owner borrowed statuses")
		}
		drift := cloneMaintenanceActive(a).Entry
		drift.Observed[0].InterfaceIndex++
		if _, err = s.statuses(drift); err == nil {
			t.Fatal("changed native ownership borrowed statuses")
		}
		break
	}
	if err = s.finish(context.Background(), active); err != nil {
		t.Fatal("rejected lookups corrupted valid transaction", err)
	}
}

func TestAssemblySnapshotHostInventoryFailuresRefuseWholeSet(t *testing.T) {
	for _, mode := range []string{"unknown-before", "namespace-before", "daemon-error-before", "kernel-error-before", "xfrm-error-before", "other-owner-link-drift", "other-owner-xfrm-drift", "other-owner-down-after", "namespace-after", "daemon-error-after", "kernel-error-after", "xfrm-error-after", "authority-expires-during-after"} {
		t.Run(mode, func(t *testing.T) {
			x := newAssemblySnapshotRig(t)
			active := x.candidates(t)
			x.daemon = func(pass int, d *DaemonInventory) error {
				if mode == "daemon-error-before" && pass == 1 || mode == "daemon-error-after" && pass == 2 {
					return errors.New("daemon read failed")
				}
				if mode == "other-owner-down-after" && pass == 2 {
					d.SAs[len(d.SAs)-1].Established = false
				}
				return nil
			}
			x.kernel = func(pass int, k *KernelInventory) error {
				if mode == "kernel-error-before" && pass == 1 || mode == "kernel-error-after" && pass == 2 {
					return errors.New("kernel read failed")
				}
				if mode == "namespace-before" && pass == 1 || mode == "namespace-after" && pass == 2 {
					k.Namespace = "net:[999999999]"
				}
				if mode == "unknown-before" && pass == 1 {
					k.Links = append(k.Links, k.Links[len(k.Links)-1])
				}
				if mode == "other-owner-link-drift" && pass == 2 {
					k.Links[len(k.Links)-1].Index++
				}
				if mode == "authority-expires-during-after" && pass == 2 {
					for _, a := range active {
						a.Authority.Invalidate()
						break
					}
				}
				return nil
			}
			x.xfrm = func(pass int, v *XFRMInventory) error {
				if mode == "xfrm-error-before" && pass == 1 || mode == "xfrm-error-after" && pass == 2 {
					return errors.New("xfrm read failed")
				}
				if mode == "other-owner-xfrm-drift" && pass == 2 {
					v.States[len(v.States)-1].SPI++
				}
				return nil
			}
			s, err := x.r.c.beginAssemblySnapshot(context.Background(), active)
			before := mode == "unknown-before" || mode == "namespace-before" || mode == "daemon-error-before" || mode == "kernel-error-before" || mode == "xfrm-error-before"
			if before {
				if err == nil || s != nil {
					t.Fatal("invalid first inventory admitted")
				}
				return
			}
			if err != nil || s == nil {
				t.Fatal("did not reach second native observation", err)
			}
			if s.finish(context.Background(), active) == nil {
				t.Fatal("changed sibling/failed native proof accepted")
			}
			if x.reads != [3]int{2, 2, 2} {
				t.Fatal("test skipped complete second snapshot", x.reads)
			}
			if s.finish(context.Background(), active) == nil {
				t.Fatal("failed snapshot replayed")
			}
			if x.client.requests != 0 {
				t.Fatal("native snapshot requested authority")
			}
		})
	}
}

func TestAssemblySnapshotRejectsAuthorityCommitAndClockBoundaryChanges(t *testing.T) {
	for _, mode := range []string{"new-authority-pointer", "candidate-policy", "candidate-removed", "original-owner-mutated", "journal-sequence", "namespace-changed", "canceled", "backward-clock", "budget-exceeded", "daemon-lost"} {
		t.Run(mode, func(t *testing.T) {
			x := newAssemblySnapshotRig(t)
			active := x.candidates(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s, err := x.r.c.beginAssemblySnapshot(ctx, active)
			if err != nil || s == nil {
				t.Fatal(err)
			}
			var id uuid.UUID
			for next := range active {
				id = next
				break
			}
			switch mode {
			case "new-authority-pointer":
				a := active[id]
				a.Authority = clonePermitLeaseAuthorityForTest(a.Authority)
				active[id] = a
			case "candidate-policy":
				a := active[id]
				a.Identity.PolicyHash = "changed"
				active[id] = a
			case "candidate-removed":
				delete(active, id)
			case "original-owner-mutated":
				a := x.r.c.active[id]
				a.Identity.PolicyHash = "changed"
				x.r.c.active[id] = a
			case "journal-sequence":
				entries, e := x.r.c.journal.Entries()
				if e != nil || x.r.c.journal.Save(entries) != nil {
					t.Fatal("failed to simulate intervening normal journal commit", e)
				}
			case "namespace-changed":
				x.r.c.namespace = func() (string, error) { return "net:[999999999]", nil }
			case "canceled":
				cancel()
			case "backward-clock":
				*x.r.now = s.started - time.Nanosecond
			case "budget-exceeded":
				*x.r.now = s.started + 5*time.Second + time.Nanosecond
			case "daemon-lost":
				x.r.c.config.DaemonAlive = func() bool { return false }
			}
			if s.finish(ctx, active) == nil {
				t.Fatal("transaction binding changed without invalidation")
			}
			if x.reads != [3]int{1, 1, 1} {
				t.Fatal("invalid binding performed second native read", x.reads)
			}
			if s.finish(ctx, active) == nil {
				t.Fatal("failed boundary left reusable snapshot")
			}
			if x.client.requests != 0 {
				t.Fatal("snapshot extended authority")
			}
		})
	}
}

func TestAssemblySnapshotDoesNotReplaceOrdinaryValidation(t *testing.T) {
	x := newAssemblySnapshotRig(t)
	s, err := x.r.c.beginAssemblySnapshot(context.Background(), assemblyClone(x.r.c.active))
	if err != nil || s != nil || x.reads != [3]int{} {
		t.Fatal("ordinary validation borrowed transaction snapshot", s, err, x.reads)
	}
}

// clonePermitLeaseAuthorityForTest returns an equal authority behind a new
// pointer without copying its mutex.
func clonePermitLeaseAuthorityForTest(a *PermitLeaseAuthority) *PermitLeaseAuthority {
	a.mu.Lock()
	defer a.mu.Unlock()
	return &PermitLeaseAuthority{elapsed: a.elapsed, last: a.last, pending: a.pending, started: a.started, identity: a.identity, deadline: a.deadline, pendingFQDN: a.pendingFQDN, fqdnDeadlines: a.fqdnDeadlines}
}
