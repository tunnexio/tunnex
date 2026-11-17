package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
)

// This regression intentionally records the current fail-closed outcome; it
// does not increase a production timeout. Unlike the virtual cadence fixture,
// these native-reader costs consume the actual public callback's wall budget.
type sharedDeadlineLeaseClient struct {
	base          RuntimeLeaseClient
	materials     map[uuid.UUID]RuntimeMaterial
	target        uuid.UUID
	conflict      bool
	deadlines     map[uuid.UUID]time.Time
	materialReads int
}

func (c *sharedDeadlineLeaseClient) RenewIPsecLease(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
	d, ok := ctx.Deadline()
	if !ok {
		return RuntimeLease{}, ErrRuntimeController
	}
	c.deadlines[id] = d
	if c.conflict && id == c.target {
		return RuntimeLease{}, testLeaseFailure("http_409_conflict")
	}
	return c.base.RenewIPsecLease(ctx, id, q)
}
func (c *sharedDeadlineLeaseClient) IPsecMaterial(ctx context.Context, id uuid.UUID, rev int64) (RuntimeMaterial, error) {
	c.materialReads++
	m := c.materials[id]
	if ctx.Err() != nil || rev != m.DesiredRevision || id != c.target {
		return RuntimeMaterial{}, ErrRuntimeController
	}
	// Real fixture-user revocation changes four descriptors to two, while the
	// independent ordinary LAN grants and the other user's descriptors survive.
	m.Policy.FQDNGrants = append([]RuntimeFQDNGrant(nil), m.Policy.FQDNGrants[2:]...)
	m.Policy.Hash = stringDigest([]byte("revoked exact fixture user"))
	return m, nil
}
func sharedDeadlineWait(r *renewalCycleRig, ctx context.Context, d time.Duration) error {
	started := time.Now()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
	r.charge("actual_native_wall_cost", time.Since(started))
	return ctx.Err()
}
func sharedDeadlineRig(t *testing.T) (*renewalCycleRig, *sharedDeadlineLeaseClient, uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	r, base := fqdnMultiOwnerCadenceRig(t, "live")
	base.t = nil
	ids := []uuid.UUID{}
	var bgpID uuid.UUID
	for id, a := range r.c.active {
		if len(a.FQDNLeaseDescriptors) != 4 {
			t.Fatal("live descriptor cardinality missing")
		}
		if a.Entry.ContractVersion == 2 {
			ids = append(ids, id)
		} else {
			bgpID = id
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	if len(ids) != 2 || bgpID == uuid.Nil || len(r.c.active) != 3 {
		t.Fatal("not mixed three-owner fixture")
	}
	r.charge("heartbeat_due", 2*time.Second)
	r.c.recoveryHistory[ids[0]].lastNow = *r.now - 2*time.Second
	r.c.recoveryHistory[ids[1]].lastNow = *r.now - time.Second
	// Avoid unrelated virtual cost: the injected reads below consume both real
	// context time and the original authority's existing monotonic time.
	r.c.prove = func(ctx context.Context, _ RuntimeJournalEntry, _ RuntimeEnvironment) error { return ctx.Err() }
	r.c.recoveryObserve = func(ctx context.Context, _ RuntimeJournalEntry) [2]string {
		if ctx.Err() != nil {
			return [2]string{"unknown", "unknown"}
		}
		return [2]string{"up", "up"}
	}
	client := &sharedDeadlineLeaseClient{base: base, materials: base.old, target: ids[1], deadlines: map[uuid.UUID]time.Time{}}
	r.c.client = client
	return r, client, ids[0], ids[1], bgpID
}

func TestPublicHeartbeatMixedFQDNBatchSharesFiveSecondDeadline(t *testing.T) {
	r, client, first, second, _ := sharedDeadlineRig(t)
	original := map[uuid.UUID]runtimeActive{}
	deadlines := map[uuid.UUID]time.Duration{}
	for id, a := range r.c.active {
		original[id] = cloneMaintenanceActive(a)
		deadlines[id] = a.Authority.deadline
	}
	reads := []uuid.UUID{}
	r.c.recoveryObserve = func(ctx context.Context, e RuntimeJournalEntry) [2]string {
		id := e.Allocation.ConnectionID
		reads = append(reads, id)
		cost := 1600 * time.Millisecond
		if id == second {
			cost = 3600 * time.Millisecond
		}
		if sharedDeadlineWait(r, ctx, cost) != nil {
			return [2]string{"unknown", "unknown"}
		}
		return [2]string{"up", "up"}
	}
	started := time.Now()
	reports, err := r.c.RefreshIPsecActiveRecovery(context.Background())
	elapsed := time.Since(started)
	if err == nil || len(reports) != 0 || len(reads) != 2 || reads[0] != first || reads[1] != second {
		t.Fatalf("not actual later-reader failure: err=%v reports=%d reads=%v", err, len(reports), reads)
	}
	if !client.deadlines[first].Equal(client.deadlines[second]) || elapsed < 4900*time.Millisecond || elapsed > 6500*time.Millisecond {
		t.Fatalf("later owner received fresh budget: elapsed=%s deadlines=%v", elapsed, client.deadlines)
	}
	for id, a := range original {
		if a.Authority.deadline != deadlines[id] || !r.applicationDenied[id] {
			t.Fatal("failure did not preserve finite authority and globally deny", id)
		}
	}
	t.Logf("public: first native=1.6s; second inherited remainder~3.4s; actual elapsed=%s; both lease deadlines equal; no report escaped", elapsed)
}

func TestQualifiedHeartbeatConflictProofUsesInheritedResidualBudget(t *testing.T) {
	for _, freshContext := range []bool{false, true} {
		t.Run(map[bool]string{false: "shared_parent_denies", true: "fresh_owner_control_isolates"}[freshContext], func(t *testing.T) {
			r, client, first, target, bgpID := sharedDeadlineRig(t)
			client.conflict = true
			originals := map[uuid.UUID]runtimeActive{}
			deadlines := map[uuid.UUID]time.Duration{}
			for id, a := range r.c.active {
				originals[id] = cloneMaintenanceActive(a)
				deadlines[id] = a.Authority.deadline
			}
			process := r.c.bgpProcesses[originals[bgpID].Entry.DeliveryID].(*bgpSessionFixture)
			native := map[string]time.Duration{}
			for k, v := range r.installed {
				native[k] = v
			}
			proofOwners := []uuid.UUID{}
			firstDone := false
			r.c.recoveryObserve = func(ctx context.Context, e RuntimeJournalEntry) [2]string {
				if !firstDone && e.Allocation.ConnectionID == first {
					if sharedDeadlineWait(r, ctx, 1600*time.Millisecond) != nil {
						return [2]string{"unknown", "unknown"}
					}
				}
				return [2]string{"up", "up"}
			}
			r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, _ RuntimeEnvironment) error {
				if !firstDone {
					return ctx.Err()
				}
				proofOwners = append(proofOwners, e.Allocation.ConnectionID)
				return sharedDeadlineWait(r, ctx, 1200*time.Millisecond)
			}
			flushes := 0
			r.c.guard.apply = func(ctx context.Context, raw []byte) error {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				var doc struct {
					NFTables []struct {
						Flush struct {
							Set struct{ Family, Table, Name string }
						}
					}
				}
				if json.Unmarshal(raw, &doc) != nil || len(doc.NFTables) != 3 {
					t.Fatal("not exact withdrawal")
				}
				allowed := map[string]bool{guardLeaseName(target): true, guardReplyLeaseName(target): true, guardSALeaseName(target): true}
				for _, cmd := range doc.NFTables {
					s := cmd.Flush.Set
					if s.Family != "inet" || s.Table != "tunnex_ipsec" || !allowed[s.Name] {
						t.Fatal("foreign mutation")
					}
					delete(allowed, s.Name)
					r.installed[s.Name] = 0
				}
				if len(allowed) != 0 {
					t.Fatal("duplicate target set")
				}
				r.applicationDenied[target] = true
				flushes++
				return nil
			}
			parent, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			seen := map[uuid.UUID]bool{}
			r.c.mu.Lock()
			samples, err := r.c.refreshIPsecActiveRecoveryLockedQualified(parent, seen, false, time.Now(), func() bool { return true })
			r.c.mu.Unlock()
			if err != nil || len(samples) != 1 || samples[0].ConnectionID != first {
				t.Fatal("first healthy native heartbeat missing", err, len(samples))
			}
			seen[first] = true
			firstDone = true
			secondCtx := parent
			if freshContext {
				var stop context.CancelFunc
				secondCtx, stop = context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
			}
			started := time.Now()
			r.c.mu.Lock()
			reports, err := r.c.refreshIPsecActiveRecoveryLockedQualified(secondCtx, seen, false, started, func() bool { return true })
			r.c.mu.Unlock()
			elapsed := time.Since(started)
			var withdrawn *runtimeRecoveryConflictWithdrawn
			if len(reports) != 0 || client.materialReads != 1 || len(proofOwners) != 3 || proofOwners[0] != target {
				t.Fatalf("conflict native/all-retained proof not reached: err=%v reports=%d material=%d proofs=%v", err, len(reports), client.materialReads, proofOwners)
			}
			for id, a := range originals {
				if a.Authority.deadline != deadlines[id] {
					t.Fatal("old authority extended", id)
				}
			}
			if freshContext {
				if !errors.As(err, &withdrawn) || flushes != 1 || process.closed || len(r.c.active) != 2 {
					t.Fatalf("independent bounded control failed isolation: err=%v flushes=%d closed=%v active=%d", err, flushes, process.closed, len(r.c.active))
				}
				for id, a := range originals {
					if id != target && !reflect.DeepEqual(r.c.active[id], a) {
						t.Fatal("changed retained owner", id)
					}
				}
				for name, deadline := range native {
					if name != guardLeaseName(target) && name != guardReplyLeaseName(target) && name != guardSALeaseName(target) && r.installed[name] != deadline {
						t.Fatal("changed retained native deadline", name)
					}
				}
				if !client.deadlines[target].After(client.deadlines[first]) {
					t.Fatal("control did not supply independent context")
				}
			} else {
				if err == nil || errors.As(err, &withdrawn) || parent.Err() != context.DeadlineExceeded || flushes != 0 {
					t.Fatalf("unknown expired proof failed open: err=%v parent=%v flushes=%d closed=%v", err, parent.Err(), flushes, process.closed)
				}
				for id := range originals {
					if !r.applicationDenied[id] {
						t.Fatal("shared timeout must globally deny", id)
					}
				}
				if !client.deadlines[first].Equal(client.deadlines[target]) {
					t.Fatal("nested context unexpectedly renewed parent")
				}
			}
			t.Logf("fresh_owner_control=%v first=1.6s; target+two retained native proofs requested3.6s; second elapsed=%s; typed isolation=%v; same deadline=%v", freshContext, elapsed, errors.As(err, &withdrawn), client.deadlines[first].Equal(client.deadlines[target]))
		})
	}
}
