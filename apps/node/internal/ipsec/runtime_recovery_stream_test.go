package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestStreamingHeartbeatPublishesBeforeLaterNativeWork(t *testing.T) {
	r, client, first, second, _ := sharedDeadlineRig(t)
	originals := map[uuid.UUID]runtimeActive{}
	deadlines := map[uuid.UUID]time.Duration{}
	for id, a := range r.c.active {
		originals[id] = cloneMaintenanceActive(a)
		deadlines[id] = a.Authority.deadline
	}
	native := map[string]time.Duration{}
	for k, v := range r.installed {
		native[k] = v
	}
	published := []uuid.UUID{}
	clocks := map[uuid.UUID]runtimeRecoveryReportClock{}
	r.c.recoveryObserve = func(ctx context.Context, e RuntimeJournalEntry) [2]string {
		cost := 1600 * time.Millisecond
		if e.Allocation.ConnectionID == second {
			if len(published) != 1 || published[0] != first {
				t.Fatal("later native owner started before first publication")
			}
			cost = 3600 * time.Millisecond
		}
		if sharedDeadlineWait(r, ctx, cost) != nil {
			return [2]string{"unknown", "unknown"}
		}
		return [2]string{"up", "up"}
	}
	started := time.Now()
	err := r.c.RefreshIPsecActiveRecoveryObserved(context.Background(), func(ctx context.Context, out RuntimeRecoveryHeartbeat) error {
		clock, ok := r.c.recoveryReportClock(r.c.active[out.ConnectionID])
		if !ok || clock.returned != *r.now || clock.sequence != *out.Report.SelectionSequence {
			t.Fatal("native return clock not immediately captured")
		}
		if d, ok := ctx.Deadline(); !ok || time.Until(d) > 5*time.Second {
			t.Fatal("unbounded owner callback")
		}
		clocks[out.ConnectionID] = clock
		published = append(published, out.ConnectionID)
		r.charge("http_after_actual_sample", 100*time.Millisecond)
		return nil
	})
	if err != nil || len(published) != 2 || published[0] != first || published[1] != second {
		t.Fatal("streamed owner missing", err, published)
	}
	if !client.deadlines[second].After(client.deadlines[first]) {
		t.Fatal("second owner inherited spent budget")
	}
	for id, clock := range clocks {
		if r.c.recoveryReportClocks[id] != clock {
			t.Fatal("publication or later owner retimed prior sample")
		}
	}
	for id, a := range originals {
		if !reflect.DeepEqual(a, r.c.active[id]) || a.Authority.deadline != deadlines[id] {
			t.Fatal("telemetry renewed authority", id)
		}
	}
	if !reflect.DeepEqual(native, r.installed) {
		t.Fatal("telemetry changed finite native leases")
	}
	t.Logf("two native observations cost1.6s+3.6s; each published before next; completed=%s", time.Since(started))
}

func TestStreamingHeartbeatDefersUnstartedOwnerAndNextCallIsFair(t *testing.T) {
	r, _, first, second, _ := sharedDeadlineRig(t)
	reads := []uuid.UUID{}
	published := []uuid.UUID{}
	r.c.recoveryObserve = func(ctx context.Context, e RuntimeJournalEntry) [2]string {
		reads = append(reads, e.Allocation.ConnectionID)
		if sharedDeadlineWait(r, ctx, 1600*time.Millisecond) != nil {
			return [2]string{"unknown", "unknown"}
		}
		return [2]string{"up", "up"}
	}
	for i, want := range []uuid.UUID{first, second} {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		err := r.c.RefreshIPsecActiveRecoveryObserved(ctx, func(_ context.Context, out RuntimeRecoveryHeartbeat) error {
			published = append(published, out.ConnectionID)
			return nil
		})
		cancel()
		if err != nil || len(reads) != i+1 || reads[i] != want || len(published) != i+1 || published[i] != want {
			t.Fatal("deferred owner starved or native work started without full reserve", err, reads, published)
		}
		if i == 0 {
			if _, ok := r.c.recoveryReportClock(r.c.active[second]); ok {
				t.Fatal("deferred owner received manufactured report")
			}
		}
	}
}

func TestStreamingHeartbeatPublicationFailureAndCancellation(t *testing.T) {
	for _, kind := range []string{"http", "parent_cancel", "authority_expired", "epoch_changed", "owner_missing", "authority_replaced"} {
		t.Run(kind, func(t *testing.T) {
			r, _, first, _, _ := sharedDeadlineRig(t)
			originals := map[uuid.UUID]runtimeActive{}
			deadlines := map[uuid.UUID]time.Duration{}
			for id, a := range r.c.active {
				originals[id] = cloneMaintenanceActive(a)
				deadlines[id] = a.Authority.deadline
			}
			reads := 0
			r.c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { reads++; return [2]string{"up", "up"} }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sent := 0
			err := r.c.RefreshIPsecActiveRecoveryObserved(ctx, func(_ context.Context, out RuntimeRecoveryHeartbeat) error {
				sent++
				if out.ConnectionID != first {
					t.Fatal("wrong oldest owner")
				}
				switch kind {
				case "owner_missing":
					delete(r.c.active, first)
				case "authority_replaced":
					a := r.c.active[first]
					a.Authority = clonePermitLeaseAuthorityForTest(a.Authority)
					r.c.active[first] = a
				case "parent_cancel":
					cancel()
				case "authority_expired":
					*r.now = originals[first].Authority.deadline + time.Second
				case "epoch_changed":
					a := r.c.active[first]
					a.Identity.PolicyHash = stringDigest([]byte("different policy"))
					r.c.active[first] = a
				}
				return errors.New("advisory delivery failed")
			})
			if err == nil || reads != 1 || sent != 1 {
				t.Fatal("continued after failed owner", err, reads, sent)
			}
			for id, a := range originals {
				if a.Authority.deadline != deadlines[id] {
					t.Fatal("authority moved")
				}
				if kind == "http" {
					if !reflect.DeepEqual(a, r.c.active[id]) || r.applicationDenied[id] {
						t.Fatal("HTTP failure changed native authority")
					}
				} else if !r.applicationDenied[id] {
					t.Fatal("unknown postpublication state did not deny", id)
				}
			}
		})
	}
}

func TestStreamingHeartbeatKnownRevocationPreservesEarlierOwner(t *testing.T) {
	r, client, first, target, bgpID := sharedDeadlineRig(t)
	client.conflict = true
	originals := map[uuid.UUID]runtimeActive{}
	deadlines := map[uuid.UUID]time.Duration{}
	for id, a := range r.c.active {
		originals[id] = cloneMaintenanceActive(a)
		deadlines[id] = a.Authority.deadline
	}
	process := r.c.bgpProcesses[originals[bgpID].Entry.DeliveryID]
	native := map[string]time.Duration{}
	for k, v := range r.installed {
		native[k] = v
	}
	published := 0
	proofs := 0
	r.c.recoveryObserve = func(ctx context.Context, e RuntimeJournalEntry) [2]string {
		if published == 0 {
			if e.Allocation.ConnectionID != first {
				t.Fatal("wrong first owner")
			}
			if sharedDeadlineWait(r, ctx, 1600*time.Millisecond) != nil {
				return [2]string{"unknown", "unknown"}
			}
		}
		return [2]string{"up", "up"}
	}
	r.c.prove = func(ctx context.Context, _ RuntimeJournalEntry, _ RuntimeEnvironment) error {
		if published == 0 {
			return ctx.Err()
		}
		proofs++
		return sharedDeadlineWait(r, ctx, 1200*time.Millisecond)
	}
	flushed := 0
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
			t.Fatal("wrong native withdrawal")
		}
		names := map[string]bool{guardLeaseName(target): true, guardReplyLeaseName(target): true, guardSALeaseName(target): true}
		for _, cmd := range doc.NFTables {
			s := cmd.Flush.Set
			if s.Family != "inet" || s.Table != "tunnex_ipsec" || !names[s.Name] {
				t.Fatal("foreign withdrawal")
			}
			delete(names, s.Name)
			r.installed[s.Name] = 0
		}
		if len(names) != 0 {
			t.Fatal("duplicate withdrawal")
		}
		r.applicationDenied[target] = true
		flushed++
		return nil
	}
	// Native Linux qualification remains the existing private fixture seam. The
	// public non-conflict streaming test above exercises the real public method.
	err := r.c.refreshIPsecActiveRecoveryObserved(context.Background(), func(_ context.Context, out RuntimeRecoveryHeartbeat) error {
		if out.ConnectionID != first {
			t.Fatal("revoked owner published")
		}
		published++
		return nil
	}, func() bool { return true })
	var withdrawn *runtimeRecoveryConflictWithdrawn
	if !errors.As(err, &withdrawn) || published != 1 || proofs != 3 || flushed != 1 || len(r.c.active) != 2 || client.materialReads != 1 {
		t.Fatal("fresh owner budget failed exact revocation isolation", err, published, proofs, flushed, len(r.c.active))
	}
	if !client.deadlines[target].After(client.deadlines[first]) {
		t.Fatal("conflict owner has spent deadline")
	}
	for id, a := range originals {
		if a.Authority.deadline != deadlines[id] {
			t.Fatal("original authority extended")
		}
		if id != target && (!reflect.DeepEqual(a, r.c.active[id]) || r.applicationDenied[id]) {
			t.Fatal("retained owner changed")
		}
	}
	for name, want := range native {
		if name != guardLeaseName(target) && name != guardReplyLeaseName(target) && name != guardSALeaseName(target) && r.installed[name] != want {
			t.Fatal("retained native deadline changed")
		}
	}
	if r.c.bgpProcesses[originals[bgpID].Entry.DeliveryID] != process || !process.Alive() {
		t.Fatal("unrelated BGP process replaced")
	}
}

func TestStreamingHeartbeatLaterUnknownOrCanceledNativeStillDenies(t *testing.T) {
	for _, kind := range []string{"unknown", "parent_cancel"} {
		t.Run(kind, func(t *testing.T) {
			r, _, first, second, _ := sharedDeadlineRig(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			published, reads := 0, 0
			r.c.recoveryObserve = func(_ context.Context, e RuntimeJournalEntry) [2]string {
				reads++
				if e.Allocation.ConnectionID == second {
					if published != 1 {
						t.Fatal("first report was not published before later read")
					}
					if kind == "parent_cancel" {
						cancel()
					} else {
						return [2]string{"unknown", "unknown"}
					}
				}
				return [2]string{"up", "up"}
			}
			err := r.c.RefreshIPsecActiveRecoveryObserved(ctx, func(_ context.Context, out RuntimeRecoveryHeartbeat) error {
				if out.ConnectionID != first {
					t.Fatal("failed later owner published")
				}
				published++
				return nil
			})
			if err == nil || reads != 2 || published != 1 {
				t.Fatal("unknown or canceled native read accepted", err, reads, published)
			}
			for id := range r.applicationDenied {
				if !r.applicationDenied[id] {
					t.Fatal("later unknown proof retained native access", id)
				}
			}
			if len(r.c.recoveryReportClocks) != 0 {
				t.Fatal("global denial retained positive report clocks")
			}
		})
	}
}
