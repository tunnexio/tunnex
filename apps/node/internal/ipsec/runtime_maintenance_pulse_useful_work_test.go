package ipsec

import (
	"context"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Seed publication clocks through the existing native sample and actual returned
// callback. No clock is invented to make optional work look fresh.
type usefulWorkPulseRig struct {
	r                                *renewalCycleRig
	allowed                          map[uuid.UUID]bool
	deferral                         *maintenancePulseDeferral
	ids                              []uuid.UUID
	reads, proofs, leases, published int
	before                           map[uuid.UUID]runtimeActive
	deadlines                        map[*PermitLeaseAuthority]time.Duration
	installed                        map[string]time.Duration
}

func newUsefulWorkPulseRig(t *testing.T) *usefulWorkPulseRig {
	t.Helper()
	r, _ := fqdnMultiOwnerCadenceRig(t)
	allowed := map[uuid.UUID]bool{}
	for id := range r.c.active {
		allowed[id] = true
	}
	publish := func(context.Context, RuntimeRecoveryHeartbeat) error { return nil }
	r.charge("initial native report due", 2*time.Second)
	for i := 0; i < 2; i++ {
		if err := r.c.refreshMaintenanceActiveRecoveryQualified(context.Background(), allowed, publish, func() bool { return true }); err != nil {
			t.Fatal("actual initial FQDN report", err)
		}
	}
	d := r.c.beginMaintenancePulseDeferral(allowed, publish)
	if d == nil || len(d.owners) != 2 {
		t.Fatal("missing two real FQDN report clocks")
	}
	x := &usefulWorkPulseRig{r: r, allowed: allowed, deferral: d, before: assemblyClone(r.c.active), deadlines: map[*PermitLeaseAuthority]time.Duration{}, installed: map[string]time.Duration{}}
	for id, a := range r.c.active {
		x.deadlines[a.Authority] = a.Authority.deadline
		if a.Entry.ContractVersion == 2 {
			x.ids = append(x.ids, id)
		}
	}
	sort.Slice(x.ids, func(i, j int) bool {
		return r.c.recoveryReportClocks[x.ids[i]].returned < r.c.recoveryReportClocks[x.ids[j]].returned
	})
	if len(x.ids) != 2 {
		t.Fatal("missing two actually published static owners")
	}
	for name, end := range r.installed {
		x.installed[name] = end
	}
	observe := r.c.recoveryObserve
	r.c.recoveryObserve = func(ctx context.Context, e RuntimeJournalEntry) [2]string { x.reads++; return observe(ctx, e) }
	prove := r.c.prove
	r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
		x.proofs++
		return prove(ctx, e, env)
	}
	client := r.c.client
	r.c.client = maintenanceLeaseFunc(func(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
		x.leases++
		return client.RenewIPsecLease(ctx, id, q)
	})
	return x
}
func (x *usefulWorkPulseRig) checkNoAuthorityChange(t *testing.T) {
	t.Helper()
	if !reflect.DeepEqual(x.r.c.active, x.before) || !reflect.DeepEqual(x.r.installed, x.installed) {
		t.Fatal("optional telemetry changed active/native forwarding authority")
	}
	for auth, end := range x.deadlines {
		if auth.deadline != end {
			t.Fatal("optional telemetry extended original deadline")
		}
	}
}
func (x *usefulWorkPulseRig) pulse(publish func(context.Context, RuntimeRecoveryHeartbeat) error) error {
	if publish == nil {
		publish = func(context.Context, RuntimeRecoveryHeartbeat) error { x.published++; return nil }
	}
	return x.r.c.refreshMaintenanceActiveRecoveryQualified(context.Background(), x.allowed, publish, func() bool { return true })
}
func TestMaintenanceUsefulWorkKnownFreshReportsSkipOptionalIO(t *testing.T) {
	x := newUsefulWorkPulseRig(t)
	clocks := map[uuid.UUID]runtimeRecoveryReportClock{}
	for id, c := range x.r.c.recoveryReportClocks {
		clocks[id] = c
	}
	*x.r.now = clocks[x.ids[0]].returned + 4900*time.Millisecond
	for _, id := range x.ids {
		if *x.r.now-clocks[id].returned < 2*time.Second {
			t.Fatal("both per-owner clocks must already be due")
		}
	}
	for i := 0; i < 3; i++ {
		if err := x.pulse(nil); err != nil {
			t.Fatal(err)
		}
	}
	if x.reads != 0 || x.proofs != 0 || x.leases != 0 || x.published != 0 {
		t.Fatalf("fresh multi-owner reports consumed optional I/O: native=%d proof=%d HTTP=%d publish=%d", x.reads, x.proofs, x.leases, x.published)
	}
	if !reflect.DeepEqual(clocks, x.r.c.recoveryReportClocks) {
		t.Fatal("scheduler advanced clocks without returned observation")
	}
	x.checkNoAuthorityChange(t)
}
func TestMaintenanceUsefulWorkFiveSecondBoundarySamplesOldest(t *testing.T) {
	x := newUsefulWorkPulseRig(t)
	old := x.r.c.recoveryReportClocks[x.ids[0]]
	*x.r.now = old.returned + 5*time.Second
	var published uuid.UUID
	err := x.pulse(func(_ context.Context, out RuntimeRecoveryHeartbeat) error {
		x.published++
		published = out.ConnectionID
		return nil
	})
	if err != nil || published != x.ids[0] || x.published != 1 || x.reads != 1 || x.proofs == 0 || x.leases != 1 {
		t.Fatalf("oldest5s owner was not freshly sampled/published: err=%v owner=%v native=%d proof=%d HTTP=%d publish=%d", err, published, x.reads, x.proofs, x.leases, x.published)
	}
	next, known := x.r.c.recoveryReportClock(x.r.c.active[x.ids[0]])
	if !known || next.sequence <= old.sequence || next.returned <= old.returned {
		t.Fatal("actual returned report did not advance its own clock")
	}
	x.checkNoAuthorityChange(t)
}
func TestMaintenanceUsefulWorkSingleOwnerKeepsTwoSeconds(t *testing.T) {
	x := newUsefulWorkPulseRig(t)
	id := x.ids[0]
	for other := range x.allowed {
		x.allowed[other] = other == id
	}
	returned := x.r.c.recoveryReportClocks[id].returned
	*x.r.now = returned + 2*time.Second - time.Nanosecond
	if err := x.pulse(nil); err != nil || x.reads != 0 || x.published != 0 {
		t.Fatal("single owner sampled before original2s boundary", err)
	}
	*x.r.now = returned + 2*time.Second
	if err := x.pulse(nil); err != nil || x.reads != 1 || x.published != 1 {
		t.Fatal("multi-owner delay affected single-owner2s behavior", err, x.reads, x.published)
	}
	x.checkNoAuthorityChange(t)
}
func TestMaintenanceUsefulWorkIncompleteEvidenceUsesOriginalScheduler(t *testing.T) {
	for _, missing := range []string{"clock", "history"} {
		t.Run(missing, func(t *testing.T) {
			x := newUsefulWorkPulseRig(t)
			*x.r.now = x.r.c.recoveryReportClocks[x.ids[0]].returned + 3*time.Second
			if missing == "clock" {
				delete(x.r.c.recoveryReportClocks, x.ids[1])
			} else {
				delete(x.r.c.recoveryHistory, x.ids[1])
			}
			var owner uuid.UUID
			err := x.pulse(func(_ context.Context, out RuntimeRecoveryHeartbeat) error {
				x.published++
				owner = out.ConnectionID
				return nil
			})
			if err != nil || owner != x.ids[0] || x.reads != 1 || x.published != 1 {
				t.Fatal("missing evidence silently enabled multi-owner debounce", missing, err, owner, x.reads, x.published)
			}
			x.checkNoAuthorityChange(t)
		})
	}
}
func TestMaintenanceUsefulWorkBackwardClockRefusesWithoutIO(t *testing.T) {
	for _, missingHistory := range []bool{false, true} {
		t.Run(map[bool]string{false: "known_history", true: "missing_history"}[missingHistory], func(t *testing.T) {
			x := newUsefulWorkPulseRig(t)
			if missingHistory {
				delete(x.r.c.recoveryHistory, x.ids[1])
			}
			*x.r.now = x.r.c.recoveryReportClocks[x.ids[1]].returned - time.Nanosecond
			if err := x.pulse(nil); err == nil {
				t.Fatal("clock moved before last returned report")
			}
			if x.reads != 0 || x.proofs != 0 || x.leases != 0 || x.published != 0 {
				t.Fatal("backward clock performed optional I/O")
			}
			x.checkNoAuthorityChange(t)
		})
	}
}
func TestMaintenanceUsefulWorkRetainsTenSecondPublicationGate(t *testing.T) {
	x := newUsefulWorkPulseRig(t)
	x.r.charge("real_collection_deferral", 900*time.Millisecond)
	if !x.deferral.deferPulse(context.Background(), x.r.c) || !x.deferral.used {
		t.Fatal("missing genuine deferred collection")
	}
	oldest := x.r.c.recoveryReportClocks[x.ids[0]].returned
	*x.r.now = oldest + 10*time.Second
	if !x.deferral.reportsCurrent(x.r.c) {
		t.Fatal("existing inclusive10s boundary changed")
	}
	*x.r.now += time.Nanosecond
	if x.deferral.reportsCurrent(x.r.c) {
		t.Fatal("new scheduling extended report freshness beyond10s")
	}
	*x.r.now = x.r.c.recoveryReportClocks[x.ids[1]].returned + 10*time.Second + time.Millisecond
	refusal := ""
	err := x.pulse(func(ctx context.Context, out RuntimeRecoveryHeartbeat) error {
		refusal = x.deferral.recoveryPublicationRefusal(ctx, x.r.c, out)
		if refusal != "" {
			return ErrRuntimeController
		}
		x.published++
		return nil
	})
	if err == nil || refusal != "other_report_age" || x.reads != 1 || x.published != 0 {
		t.Fatalf("fresh native report bypassed stale sibling admission: err=%v reason=%s reads=%d published=%d", err, refusal, x.reads, x.published)
	}
	x.checkNoAuthorityChange(t)
}

func TestMaintenanceUsefulWorkOrdinaryOwnersKeepOriginalScheduler(t *testing.T) {
	r, allowed, _ := pulseDeferralFixture(t)
	oldest := *r.now
	for _, clock := range r.c.recoveryReportClocks {
		if clock.returned < oldest {
			oldest = clock.returned
		}
	}
	*r.now = oldest + 3*time.Second
	published := 0
	if err := r.c.refreshMaintenanceActiveRecovery(context.Background(), allowed, func(context.Context, RuntimeRecoveryHeartbeat) error { published++; return nil }); err != nil || published != 1 {
		t.Fatal("short-FQDN scheduling changed ordinary owner cadence", err, published)
	}
}
