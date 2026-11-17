package ipsec

import (
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
)

func maintenanceDueFixture(t *testing.T) (*renewalCycleRig, runtimeActive) {
	t.Helper()
	r := newRenewalCycleRig(t)
	ids := make([]uuid.UUID, 0, len(r.c.active))
	for id := range r.c.active {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	for _, id := range ids[3:] {
		delete(r.c.active, id)
	}
	// Advice is bound to the real finite set emitted by the fixture's successful
	// native commit, not to a new authority or a desired configuration.
	r.c.ordinaryNativeWindows = map[uuid.UUID]runtimeOrdinaryNativeWindow{}
	for id, a := range r.c.active {
		deadline, present := r.installed[guardLeaseName(id)]
		if !present || deadline <= *r.now+35*time.Second {
			t.Fatal("fixture lacks committed ordinary runway")
		}
		r.c.ordinaryNativeWindows[id] = runtimeOrdinaryNativeWindow{owner: cloneMaintenanceActive(a), observedAt: *r.now, deadline: deadline}
	}
	return r, r.c.active[ids[0]]
}

func TestMaintenanceDueUsesActualNativeBoundaryWithoutRenewing(t *testing.T) {
	r, old := maintenanceDueFixture(t)
	id := old.Entry.Allocation.ConnectionID
	window := r.c.ordinaryNativeWindows[id]
	deadline := old.Authority.deadline
	for _, tc := range []struct {
		name string
		at   time.Duration
		due  bool
	}{
		{"fresh", *r.now, false},
		{"before-full-proof-reserve", window.deadline - 35*time.Second - time.Nanosecond, false},
		{"at-full-proof-reserve", window.deadline - 35*time.Second, true},
		{"native-expired", window.deadline, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			*r.now = tc.at
			if got := r.c.maintenanceRenewalDue(old); got != tc.due {
				t.Fatalf("due=%t want=%t", got, tc.due)
			}
			if old.Authority.deadline != deadline || !reflect.DeepEqual(r.c.active[id], old) || !reflect.DeepEqual(r.c.ordinaryNativeWindows[id], window) {
				t.Fatal("scheduling changed original authority, active owner, or native advice")
			}
		})
	}
}

func TestMaintenanceDueInvalidAdviceCannotDefer(t *testing.T) {
	for _, mode := range []string{"missing", "foreign-authority", "foreign-policy", "active-owner-changed", "clock-backwards", "invalid-deadline", "ordinary-authority-short", "no-authority", "closed"} {
		t.Run(mode, func(t *testing.T) {
			r, old := maintenanceDueFixture(t)
			id := old.Entry.Allocation.ConnectionID
			w := r.c.ordinaryNativeWindows[id]
			switch mode {
			case "missing":
				delete(r.c.ordinaryNativeWindows, id)
			case "foreign-authority":
				w.owner.Authority = NewPermitLeaseAuthority()
				r.c.ordinaryNativeWindows[id] = w
			case "foreign-policy":
				w.owner.Identity.PolicyHash = stringDigest([]byte("other policy"))
				r.c.ordinaryNativeWindows[id] = w
			case "active-owner-changed":
				a := old
				a.Identity.PolicyHash = stringDigest([]byte("new current policy"))
				r.c.active[id] = a
			case "clock-backwards":
				w.observedAt = *r.now + time.Second
				r.c.ordinaryNativeWindows[id] = w
			case "invalid-deadline":
				w.deadline = w.observedAt
				r.c.ordinaryNativeWindows[id] = w
			case "ordinary-authority-short":
				*r.now += 40 * time.Second
				w.deadline = *r.now + time.Minute
				r.c.ordinaryNativeWindows[id] = w
			case "no-authority":
				old.Authority = nil
			case "closed":
				r.c.closed = true
			}
			if !r.c.maintenanceRenewalDue(old) {
				t.Fatal("invalid scheduling evidence deferred ordinary renewal")
			}
		})
	}
	var absent *RuntimeController
	if !absent.maintenanceRenewalDue(runtimeActive{}) {
		t.Fatal("missing runtime deferred renewal")
	}
}
