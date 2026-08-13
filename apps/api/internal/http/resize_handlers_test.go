package http

import (
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/ipalloc"
)

// mkOrphans builds n orphans already ordered (as ipalloc.Orphans returns them),
// alternating reasons so the cap test proves it doesn't group by reason.
func mkOrphans(n int) []devices.OrphanDevice {
	out := make([]devices.OrphanDevice, n)
	for i := 0; i < n; i++ {
		reason := ipalloc.ReasonOutOfRange
		if i%2 == 1 {
			reason = ipalloc.ReasonReservedCollision
		}
		out[i] = devices.OrphanDevice{
			DeviceID:   uuid.New(),
			Name:       fmt.Sprintf("dev-%02d", i),
			AssignedIP: fmt.Sprintf("10.0.0.%d", i),
			Reason:     reason,
		}
	}
	return out
}

// TestToResizeConflictCapBoundary pins the honest-count-vs-capped-list contract
// at the boundary — the off-by-one where "N devices must be removed" could lie.
func TestToResizeConflictCapBoundary(t *testing.T) {
	// Exactly 21: count is the true total (21), list is capped to 20.
	c21 := toResizeConflict(mkOrphans(21))
	if c21.OrphanCount != 21 {
		t.Fatalf("orphan_count = %d, want 21 (honest total)", c21.OrphanCount)
	}
	if len(c21.Orphans) != orphanCap {
		t.Fatalf("rendered orphans = %d, want %d (capped)", len(c21.Orphans), orphanCap)
	}

	// Exactly 20: count 20, list 20, no truncation artifact.
	c20 := toResizeConflict(mkOrphans(20))
	if c20.OrphanCount != 20 || len(c20.Orphans) != 20 {
		t.Fatalf("at cap: count=%d list=%d, want 20/20", c20.OrphanCount, len(c20.Orphans))
	}

	// Under cap: count == list.
	c5 := toResizeConflict(mkOrphans(5))
	if c5.OrphanCount != 5 || len(c5.Orphans) != 5 {
		t.Fatalf("under cap: count=%d list=%d, want 5/5", c5.OrphanCount, len(c5.Orphans))
	}

	// The rendered slice preserves the input order (numerically-lowest first) and
	// does NOT group by reason — the first 20 are indices 0..19 as given.
	for i, o := range c21.Orphans {
		wantIP := fmt.Sprintf("10.0.0.%d", i)
		if o.AssignedIp != wantIP {
			t.Fatalf("orphan[%d].assigned_ip = %s, want %s (order preserved, not reason-grouped)", i, o.AssignedIp, wantIP)
		}
	}
}
