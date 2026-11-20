package nodes

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// SSI-12: the receive counter is the fast heartbeat. These pin the rule in deriveMemberLiveness.
func TestDeriveMemberLivenessRxProgress(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	hub := uuid.New()
	w1, w2 := uuid.New(), uuid.New()
	const key = "hub-pubkey"
	ts := func(ago time.Duration) pgtype.Timestamptz {
		return pgtype.Timestamptz{Time: now.Add(-ago), Valid: true}
	}
	row := func(witness uuid.UUID, handshakeAgo, reportedAgo, rxAgo time.Duration, stalled int32) sqlc.NodePeerStatus {
		return sqlc.NodePeerStatus{NodeID: witness, PublicKey: key, LastHandshakeAt: ts(handshakeAgo),
			UpdatedAt: now.Add(-reportedAgo), RxAdvancedAt: ts(rxAgo), StalledReports: stalled}
	}
	derive := func(rows ...sqlc.NodePeerStatus) MemberLiveness {
		return deriveMemberLiveness([]uuid.UUID{hub}, map[uuid.UUID]string{hub: key}, rows, nil, now)[hub]
	}

	t.Run("a frozen counter is stale long before the handshake window", func(t *testing.T) {
		// handshake only 60s old: the old rule called this fresh for another three minutes
		got := derive(row(w1, 60*time.Second, 5*time.Second, 45*time.Second, 3))
		if !got.Observed || got.Fresh {
			t.Fatalf("want observed+stale, got %+v", got)
		}
		if got.Silent != 45*time.Second {
			t.Fatalf("silent = %v, want the receive silence 45s", got.Silent)
		}
	})
	t.Run("an old handshake on a link still receiving is fresh", func(t *testing.T) {
		// 300s handshake age would be STALE by the handshake rule; keepalives are still arriving
		got := derive(row(w1, 300*time.Second, 5*time.Second, 8*time.Second, 0))
		if !got.Fresh {
			t.Fatalf("receive progress must outrank handshake age, got %+v", got)
		}
	})
	t.Run("one unchanged report is not a stall", func(t *testing.T) {
		if got := derive(row(w1, 60*time.Second, 5*time.Second, 50*time.Second, 1)); !got.Fresh {
			t.Fatalf("a single frozen report must not be stale, got %+v", got)
		}
	})
	t.Run("frozen reports inside the window are not a stall", func(t *testing.T) {
		if got := derive(row(w1, 60*time.Second, 2*time.Second, 20*time.Second, 4)); !got.Fresh {
			t.Fatalf("frozen for 20s (< window) must not be stale, got %+v", got)
		}
	})
	t.Run("any witness seeing progress outvotes a stalled one", func(t *testing.T) {
		got := derive(row(w1, 60*time.Second, 5*time.Second, 90*time.Second, 5), row(w2, 60*time.Second, 5*time.Second, 6*time.Second, 0))
		if !got.Fresh {
			t.Fatalf("one witness with a broken path must not demote the hub, got %+v", got)
		}
	})
	t.Run("a witness that stopped reporting says nothing: the handshake rule decides", func(t *testing.T) {
		// the witness died 5 minutes ago; its frozen row is not testimony
		fresh := derive(row(w1, 100*time.Second, 300*time.Second, 300*time.Second, 9))
		if !fresh.Fresh {
			t.Fatalf("silent witness + 100s handshake must be fresh by the handshake rule, got %+v", fresh)
		}
		stale := derive(row(w1, 400*time.Second, 300*time.Second, 300*time.Second, 9))
		if stale.Fresh {
			t.Fatalf("silent witness + 400s handshake must be stale by the handshake rule, got %+v", stale)
		}
	})
	t.Run("a link that never handshaked gives no verdict", func(t *testing.T) {
		r := row(w1, 0, 5*time.Second, 90*time.Second, 5)
		r.LastHandshakeAt = pgtype.Timestamptz{}
		if got := derive(r); got.Observed {
			t.Fatalf("never-handshaked link must be unobserved, got %+v", got)
		}
	})
	t.Run("a row from before the migration falls back to the handshake rule", func(t *testing.T) {
		r := row(w1, 100*time.Second, 5*time.Second, 0, 0)
		r.RxAdvancedAt = pgtype.Timestamptz{}
		if got := derive(r); !got.Fresh || got.Silent != 100*time.Second {
			t.Fatalf("want handshake-rule fresh with silent=100s, got %+v", got)
		}
	})
}

// The box-walk deleted the only other network: its gateway stopped reporting the hubs, its rows froze like a
// dead hub's, and both hubs were demoted with nobody left to restore them. An unbound gateway is no witness.
func TestWitnessRowsDropsGatewaysThatNoLongerPeer(t *testing.T) {
	bound, unbound := uuid.New(), uuid.New()
	site := pgtype.UUID{Bytes: uuid.New(), Valid: true}
	rows := []sqlc.NodePeerStatus{{NodeID: bound, PublicKey: "hub"}, {NodeID: unbound, PublicKey: "hub"}}
	got := witnessRows(rows, []sqlc.ListSiteGatewaysForOrgRow{{ID: bound, SiteID: site}, {ID: unbound}})
	if len(got) != 1 || got[0].NodeID != bound {
		t.Fatalf("want only the bound gateway's row, got %+v", got)
	}
	if left := witnessRows(rows, nil); len(left) != 0 {
		t.Fatalf("with no bound gateway there is no witness, got %+v", left)
	}
}
