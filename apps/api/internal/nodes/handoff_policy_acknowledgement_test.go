package nodes

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

func TestHandoffPolicyAcknowledgementsReuseKnownHealthAndFailClosed(t *testing.T) {
	site, otherSite := uuid.New(), uuid.New()
	known, unknown, crossSite, unrequested := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	wanted := map[uuid.UUID]struct{}{known: {}, unknown: {}, crossSite: {}}
	nodes := []sqlc.Node{
		{ID: known, SiteID: pgtype.UUID{Bytes: site, Valid: true}},
		{ID: unknown, SiteID: pgtype.UUID{Bytes: site, Valid: true}},
		{ID: crossSite, SiteID: pgtype.UUID{Bytes: otherSite, Valid: true}},
		{ID: unrequested, SiteID: pgtype.UUID{Bytes: site, Valid: true}},
	}
	health := map[uuid.UUID]PolicyHealth{
		known:       {PushKnown: true, PushedHash: "expected", AppliedHash: "expected"},
		unknown:     {PushKnown: false, Degraded: true},
		crossSite:   {PushKnown: true, PushedHash: "cross-site"},
		unrequested: {PushKnown: true, PushedHash: "unrequested"},
	}

	got := handoffPolicyAcknowledgementsFromHealth(site, wanted, nodes, health)
	if len(got) != 2 {
		t.Fatalf("only requested exact-site nodes may be projected: %#v", got)
	}
	if ack := got[known]; !ack.ExpectedKnown || ack.ExpectedHash != "expected" || !ack.HealthKnown || ack.Degraded {
		t.Fatalf("known single-source health was not preserved: %#v", ack)
	}
	if ack := got[unknown]; ack.ExpectedKnown || ack.ExpectedHash != "" || ack.HealthKnown || !ack.Degraded {
		t.Fatalf("unknown compile/topology must stay fail-closed: %#v", ack)
	}
	if _, ok := got[crossSite]; ok {
		t.Fatal("cross-site node must not gain a handoff acknowledgement")
	}
	if _, ok := got[unrequested]; ok {
		t.Fatal("unrequested node must not gain a handoff acknowledgement")
	}
}
