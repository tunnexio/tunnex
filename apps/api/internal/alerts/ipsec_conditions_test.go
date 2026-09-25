package alerts

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"testing"
)

func TestIPsecConditionsEvidenceAndSeverity(t *testing.T) {
	c := ipsec.Connection{ID: uuid.New(), OrgID: uuid.New(), Name: "AWS"}
	for _, tc := range []struct {
		a, b                            string
		down, critical, unknown, retain int
	}{
		{"up", "up", 0, 0, 0, 0}, {"down", "up", 1, 0, 0, 0}, {"up", "down", 1, 0, 0, 0},
		{"down", "down", 2, 1, 0, 0}, {"unknown", "unknown", 0, 0, 1, 3},
		{"unknown", "down", 1, 0, 1, 2}, {"up", "unknown", 0, 0, 1, 1},
	} {
		t.Run(tc.a+"/"+tc.b, func(t *testing.T) {
			status := ipsec.ConnectionStatus{Tunnels: []ipsec.RuntimeTunnelStatus{{Slot: 1, Status: tc.a}, {Slot: 2, Status: tc.b}}}
			events, retain := ipsecConditions(c, status)
			counts := map[EventKey]int{}
			for _, e := range events {
				if err := e.Validate(); err != nil {
					t.Fatal(err)
				}
				if e.OrgID != c.OrgID || e.Resource.ID != c.ID.String() {
					t.Fatal("resource scope lost")
				}
				counts[e.Key]++
				if (e.Key == EventIPsecConnectionDown) != (e.Severity == SeverityCritical) {
					t.Fatalf("severity: %#v", e)
				}
			}
			if counts[EventIPsecTunnelDown] != tc.down || counts[EventIPsecConnectionDown] != tc.critical || counts[EventIPsecStatusUnavailable] != tc.unknown || len(retain) != tc.retain {
				t.Fatalf("events=%v retain=%v", events, retain)
			}
		})
	}
}
func TestIPsecUnknownDoesNotResolveDownIncidents(t *testing.T) {
	c := ipsec.Connection{ID: uuid.New(), OrgID: uuid.New(), Name: "AWS"}
	down, _ := ipsecConditions(c, ipsec.ConnectionStatus{Tunnels: []ipsec.RuntimeTunnelStatus{{Slot: 1, Status: "down"}, {Slot: 2, Status: "down"}}})
	unknown, retain := ipsecConditions(c, ipsec.ConnectionStatus{})
	pub := &lifecycleRecorder{active: down}
	scanner := NewScopedProductConditionScanner(productSource{snapshots: []ProductHealthSnapshot{{OrgID: c.OrgID, Events: unknown, RetainDedupKeys: retain}}}, pub, IPsecKeys())
	if err := scanner.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(pub.published) != 1 || pub.published[0].Key != EventIPsecStatusUnavailable || pub.published[0].State != EventStateFiring {
		t.Fatalf("false recovery: %#v", pub.published)
	}
	pub.published = nil
	pub.active = append(down, unknown...)
	scanner = NewScopedProductConditionScanner(productSource{snapshots: []ProductHealthSnapshot{{OrgID: c.OrgID}}}, pub, IPsecKeys())
	if err := scanner.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(pub.published) != 4 {
		t.Fatalf("recovery count %d", len(pub.published))
	}
	for _, e := range pub.published {
		if e.State != EventStateResolved {
			t.Fatal("not resolved")
		}
	}
}
