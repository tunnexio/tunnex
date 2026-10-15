package fqdnresolver

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func staticWork(name string, records ...StaticRecord) Work {
	w := work(name)
	w.ResolverConfig = ResolverConfig{ID: "config", Version: 1, ProfileID: "profile", MatchedSuffix: "test.internal", StaticRecords: records}
	return w
}

func TestStaticSchedulerPublishesAliasWithoutGatewayLookup(t *testing.T) {
	w := staticWork("alias.test.internal",
		StaticRecord{"alias.test.internal", "CNAME", "web.test.internal", 60},
		StaticRecord{"web.test.internal", "A", "10.180.10.229", 300},
		StaticRecord{"web.test.internal", "AAAA", "fd00::229", 300})
	store := &memoryStore{work: []Work{w}}
	lookup := &scopedFixtureResolver{}
	NewScheduler(store, lookup, SchedulerConfig{}).Tick(context.Background())
	if lookup.got.Hostname != "" {
		t.Fatal("static authority used gateway transport")
	}
	if len(store.published) != 1 || len(store.withdrawn) != 0 {
		t.Fatalf("publication=%v withdrawal=%v", store.published, store.withdrawn)
	}
	g := store.published[0]
	if len(g.Addresses) != 2 || g.Addresses[0] != netip.MustParseAddr("10.180.10.229") || g.TTL > time.Minute || g.TTL < MinTTL {
		t.Fatalf("generation=%+v", g)
	}
}

func TestStaticSchedulerMissAndExternalAliasNeverFallBack(t *testing.T) {
	for _, tc := range []struct {
		name   string
		record StaticRecord
	}{
		{"missing.test.internal", StaticRecord{"web.test.internal", "A", "10.180.10.229", 60}},
		{"alias.test.internal", StaticRecord{"alias.test.internal", "CNAME", "outside.example.com", 60}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := staticWork(tc.name, tc.record)
			store := &memoryStore{work: []Work{w}}
			lookup := &scopedFixtureResolver{responses: []Response{answer(a(tc.name, "10.2.3.4", time.Minute))}}
			NewScheduler(store, lookup, SchedulerConfig{}).Tick(context.Background())
			if lookup.got.Hostname != "" || len(store.published) != 0 || len(store.withdrawn) != 1 {
				t.Fatalf("unexpected fallback/publication: %+v %+v", lookup, store)
			}
		})
	}
}

func TestStaticSnapshotValidationFailsClosed(t *testing.T) {
	valid := StaticRecord{"web.test.internal", "A", "10.180.10.229", 60}
	for _, tc := range []struct {
		name    string
		records []StaticRecord
	}{
		{"public address", []StaticRecord{{"web.test.internal", "A", "8.8.8.8", 60}}},
		{"wrong family", []StaticRecord{{"web.test.internal", "AAAA", "10.180.10.229", 60}}},
		{"cycle", []StaticRecord{{"web.test.internal", "CNAME", "alias.test.internal", 60}, {"alias.test.internal", "CNAME", "web.test.internal", 60}}},
		{"alias address coexistence", []StaticRecord{valid, {"web.test.internal", "CNAME", "alias.test.internal", 60}}},
		{"duplicates", []StaticRecord{valid, valid}},
		{"TTL", []StaticRecord{{"web.test.internal", "A", "10.180.10.229", 0}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if staticWork("web.test.internal", tc.records...).ResolverConfig.valid() {
				t.Fatal("accepted malformed snapshot")
			}
		})
	}
	w := staticWork("web.test.internal", valid)
	w.ResolverConfig.Endpoints = []ResolverEndpoint{{Address: netip.MustParseAddr("10.1.1.53"), Port: 53, Transport: "udp"}}
	if w.ResolverConfig.valid() {
		t.Fatal("static records mixed with upstream authority")
	}
	w = staticWork("outside.example.com", valid)
	if _, err := lookupStatic(context.Background(), w); err == nil {
		t.Fatal("lookup escaped profile suffix")
	}
}

func TestStaticCompletionEndpointsNeverCreateDynamicApplicationGrants(t *testing.T) {
	for _, external := range []bool{false, true} {
		record := StaticRecord{"app.test.internal", "A", "10.180.10.229", 300}
		if external {
			record = StaticRecord{"app.test.internal", "CNAME", "outside.example.com", 300}
		}
		w := staticWork("app.test.internal", record)
		w.ResolverConfig.Endpoints = []ResolverEndpoint{{Address: netip.MustParseAddr("1.1.1.1"), Port: 53, Transport: "udp"}}
		if !w.ResolverConfig.valid() {
			t.Fatal("optional completion snapshot invalid")
		}
		store := &memoryStore{work: []Work{w}}
		lookup := &scopedFixtureResolver{responses: []Response{answer(a(w.Hostname, "10.2.3.4", time.Minute))}}
		NewScheduler(store, lookup, SchedulerConfig{}).Tick(context.Background())
		if lookup.got.Hostname != "" {
			t.Fatal("public completion leaked into application resolver RPC")
		}
		if external {
			if len(store.published) != 0 || len(store.withdrawn) != 1 {
				t.Fatal("external alias authorized dynamic application", store)
			}
		} else if len(store.published) != 1 || store.published[0].Addresses[0] != netip.MustParseAddr("10.180.10.229") {
			t.Fatal("static A behavior changed", store)
		}
	}
}
