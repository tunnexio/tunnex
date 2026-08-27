package fqdnresolver

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

type fixtureResolver struct {
	responses []Response
	err       error
	got       Context
}

func (r *fixtureResolver) Lookup(_ context.Context, c Context, _ string) ([]Response, error) {
	r.got = c
	return r.responses, r.err
}

func addr(s string) netip.Addr          { return netip.MustParseAddr(s) }
func answer(records ...Record) Response { return Response{Status: StatusNoError, Records: records} }
func a(name, ip string, ttl time.Duration) Record {
	return Record{Name: name, Type: TypeA, Address: addr(ip), TTL: ttl}
}
func aaaa(name, ip string, ttl time.Duration) Record {
	return Record{Name: name, Type: TypeAAAA, Address: addr(ip), TTL: ttl}
}
func cname(name, target string, ttl time.Duration) Record {
	return Record{Name: name, Type: TypeCNAME, Target: target, TTL: ttl}
}

var selected = Context{ResolverID: "site-resolver-a", GatewayID: "gateway-a"}

func TestRefreshPublishesCanonicalBoundedGeneration(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	r := &fixtureResolver{responses: []Response{answer(
		cname("orders.internal.example.com.", "backend.internal.example.com.", 10*time.Second),
		a("backend.internal.example.com", "10.1.2.3", 2*time.Hour),
		aaaa("backend.internal.example.com", "fd00::3", time.Minute),
		a("backend.internal.example.com", "10.1.2.3", time.Minute),
	)}}
	var l Lifecycle
	s := l.Refresh(context.Background(), now, r, selected, "orders.internal.example.com")
	if s.State != StateHealthy || s.Active == nil || s.Active.ID != 1 {
		t.Fatalf("unexpected snapshot: %#v", s)
	}
	if r.got != selected {
		t.Fatalf("resolver context was not passed: %#v", r.got)
	}
	if got, want := s.Active.Addresses, []netip.Addr{addr("10.1.2.3"), addr("fd00::3")}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("addresses = %v, want %v", got, want)
	}
	if s.Active.TTL < MinTTL || s.Active.TTL > MaxTTL {
		t.Fatalf("effective TTL %s outside bounds", s.Active.TTL)
	}
	if !s.Active.RefreshAt.Equal(now.Add(s.Active.TTL * RefreshAt / 100)) {
		t.Fatalf("refresh time = %s", s.Active.RefreshAt)
	}

	// Returned snapshots are immutable views; a caller cannot mutate the active generation.
	s.Active.Addresses[0] = addr("10.9.9.9")
	if got := l.Snapshot(now).Active.Addresses[0]; got != addr("10.1.2.3") {
		t.Fatalf("generation leaked mutable addresses: %s", got)
	}
}

func TestRefreshRejectsOnlyBadAddressFamily(t *testing.T) {
	var l Lifecycle
	r := &fixtureResolver{responses: []Response{answer(
		a("db.internal", "127.0.0.1", time.Minute),  // rejected IPv4 family
		aaaa("db.internal", "fd00::7", time.Minute), // usable IPv6 family
	)}}
	s := l.Refresh(context.Background(), time.Now(), r, selected, "db.internal")
	if s.Active == nil || len(s.Active.Addresses) != 1 || s.Active.Addresses[0] != addr("fd00::7") {
		t.Fatalf("invalid A must not discard valid AAAA: %#v", s)
	}
}

func TestRefreshWithdrawsOnFailuresAndRetainsDiagnosticLastGood(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	good := &fixtureResolver{responses: []Response{answer(a("db.internal", "10.2.3.4", time.Minute))}}
	var l Lifecycle
	if s := l.Refresh(context.Background(), now, good, selected, "db.internal"); s.Active == nil {
		t.Fatal("good answer not published")
	}

	timeout := &fixtureResolver{err: errors.New("deadline exceeded")}
	s := l.Refresh(context.Background(), now.Add(time.Minute), timeout, selected, "db.internal")
	if s.State != StateStale || s.Active != nil || s.LastGood == nil || !errors.Is(s.Failure, ErrTimeout) {
		t.Fatalf("timeout must withdraw active generation: %#v", s)
	}

	nxdomain := &fixtureResolver{responses: []Response{{Status: StatusNXDOMAIN}}}
	s = l.Refresh(context.Background(), now.Add(2*time.Minute), nxdomain, selected, "db.internal")
	if s.State != StateNXDOMAIN || s.Active != nil || !errors.Is(s.Failure, ErrNXDOMAIN) {
		t.Fatalf("NXDOMAIN must be visibly distinct and withdrawn: %#v", s)
	}

	s = l.Snapshot(now.Add(LastGoodMaxAge + time.Second))
	if s.LastGood != nil {
		t.Fatalf("last good exceeded maximum age: %#v", s.LastGood)
	}
}

func TestRefreshFailsClosedForDisagreementOverflowAndCNAMELoop(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name      string
		responses []Response
		want      error
	}{
		{"disagreement", []Response{answer(a("x.internal", "10.0.0.1", time.Minute)), answer(a("x.internal", "10.0.0.2", time.Minute))}, ErrDisagreement},
		{"cname loop", []Response{answer(cname("x.internal", "y.internal", time.Minute), cname("y.internal", "x.internal", time.Minute))}, ErrCNAMEChain},
	}
	overflow := make([]Record, 0, MaxAnswers+1)
	for i := 1; i <= MaxAnswers+1; i++ {
		overflow = append(overflow, a("x.internal", "10.0.0."+strconv.Itoa(i), time.Minute))
	}
	cases = append(cases, struct {
		name      string
		responses []Response
		want      error
	}{"overflow", []Response{answer(overflow...)}, ErrAnswerOverflow})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var l Lifecycle
			s := l.Refresh(context.Background(), now, &fixtureResolver{responses: tc.responses}, selected, "x.internal")
			if s.Active != nil || !errors.Is(s.Failure, tc.want) {
				t.Fatalf("must fail closed with %v: %#v", tc.want, s)
			}
		})
	}
}

func TestRefreshRefusesUnboundContextAndDocumentationRanges(t *testing.T) {
	var l Lifecycle
	s := l.Refresh(context.Background(), time.Now(), &fixtureResolver{responses: []Response{answer(a("x", "10.0.0.1", time.Minute))}}, Context{}, "x")
	if s.Active != nil || !errors.Is(s.Failure, ErrUnboundContext) {
		t.Fatalf("unbound context must never resolve: %#v", s)
	}
	for _, ip := range []string{"192.0.2.1", "198.51.100.1", "203.0.113.1", "169.254.169.254", "100.100.100.200", "2001:db8::1", "::1"} {
		var bad Lifecycle
		s := bad.Refresh(context.Background(), time.Now(), &fixtureResolver{responses: []Response{answer(a("x", ip, time.Minute))}}, selected, "x")
		if s.Active != nil || !errors.Is(s.Failure, ErrNoUsableAddresses) {
			t.Fatalf("%s must be prohibited: %#v", ip, s)
		}
	}
}
