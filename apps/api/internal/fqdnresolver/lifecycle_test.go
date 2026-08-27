package fqdnresolver

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"
)

type fixtureResolver struct {
	mu        sync.Mutex
	responses []Response
	err       error
	got       Context
}

func (r *fixtureResolver) Lookup(_ context.Context, c Context, _ string) ([]Response, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
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

func TestRefreshRejectsWholeCorruptedFamily(t *testing.T) {
	var l Lifecycle
	s := l.Refresh(context.Background(), time.Now(), &fixtureResolver{responses: []Response{answer(
		a("db.internal", "10.2.3.4", time.Minute),
		a("db.internal", "192.0.2.1", time.Minute), // corrupts all of A
		aaaa("db.internal", "fd00::7", time.Minute),
	)}}, selected, "db.internal")
	if s.Active == nil || len(s.Active.Addresses) != 1 || s.Active.Addresses[0] != addr("fd00::7") {
		t.Fatalf("corrupted A family must not publish any A address: %#v", s)
	}

	// A malformed AAAA must similarly discard all AAAA, without harming A.
	s = l.Refresh(context.Background(), time.Now(), &fixtureResolver{responses: []Response{answer(
		a("db.internal", "10.2.3.4", time.Minute),
		Record{Name: "db.internal", Type: TypeAAAA, TTL: time.Minute},
		aaaa("db.internal", "fd00::7", time.Minute),
	)}}, selected, "db.internal")
	if s.Active == nil || len(s.Active.Addresses) != 1 || s.Active.Addresses[0] != addr("10.2.3.4") {
		t.Fatalf("malformed AAAA family must not publish any AAAA address: %#v", s)
	}
}

func TestRefreshFailsClosedWhenBothFamiliesAreCorrupted(t *testing.T) {
	var l Lifecycle
	s := l.Refresh(context.Background(), time.Now(), &fixtureResolver{responses: []Response{answer(
		a("db.internal", "127.0.0.1", time.Minute),
		aaaa("db.internal", "::1", time.Minute),
	)}}, selected, "db.internal")
	if s.Active != nil || !errors.Is(s.Failure, ErrNoUsableAddresses) || s.Withdrawal == nil || s.Withdrawal.Cause != WithdrawalInvalidAnswer {
		t.Fatalf("both corrupted families must atomically withdraw: %#v", s)
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
	if s.LastGood != nil || s.Withdrawal == nil || s.Withdrawal.Cause != WithdrawalLastGoodExpiry {
		t.Fatalf("last good exceeded maximum age: %#v", s.LastGood)
	}
}

func TestLastGoodExpiryWithdrawsAnOtherwiseActiveGeneration(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	var l Lifecycle
	if s := l.Refresh(context.Background(), now, &fixtureResolver{responses: []Response{answer(a("db.internal", "10.2.3.4", time.Minute))}}, selected, "db.internal"); s.Active == nil {
		t.Fatal("setup did not publish")
	}
	s := l.Snapshot(now.Add(LastGoodMaxAge + time.Second))
	if s.Active != nil || s.LastGood != nil || s.State != StateFailed || !errors.Is(s.Failure, ErrLastGoodExpired) || s.Withdrawal == nil || s.Withdrawal.Cause != WithdrawalLastGoodExpiry || s.Withdrawal.PreviousGenerationID != 1 {
		t.Fatalf("last-good expiry must atomically withdraw active generation: %#v", s)
	}
}

func TestWithdrawalCausesAreAtomicAndStable(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	overflow := make([]Record, 0, MaxAnswers+1)
	for i := 1; i <= MaxAnswers+1; i++ {
		overflow = append(overflow, a("db.internal", "10.0.0."+strconv.Itoa(i), time.Minute))
	}
	cases := []struct {
		name  string
		r     *fixtureResolver
		cause WithdrawalCause
	}{
		{"nxdomain", &fixtureResolver{responses: []Response{{Status: StatusNXDOMAIN}}}, WithdrawalNXDOMAIN},
		{"servfail", &fixtureResolver{responses: []Response{{Status: StatusSERVFAIL}}}, WithdrawalSERVFAIL},
		{"timeout", &fixtureResolver{err: errors.New("deadline exceeded")}, WithdrawalTimeout},
		{"disagreement", &fixtureResolver{responses: []Response{answer(a("db.internal", "10.0.0.1", time.Minute)), answer(a("db.internal", "10.0.0.2", time.Minute))}}, WithdrawalDisagreement},
		{"overflow", &fixtureResolver{responses: []Response{answer(overflow...)}}, WithdrawalOverflow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var l Lifecycle
			if l.Refresh(context.Background(), now, &fixtureResolver{responses: []Response{answer(a("db.internal", "10.2.3.4", time.Minute))}}, selected, "db.internal").Active == nil {
				t.Fatal("setup did not publish")
			}
			s := l.Refresh(context.Background(), now.Add(time.Minute), tc.r, selected, "db.internal")
			if s.Active != nil || s.Withdrawal == nil || s.Withdrawal.Cause != tc.cause || s.Withdrawal.PreviousGenerationID != 1 || !s.Withdrawal.At.Equal(now.Add(time.Minute)) {
				t.Fatalf("withdrawal = %#v, snapshot = %#v", s.Withdrawal, s)
			}
		})
	}
}

func TestLifecycleConcurrentRefreshAndSnapshot(t *testing.T) {
	var l Lifecycle
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	r := &fixtureResolver{responses: []Response{answer(a("db.internal", "10.2.3.4", time.Minute))}}
	l.Refresh(context.Background(), now, r, selected, "db.internal")
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			at := now.Add(time.Duration(i+1) * time.Second)
			if i%2 == 0 {
				l.Refresh(context.Background(), at, r, selected, "db.internal")
				return
			}
			s := l.Snapshot(at)
			if s.Active != nil && s.Withdrawal != nil {
				t.Errorf("published and withdrawn simultaneously: %#v", s)
			}
		}(i)
	}
	wg.Wait()
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

func TestRefreshRefusesUnboundContextAndNonPublicRanges(t *testing.T) {
	var l Lifecycle
	s := l.Refresh(context.Background(), time.Now(), &fixtureResolver{responses: []Response{answer(a("x", "10.0.0.1", time.Minute))}}, Context{}, "x")
	if s.Active != nil || !errors.Is(s.Failure, ErrUnboundContext) {
		t.Fatalf("unbound context must never resolve: %#v", s)
	}
	for _, ip := range []string{
		"192.0.2.1", "198.51.100.1", "203.0.113.1", // documentation
		"169.254.169.254", "100.100.100.200", // link-local and metadata
		"100.64.0.1", "198.18.0.1", "192.0.0.1", "240.0.0.1", // non-public v4
		"2001:2::1", "2001:db8::1", "fd00:ec2::254", "::1", // special, documentation, metadata, loopback
	} {
		var bad Lifecycle
		record := a("x", ip, time.Minute)
		if addr(ip).Is6() {
			record = aaaa("x", ip, time.Minute)
		}
		s := bad.Refresh(context.Background(), time.Now(), &fixtureResolver{responses: []Response{answer(record)}}, selected, "x")
		if s.Active != nil || !errors.Is(s.Failure, ErrNoUsableAddresses) {
			t.Fatalf("%s must be prohibited: %#v", ip, s)
		}
	}
}

func TestRefreshPermitsOnlyPublicOrRFC1918ULAAddresses(t *testing.T) {
	for _, ip := range []string{"8.8.8.8", "10.2.3.4", "172.16.0.1", "192.168.1.1", "2606:4700:4700::1111", "fd00::7"} {
		t.Run(ip, func(t *testing.T) {
			var l Lifecycle
			record := a("allowed.internal", ip, time.Minute)
			if addr(ip).Is6() {
				record = aaaa("allowed.internal", ip, time.Minute)
			}
			s := l.Refresh(context.Background(), time.Now(), &fixtureResolver{responses: []Response{answer(record)}}, selected, "allowed.internal")
			if s.Active == nil || len(s.Active.Addresses) != 1 || s.Active.Addresses[0] != addr(ip) {
				t.Fatalf("%s must remain eligible under the D4 allow-list: %#v", ip, s)
			}
		})
	}
}
