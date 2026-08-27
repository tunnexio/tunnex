package fqdnrpc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

const (
	testOrg      = "11111111-1111-1111-1111-111111111111"
	testResource = "22222222-2222-2222-2222-222222222222"
	testSite     = "33333333-3333-3333-3333-333333333333"
	testGateway  = "44444444-4444-4444-4444-444444444444"
)

func testRequest(now time.Time) Request {
	return Request{Version: Version, RequestID: "55555555-5555-5555-5555-555555555555",
		OrgID: testOrg, ResourceID: testResource, SiteID: testSite,
		GatewayID: testGateway, Hostname: "api.example.test", RecordTypes: []RecordType{RecordA, RecordAAAA, RecordCNAME},
		Deadline: now.Add(10 * time.Second)}
}

type fakeResolver struct {
	mu      sync.Mutex
	calls   int
	records []Record
	err     error
}

func (f *fakeResolver) Resolve(ctx context.Context, host string, types []RecordType) ([]Record, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return append([]Record(nil), f.records...), nil
}

func TestResponderBindsIdentityAndPreservesDualStackRecords(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	resolver := &fakeResolver{records: []Record{
		{Name: "api.example.test", Type: RecordCNAME, Target: "edge.example.test", TTLSeconds: 45},
		{Name: "edge.example.test", Type: RecordA, Address: "10.10.0.8", TTLSeconds: 45},
		{Name: "edge.example.test", Type: RecordAAAA, Address: "fd00::8", TTLSeconds: 45},
	}}
	r := NewResponder(resolver)
	r.now = func() time.Time { return now }
	req := testRequest(now)
	resp := r.Handle(context.Background(), testGateway, req)
	if resp.Status != StatusNoError || resp.RequestID != req.RequestID || resp.OrgID != testOrg || resp.ResourceID != testResource || resp.SiteID != testSite || resp.GatewayID != testGateway {
		t.Fatalf("response did not echo full binding: %+v", resp)
	}
	if len(resp.Records) != 3 || resp.Records[1].Address != "10.10.0.8" || resp.Records[2].Address != "fd00::8" {
		t.Fatalf("dual-stack/CNAME records changed: %+v", resp.Records)
	}
}

// TestGatewayDNSRPCV1WireShape mirrors Lane2's serialized v1 contract. Keep
// this as a byte-level tripwire: API and node are different Go modules, so JSON
// field drift cannot be caught by a shared internal type.
func TestGatewayDNSRPCV1WireShape(t *testing.T) {
	deadline := time.Date(2026, 8, 27, 12, 0, 30, 0, time.UTC)
	observed := time.Date(2026, 8, 27, 12, 0, 1, 0, time.UTC)
	req := testRequest(deadline.Add(-10 * time.Second))
	req.Deadline = deadline
	response := responseFor(req, StatusNoError, "", observed)
	response.Records = []Record{{Name: "api.example.test", Type: RecordA, Address: "10.10.0.8", TTLSeconds: 30}, {Name: "api.example.test", Type: RecordAAAA, Address: "fd00::8", TTLSeconds: 30}, {Name: "api.example.test", Type: RecordCNAME, Target: "edge.example.test", TTLSeconds: 30}}
	got, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"version":1,"request_id":"55555555-5555-5555-5555-555555555555","org_id":"11111111-1111-1111-1111-111111111111","resource_id":"22222222-2222-2222-2222-222222222222","site_id":"33333333-3333-3333-3333-333333333333","gateway_id":"44444444-4444-4444-4444-444444444444","hostname":"api.example.test","record_types":["A","AAAA","CNAME"],"status":"noerror","observed_at":"2026-08-27T12:00:01Z","records":[{"name":"api.example.test","type":"A","address":"10.10.0.8","ttl_seconds":30},{"name":"api.example.test","type":"AAAA","address":"fd00::8","ttl_seconds":30},{"name":"api.example.test","type":"CNAME","target":"edge.example.test","ttl_seconds":30}]}`
	if string(got) != want {
		t.Fatalf("Gateway DNS RPC v1 JSON mismatch\nwant %s\n got %s", want, got)
	}
}

func TestResponderRefusesOlderProtocolAndWrongGatewayBeforeDNS(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	resolver := &fakeResolver{}
	r := NewResponder(resolver)
	r.now = func() time.Time { return now }

	old := testRequest(now)
	old.Version = 0
	if got := r.Handle(context.Background(), testGateway, old); got.Status != StatusServFail || got.ErrorCode != "unsupported_version" {
		t.Fatalf("old protocol must refuse loudly: %+v", got)
	}
	wrong := testRequest(now)
	if got := r.Handle(context.Background(), "66666666-6666-6666-6666-666666666666", wrong); got.Status != StatusServFail || got.ErrorCode != "disconnected" {
		t.Fatalf("wrong selected gateway must refuse: %+v", got)
	}
	if resolver.calls != 0 {
		t.Fatalf("invalid binding reached DNS %d times", resolver.calls)
	}
}

func TestResponderDeadlineAndDisconnectFailuresFailClosed(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	r := NewResponder(&fakeResolver{})
	r.now = func() time.Time { return now }
	expired := testRequest(now)
	expired.Deadline = now
	if got := r.Handle(context.Background(), testGateway, expired); got.Status != StatusServFail || got.ErrorCode != "deadline_exceeded" {
		t.Fatalf("expired request must not resolve: %+v", got)
	}

	disconnected := &fakeResolver{err: errors.New("network disconnected")}
	r = NewResponder(disconnected)
	r.now = func() time.Time { return now }
	if got := r.Handle(context.Background(), testGateway, testRequest(now)); got.Status != StatusServFail || got.ErrorCode != "disconnected" {
		t.Fatalf("disconnect must be explicit unavailable, got %+v", got)
	}

	timeout := &fakeResolver{err: context.DeadlineExceeded}
	r = NewResponder(timeout)
	r.now = func() time.Time { return now }
	if got := r.Handle(context.Background(), testGateway, testRequest(now)); got.Status != StatusServFail || got.ErrorCode != "deadline_exceeded" {
		t.Fatalf("timeout must be explicit, got %+v", got)
	}

	nxdomain := &fakeResolver{err: &net.DNSError{IsNotFound: true}}
	r = NewResponder(nxdomain)
	r.now = func() time.Time { return now }
	if got := r.Handle(context.Background(), testGateway, testRequest(now)); got.Status != StatusNXDomain || got.ErrorCode != "" {
		t.Fatalf("NXDOMAIN must preserve DNS status, got %+v", got)
	}
}

func TestResponderReplayIsIdempotentAndReusedRequestIDRefuses(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	resolver := &fakeResolver{records: []Record{{Name: "api.example.test", Type: RecordA, Address: "10.10.0.8", TTLSeconds: 30}}}
	r := NewResponder(resolver)
	r.now = func() time.Time { return now }
	req := testRequest(now)
	first := r.Handle(context.Background(), testGateway, req)
	second := r.Handle(context.Background(), testGateway, req)
	if first.Status != second.Status || first.ObservedAt != second.ObservedAt || len(first.Records) != len(second.Records) || first.Records[0] != second.Records[0] || resolver.calls != 1 {
		t.Fatalf("retry after response-post disconnect must replay same observation once: calls=%d first=%+v second=%+v", resolver.calls, first, second)
	}
	changed := req
	changed.Hostname = "other.example.test"
	if got := r.Handle(context.Background(), testGateway, changed); got.Status != StatusServFail || got.ErrorCode != "resolver_unavailable" {
		t.Fatalf("same request id with changed binding must refuse: %+v", got)
	}
	if resolver.calls != 1 {
		t.Fatalf("reused request id reached resolver: %d", resolver.calls)
	}
}

func TestResponderFailoverOnlySelectedGatewayMayAnswer(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	resolverA := &fakeResolver{records: []Record{{Name: "api.example.test", Type: RecordA, Address: "10.10.0.8", TTLSeconds: 30}}}
	resolverB := &fakeResolver{records: []Record{{Name: "api.example.test", Type: RecordA, Address: "10.20.0.8", TTLSeconds: 30}}}
	a, b := NewResponder(resolverA), NewResponder(resolverB)
	a.now, b.now = func() time.Time { return now }, func() time.Time { return now }
	req := testRequest(now)
	if got := b.Handle(context.Background(), "66666666-6666-6666-6666-666666666666", req); got.Status != StatusServFail || got.ErrorCode != "disconnected" {
		t.Fatalf("standby must not answer a primary-addressed request: %+v", got)
	}
	if got := a.Handle(context.Background(), testGateway, req); got.Status != StatusNoError || got.Records[0].Address != "10.10.0.8" {
		t.Fatalf("selected primary did not answer: %+v", got)
	}
	// A controller failover is a new bound request, not a standby answering the
	// old request. It must carry a new request id and selected-gateway identity.
	failover := req
	failover.RequestID = "77777777-7777-7777-7777-777777777777"
	failover.GatewayID = "66666666-6666-6666-6666-666666666666"
	if got := b.Handle(context.Background(), failover.GatewayID, failover); got.Status != StatusNoError || got.Records[0].Address != "10.20.0.8" {
		t.Fatalf("new selected failover gateway did not answer: %+v", got)
	}
	if resolverA.calls != 1 || resolverB.calls != 1 {
		t.Fatalf("unexpected resolver calls primary=%d standby=%d", resolverA.calls, resolverB.calls)
	}
}

func TestResponderRefusesStaleAndOverflowAnswers(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	records := make([]Record, maxRecords+1)
	for i := range records {
		records[i] = Record{Name: "api.example.test", Type: RecordA, Address: "10.10.0.8", TTLSeconds: 30}
	}
	r := NewResponder(&fakeResolver{records: records})
	r.now = func() time.Time { return now }
	if got := r.Handle(context.Background(), testGateway, testRequest(now)); got.Status != StatusServFail || got.ErrorCode != "resolver_unavailable" {
		t.Fatalf("overflow must refuse: %+v", got)
	}

	stale := testRequest(now)
	stale.Deadline = now.Add(time.Second)
	r = NewResponder(&fakeResolver{records: []Record{{Name: "api.example.test", Type: RecordA, Address: "10.10.0.8", TTLSeconds: 30}}})
	r.now = func() time.Time { return now.Add(2 * time.Second) }
	if got := r.Handle(context.Background(), testGateway, stale); got.Status != StatusServFail || got.ErrorCode != "deadline_exceeded" {
		t.Fatalf("stale request must refuse before DNS: %+v", got)
	}
}
