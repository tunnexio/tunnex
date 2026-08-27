package fqdnresolver

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
)

type scriptedMailbox struct {
	request GatewayDNSRequest
	call    func(context.Context, GatewayDNSRequest) (GatewayDNSResponse, error)
	expired bool
}

func (m *scriptedMailbox) Enqueue(_ context.Context, request GatewayDNSRequest) error {
	m.request = request
	return nil
}
func (m *scriptedMailbox) Await(ctx context.Context, _ uuid.UUID) (GatewayDNSResponse, error) {
	return m.call(ctx, m.request)
}
func (m *scriptedMailbox) Expire(context.Context, uuid.UUID, time.Time) error {
	m.expired = true
	return nil
}

func rpcWork() Work {
	return Work{
		OrgID:      uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		ResourceID: uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		Hostname:   "orders.internal.example",
		Context: Context{
			ResolverID: "33333333-3333-3333-3333-333333333333",
			GatewayID:  "44444444-4444-4444-4444-444444444444",
		},
	}
}

func wireRecord(record Record) GatewayDNSRecord {
	wire := GatewayDNSRecord{Name: record.Name, Type: record.Type, Target: record.Target, TTLSeconds: uint32(record.TTL / time.Second)}
	if record.Address.IsValid() {
		wire.Address = record.Address.String()
	}
	return wire
}

func responseFor(request GatewayDNSRequest, now time.Time, records ...Record) GatewayDNSResponse {
	wired := make([]GatewayDNSRecord, 0, len(records))
	for _, record := range records {
		wired = append(wired, wireRecord(record))
	}
	return GatewayDNSResponse{
		Version: request.Version, RequestID: request.RequestID,
		OrgID: request.OrgID, ResourceID: request.ResourceID, SiteID: request.SiteID, GatewayID: request.GatewayID,
		Hostname: request.Hostname, RecordTypes: append([]RecordType(nil), request.RecordTypes...),
		ObservedAt: now, Status: StatusNoError, Records: wired,
	}
}

func newRPCTestTransport(t *testing.T, call func(context.Context, GatewayDNSRequest) (GatewayDNSResponse, error)) (*GatewayDNSRPCTransport, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	transport := NewGatewayDNSRPCTransport(&scriptedMailbox{call: call})
	transport.now = func() time.Time { return now }
	transport.newRequestID = func() uuid.UUID { return uuid.MustParse("55555555-5555-5555-5555-555555555555") }
	return transport, now
}

func TestGatewayDNSRPCTransportScopesAndValidatesCompleteDualStackObservation(t *testing.T) {
	w := rpcWork()
	var now time.Time
	transport, now := newRPCTestTransport(t, func(ctx context.Context, request GatewayDNSRequest) (GatewayDNSResponse, error) {
		if request.Version != GatewayDNSRPCVersion || request.OrgID != w.OrgID || request.ResourceID != w.ResourceID || request.SiteID.String() != w.Context.ResolverID || request.GatewayID.String() != w.Context.GatewayID {
			t.Fatalf("request lost server-owned scope: %#v", request)
		}
		if got, want := request.RecordTypes, []RecordType{TypeA, TypeAAAA, TypeCNAME}; !sameRecordTypes(want, got) {
			t.Fatalf("record types = %v, want %v", got, want)
		}
		if request.Deadline.IsZero() || request.RequestID == uuid.Nil {
			t.Fatalf("request missing deadline/correlation: %#v", request)
		}
		if deadline, ok := ctx.Deadline(); !ok || !deadline.Equal(request.Deadline) {
			t.Fatalf("broker context deadline = %s/%v, want request deadline %s", deadline, ok, request.Deadline)
		}
		return responseFor(request, now,
			Record{Name: w.Hostname, Type: TypeA, Address: netip.MustParseAddr("10.20.30.40"), TTL: time.Minute},
			Record{Name: w.Hostname, Type: TypeAAAA, Address: netip.MustParseAddr("fd00::40"), TTL: time.Minute},
		), nil
	})
	responses, err := transport.LookupWork(context.Background(), w)
	if err != nil {
		t.Fatal(err)
	}
	result, err := canonical(w.Hostname, responses)
	if err != nil || len(result.addresses) != 2 {
		t.Fatalf("dual-stack response must remain usable: result=%#v err=%v", result, err)
	}
}

func TestGatewayDNSRPCTransportFailsClosedForIdentityFreshnessReplayAndLimits(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*GatewayDNSResponse, time.Time)
		want   error
	}{
		{"version", func(r *GatewayDNSResponse, _ time.Time) { r.Version++ }, ErrGatewayDNSRPCVersion},
		{"identity", func(r *GatewayDNSResponse, _ time.Time) { r.GatewayID = uuid.New() }, ErrGatewayDNSRPCIdentity},
		{"replay", func(r *GatewayDNSResponse, _ time.Time) { r.RequestID = uuid.New() }, ErrGatewayDNSRPCReplay},
		{"stale", func(r *GatewayDNSResponse, now time.Time) {
			r.ObservedAt = now.Add(-GatewayDNSResponseMaxAge - time.Second)
		}, ErrGatewayDNSRPCStale},
		{"after deadline", func(r *GatewayDNSResponse, now time.Time) { r.ObservedAt = now.Add(6 * time.Second) }, ErrGatewayDNSRPCStale},
		{"bad A", func(r *GatewayDNSResponse, _ time.Time) { r.Records[0].Address = "fd00::1" }, ErrGatewayDNSRPCMalformed},
		{"too many", func(r *GatewayDNSResponse, _ time.Time) {
			r.Records = make([]GatewayDNSRecord, MaxAnswers+1)
			for i := range r.Records {
				r.Records[i] = GatewayDNSRecord{Name: "orders.internal.example", Type: TypeA, Address: "10.2.3.4", TTLSeconds: 60}
			}
		}, ErrGatewayDNSRPCLimit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := rpcWork()
			var now time.Time
			transport, now := newRPCTestTransport(t, func(_ context.Context, request GatewayDNSRequest) (GatewayDNSResponse, error) {
				r := responseFor(request, now, Record{Name: w.Hostname, Type: TypeA, Address: netip.MustParseAddr("10.2.3.4"), TTL: time.Minute})
				tc.mutate(&r, now)
				return r, nil
			})
			_, err := transport.LookupWork(context.Background(), w)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err=%v, want %v", err, tc.want)
			}
		})
	}
}

func TestGatewayDNSRPCTransportDisconnectAndTimeoutRemainLifecycleWithdrawals(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"disconnect", ErrGatewayDNSRPCUnavailable},
		{"timeout", context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := rpcWork()
			transport, _ := newRPCTestTransport(t, func(context.Context, GatewayDNSRequest) (GatewayDNSResponse, error) {
				return GatewayDNSResponse{}, tc.err
			})
			var lifecycle Lifecycle
			s := lifecycle.Refresh(context.Background(), time.Now(), resolverFunc(func(ctx context.Context, _ Context, _ string) ([]Response, error) {
				return transport.LookupWork(ctx, w)
			}), w.Context, w.Hostname)
			if s.Active != nil || s.Withdrawal == nil || s.Withdrawal.Cause != WithdrawalTimeout {
				t.Fatalf("transport %s must fail closed: %#v", tc.name, s)
			}
		})
	}
}

func TestGatewayDNSRPCTransportClassifiesGatewayCompatibilityAndDisconnectResponses(t *testing.T) {
	for _, tc := range []struct {
		name string
		code GatewayDNSRPCErrorCode
		want error
	}{
		{"unsupported version", GatewayDNSRPCUnsupportedVersion, ErrGatewayDNSRPCVersion},
		{"disconnected", GatewayDNSRPCDisconnected, ErrGatewayDNSRPCUnavailable},
		{"deadline", GatewayDNSRPCDeadlineExceeded, ErrTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := rpcWork()
			var now time.Time
			transport, now := newRPCTestTransport(t, func(_ context.Context, request GatewayDNSRequest) (GatewayDNSResponse, error) {
				response := responseFor(request, now)
				response.ErrorCode = tc.code
				return response, nil
			})
			if _, err := transport.LookupWork(context.Background(), w); !errors.Is(err, tc.want) {
				t.Fatalf("err=%v, want %v", err, tc.want)
			}
		})
	}
}

func TestGatewayDNSRPCTransportRequiresServerScope(t *testing.T) {
	transport, _ := newRPCTestTransport(t, func(context.Context, GatewayDNSRequest) (GatewayDNSResponse, error) {
		t.Fatal("mailbox must not be called without a complete selected scope")
		return GatewayDNSResponse{}, nil
	})
	if _, err := transport.LookupWork(context.Background(), Work{Hostname: "orders.internal"}); !errors.Is(err, ErrUnboundContext) {
		t.Fatalf("err=%v, want selected-context failure", err)
	}
}

func TestGatewayDNSRPCTransportRejectsUnscopedResolverUse(t *testing.T) {
	transport, _ := newRPCTestTransport(t, func(context.Context, GatewayDNSRequest) (GatewayDNSResponse, error) {
		t.Fatal("unscoped lookup must not call mailbox")
		return GatewayDNSResponse{}, nil
	})
	if _, err := transport.Lookup(context.Background(), selected, "orders.internal"); !errors.Is(err, ErrUnboundContext) {
		t.Fatalf("unscoped resolver err=%v, want ErrUnboundContext", err)
	}
}

func TestGatewayDNSRPCTransportKeepsFailoverGatewayScopeSeparate(t *testing.T) {
	first, second := rpcWork(), rpcWork()
	second.Context.GatewayID = "66666666-6666-6666-6666-666666666666"
	seen := make([]uuid.UUID, 0, 2)
	var now time.Time
	transport, now := newRPCTestTransport(t, func(_ context.Context, request GatewayDNSRequest) (GatewayDNSResponse, error) {
		seen = append(seen, request.GatewayID)
		return responseFor(request, now, Record{Name: request.Hostname, Type: TypeA, Address: netip.MustParseAddr("10.2.3.4"), TTL: time.Minute}), nil
	})
	for _, w := range []Work{first, second} {
		if _, err := transport.LookupWork(context.Background(), w); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := seen, []uuid.UUID{uuid.MustParse(first.Context.GatewayID), uuid.MustParse(second.Context.GatewayID)}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("gateway failover scope leaked or substituted: got %v want %v", got, want)
	}
}
