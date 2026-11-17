package dnsforward

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"golang.org/x/net/dns/dnsmessage"
)

func TestStaticCNAMEBrokeredRPCUsesCommittedAliasAndExternalTail(t *testing.T) {
	f := New(nil, nil)
	p := externalProfileFixture()
	f.SetResolverProfiles([]ResolverProfile{p})
	var calls atomic.Int32
	f.staticTargetTransport = privateProfileTransport(func(_ context.Context, c fqdnrpc.ResolverConfig, e fqdnrpc.ResolverEndpoint, wire []byte) ([]byte, error) {
		calls.Add(1)
		q := decodeDNS(t, wire).Questions[0]
		if q.Name.String() != "internal.lb.example." || c.IPsecPath != nil || e.Address != "1.1.1.1" {
			t.Error("private alias leaked or transport fabricated", q.Name, e)
		}
		return targetAnswer(wire, addressRecord(q.Name.String(), q.Type, 57)), nil
	})
	req := fqdnrpc.Request{Version: 2, RequestID: "55555555-5555-5555-5555-555555555555", OrgID: "11111111-1111-1111-1111-111111111111", ResourceID: "22222222-2222-2222-2222-222222222222", SiteID: "33333333-3333-3333-3333-333333333333", GatewayID: "44444444-4444-4444-4444-444444444444", Hostname: "external.office.test", RecordTypes: []fqdnrpc.RecordType{fqdnrpc.RecordA, fqdnrpc.RecordAAAA, fqdnrpc.RecordCNAME}, Deadline: time.Now().Add(10 * time.Second), ResolverConfigID: p.Config.ID, ResolverConfigVersion: p.Config.Version, ResolverProfileID: p.Config.ProfileID, ResolverMatchSuffix: "office.test", ResolverEndpoints: p.Config.Endpoints, ResolverKind: "static_cname"}
	responder := fqdnrpc.NewResponder(fqdnrpc.DirectResolver{StaticTransport: f})
	response := responder.Handle(context.Background(), req.GatewayID, req)
	if response.Status != fqdnrpc.StatusNoError || response.ResolverKind != "static_cname" || len(response.Records) != 3 || calls.Load() != 2 {
		t.Fatalf("no complete bound CNAME/A/AAAA generation: %+v calls%d", response, calls.Load())
	}
	cname, answer := false, false
	for _, r := range response.Records {
		cname = cname || r.Type == fqdnrpc.RecordCNAME && r.Name == req.Hostname && r.Target == "internal.lb.example"
		answer = answer || r.Type == fqdnrpc.RecordA && r.TTLSeconds == 57
	}
	if !cname || !answer {
		t.Fatal("lost connected alias/TTL")
	}
	// A replay must reprove the profile, not resurrect cached DNS authority.
	f.SetResolverProfiles(nil)
	replay := responder.Handle(context.Background(), req.GatewayID, req)
	if replay.Status != fqdnrpc.StatusServFail || calls.Load() != 2 {
		t.Fatal("revoked profile replayed or leaked alias")
	}
	f.SetResolverProfiles([]ResolverProfile{p})
	for _, mutate := range []func(*fqdnrpc.Request){func(r *fqdnrpc.Request) { r.ResolverKind = "unknown" }, func(r *fqdnrpc.Request) { r.ResolverConfigVersion++ }, func(r *fqdnrpc.Request) { r.Hostname = "arbitrary.office.test" }, func(r *fqdnrpc.Request) {
		r.ResolverIPsecPath = &fqdnrpc.IPsecPath{ConnectionID: r.ResourceID, ConfigurationRevision: 1, SourceAddress: "10.1.1.1"}
	}} {
		bad := req
		bad.RequestID = "66666666-6666-6666-6666-666666666666"
		mutate(&bad)
		if got := responder.Handle(context.Background(), bad.GatewayID, bad); got.Status != fqdnrpc.StatusServFail {
			t.Fatal("unbound request accepted", got)
		}
	}
	if calls.Load() != 2 {
		t.Fatal("refused request contacted external resolver")
	}
}

func TestStaticCNAMEBrokeredRPCEndpointDisagreementRefuses(t *testing.T) {
	f := New(nil, nil)
	p := externalProfileFixture()
	p.Config.Endpoints = append(p.Config.Endpoints, fqdnrpc.ResolverEndpoint{Address: "8.8.8.8", Port: 53, Transport: "udp"})
	f.SetResolverProfiles([]ResolverProfile{p})
	f.staticTargetTransport = privateProfileTransport(func(_ context.Context, _ fqdnrpc.ResolverConfig, e fqdnrpc.ResolverEndpoint, wire []byte) ([]byte, error) {
		q := decodeDNS(t, wire).Questions[0]
		a := addressRecord(q.Name.String(), q.Type, 57)
		if e.Address == "8.8.8.8" && q.Type == dnsmessage.TypeA {
			a.Body = &dnsmessage.AResource{A: [4]byte{10, 180, 10, 230}}
		}
		return targetAnswer(wire, a), nil
	})
	config := p.Config
	config.Kind = "static_cname"
	config.MatchedSuffix = "office.test"
	if _, err := (fqdnrpc.DirectResolver{StaticTransport: f}).ResolveBound(context.Background(), "external.office.test", []fqdnrpc.RecordType{fqdnrpc.RecordA, fqdnrpc.RecordAAAA, fqdnrpc.RecordCNAME}, config); err == nil {
		t.Fatal("disagreeing endpoints authorized answer")
	}
}

func TestStaticCNAMEBrokeredRPCProfileChangeDuringAnswerRefuses(t *testing.T) {
	f := New(nil, nil)
	p := externalProfileFixture()
	f.SetResolverProfiles([]ResolverProfile{p})
	calls := 0
	f.staticTargetTransport = privateProfileTransport(func(_ context.Context, _ fqdnrpc.ResolverConfig, _ fqdnrpc.ResolverEndpoint, wire []byte) ([]byte, error) {
		calls++
		q := decodeDNS(t, wire).Questions[0]
		if q.Name.String() != "internal.lb.example." {
			t.Fatal("private alias sent upstream")
		}
		f.SetResolverProfiles(nil)
		return targetAnswer(wire, addressRecord(q.Name.String(), q.Type, 57)), nil
	})
	config := p.Config
	config.Kind = "static_cname"
	config.MatchedSuffix = "office.test"
	if _, err := f.ExchangeDNS(context.Background(), config, config.Endpoints[0], queryType("external.office.test.", dnsmessage.TypeA)); err == nil || calls != 1 {
		t.Fatal("changed resolver context accepted an in-flight answer")
	}
}

func TestStaticCNAMEBrokeredRPCSingleFamilyAndNoData(t *testing.T) {
	for _, tc := range []struct {
		name     string
		positive dnsmessage.Type
		want     fqdnrpc.Status
	}{
		{"IPv4_only", dnsmessage.TypeA, fqdnrpc.StatusNoError},
		{"IPv6_only", dnsmessage.TypeAAAA, fqdnrpc.StatusNoError},
		{"both_NODATA", 0, fqdnrpc.StatusServFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := New(nil, nil)
			p := externalProfileFixture()
			f.SetResolverProfiles([]ResolverProfile{p})
			var calls atomic.Int32
			f.staticTargetTransport = privateProfileTransport(func(_ context.Context, _ fqdnrpc.ResolverConfig, _ fqdnrpc.ResolverEndpoint, wire []byte) ([]byte, error) {
				calls.Add(1)
				q := decodeDNS(t, wire).Questions[0]
				if q.Name.String() != "internal.lb.example." {
					t.Error("private alias leaked or external tail requeried", q.Name)
				}
				if q.Type != tc.positive {
					return targetAnswer(wire), nil
				}
				return targetAnswer(wire, addressRecord(q.Name.String(), q.Type, 30)), nil
			})
			req := fqdnrpc.Request{Version: 2, RequestID: "55555555-5555-5555-5555-555555555555", OrgID: "11111111-1111-1111-1111-111111111111", ResourceID: "22222222-2222-2222-2222-222222222222", SiteID: "33333333-3333-3333-3333-333333333333", GatewayID: "44444444-4444-4444-4444-444444444444", Hostname: "external.office.test", RecordTypes: []fqdnrpc.RecordType{fqdnrpc.RecordA, fqdnrpc.RecordAAAA, fqdnrpc.RecordCNAME}, Deadline: time.Now().Add(10 * time.Second), ResolverConfigID: p.Config.ID, ResolverConfigVersion: p.Config.Version, ResolverProfileID: p.Config.ProfileID, ResolverMatchSuffix: "office.test", ResolverEndpoints: p.Config.Endpoints, ResolverKind: "static_cname"}
			responder := fqdnrpc.NewResponder(fqdnrpc.DirectResolver{StaticTransport: f})
			got := responder.Handle(context.Background(), req.GatewayID, req)
			if got.Status != tc.want || calls.Load() != 2 {
				t.Fatalf("status=%s calls=%d: %+v", got.Status, calls.Load(), got)
			}
			if tc.want == fqdnrpc.StatusNoError {
				if len(got.Records) != 2 {
					t.Fatal("expected exactly alias plus one terminal address", got.Records)
				}
				for _, r := range got.Records {
					if r.Type != fqdnrpc.RecordCNAME && r.TTLSeconds != 30 {
						t.Fatal("lost bounded TTL", r)
					}
				}
				f.SetResolverProfiles(nil)
				if replay := responder.Handle(context.Background(), req.GatewayID, req); replay.Status != fqdnrpc.StatusServFail || calls.Load() != 2 {
					t.Fatal("revoked profile replayed", replay)
				}
			} else if len(got.Records) != 0 {
				t.Fatal("NODATA supplied authority", got.Records)
			}
		})
	}
}
