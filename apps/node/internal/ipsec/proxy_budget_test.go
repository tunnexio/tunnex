package ipsec

import (
	"context"
	"fmt"
	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"golang.org/x/net/dns/dnsmessage"
	"testing"
	"time"
)

// This is a deterministic cost model, not a live socket/native latency replay.
// It uses the real immutable owner, accepted lease, native guard/route/source
// checks and final sameResolverDNSProof. Only the socket response is synthetic.
type budgetModelTransport struct {
	fixture *dnsOwnerViewFixture
	large   bool
	order   []string
}

func (m *budgetModelTransport) ExchangeDNS(ctx context.Context, c fqdnrpc.ResolverConfig, e fqdnrpc.ResolverEndpoint, p []byte) ([]byte, error) {
	m.order = append(m.order, e.Transport+"/before")
	before, err := m.fixture.c.proveResolverDNSStage(ctx, c, e, "dns_before_proof")
	if err != nil {
		return nil, ErrRuntimeController
	}
	m.order = append(m.order, e.Transport+"/socket")
	var q dnsmessage.Message
	if err = q.Unpack(p); err != nil {
		return nil, err
	}
	q.Response = true
	q.Truncated = m.large && e.Transport == "udp"
	response, err := q.Pack()
	if err != nil {
		return nil, err
	}
	m.order = append(m.order, e.Transport+"/after")
	after, err := m.fixture.c.proveResolverDNSStage(ctx, c, e, "dns_after_proof")
	if err != nil || !sameResolverDNSProof(after, before) || ctx.Err() != nil {
		return nil, ErrRuntimeController
	}
	return response, nil
}
func TestOriginalDNSBudgetModel(t *testing.T) {
	for _, tc := range []struct {
		name             string
		large            bool
		cost             time.Duration
		proofs, complete int32
		refused          bool
	}{
		{"small_700ms", false, 700 * time.Millisecond, 2, 2, false},
		{"large_TC_200ms", true, 200 * time.Millisecond, 4, 4, false},
		{"large_TC_700ms", true, 700 * time.Millisecond, 4, 3, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDNSOwnerViewFixture(t, func(ctx context.Context) error {
				select {
				case <-time.After(tc.cost):
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
			owner := f.c.active[f.material.Manifest.ConnectionID]
			deadline := owner.Authority.deadline
			q := dnsmessage.Message{Header: dnsmessage.Header{ID: 51}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("service.corp.test."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}}}
			payload, err := q.Pack()
			if err != nil {
				t.Fatal(err)
			}
			m := &budgetModelTransport{fixture: f, large: tc.large}
			ctx, cancel := context.WithTimeout(t.Context(), 2500*time.Millisecond)
			defer cancel()
			started := time.Now()
			response, err := fqdnrpc.ExchangeDNS(ctx, m, f.config, f.config.Endpoints[0], payload)
			if (err != nil) != tc.refused {
				t.Fatalf("refused=%v want%v error%v", err != nil, tc.refused, err)
			}
			if f.nativeProofs.Load() != tc.proofs || f.guardReads.Load() != tc.complete || f.sourceReads.Load() != 2*tc.complete || f.routeReads.Load() != tc.complete {
				t.Fatalf("fresh checks proofs%d guards%d sources%d routes%d", f.nativeProofs.Load(), f.guardReads.Load(), f.sourceReads.Load(), f.routeReads.Load())
			}
			if owner.Authority.deadline != deadline || owner.Authority.pending != nil {
				t.Fatal("DNS observation renewed authority")
			}
			if tc.refused {
				if ctx.Err() != context.DeadlineExceeded || response != nil {
					t.Fatal("expired attempt returned answer")
				}
			} else {
				var a dnsmessage.Message
				if a.Unpack(response) != nil || a.Truncated {
					t.Fatal("full answer required")
				}
			}
			t.Log(fmt.Sprintf("original budget=2.5s elapsed=%s native_attempts=%d complete_fresh_brackets=%d order=%v deadline_unchanged=true synthetic_cost=%s live_cause_proved=false", time.Since(started), f.nativeProofs.Load(), f.guardReads.Load(), m.order, tc.cost))
		})
	}
}

func TestProxyDNSBudgetKeepsIndependentOriginalChecks(t *testing.T) {
	f := newDNSOwnerViewFixture(t, func(ctx context.Context) error {
		select {
		case <-time.After(700 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	owner := f.c.active[f.material.Manifest.ConnectionID]
	deadline := owner.Authority.deadline
	q := dnsmessage.Message{Header: dnsmessage.Header{ID: 51}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("service.corp.test."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}}}
	payload, _ := q.Pack()
	m := &budgetModelTransport{fixture: f, large: true}
	for _, protocol := range []string{"udp", "tcp"} {
		ctx, cancel := context.WithTimeout(t.Context(), 2500*time.Millisecond)
		start := time.Now()
		response, err := fqdnrpc.ExchangeProxyDNS(ctx, m, f.config, f.config.Endpoints[0], protocol, payload)
		cancel()
		var a dnsmessage.Message
		if err != nil || a.Unpack(response) != nil || a.Truncated != (protocol == "udp") {
			t.Fatalf("%s response/refusal TC%v err%v", protocol, a.Truncated, err)
		}
		t.Logf("%s original2.5s elapsed%s", protocol, time.Since(start))
	}
	if f.nativeProofs.Load() != 4 || f.guardReads.Load() != 4 || f.sourceReads.Load() != 8 || f.routeReads.Load() != 4 || owner.Authority.deadline != deadline || owner.Authority.pending != nil {
		t.Fatal("socket lost independent checks or renewed authority")
	}
}
func TestProxyDNSDerivedTCPRequiresExactProtocolGrant(t *testing.T) {
	f := newDNSOwnerViewFixture(t, nil)
	id := f.material.Manifest.ConnectionID
	a := f.c.active[id]
	g := a.Grants[:0:0]
	for _, grant := range a.Grants {
		if grant.Protocol != GuardTCP {
			g = append(g, grant)
		}
	}
	a.Grants = g
	f.c.active[id] = a
	f.publish(t)
	q := dnsmessage.Message{Header: dnsmessage.Header{ID: 51}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("service.corp.test."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}}}
	payload, _ := q.Pack()
	m := &budgetModelTransport{fixture: f, large: true}
	if response, err := fqdnrpc.ExchangeProxyDNS(t.Context(), m, f.config, f.config.Endpoints[0], "tcp", payload); err == nil || response != nil || f.nativeProofs.Load() != 0 || len(m.order) != 1 {
		t.Fatal("derived TCP bypassed exact protocol grant")
	}
}
