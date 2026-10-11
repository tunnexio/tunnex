package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestRuntimeDNSExchangeDiagnosticStages(t *testing.T) {
	for _, failure := range []string{"before", "socket", "after", "identity", "context", "success"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var events []RuntimeDiagnostic
			var calls []string
			fixture := newDNSOwnerViewFixture(t, func(context.Context) error { return nil })
			proof, proofErr := fixture.prove(ctx)
			if proofErr != nil {
				t.Fatal(proofErr)
			}
			n := 0
			prove := func(context.Context, fqdnrpc.ResolverConfig, fqdnrpc.ResolverEndpoint) (runtimeDNSProof, error) {
				n++
				calls = append(calls, "prove")
				if failure == "before" && n == 1 || failure == "after" && n == 2 {
					return runtimeDNSProof{}, errors.New("hostname answer secret payload")
				}
				if failure == "identity" && n == 2 {
					p := proof
					p.InterfaceIndex = 99
					return p, nil
				}
				if failure == "context" && n == 2 {
					cancel()
				}
				return proof, nil
			}
			exchange := func(context.Context, fqdnrpc.ResolverEndpoint, netip.Addr, []byte) ([]byte, error) {
				calls = append(calls, "socket")
				if failure == "socket" {
					return nil, errors.New("hostname answer secret payload")
				}
				return []byte("answer"), nil
			}
			result, err := exchangeResolverDNSObserved(ctx, fqdnrpc.ResolverConfig{}, fqdnrpc.ResolverEndpoint{}, []byte("secret request"), prove, exchange, func(stage string, started time.Time, refused bool) {
				emitRuntimeDiagnostic(func(v RuntimeDiagnostic) { events = append(events, v) }, ctx, "dns_exchange", stage, uuid.Nil, started, refused)
			})
			count := 3
			if failure == "before" {
				count = 1
			}
			if failure == "socket" {
				count = 2
			}
			if len(events) != count || len(calls) != count {
				t.Fatalf("sequence events=%v calls=%v", events, calls)
			}
			names := []string{"dns_proof_before", "dns_socket", "dns_proof_after"}
			if failure == "after" {
				names[2] = "dns_after_proof_refused"
			}
			if failure == "identity" {
				names[2] = "dns_after_binding_refused"
			}
			if failure == "context" {
				names[2] = "dns_after_context_refused"
			}
			for i, v := range events {
				if v.Stage != names[i] || v.Operation != "dns_exchange" || v.ElapsedMillis < 0 {
					t.Fatalf("event %+v", v)
				}
			}
			if failure == "success" {
				if err != nil || string(result) != "answer" || events[count-1].Refused {
					t.Fatal("success changed")
				}
			} else if err != ErrRuntimeController || result != nil || !events[count-1].Refused {
				t.Fatal("failure changed")
			}
			raw, _ := json.Marshal(events)
			for _, s := range []string{"hostname", "answer", "secret", "payload", "10.70"} {
				if strings.Contains(string(raw), s) {
					t.Fatal("diagnostic disclosed input")
				}
			}
		})
	}
}

func TestDNSAfterDiagnosticShortCircuitOrder(t *testing.T) {
	for _, tc := range []struct {
		name                            string
		proofError, mismatch, cancelled bool
		stage                           string
	}{
		{"success", false, false, false, "dns_proof_after"},
		{"proof dominates binding and context", true, true, true, "dns_after_proof_refused"},
		{"binding dominates context", false, true, true, "dns_after_binding_refused"},
		{"binding", false, true, false, "dns_after_binding_refused"},
		{"context", false, false, true, "dns_after_context_refused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fixture := newDNSOwnerViewFixture(t, func(context.Context) error { return nil })
			proof, err := fixture.prove(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var calls, stages []string
			n := 0
			got, e := exchangeResolverDNSObserved(ctx, fqdnrpc.ResolverConfig{}, fqdnrpc.ResolverEndpoint{}, nil,
				func(context.Context, fqdnrpc.ResolverConfig, fqdnrpc.ResolverEndpoint) (runtimeDNSProof, error) {
					calls = append(calls, "proof")
					n++
					p := proof
					if n == 2 {
						if tc.cancelled {
							cancel()
						}
						if tc.mismatch {
							p.InterfaceIndex++
						}
						if tc.proofError {
							return p, errors.New("private response detail")
						}
					}
					return p, nil
				}, func(context.Context, fqdnrpc.ResolverEndpoint, netip.Addr, []byte) ([]byte, error) {
					calls = append(calls, "socket")
					return []byte("unchanged"), nil
				},
				func(s string, _ time.Time, _ bool) { stages = append(stages, s) })
			if strings.Join(calls, ",") != "proof,socket,proof" || len(stages) != 3 || stages[2] != tc.stage {
				t.Fatalf("calls=%v stages=%v", calls, stages)
			}
			refused := tc.proofError || tc.mismatch || tc.cancelled
			if refused {
				if e != ErrRuntimeController || got != nil {
					t.Fatal("refusal semantics changed")
				}
			} else if e != nil || string(got) != "unchanged" {
				t.Fatal("success semantics changed")
			}
		})
	}
}
