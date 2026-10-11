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
