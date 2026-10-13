package ipsec

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDNSProofRefusalDiagnosticsPreserveOutcomeAndReads(t *testing.T) {
	for _, tc := range []struct {
		name, stage                  string
		native, guard, source, route int32
	}{
		{"positive", "", 1, 1, 2, 1},
		{"input", "dns_refusal_input", 0, 0, 0, 0},
		{"owner", "dns_refusal_owner", 0, 0, 0, 0},
		{"native", "dns_refusal_native", 1, 0, 0, 0},
		{"guard", "dns_refusal_guard_initial", 1, 1, 0, 0},
		{"source", "dns_refusal_source_before", 1, 1, 1, 0},
		{"route", "dns_refusal_route", 1, 1, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDNSOwnerViewFixture(t, func(context.Context) error {
				if tc.name == "native" {
					return ErrRuntimeController
				}
				return nil
			})
			var events []RuntimeDiagnostic
			f.c.config.Diagnostic = func(d RuntimeDiagnostic) { events = append(events, d) }
			switch tc.name {
			case "input":
				f.config.IPsecPath = nil
			case "owner":
				f.c.withdrawDNSOwnerView(f.material.Manifest.ConnectionID)
			case "guard":
				f.observed.Store(`{"nftables":[]}`)
			case "source", "route":
				view := *f.c.dnsView.Load()
				if tc.name == "source" {
					view.observer.source = func(netip.Addr, []int) (int, error) { f.sourceReads.Add(1); return 0, ErrRuntimeController }
				} else {
					view.observer.route = func(context.Context, string, ...string) ([]byte, error) {
						f.routeReads.Add(1)
						return nil, ErrRuntimeController
					}
				}
				f.c.dnsView.Store(&view)
			}
			proof, err := f.prove(context.Background())
			if tc.stage == "" {
				if err != nil || proof.authority == nil || len(events) != 0 {
					t.Fatal("positive changed", err, events)
				}
			} else {
				if err != ErrRuntimeController || proof != (runtimeDNSProof{}) || len(events) != 1 {
					t.Fatal("refusal changed", err, events)
				}
				d := events[0]
				if d.Operation != "dns_proof" || d.Stage != tc.stage || d.ConnectionID != func() uuid.UUID {
					if tc.name == "input" {
						return uuid.Nil
					}
					return f.material.Manifest.ConnectionID
				}() || !d.Refused || d.ContextState != "active" {
					t.Fatal("unsafe diagnostic", d)
				}
			}
			if f.nativeProofs.Load() != tc.native || f.guardReads.Load() != tc.guard || f.sourceReads.Load() != tc.source || f.routeReads.Load() != tc.route {
				t.Fatal("read order/count changed", f.nativeProofs.Load(), f.guardReads.Load(), f.sourceReads.Load(), f.routeReads.Load())
			}
		})
	}
}

func TestDNSProofDiagnosticVocabularyClosed(t *testing.T) {
	labels := []string{"input", "endpoint", "addresses", "binding", "view", "owner", "active", "grant", "authority_before", "native", "slot", "interface", "guard_initial", "source_before", "route", "source_after", "authority_after", "owner_before_final", "view_final", "guard_retry_budget", "guard_retry", "owner_final", "guard_final"}
	for _, label := range labels {
		if !validRuntimeDiagnostic("dns_proof", "dns_refusal_"+label) || validRuntimeDiagnostic("dns_exchange", "dns_refusal_"+label) {
			t.Fatal(label)
		}
	}
	for _, bad := range []string{"dns_socket", "proof_complete", "dns_refusal_unknown", "dns_refusal_secret.example", "dns_refusal_native: raw error", strings.Repeat("x", 1000)} {
		if validRuntimeDiagnostic("dns_proof", bad) {
			t.Fatal("untrusted stage admitted")
		}
	}
	var events []RuntimeDiagnostic
	emitRuntimeDiagnostic(func(d RuntimeDiagnostic) { events = append(events, d) }, context.Background(), "dns_proof", "dns_refusal_secret", uuid.Nil, time.Now(), true)
	if len(events) != 0 {
		t.Fatal("unknown leaked")
	}
}
