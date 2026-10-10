package ipsec

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDNSDiagnosticClassifiesNativeGuardGrantAndRouteRefusal(t *testing.T) {
	for _, scenario := range []string{"native", "grant", "guard", "route", "epoch"} {
		t.Run(scenario, func(t *testing.T) {
			f := newDNSOwnerViewFixture(t, nil)
			var diagnostic RuntimeDiagnostic
			f.c.config.Diagnostic = func(d RuntimeDiagnostic) { diagnostic = d }
			expected := ""
			switch scenario {
			case "native":
				f.c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error {
					return errors.New("private error must never enter diagnostic")
				}
				f.publish(t)
				expected = "dns_native_proof"
			case "grant":
				f.config.Version++
				expected = "dns_grant"
			case "guard":
				f.observed.Store(`{"private":"never emit"}`)
				expected = "dns_guard"
			case "route":
				view := *f.c.dnsView.Load()
				view.observer.route = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("private route") }
				f.c.dnsView.Store(&view)
				expected = "dns_route"
			case "epoch":
				view := *f.c.dnsView.Load()
				old := view.observer.source
				view.observer.source = func(source netip.Addr, indices []int) (int, error) {
					index, err := old(source, indices)
					if f.sourceReads.Load() == 2 {
						for _, owner := range view.entries {
							owner.epoch.revoked.Store(true)
						}
					}
					return index, err
				}
				f.c.dnsView.Store(&view)
				expected = "dns_epoch"
			}
			if _, err := f.c.proveResolverDNSStage(context.Background(), f.config, f.config.Endpoints[0], "dns_after_proof"); err == nil {
				t.Fatal("mandatory refusal changed")
			}
			if diagnostic.Operation != "dns_after_proof" || diagnostic.Stage != expected || !diagnostic.Refused || diagnostic.ContextState != "active" {
				t.Fatalf("wrong fixed stage: %+v", diagnostic)
			}
		})
	}
}
func TestDNSDiagnosticRateIsConcurrentAndDoesNotAlterProof(t *testing.T) {
	f := newDNSOwnerViewFixture(t, nil)
	var calls atomic.Int32
	f.c.config.Diagnostic = func(RuntimeDiagnostic) { calls.Add(1) }
	// Successful proof remains silent and retains every independent read.
	if _, err := f.prove(context.Background()); err != nil || calls.Load() != 0 || f.nativeProofs.Load() != 1 || f.guardReads.Load() != 1 || f.routeReads.Load() != 1 || f.sourceReads.Load() != 2 {
		t.Fatal("successful proof changed")
	}
	start := time.Unix(1000, 0)
	f.c.dnsDiagnosticAfter.Store(0)
	var accepted atomic.Int32
	var wait sync.WaitGroup
	for i := 0; i < 100; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if f.c.claimDNSDiagnostic(start) {
				accepted.Add(1)
			}
		}()
	}
	wait.Wait()
	if accepted.Load() != 1 || f.c.claimDNSDiagnostic(start.Add(time.Second-time.Nanosecond)) || !f.c.claimDNSDiagnostic(start.Add(time.Second)) {
		t.Fatal("DNS diagnostics are not one per second")
	}
	if validRuntimeDiagnostic("dns_proof", "private error or hostname") {
		t.Fatal("arbitrary diagnostic accepted")
	}
}

func TestDNSDiagnosticSocketRefusalPreservesActiveContext(t *testing.T) {
	f := newDNSOwnerViewFixture(t, nil)
	var diagnostic RuntimeDiagnostic
	f.c.config.Diagnostic = func(d RuntimeDiagnostic) { diagnostic = d }
	// A malformed packet is rejected before any socket; no real network fixture.
	if _, err := f.c.exchangeResolverDNS(context.Background(), f.config, f.config.Endpoints[0], []byte("short")); err == nil {
		t.Fatal("malformed DNS packet accepted")
	}
	if diagnostic.Operation != "dns_exchange" || diagnostic.Stage != "dns_socket" || diagnostic.ContextState != "active" || !diagnostic.Refused {
		t.Fatalf("wrong socket refusal or context: %+v", diagnostic)
	}
}
