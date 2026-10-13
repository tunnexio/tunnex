package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDNSGuardTimingPreservesBracketAndRefusal(t *testing.T) {
	raw, id := guardParserFixture(t, 1)
	for _, kind := range []string{"success", "expired", "structural", "read", "canceled", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			observed := raw
			if kind == "expired" {
				observed = guardTableFixtureEdit(t, raw, func(o map[string]any) {
					if s, ok := o["set"].(map[string]any); ok && s["name"] == guardLeaseName(id) {
						for _, member := range s["elem"].([]any) {
							member.(map[string]any)["elem"].(map[string]any)["expires"] = json.Number("0")
						}
					}
				})
			}
			if kind == "structural" {
				observed = []byte(`{"private":"never export"}`)
			}
			v := dnsParseReuseView(observed, raw)
			var sequence []string
			r := v.observer.guardReader
			r.namespace = func() (string, error) { sequence = append(sequence, "namespace"); return v.guard.Namespace, nil }
			r.interfaces = func() ([]GuardInterface, error) { sequence = append(sequence, "interfaces"); return nil, nil }
			r.run = func(_ context.Context, args ...string) ([]byte, error) {
				sequence = append(sequence, "command")
				if !reflect.DeepEqual(args, []string{"-j", "list", "table", "inet", "tunnex_ipsec"}) {
					t.Fatal("command changed")
				}
				if kind == "read" {
					return nil, errors.New("private error")
				}
				return observed, nil
			}
			ctx := context.Background()
			if kind == "canceled" {
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			if kind == "deadline" {
				c, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
				ctx = c
			}
			objects, ok := normalizedGuardObjects(raw)
			if !ok {
				t.Fatal("fixture")
			}
			snapshot := guardExpectedSnapshot{raw: string(raw), objects: objects}
			plain := r.checkConnectionSnapshot(ctx, v.guard, id, snapshot)
			plainSequence := append([]string(nil), sequence...)
			sequence = nil
			var timing guardReadTiming
			calls := 0
			measured := r.checkConnectionSnapshotObserved(ctx, v.guard, id, snapshot, func(x guardReadTiming) { timing = x; calls++ })
			if measured != plain || !reflect.DeepEqual(sequence, plainSequence) || calls != 1 {
				t.Fatal("diagnostic changed result/bracket", plain, measured, sequence, plainSequence, calls)
			}
			want := map[string]string{"success": "none", "expired": "target_not_permitted", "structural": "observed_invalid", "read": "structural_or_read", "canceled": "context_canceled", "deadline": "context_deadline"}[kind]
			if timing.FailureClass != want || timing.CommandMillis < 0 || timing.VerificationMillis < 0 {
				t.Fatal("classification", timing)
			}
			if kind == "success" && !reflect.DeepEqual(sequence, []string{"namespace", "interfaces", "command", "interfaces", "namespace"}) {
				t.Fatal("fresh bracket order")
			}
		})
	}
}

func TestDNSReadTimingDefaultOffAndRateBound(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		var events []RuntimeDiagnostic
		c := &RuntimeController{config: RuntimeControllerConfig{DNSReadTiming: enabled, Diagnostic: func(d RuntimeDiagnostic) { events = append(events, d) }}}
		detail := runtimeDNSReadTiming{Native: runtimeNativePhaseTiming{Environment: runtimeEnvironmentTiming{CommandMillis: 2, VerificationMillis: 1, CommandCount: 18}, RouteMillis: 1, RecoveryMillis: 2, EnvironmentMillis: 3, ElapsedMillis: 7, RemainingAtEntryMillis: 100}, GuardBracketCount: 1, GuardCommandMillis: 3, GuardVerificationMillis: 7, GuardFailureClass: "target_not_permitted", SocketMillis: 20, SocketStage: "body"}
		c.emitDNSRuntimeDiagnostic(context.Background(), "dns_proof", "dns_refusal_guard_initial", uuid.Nil, time.Now(), true, detail)
		c.emitDNSRuntimeDiagnostic(context.Background(), "dns_proof", "dns_refusal_guard_initial", uuid.Nil, time.Now(), true, detail)
		if len(events) != 1 || (events[0].DNSReadTiming != nil) != enabled {
			t.Fatal("default or rate bound changed")
		}
		if enabled && *events[0].DNSReadTiming != detail {
			t.Fatal("fixed scalar timing changed")
		}
		c.dnsDiagnosticAfter.Store(0)
		c.emitDNSRuntimeDiagnostic(context.Background(), "dns_proof", "dns_refusal_guard_initial", uuid.Nil, time.Now(), false, detail)
		if len(events) != 1 {
			t.Fatal("success emitted extra event")
		}
	}
	for _, bad := range []runtimeDNSReadTiming{{GuardFailureClass: "private payload"}, {SocketStage: "hostname"}, {SocketMillis: -1}, {GuardCommandMillis: 60001}, {GuardBracketCount: 5}} {
		if validDNSReadTiming(bad) {
			t.Fatal("unbounded diagnostic accepted")
		}
	}
}

func TestDNSReadTimingUDPUsesSocketOnlyElapsed(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		f := newDNSOwnerViewFixture(t, nil)
		f.c.config.DNSReadTiming = enabled
		f.c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error {
			time.Sleep(20 * time.Millisecond)
			return nil
		}
		f.publish(t)
		var events []RuntimeDiagnostic
		f.c.config.Diagnostic = func(d RuntimeDiagnostic) { events = append(events, d) }
		// Invalid packet reaches the socket's input validation after a genuine
		// unchanged before-proof. It performs no socket network IO.
		if _, err := f.c.exchangeResolverDNS(context.Background(), f.config, f.config.Endpoints[0], nil); err == nil {
			t.Fatal("socket refusal changed")
		}
		if len(events) != 1 || events[0].Stage != "dns_socket_udp" || events[0].ElapsedMillis < 20 || (events[0].DNSReadTiming != nil) != enabled {
			t.Fatal("original refusal/rate/default changed", events)
		}
		if enabled && (events[0].DNSReadTiming.SocketStage != "input" || events[0].DNSReadTiming.SocketMillis >= 20) {
			t.Fatal("socket timing includes preceding proof")
		}
		if f.nativeProofs.Load() != 0 || f.guardReads.Load() != 1 || f.routeReads.Load() != 1 || f.sourceReads.Load() != 2 {
			t.Fatal("socket diagnostics altered proof reads")
		}
	}
}

func TestDNSReadTimingDoesNotSpendAnotherGuardRetry(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		f := newDNSOwnerViewFixture(t, nil)
		f.c.config.DNSReadTiming = enabled
		f.c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error {
			renewDNSDiagnosticGuard(t, f)
			return nil
		}
		f.publish(t)
		view := *f.c.dnsView.Load()
		route := view.observer.route
		view.observer.route = func(ctx context.Context, path string, args ...string) ([]byte, error) {
			raw, err := route(ctx, path, args...)
			renewDNSDiagnosticGuard(t, f)
			return raw, err
		}
		f.c.dnsView.Store(&view)
		run := f.c.guard.reader.run
		f.c.guard.reader.run = func(ctx context.Context, args ...string) ([]byte, error) {
			if f.guardReads.Load() == 2 {
				renewDNSDiagnosticGuard(t, f)
			}
			return run(ctx, args...)
		}
		var events []RuntimeDiagnostic
		f.c.config.Diagnostic = func(d RuntimeDiagnostic) { events = append(events, d) }
		if _, err := f.prove(context.Background()); err == nil || f.guardReads.Load() != 3 {
			t.Fatal("diagnostic changed bounded retry/refusal", enabled, f.guardReads.Load())
		}
		if len(events) != 1 || (events[0].DNSReadTiming != nil) != enabled {
			t.Fatal("rate/default changed")
		}
		if enabled && events[0].DNSReadTiming.GuardBracketCount != 3 {
			t.Fatal("timing did not describe the last of three actual brackets")
		}
	}
}

func TestDNSGuardTimingDeadlineInsideCommand(t *testing.T) {
	raw, id := guardParserFixture(t, 1)
	v := dnsParseReuseView(raw, raw)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	v.observer.guardReader.run = func(ctx context.Context, _ ...string) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	objects, ok := normalizedGuardObjects(raw)
	if !ok {
		t.Fatal("fixture")
	}
	var timing guardReadTiming
	err := v.observer.guardReader.checkConnectionSnapshotObserved(ctx, v.guard, id, guardExpectedSnapshot{raw: string(raw), objects: objects}, func(d guardReadTiming) { timing = d })
	if err != ErrGuardRead || timing.FailureClass != "context_deadline" || timing.CommandMillis < 10 || timing.VerificationMillis != 0 {
		t.Fatal("command deadline mislabeled or parser ran after expiration", err, timing)
	}
}
