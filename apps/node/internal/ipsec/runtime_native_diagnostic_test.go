package ipsec

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestNativeDiagnosticReadersPreserveResultsAndOrder(t *testing.T) {
	for _, kind := range []string{"success", "daemon_read", "kernel_read", "xfrm_read", "kernel_snapshot_changed", "xfrm_snapshot_changed", "context_canceled", "context_deadline"} {
		t.Run(kind, func(t *testing.T) {
			var reference [2]string
			var referenceOrder []string
			for _, enabled := range []bool{false, true} {
				e, d, k, x := runtimeProofFixture()
				ctx, cancel := context.WithCancel(context.Background())
				if kind == "context_canceled" {
					cancel()
				}
				if kind == "context_deadline" {
					var stop context.CancelFunc
					ctx, stop = context.WithDeadline(ctx, time.Now().Add(-time.Second))
					defer stop()
				}
				var order, classes []string
				pass := 0
				var observer func(string)
				if enabled {
					observer = func(s string) { classes = append(classes, s) }
				}
				r := runtimeStatusReaders{alive: func() bool { return true }, daemon: func(context.Context) (DaemonInventory, error) {
					order = append(order, "daemon")
					pass++
					if kind == "daemon_read" {
						return d, errors.New("private")
					}
					return d, nil
				}, kernel: func(context.Context) (KernelInventory, error) {
					order = append(order, "kernel")
					if kind == "kernel_read" {
						return k, errors.New("private")
					}
					if kind == "kernel_snapshot_changed" && pass == 2 {
						return KernelInventory{Namespace: k.Namespace}, nil
					}
					return k, nil
				}, xfrm: func(context.Context) (XFRMInventory, error) {
					order = append(order, "xfrm")
					if kind == "xfrm_read" {
						return x, errors.New("private")
					}
					if kind == "xfrm_snapshot_changed" && pass == 2 {
						return XFRMInventory{Namespace: x.Namespace}, nil
					}
					return x, nil
				}}
				got := runtimeObservedStatusesObserved(ctx, e, r, observer)
				cancel()
				if !enabled {
					reference = got
					referenceOrder = order
				} else {
					if got != reference || !reflect.DeepEqual(order, referenceOrder) {
						t.Fatal("changed result/order")
					}
					if kind == "success" {
						if len(classes) != 0 {
							t.Fatal(classes)
						}
					} else if !reflect.DeepEqual(classes, []string{kind}) {
						t.Fatal(classes)
					}
				}
				want := 6
				if kind == "daemon_read" || kind == "kernel_read" || kind == "xfrm_read" || kind == "context_canceled" || kind == "context_deadline" {
					want = 3
				}
				if len(order) != want {
					t.Fatal(order)
				}
			}
		})
	}
}
func TestNativeDiagnosticFixedAllowlist(t *testing.T) {
	for _, s := range []string{"binding_invalid", "route_read_or_binding", "daemon_read", "kernel_read", "xfrm_read", "kernel_snapshot_changed", "xfrm_snapshot_changed", "owned_status_unknown", "all_tunnels_down", "environment_read_or_validation", "environment_changed", "context_deadline", "context_canceled"} {
		if !validDNSReadTiming(runtimeDNSReadTiming{NativeFailureClass: s}) {
			t.Fatal(s)
		}
	}
	if validDNSReadTiming(runtimeDNSReadTiming{NativeFailureClass: "private arbitrary error"}) {
		t.Fatal("raw accepted")
	}
}

type nativeDiagnosticEnvironment struct {
	value RuntimeEnvironment
	err   error
	calls int
}

func (f *nativeDiagnosticEnvironment) Observe(context.Context, KernelAllocation, [2]EngineTunnel) (RuntimeEnvironment, error) {
	f.calls++
	return f.value, f.err
}
func (*nativeDiagnosticEnvironment) Drain(context.Context, []RuntimeJournalEntry) error { return nil }
func TestNativeDiagnosticBGPBranchesPreserveResults(t *testing.T) {
	for _, kind := range []string{"success", "binding_invalid", "route_read_or_binding", "owned_status_unknown", "all_tunnels_down", "environment_read_or_validation", "environment_changed"} {
		t.Run(kind, func(t *testing.T) {
			var reference error
			var reads int
			for _, enabled := range []bool{false, true} {
				c, kernel, _, _ := bgpControllerFixture(t, true)
				var a runtimeActive
				for _, v := range c.active {
					a = v
				}
				env := &nativeDiagnosticEnvironment{value: a.Environment}
				c.config.Environment = env
				switch kind {
				case "binding_invalid":
					a.Entry.ContractVersion = 0
				case "route_read_or_binding":
					kernel.missing = 0
				case "owned_status_unknown":
					c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { return [2]string{"unknown", "up"} }
				case "all_tunnels_down":
					c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { return [2]string{"down", "down"} }
				case "environment_read_or_validation":
					env.err = errors.New("private")
				case "environment_changed":
					env.value.Namespace = "different"
				}
				var classes []string
				var observer func(string)
				if enabled {
					observer = func(s string) { classes = append(classes, s) }
				}
				got := c.proveBGPCurrentObserved(context.Background(), a.Entry, a.Environment, observer)
				if !enabled {
					reference = got
					reads = env.calls
				} else {
					if !errors.Is(got, reference) || reads != env.calls {
						t.Fatal("changed result/read count")
					}
					if kind == "success" {
						if got != nil || len(classes) != 0 {
							t.Fatal(got, classes)
						}
					} else if !reflect.DeepEqual(classes, []string{kind}) {
						t.Fatal(classes)
					}
				}
			}
		})
	}
}
