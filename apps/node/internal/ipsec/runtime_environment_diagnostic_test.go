package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
)

func TestRuntimeEnvironmentDiagnosticsPreserveReadsAndRefusal(t *testing.T) {
	raw, err := os.ReadFile("testdata/runtime-environment-iproute2-6.9.0.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		IP  map[string]json.RawMessage
		NFT json.RawMessage
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("fixture")
	}
	e := journalFixture()
	for i := range e.Engines {
		e.Engines[i].LocalPrefixes = []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")}
		e.Engines[i].RemoteAddress = netip.MustParseAddr([]string{"198.19.240.20", "198.19.240.21"}[i])
	}
	for _, mode := range []string{"success", "read_refusal", "canceled"} {
		var prior RuntimeEnvironment
		var priorErr error
		var priorReads []string
		for _, enabled := range []bool{false, true} {
			reads := []string{}
			var readsMu sync.Mutex
			recordRead := func(q string) { readsMu.Lock(); defer readsMu.Unlock(); reads = append(reads, q) }
			events := []RuntimeDiagnostic{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r := &runtimeEnvironmentInspector{namespace: func() (string, error) { recordRead("namespace"); return e.Allocation.Namespace, nil }, nft: func(context.Context, ...string) ([]byte, error) { recordRead("nft"); return f.NFT, nil }, ip: func(_ context.Context, a ...string) ([]byte, error) {
				q := strings.Join(a, " ")
				recordRead(q)
				if mode != "success" && q == "-j -4 rule show" {
					if mode == "canceled" {
						cancel()
					}
					return nil, errors.New("synthetic-secret-body")
				}
				return f.IP[q], nil
			}}
			if enabled {
				r.diagnostic = func(v RuntimeDiagnostic) { events = append(events, v) }
			}
			got, err := r.Observe(ctx, e.Allocation, e.Engines)
			sort.Strings(reads)
			if !enabled {
				prior, priorErr, priorReads = got, err, reads
				continue
			}
			if !reflect.DeepEqual(got, prior) || err != priorErr || mode == "success" && !reflect.DeepEqual(reads, priorReads) {
				t.Fatal("diagnostics changed reads/result/error")
			}
			// Parallel snapshot reads cancel cooperatively. A failure may stop different
			// peers first, but diagnostics must never add duplicate reads or lose
			// the required failing rule read and original refusal.
			if mode != "success" {
				seen := map[string]int{}
				for _, q := range reads {
					seen[q]++
					if seen[q] > 1 {
						t.Fatal("diagnostic duplicated read", q)
					}
				}
				if seen["namespace"] != 1 || seen["-j -4 rule show"] != 1 {
					t.Fatal("missing required refusal read", reads)
				}
			}
			if len(events) != 1 || events[0].Operation != "environment_observe" || events[0].ConnectionID != e.Allocation.ConnectionID {
				t.Fatal("diagnostic binding")
			}
			if mode == "success" {
				if events[0].Stage != "env_complete" || events[0].Refused {
					t.Fatal("completion")
				}
			} else {
				if err != ErrRuntimeEnvironment || events[0].Stage != "env_snapshot_before" || !events[0].Refused {
					t.Fatal("fixed refusal")
				}
			}
			if mode == "canceled" && events[0].ContextState != "canceled" {
				t.Fatal("context state")
			}
		}
	}
}
func TestRuntimeEnvironmentDiagnosticConstructorCompatibility(t *testing.T) {
	old, e := NewRuntimeEnvironmentInspector("relative", "/usr/sbin/nft")
	next, n := NewRuntimeEnvironmentInspectorWithDiagnostics("relative", "/usr/sbin/nft", func(RuntimeDiagnostic) { t.Fatal("construction emits") })
	if old != nil || next != nil || e != ErrRuntimeEnvironment || n != e {
		t.Fatal("constructor changed")
	}
	var r *runtimeEnvironmentInspector
	if _, e := r.Observe(context.Background(), KernelAllocation{}, [2]EngineTunnel{}); e != ErrRuntimeEnvironment {
		t.Fatal("nil receiver")
	}
}
