//go:build linux

package egress

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// newTestWatcher builds a K8sWatcher pointed at a fake API server (no in-cluster token/CA needed) — the
// SUBSTITUTE for the real watch (WF-K5). The real watch on live k3s + a pod-restart-under-a-live-connection
// are WALK-OWED.
func newTestWatcher(base string, client *http.Client, kick func()) *K8sWatcher {
	return &K8sWatcher{
		base: base, client: client, kick: kick,
		services: map[string]svcPorts{}, slices: map[string]map[string]epGroup{},
	}
}

// parseSlice is FAIL-CLOSED on readiness: a nil ready condition is NOT ready (never assumed), only ready
// addresses become DNAT targets, and an orphan slice (no owning-Service label) is skipped.
func TestParseSliceReadyFiltering(t *testing.T) {
	raw := json.RawMessage(`{
      "metadata":{"name":"api-abc","namespace":"prod","labels":{"kubernetes.io/service-name":"api"}},
      "endpoints":[
        {"addresses":["10.42.0.14"],"conditions":{"ready":true}},
        {"addresses":["10.42.0.15"],"conditions":{"ready":false}},
        {"addresses":["10.42.0.16"],"conditions":{}}
      ],
      "ports":[{"name":"","port":8080}]}`)
	svcKey, sliceName, g, ok := parseSlice(raw)
	if !ok || svcKey != "prod/api" || sliceName != "api-abc" {
		t.Fatalf("parse=%v key=%q name=%q", ok, svcKey, sliceName)
	}
	if len(g.ready) != 1 || g.ready[0] != "10.42.0.14" {
		t.Fatalf("only the ready endpoint may survive (nil/false dropped), got %+v", g.ready)
	}
	if g.ports[""] != 8080 {
		t.Fatalf("port name->number map wrong: %+v", g.ports)
	}
	// An orphan slice (no kubernetes.io/service-name label) is not ours to map.
	if _, _, _, ok := parseSlice(json.RawMessage(`{"metadata":{"name":"x","namespace":"prod"}}`)); ok {
		t.Fatal("an orphan slice (no owning Service) must be skipped")
	}
}

// Targets correlates the exposed servicePort -> its Service port NAME -> the EndpointSlice port of that name
// (the resolved container port). It needs BOTH caches; a missing either side fails closed (ok=false).
func TestTargetsCorrelatesServicePortToEndpointPort(t *testing.T) {
	w := newTestWatcher("", nil, func() {})
	// Slices synced but Services NOT yet synced → the API view is not fully live → fail closed (L12).
	w.slices["prod/api"] = map[string]epGroup{"s1": {ready: []string{"10.42.0.14"}, ports: map[string]int{"web": 8080}}}
	w.slicesSynced = true
	if _, ok := w.Targets("prod", "api", 80); ok {
		t.Fatal("a not-fully-synced view must fail closed (ok=false)")
	}
	// Both synced: servicePort 80 has name "web" -> the slice's "web" port is 8080.
	w.services["prod/api"] = svcPorts{80: "web"}
	w.servicesSynced = true
	ts, ok := w.Targets("prod", "api", 80)
	if !ok || len(ts) != 1 || ts[0].ip != "10.42.0.14" || ts[0].port != 8080 {
		t.Fatalf("expected 10.42.0.14:8080, got ok=%v %+v", ok, ts)
	}
	// A servicePort the Service does not expose -> ok=true but no target (refuse, not guess).
	if ts, ok := w.Targets("prod", "api", 443); !ok || len(ts) != 0 {
		t.Fatalf("an unexposed servicePort must yield zero targets, got ok=%v %+v", ok, ts)
	}
}

// The correctness-critical relist path (WF-K5 condition 2): a 410 Gone on the watch forces a full relist,
// and after it the endpoint view reflects the CURRENT endpoints — never silently stops updating.
func TestWatchRelistOn410ReflectsCurrent(t *testing.T) {
	var mu sync.Mutex
	epListN, epWatchN := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		watching := r.URL.Query().Get("watch") == "1"
		switch r.URL.Path {
		case servicePath:
			if watching {
				<-r.Context().Done() // no service changes — block until the test ends
				return
			}
			io.WriteString(w, `{"metadata":{"resourceVersion":"10"},"items":[{"metadata":{"name":"api","namespace":"prod"},"spec":{"ports":[{"name":"","port":80}]}}]}`)
		case epSlicePath:
			if watching {
				mu.Lock()
				epWatchN++
				first := epWatchN == 1
				mu.Unlock()
				if first {
					w.WriteHeader(http.StatusGone) // rv expired → the agent must relist
					return
				}
				<-r.Context().Done()
				return
			}
			mu.Lock()
			epListN++
			n := epListN
			mu.Unlock()
			ip := "10.42.0.14"
			if n >= 2 {
				ip = "10.42.0.99" // the pod restarted onto a new IP between the two lists
			}
			fmt.Fprintf(w, `{"metadata":{"resourceVersion":"20"},"items":[{"metadata":{"name":"api-xyz","namespace":"prod","labels":{"kubernetes.io/service-name":"api"}},"endpoints":[{"addresses":["%s"],"conditions":{"ready":true}}],"ports":[{"name":"","port":8080}]}]}`, ip)
		}
	}))
	defer srv.Close()

	w := newTestWatcher(srv.URL, srv.Client(), func() {})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	deadline := time.After(3 * time.Second)
	for {
		ts, ok := w.Targets("prod", "api", 80)
		if ok && len(ts) == 1 && ts[0].ip == "10.42.0.99" && ts[0].port == 8080 {
			return // relisted after the 410 and reflects the CURRENT (restarted) endpoint
		}
		select {
		case <-deadline:
			t.Fatalf("watch did not relist to current endpoints after 410; got ok=%v ts=%+v", ok, ts)
		case <-time.After(15 * time.Millisecond):
		}
	}
}

// Fail-closed (WF-K5 condition 1): a list FAILURE clears the view so no stale endpoint can back a DNAT.
func TestListFailureClearsView(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError) // the API is failing every read
	}))
	defer srv.Close()

	w := newTestWatcher(srv.URL, srv.Client(), func() {})
	// Pre-populate a good, SYNCED view (ok=true), then let the failing loop CLEAR it (synced→false → ok=false).
	w.services["prod/api"] = svcPorts{80: ""}
	w.servicesSynced = true
	w.slices["prod/api"] = map[string]epGroup{"s1": {ready: []string{"10.42.0.14"}, ports: map[string]int{"": 8080}}}
	w.slicesSynced = true

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.loop(ctx, epSlicePath, w.listSlices, w.applySliceEvent, w.clearSlices)

	deadline := time.After(3 * time.Second)
	for {
		if _, ok := w.Targets("prod", "api", 80); !ok {
			return // the failing list cleared the slice view → fail-closed
		}
		select {
		case <-deadline:
			t.Fatal("a persistent list failure must CLEAR the endpoint view (fail-closed), it did not")
		case <-time.After(15 * time.Millisecond):
		}
	}
}
