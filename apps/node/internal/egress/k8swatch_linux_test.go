//go:build linux

package egress

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestWatcher builds a K8sWatcher pointed at a fake API server (no in-cluster token/CA needed) — the
// SUBSTITUTE for the real watch (WF-K5). The real watch on live k3s + a pod-restart-under-a-live-connection
// are WALK-OWED.
func newTestWatcher(base string, client *http.Client, kick func()) *K8sWatcher {
	return &K8sWatcher{
		base: base, client: client, kick: kick,
		services: map[string]serviceInfo{}, slices: map[string]map[string]epGroup{}, uidTombstones: map[string]string{}, now: time.Now,
	}
}

func waitForLiveSnapshot(t *testing.T, w *K8sWatcher, want bool) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if w.LiveSnapshotReady() == want {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("live snapshot readiness=%v, want %v", w.LiveSnapshotReady(), want)
		case <-ticker.C:
		}
	}
}

func TestGetListReloadsProjectedServiceAccountToken(t *testing.T) {
	tokenPath := t.TempDir() + "/token"
	if err := os.WriteFile(tokenPath, []byte("first-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		got = append(got, req.Header.Get("Authorization"))
		rw.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(rw, `{"metadata":{"resourceVersion":"1"},"items":[]}`)
	}))
	defer srv.Close()
	w := newTestWatcher(srv.URL, srv.Client(), func() {})
	w.tokenPath = tokenPath
	if _, _, err := w.getList(context.Background(), servicePath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("rotated-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.getList(context.Background(), servicePath); err != nil {
		t.Fatal(err)
	}
	want := []string{"Bearer first-token", "Bearer rotated-token"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("authorization headers = %q, want %q", got, want)
	}
}

func TestServiceUIDObservationsKeepDeleteRecreateIncarnationsSeparate(t *testing.T) {
	w := newTestWatcher("", nil, func() {})
	w.servicesSynced = true
	w.servicesWatching = true
	w.applyServiceEvent("ADDED", json.RawMessage(`{"metadata":{"name":"api","namespace":"prod","uid":"uid-a"},"spec":{"ports":[{"port":80}]}}`))
	if got, ok := w.ServiceUIDObservations("prod", "api"); !ok || len(got) != 1 || got[0].UID != "uid-a" || got[0].State != "live" {
		t.Fatalf("live UID observation = %+v, ok=%v", got, ok)
	}
	w.applyServiceEvent("DELETED", json.RawMessage(`{"metadata":{"name":"api","namespace":"prod","uid":"uid-a"},"spec":{}}`))
	w.applyServiceEvent("ADDED", json.RawMessage(`{"metadata":{"name":"api","namespace":"prod","uid":"uid-b"},"spec":{"ports":[{"port":80}]}}`))
	got, ok := w.ServiceUIDObservations("prod", "api")
	if !ok || len(got) != 2 || got[0].UID != "uid-a" || got[0].State != "deleted" || got[1].UID != "uid-b" || got[1].State != "live" {
		t.Fatalf("delete/recreate observations = %+v, ok=%v", got, ok)
	}
	if _, ok := w.ServiceUIDObservations("prod", "other"); ok {
		t.Fatal("exact lookup must not expose broad Service inventory")
	}
	w.clearServices()
	if _, ok := w.ServiceUIDObservations("prod", "api"); ok {
		t.Fatal("watch fault must clear UID observation state fail-closed")
	}
}

func TestServiceInventoryIsDeterministicBoundedAndNonSensitive(t *testing.T) {
	w := newTestWatcher("", nil, func() {})
	w.servicesSynced = true
	w.servicesWatching = true
	w.applyServiceEvent("ADDED", json.RawMessage(`{"metadata":{"name":"dns","namespace":"prod","uid":"uid-dns"},"spec":{"ports":[{"name":"dns-udp","port":53,"protocol":"UDP"},{"name":"dns-tcp","port":53,"protocol":"TCP"},{"name":"sctp","port":54,"protocol":"SCTP"}]}}`))
	w.applyServiceEvent("ADDED", json.RawMessage(`{"metadata":{"name":"api","namespace":"apps","uid":"uid-api"},"spec":{"ports":[{"name":"https","port":443}]}}`))
	items, ok := w.ServiceInventory()
	if !ok || len(items) != 2 || items[0].Namespace != "apps" || items[1].Service != "dns" {
		t.Fatalf("inventory ok=%v items=%+v", ok, items)
	}
	if len(items[1].Ports) != 2 || items[1].Ports[0].Protocol != "tcp" || items[1].Ports[1].Protocol != "udp" {
		t.Fatalf("supported ordered ports=%+v", items[1].Ports)
	}
	tooManyPorts := svcPorts{}
	for i := 1; i <= maxServiceInventoryPorts+1; i++ {
		tooManyPorts[svcPortKey{protocol: "tcp", port: i}] = "p"
	}
	w.services["prod/overflow"] = serviceInfo{uid: "uid-overflow", ports: tooManyPorts}
	if _, ok := w.ServiceInventory(); ok {
		t.Fatal("port overflow was truncated instead of refused")
	}
	w.clearServices()
	if _, ok := w.ServiceInventory(); ok {
		t.Fatal("unsynced view was represented as empty inventory")
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
	if g.ports[endpointPortKey{protocol: "tcp", name: ""}] != 8080 {
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
	w.slices["prod/api"] = map[string]epGroup{"s1": {ready: []string{"10.42.0.14"}, ports: map[endpointPortKey]int{{protocol: "tcp", name: "web"}: 8080}}}
	w.slicesSynced = true
	if _, ok := w.Targets("prod", "api", "tcp", 80); ok {
		t.Fatal("a not-fully-synced view must fail closed (ok=false)")
	}
	// Both synced: servicePort 80 has name "web" -> the slice's "web" port is 8080.
	w.services["prod/api"] = serviceInfo{ports: svcPorts{{protocol: "tcp", port: 80}: "web"}}
	w.servicesSynced = true
	w.servicesWatching, w.slicesWatching = true, true
	ts, ok := w.Targets("prod", "api", "tcp", 80)
	if !ok || len(ts) != 1 || ts[0].ip != "10.42.0.14" || ts[0].port != 8080 {
		t.Fatalf("expected 10.42.0.14:8080, got ok=%v %+v", ok, ts)
	}
	// A servicePort the Service does not expose -> ok=true but no target (refuse, not guess).
	if ts, ok := w.Targets("prod", "api", "tcp", 443); !ok || len(ts) != 0 {
		t.Fatalf("an unexposed servicePort must yield zero targets, got ok=%v %+v", ok, ts)
	}
}

func TestLiveSnapshotDistinguishesZeroReadyPodsFromAPIUnavailable(t *testing.T) {
	w := newTestWatcher("", nil, func() {})
	w.services["prod/api"] = serviceInfo{ports: svcPorts{{protocol: "tcp", port: 80}: "web"}}
	w.servicesSynced, w.slicesSynced = true, true
	w.servicesWatching, w.slicesWatching = true, true

	if !w.LiveSnapshotReady() {
		t.Fatal("successful empty Services/EndpointSlices snapshot was not live")
	}
	if targets, ok := w.Targets("prod", "api", "tcp", 80); !ok || len(targets) != 0 {
		t.Fatalf("zero ready pods must be a live empty result, got ok=%v targets=%+v", ok, targets)
	}

	w.setWatching(epSlicePath, false)
	if w.LiveSnapshotReady() {
		t.Fatal("lost EndpointSlice watch retained live snapshot readiness")
	}
	if targets, ok := w.Targets("prod", "api", "tcp", 80); ok || len(targets) != 0 {
		t.Fatalf("API-unavailable snapshot must fail closed, got ok=%v targets=%+v", ok, targets)
	}
}

func TestPlannedWatchRenewalRetainsLiveSnapshot(t *testing.T) {
	requestStarted := make(chan struct{})
	allowHeaders := make(chan struct{})
	streamStarted := make(chan struct{})
	releaseStream := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		close(requestStarted)
		<-allowHeaders
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		rw.(http.Flusher).Flush()
		close(streamStarted)
		<-releaseStream
	}))
	defer srv.Close()

	w := newTestWatcher(srv.URL, srv.Client(), func() {})
	var clockNanos atomic.Int64
	w.now = func() time.Time { return time.Unix(0, clockNanos.Load()) }
	w.servicesSynced, w.slicesSynced = true, true
	w.servicesWatching = true
	done := make(chan error, 1)
	go func() {
		_, err := w.watch(context.Background(), epSlicePath, "1", func(string, json.RawMessage) {})
		done <- err
	}()
	<-requestStarted
	if w.LiveSnapshotReady() {
		t.Fatal("initial readiness was accepted before the first EndpointSlices watch HTTP 200")
	}
	close(allowHeaders)
	<-streamStarted
	waitForLiveSnapshot(t, w, true)
	clockNanos.Store(int64(time.Duration(watchServerTimeoutSec) * time.Second))
	close(releaseStream)
	if err := <-done; err != nil {
		t.Fatalf("clean watch close: %v", err)
	}
	if !w.LiveSnapshotReady() {
		t.Fatal("normal bounded watch renewal flapped the last-good live snapshot")
	}
}

func TestEarlyCleanWatchEOFRetractsLiveSnapshot(t *testing.T) {
	streamStarted := make(chan struct{})
	releaseStream := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		rw.(http.Flusher).Flush()
		close(streamStarted)
		<-releaseStream
	}))
	defer srv.Close()

	w := newTestWatcher(srv.URL, srv.Client(), func() {})
	var clockNanos atomic.Int64
	w.now = func() time.Time { return time.Unix(0, clockNanos.Load()) }
	w.servicesSynced, w.slicesSynced = true, true
	w.servicesWatching = true
	done := make(chan error, 1)
	go func() {
		_, err := w.watch(context.Background(), epSlicePath, "1", func(string, json.RawMessage) {})
		done <- err
	}()
	<-streamStarted
	waitForLiveSnapshot(t, w, true)
	clockNanos.Store(int64(time.Second))
	close(releaseStream)
	if err := <-done; err == nil {
		t.Fatal("early clean EOF was accepted as the planned Kubernetes watch timeout")
	}
	if w.LiveSnapshotReady() {
		t.Fatal("early clean EOF retained stale snapshot readiness")
	}
}

func TestWatchDecodeErrorRetractsLiveSnapshot(t *testing.T) {
	streamStarted := make(chan struct{})
	corruptStream := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		rw.(http.Flusher).Flush()
		close(streamStarted)
		<-corruptStream
		_, _ = io.WriteString(rw, "not-json\n")
	}))
	defer srv.Close()

	w := newTestWatcher(srv.URL, srv.Client(), func() {})
	w.servicesSynced, w.slicesSynced = true, true
	w.servicesWatching = true
	done := make(chan error, 1)
	go func() {
		_, err := w.watch(context.Background(), epSlicePath, "1", func(string, json.RawMessage) {})
		done <- err
	}()
	<-streamStarted
	waitForLiveSnapshot(t, w, true)
	close(corruptStream)
	if err := <-done; err == nil {
		t.Fatal("malformed watch event was accepted as a clean renewal")
	}
	if w.LiveSnapshotReady() {
		t.Fatal("watch decode failure retained stale snapshot readiness")
	}
}

func TestRBACListFailureNeverEstablishesLiveSnapshot(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	w := newTestWatcher(srv.URL, srv.Client(), func() {})

	if _, err := w.listServices(context.Background()); err == nil {
		t.Fatal("Services RBAC denial was accepted")
	}
	if _, err := w.listSlices(context.Background()); err == nil {
		t.Fatal("EndpointSlices RBAC denial was accepted")
	}
	if w.LiveSnapshotReady() {
		t.Fatal("RBAC-denied Kubernetes API reported a live Services/EndpointSlices snapshot")
	}
}

func TestListRequestDeadlineBoundsUnresponsiveKubernetesAPI(t *testing.T) {
	requestStarted := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		close(requestStarted)
		<-req.Context().Done()
	}))
	defer srv.Close()
	w := newTestWatcher(srv.URL, srv.Client(), func() {})
	w.listTimeout = 40 * time.Millisecond

	startedAt := time.Now()
	_, _, err := w.getList(context.Background(), servicePath)
	if err == nil {
		t.Fatal("unresponsive Kubernetes API LIST had no request deadline")
	}
	<-requestStarted
	if elapsed := time.Since(startedAt); elapsed > 500*time.Millisecond {
		t.Fatalf("unresponsive LIST returned after %v, want a bounded retry", elapsed)
	}
	if w.LiveSnapshotReady() {
		t.Fatal("timed-out LIST established Kubernetes API readiness")
	}
}

func TestK8sAPIClientBoundsConnectionSetupWithoutTimingOutWatchBody(t *testing.T) {
	client := newK8sAPIClient(nil)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Kubernetes API transport=%T, want *http.Transport", client.Transport)
	}
	if client.Timeout != 0 {
		t.Fatalf("whole-client timeout=%v would terminate healthy watch bodies", client.Timeout)
	}
	if transport.ResponseHeaderTimeout != apiResponseTimeout {
		t.Fatalf("response-header timeout=%v, want %v", transport.ResponseHeaderTimeout, apiResponseTimeout)
	}
	if transport.TLSHandshakeTimeout != apiTLSHandshakeTimeout {
		t.Fatalf("TLS handshake timeout=%v, want %v", transport.TLSHandshakeTimeout, apiTLSHandshakeTimeout)
	}
	if client.CheckRedirect == nil {
		t.Fatal("Kubernetes API client follows redirects")
	}
}

func TestK8sWatcherRefusesRedirectWithoutForwardingServiceAccountBearer(t *testing.T) {
	var mu sync.Mutex
	targetCalls := 0
	targetAuthorization := ""
	target := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		mu.Lock()
		targetCalls++
		targetAuthorization = req.Header.Get("Authorization")
		mu.Unlock()
		rw.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	sourceAuthorization := ""
	source := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		mu.Lock()
		sourceAuthorization = req.Header.Get("Authorization")
		mu.Unlock()
		http.Redirect(rw, req, target.URL+"/credential-leak", http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	tokenPath := t.TempDir() + "/token"
	if err := os.WriteFile(tokenPath, []byte("projected-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := source.Client()
	client.CheckRedirect = refuseK8sAPIRedirect
	w := newTestWatcher(source.URL, client, func() {})
	w.tokenPath = tokenPath
	if _, _, err := w.getList(context.Background(), servicePath); err == nil {
		t.Fatal("Kubernetes API redirect was accepted")
	}
	mu.Lock()
	defer mu.Unlock()
	if sourceAuthorization != "Bearer projected-secret" {
		t.Fatalf("source bearer=%q, want projected credential", sourceAuthorization)
	}
	if targetCalls != 0 || targetAuthorization != "" {
		t.Fatalf("redirect target calls=%d authorization=%q; projected bearer must never leave the API origin", targetCalls, targetAuthorization)
	}
}

func TestTargetsKeysSameServicePortByProtocol(t *testing.T) {
	w := newTestWatcher("", nil, func() {})
	w.services["prod/dns"] = serviceInfo{ports: svcPorts{
		{protocol: "tcp", port: 53}: "dns-tcp",
		{protocol: "udp", port: 53}: "dns-udp",
	}}
	w.slices["prod/dns"] = map[string]epGroup{"dns-1": {
		ready: []string{"10.42.0.53"},
		ports: map[endpointPortKey]int{
			{protocol: "tcp", name: "dns-tcp"}: 5353,
			{protocol: "udp", name: "dns-udp"}: 5354,
		},
	}}
	w.servicesSynced, w.slicesSynced = true, true
	w.servicesWatching, w.slicesWatching = true, true
	for _, tc := range []struct {
		protocol string
		wantPort int
	}{{"tcp", 5353}, {"udp", 5354}} {
		t.Run(tc.protocol, func(t *testing.T) {
			targets, ok := w.Targets("prod", "dns", tc.protocol, 53)
			if !ok || len(targets) != 1 || targets[0] != (k8sTarget{ip: "10.42.0.53", port: tc.wantPort}) {
				t.Fatalf("%s/53 targets = ok=%v %+v", tc.protocol, ok, targets)
			}
		})
	}
}

func TestUnsupportedK8sProtocolsNeverAliasTCP(t *testing.T) {
	service := json.RawMessage(`{"metadata":{"name":"api","namespace":"prod"},"spec":{"ports":[{"name":"https","port":443,"protocol":"SCTP"}]}}`)
	key, info, ok := parseService(service)
	if !ok || key != "prod/api" || len(info.ports) != 0 {
		t.Fatalf("unsupported Service protocol entered target index: key=%q info=%+v ok=%v", key, info, ok)
	}
	slice := json.RawMessage(`{"metadata":{"name":"api-1","namespace":"prod","labels":{"kubernetes.io/service-name":"api"}},"endpoints":[{"addresses":["10.42.0.14"],"conditions":{"ready":true}}],"ports":[{"name":"https","port":8443,"protocol":"SCTP"}]}`)
	_, _, group, ok := parseSlice(slice)
	if !ok || len(group.ports) != 0 {
		t.Fatalf("unsupported EndpointSlice protocol entered target index: ports=%+v ok=%v", group.ports, ok)
	}
	w := newTestWatcher("", nil, func() {})
	w.services[key], w.slices[key] = info, map[string]epGroup{"api-1": group}
	w.servicesSynced, w.slicesSynced = true, true
	w.servicesWatching, w.slicesWatching = true, true
	for _, protocol := range []string{"tcp", "SCTP"} {
		if targets, live := w.Targets("prod", "api", protocol, 443); !live || len(targets) != 0 {
			t.Fatalf("%s must fail closed without TCP alias: live=%v targets=%+v", protocol, live, targets)
		}
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
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
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
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
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
		ts, ok := w.Targets("prod", "api", "tcp", 80)
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
	w.services["prod/api"] = serviceInfo{ports: svcPorts{{protocol: "tcp", port: 80}: ""}}
	w.servicesSynced = true
	w.slices["prod/api"] = map[string]epGroup{"s1": {ready: []string{"10.42.0.14"}, ports: map[endpointPortKey]int{{protocol: "tcp", name: ""}: 8080}}}
	w.slicesSynced = true
	w.servicesWatching, w.slicesWatching = true, true
	if _, ok := w.Targets("prod", "api", "tcp", 80); !ok {
		t.Fatal("test precondition: successful live snapshot was not readable")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.loop(ctx, epSlicePath, w.listSlices, w.applySliceEvent, w.clearSlices)

	deadline := time.After(3 * time.Second)
	for {
		if _, ok := w.Targets("prod", "api", "tcp", 80); !ok {
			return // the failing list cleared the slice view → fail-closed
		}
		select {
		case <-deadline:
			t.Fatal("a persistent list failure must CLEAR the endpoint view (fail-closed), it did not")
		case <-time.After(15 * time.Millisecond):
		}
	}
}
