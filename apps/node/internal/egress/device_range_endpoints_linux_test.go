//go:build linux

package egress

import (
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// K8N-5 item 2: a Service whose EndpointSlice holds a device address makes the gateway not ready.

func liveTestWatcher() *K8sWatcher {
	w := newTestWatcher("", nil, func() {})
	w.servicesSynced, w.slicesSynced = true, true
	w.servicesWatching, w.slicesWatching = true, true
	return w
}

func sliceEvent(t *testing.T, w *K8sWatcher, evType, raw string) {
	t.Helper()
	if !json.Valid([]byte(raw)) {
		t.Fatalf("invalid test slice: %s", raw)
	}
	w.applySliceEvent(evType, json.RawMessage(raw))
}

const (
	deviceSliceTeamA = `{"metadata":{"name":"db-1","namespace":"team-a","labels":{"kubernetes.io/service-name":"db"}},
	  "addressType":"IPv4","endpoints":[{"addresses":["10.99.0.7"],"conditions":{"ready":false}}],"ports":[{"name":"","port":5432}]}`
	deviceSliceTeamB = `{"metadata":{"name":"web-1","namespace":"team-b","labels":{"kubernetes.io/service-name":"web"}},
	  "addressType":"IPv4","endpoints":[{"addresses":["10.99.0.10"],"conditions":{"ready":true}},{"addresses":["10.99.0.9"]}]}`
	podSlice = `{"metadata":{"name":"api-1","namespace":"prod","labels":{"kubernetes.io/service-name":"api"}},
	  "addressType":"IPv4","endpoints":[{"addresses":["10.42.0.14"],"conditions":{"ready":true}}],"ports":[{"name":"","port":8080}]}`
)

func TestParseSliceKeepsEveryAddressWhateverItsConditions(t *testing.T) {
	raw := json.RawMessage(`{
      "metadata":{"name":"db-1","namespace":"team-a","labels":{"kubernetes.io/service-name":"db"}},
      "endpoints":[
        {"addresses":["10.99.0.4"],"conditions":{"ready":true}},
        {"addresses":["10.99.0.5"],"conditions":{"ready":false}},
        {"addresses":["10.99.0.6"],"conditions":{}},
        {"addresses":["10.99.0.7"],"conditions":{"ready":false,"serving":true,"terminating":true}}
      ]}`)
	_, _, g, ok := parseSlice(raw)
	if !ok {
		t.Fatal("slice not parsed")
	}
	if !reflect.DeepEqual(g.all, []string{"10.99.0.4", "10.99.0.5", "10.99.0.6", "10.99.0.7"}) {
		t.Fatalf("every address must be kept for the device-range check, got %v", g.all)
	}
	if !reflect.DeepEqual(g.ready, []string{"10.99.0.4"}) {
		t.Fatalf("the DNAT view must still hold only the ready address, got %v", g.ready)
	}
}

func TestEndpointsInRangesFindsDeviceAddressesInBothFamiliesAndOnlyThose(t *testing.T) {
	w := liveTestWatcher()
	sliceEvent(t, w, "ADDED", deviceSliceTeamB)
	sliceEvent(t, w, "ADDED", deviceSliceTeamA)
	sliceEvent(t, w, "ADDED", podSlice)
	sliceEvent(t, w, "ADDED", `{"metadata":{"name":"v6-1","namespace":"team-c","labels":{"kubernetes.io/service-name":"v6"}},
	  "addressType":"IPv6","endpoints":[{"addresses":["fd00:99::5"]}]}`)
	sliceEvent(t, w, "ADDED", `{"metadata":{"name":"ext-1","namespace":"team-d","labels":{"kubernetes.io/service-name":"ext"}},
	  "addressType":"FQDN","endpoints":[{"addresses":["db.example.com"]}]}`)
	// Not labelled with a Service: kube-proxy programs nothing for it, and the watcher does not hold it.
	sliceEvent(t, w, "ADDED", `{"metadata":{"name":"orphan","namespace":"team-e"},"endpoints":[{"addresses":["10.99.0.8"]}]}`)

	ranges := []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24"), netip.MustParsePrefix("fd00:99::/64")}
	hits, ok := w.EndpointsInRanges(ranges)
	if !ok {
		t.Fatal("a live view must answer")
	}
	want := []DeviceRangeEndpoint{
		{Service: "team-a/db", Address: "10.99.0.7", Range: "10.99.0.0/24"},
		{Service: "team-b/web", Address: "10.99.0.9", Range: "10.99.0.0/24"},
		{Service: "team-b/web", Address: "10.99.0.10", Range: "10.99.0.0/24"},
		{Service: "team-c/v6", Address: "fd00:99::5", Range: "fd00:99::/64"},
	}
	if !reflect.DeepEqual(hits, want) {
		t.Fatalf("hits=%+v\nwant %+v", hits, want)
	}

	// A deleted slice no longer counts.
	sliceEvent(t, w, "DELETED", deviceSliceTeamA)
	if hits, _ := w.EndpointsInRanges(ranges[:1]); len(hits) != 2 || hits[0].Service != "team-b/web" {
		t.Fatalf("after the delete: %+v", hits)
	}

	// No live view: no answer, and no claim of a clean cluster either.
	w.slicesSynced = false
	if hits, ok := w.EndpointsInRanges(ranges); ok || hits != nil {
		t.Fatalf("a view that is not live answered: ok=%v %+v", ok, hits)
	}
	var none *K8sWatcher
	if _, ok := none.EndpointsInRanges(ranges); ok {
		t.Fatal("a nil watcher answered")
	}
}

func readyNetPrep() *fakeK8sNetPrep {
	return &fakeK8sNetPrep{status: k8snetprep.ReconcileStatus{
		Host:     k8snetprep.ComponentStatus{Name: "wireguard_rp_filter", State: k8snetprep.StateReady},
		Adapters: []k8snetprep.ComponentStatus{{Name: "observed_cni", State: k8snetprep.StateReady}},
	}}
}

func deviceRangeManager(source endpointSource) *Manager {
	m := New("wg0")
	m.SetKubernetesMode(true)
	m.k8sNetPrep = readyNetPrep()
	m.SetEndpointSource(source)
	return m
}

func netPrepSummary(m *Manager) string {
	if s := m.k8sNetPrepStatus.Load(); s != nil {
		return *s
	}
	return ""
}

func TestServiceEndpointInsideDeviceRangeMakesGatewayNotReadyUntilRemoved(t *testing.T) {
	ctx := context.Background()
	w := liveTestWatcher()
	sliceEvent(t, w, "ADDED", podSlice)
	m := deviceRangeManager(w)

	// A cluster with no such endpoint is unaffected.
	if err := m.reconcileK8sNetPrep(ctx, "10.99.0.1/24"); err != nil || !m.K8sNetPrepReady() {
		t.Fatalf("a clean cluster is not ready: err=%v", err)
	}
	if strings.Contains(netPrepSummary(m), "device range") {
		t.Fatalf("a clean cluster carries the refusal: %s", netPrepSummary(m))
	}

	sliceEvent(t, w, "ADDED", deviceSliceTeamA)
	if err := m.reconcileK8sNetPrep(ctx, "10.99.0.1/24"); err != nil || m.K8sNetPrepReady() {
		t.Fatalf("a device endpoint left the gateway ready: err=%v ready=%v", err, m.K8sNetPrepReady())
	}
	want := "Service team-a/db has endpoint 10.99.0.7, inside the Tunnex device range 10.99.0.0/24. " +
		"Kubernetes marks and masquerades traffic to it, so this gateway is not ready. Remove that endpoint or Service."
	if got := m.deviceRangeEndpointRefusal(ctx, "10.99.0.1/24"); got != want {
		t.Fatalf("reason:\n%s\nwant:\n%s", got, want)
	}
	if !strings.Contains(netPrepSummary(m), "wireguard_rp_filter:blocked:Service team-a/db has endpoint 10.99.0.7") {
		t.Fatalf("the logged status does not carry the reason: %s", netPrepSummary(m))
	}

	sliceEvent(t, w, "ADDED", deviceSliceTeamB)
	if got := m.deviceRangeEndpointRefusal(ctx, "10.99.0.1/24"); !strings.HasPrefix(got, "Service team-a/db ") || !strings.HasSuffix(got, " (2 Services in all)") {
		t.Fatalf("two Services: %s", got)
	}

	sliceEvent(t, w, "DELETED", deviceSliceTeamA)
	sliceEvent(t, w, "DELETED", deviceSliceTeamB)
	if err := m.reconcileK8sNetPrep(ctx, "10.99.0.1/24"); err != nil || !m.K8sNetPrepReady() {
		t.Fatalf("removing the endpoints did not restore readiness: err=%v", err)
	}
}

func TestDeviceRangeIncludesThePolicyDevicePool(t *testing.T) {
	ctx := context.Background()
	w := liveTestWatcher()
	// Outside this gateway's wg0 subnet, inside the organisation's device pool.
	sliceEvent(t, w, "ADDED", `{"metadata":{"name":"db-1","namespace":"team-a","labels":{"kubernetes.io/service-name":"db"}},
	  "endpoints":[{"addresses":["10.99.4.7"],"conditions":{"ready":true}}]}`)
	m := deviceRangeManager(w)
	if err := m.reconcileK8sNetPrep(ctx, "10.99.0.1/24"); err != nil || !m.K8sNetPrepReady() {
		t.Fatalf("without a pool the address is outside the device range: err=%v", err)
	}
	m.SetPolicy(&nodepolicy.Compiled{Version: 7, Mode: nodepolicy.ModeEnforcing, PoolCIDR: "10.99.0.0/16"})
	if err := m.reconcileK8sNetPrep(ctx, "10.99.0.1/24"); err != nil || m.K8sNetPrepReady() {
		t.Fatalf("an endpoint in the device pool left the gateway ready: err=%v", err)
	}
	if got := m.deviceRangeEndpointRefusal(ctx, "10.99.0.1/24"); !strings.Contains(got, "endpoint 10.99.4.7, inside the Tunnex device range 10.99.0.0/16") {
		t.Fatalf("reason: %s", got)
	}
}

func TestDeviceRangeCheckKeepsAnEarlierHostRefusal(t *testing.T) {
	w := liveTestWatcher()
	sliceEvent(t, w, "ADDED", deviceSliceTeamA)
	m := deviceRangeManager(w)
	m.k8sNetPrep = &fakeK8sNetPrep{status: k8snetprep.ReconcileStatus{
		Host:     k8snetprep.ComponentStatus{Name: "wireguard_rp_filter", State: k8snetprep.StateBlocked, Reason: "rp_filter is strict"},
		Adapters: []k8snetprep.ComponentStatus{{Name: "observed_cni", State: k8snetprep.StateReady}},
	}}
	_ = m.reconcileK8sNetPrep(context.Background(), "10.99.0.1/24")
	if m.K8sNetPrepReady() || !strings.HasPrefix(netPrepSummary(m), "wireguard_rp_filter:blocked:rp_filter is strict; Service team-a/db ") {
		t.Fatalf("summary: %s", netPrepSummary(m))
	}
}

func TestSourcesWithoutTheClusterViewSkipTheDeviceRangeCheck(t *testing.T) {
	// A fake (or a VM gateway's nil) source has no cluster-wide slice view; readiness is unchanged.
	m := deviceRangeManager(&fakeSource{m: map[string]fakeEntry{}})
	if err := m.reconcileK8sNetPrep(context.Background(), "10.99.0.1/24"); err != nil || !m.K8sNetPrepReady() {
		t.Fatalf("err=%v ready=%v", err, m.K8sNetPrepReady())
	}
	// A view that is not live adds no refusal of its own: agent readiness already requires it.
	w := newTestWatcher("", nil, func() {})
	sliceEvent(t, w, "ADDED", deviceSliceTeamA)
	m = deviceRangeManager(w)
	if got := m.deviceRangeEndpointRefusal(context.Background(), "10.99.0.1/24"); got != "" {
		t.Fatalf("a view that is not live refused: %s", got)
	}
}
