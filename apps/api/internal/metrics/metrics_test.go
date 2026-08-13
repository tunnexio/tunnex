package metrics

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
)

// collect gathers the fleet metric's series as kind -> value.
func collect(t *testing.T, health FleetHealthFunc) map[string]float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(health))
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, f := range families {
		if f.GetName() != "tunnex_gateway_policy_health" {
			continue
		}
		for _, m := range f.Metric {
			var kind string
			for _, l := range m.Label {
				if l.GetName() == "kind" {
					kind = l.GetValue()
				}
			}
			out[kind] = m.GetGauge().GetValue()
		}
	}
	return out
}

// TestCollectorEmitsEveryKind — D3.1's other half (the census red in package nodes holds the first).
//
// The metric ranges over nodes.AllKinds(), so EVERY kind emits a series even at zero. Two failures this
// prevents: an absent series is indistinguishable from a scrape failure (an operator alerting on
// "apply_failing > 0" learns nothing from a series that isn't there), and a kind with no metric path would
// be a producer with no consumer — invisible until someone asks why the graph is empty.
func TestCollectorEmitsEveryKind(t *testing.T) {
	got := collect(t, func() map[nodes.PolicyDegradedKind]int { return nil })

	all := nodes.AllKinds()
	if len(all) == 0 {
		t.Fatal("AllKinds() is empty — the metric would expose nothing")
	}
	for _, k := range all {
		v, ok := got[string(k)]
		if !ok {
			t.Fatalf("kind %q emits NO series — a kind with no metric path is invisible to monitoring", k)
		}
		if v != 0 {
			t.Fatalf("kind %q should report 0 when the fleet reports nothing, got %v", k, v)
		}
	}
	if len(got) != len(all) {
		t.Fatalf("series count %d != kind count %d — the metric invented or dropped a kind", len(got), len(all))
	}
}

// TestCollectorReportsCounts — the values are the fleet's, and unreported kinds still emit 0.
func TestCollectorReportsCounts(t *testing.T) {
	got := collect(t, func() map[nodes.PolicyDegradedKind]int {
		return map[nodes.PolicyDegradedKind]int{
			nodes.KindHealthy:      7,
			nodes.KindApplyFailing: 2,
		}
	})
	if got[string(nodes.KindHealthy)] != 7 || got[string(nodes.KindApplyFailing)] != 2 {
		t.Fatalf("counts not reported: healthy=%v apply_failing=%v", got[string(nodes.KindHealthy)], got[string(nodes.KindApplyFailing)])
	}
	if v, ok := got[string(nodes.KindSilentDesync)]; !ok || v != 0 {
		t.Fatalf("an unreported kind must still emit 0, got ok=%v v=%v", ok, v)
	}
}

// TestNoOrgOrNodeLabels — D3.3's cardinality ruling, enforced rather than documented.
//
// Fleet counts by kind ONLY. A well-meaning future change adding an org_id or node_id label would multiply
// the series count by the tenant/fleet size on a shared Prometheus — the failure mode that takes monitoring
// stacks down. Per-node detail is REGISTERED with a trigger (a customer running their own Prometheus who
// asks for it); until then the dashboard answers "which", and this metric answers "how many".
func TestNoOrgOrNodeLabels(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(func() map[nodes.PolicyDegradedKind]int { return nil }))
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	banned := []string{"org", "org_id", "node", "node_id", "device", "device_id", "user", "user_id"}
	for _, f := range families {
		for _, m := range f.Metric {
			for _, l := range m.Label {
				name := strings.ToLower(l.GetName())
				for _, b := range banned {
					if name == b {
						t.Fatalf("metric %q carries label %q — unbounded cardinality (D3.3): fleet counts "+
							"by kind only; per-node detail belongs in the API/dashboard", f.GetName(), name)
					}
				}
			}
		}
	}
	_ = dto.MetricType_GAUGE // keep the dto import honest across client_golang versions
}

// TestWildcardBindDetection — the security-relevant half of D3.2. The default must be loopback, and a
// wildcard bind must be RECOGNISED (it is warned about, not silently accepted).
func TestWildcardBindDetection(t *testing.T) {
	if !strings.HasPrefix(DefaultAddr, "127.0.0.1:") {
		t.Fatalf("the metrics default MUST be loopback so a public endpoint is impossible by construction, got %q", DefaultAddr)
	}
	for _, addr := range []string{":9090", "0.0.0.0:9090", "[::]:9090"} {
		if !isWildcard(addr) {
			t.Fatalf("%q binds every interface but was not detected as a wildcard", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:9090", "10.0.0.4:9090", "[::1]:9090"} {
		if isWildcard(addr) {
			t.Fatalf("%q is a specific interface but was flagged as a wildcard", addr)
		}
	}
}

// TestFollowerIsReady — D4's readiness ruling, enforced.
//
// A follower SERVES; it merely does not tick. Reporting it as not-ready would pull healthy replicas out of a
// load balancer the moment leader election was enabled, turning an HA feature into an outage — the exact
// conflation the ruling forbids. So: role is REPORTED in the body, and readiness is 200 for both roles.
func TestFollowerIsReady(t *testing.T) {
	for _, tc := range []struct {
		name   string
		leader bool
		want   string
	}{
		{"leader", true, "ok leader"},
		{"follower", false, "ok follower"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := ln.Addr().String()
			_ = ln.Close()

			go func() {
				_ = Serve(ctx, addr, NewRegistry(nil, nil), nil, nil, func() bool { return tc.leader })
			}()

			var resp *http.Response
			for i := 0; i < 60; i++ {
				resp, err = http.Get("http://" + addr + "/readyz")
				if err == nil {
					break
				}
				time.Sleep(25 * time.Millisecond)
			}
			if err != nil {
				t.Fatalf("readyz never came up: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s must be READY (200) — a follower serves; got %d. Reporting a follower "+
					"not-ready evicts healthy replicas from the load balancer.", tc.name, resp.StatusCode)
			}
			if string(body) != tc.want {
				t.Fatalf("readyz must REPORT the role: want %q, got %q", tc.want, string(body))
			}
		})
	}
}

// TestSchedulerLeaderGaugeIsEmitted — review #6: leaderlessness was the design's chosen SAFE failure direction and
// also its INVISIBLE one. Nothing ticks, and every replica answers 200 "ok follower", which is a documented healthy
// state — so a stranded advisory lock or a saturated pool stopped hub failover promotion, CRL refresh, retention
// sweeps and challenge pruning indefinitely with no metric, no log and no health kind.
//
// A per-gateway health kind was the wrong home for it: PolicyDegradedKind describes GATEWAYS, and scheduler
// leadership is a property of the control plane. The metrics floor EPIC 11 built is the right surface, and summing
// the gauge across replicas is how an operator sees "nobody leads".
//
// Emitted as 0 rather than omitted when this replica is a follower, for the same reason the per-kind series are:
// an absent series is indistinguishable from a scrape failure.
func TestSchedulerLeaderGaugeIsEmitted(t *testing.T) {
	for _, tc := range []struct {
		name   string
		leader bool
		want   string
	}{
		{"leader", true, "tunnex_scheduler_leader 1"},
		{"follower", false, "tunnex_scheduler_leader 0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := NewRegistry(nil, func() bool { return tc.leader })
			want := 0.0
			if tc.leader {
				want = 1
			}
			got, found := leaderGauge(t, reg)
			if !found {
				t.Fatal("the leadership gauge must be emitted in BOTH roles so a zero sum across replicas is " +
					"detectable — an absent series is indistinguishable from a scrape failure")
			}
			if got != want {
				t.Errorf("tunnex_scheduler_leader = %v, want %v", got, want)
			}
		})
	}

	// With no role wired the series is absent rather than reporting a fabricated 0 — an unwired collector must not
	// claim this replica is a follower, because that is a positive statement it cannot make.
	if _, found := leaderGauge(t, NewRegistry(nil, nil)); found {
		t.Error("with no role wired the gauge must be absent, not 0 — reporting follower would assert something " +
			"the collector does not know")
	}
}

// leaderGauge reads tunnex_scheduler_leader out of a registry, reporting whether the series exists at all —
// present-with-0 and absent are different claims and the tests above depend on the difference.
func leaderGauge(t *testing.T, reg *prometheus.Registry) (float64, bool) {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != "tunnex_scheduler_leader" {
			continue
		}
		for _, m := range f.GetMetric() {
			return m.GetGauge().GetValue(), true
		}
	}
	return 0, false
}
