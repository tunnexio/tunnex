// Package metrics exposes the control plane's Prometheus surface (S11 D3.1–D3.3).
//
// ONE TRUTH, TWO RENDERINGS. The fleet-health metric is DERIVED from the health kinds the product already
// ships (nodes.AllKinds(), itself derived from the transitionTable that drives the dashboard) — never a
// parallel vocabulary invented for monitoring. The dashboard and the metric answer the same question from
// the same source; only the rendering differs.
//
// CARDINALITY (D3.3): fleet-level counts by KIND ONLY — no org or node labels. Per-org/per-node series on a
// shared Prometheus is unbounded cardinality, which is how monitoring stacks fall over, and that detail
// already lives in the API + dashboard. The honest limit, stated so nobody mis-reads the metric: it answers
// "HOW MANY gateways are apply_failing", never "WHICH ones" — the dashboard answers which.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
)

// FleetHealthFunc returns the CURRENT count of gateways per health kind. It is called on every scrape, so it
// must be cheap and must never block the scrape indefinitely (the caller bounds it with a context).
// A nil/empty map is valid — it means "no gateways", and every kind still reports 0.
type FleetHealthFunc func() map[nodes.PolicyDegradedKind]int

// Collector reports fleet health. It implements prometheus.Collector so the counts are read at scrape time
// rather than cached behind a ticker — no staleness window, and no extra scheduler to leader-gate (D4).
type Collector struct {
	health FleetHealthFunc
	desc   *prometheus.Desc
	// role reports whether THIS replica currently holds scheduler leadership. nil → the series is not emitted.
	role     func() bool
	roleDesc *prometheus.Desc
}

// NewCollector builds the fleet collector. health may be nil (then every kind reports 0 — an honest
// "nothing known" rather than a missing series).
func NewCollector(health FleetHealthFunc) *Collector {
	return &Collector{
		health: health,
		roleDesc: prometheus.NewDesc(
			"tunnex_scheduler_leader",
			"1 if this control-plane replica currently holds scheduler leadership, 0 if not. ALERT ON THE SUM "+
				"BEING ZERO across replicas: leaderlessness is the design's chosen SAFE failure direction and was "+
				"also its invisible one — nothing ticks, and every replica answers 200 \"ok follower\", which is a "+
				"documented healthy state. A stranded advisory lock or a saturated pool stops hub failover "+
				"promotion, CRL refresh, retention sweeps and re-key challenge pruning indefinitely with no signal.",
			nil, nil,
		),
		desc: prometheus.NewDesc(
			"tunnex_gateway_policy_health",
			"Number of gateways in each policy-health kind. Kinds are the product's own health vocabulary "+
				"(one truth with the dashboard). Fleet-wide: this answers how many, not which.",
			[]string{"kind"}, nil,
		),
	}
}

// SetRole wires the leadership gauge (review #6). Separate from NewCollector so the elector, which is built later
// in startup, can be attached without reordering construction.
func (c *Collector) SetRole(fn func() bool) { c.role = fn }

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
	ch <- c.roleDesc
}

// Collect emits ONE SERIES PER KIND, ranging over nodes.AllKinds() — so a kind with zero gateways reports 0
// rather than vanishing. That matters twice over: an absent series is indistinguishable from a scrape
// failure, and (D3.1) ranging over the enum means a 14th kind cannot be a series that silently never
// appears. TestEveryHealthKindIsEnumerated + TestCollectorEmitsEveryKind hold both halves.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	var counts map[nodes.PolicyDegradedKind]int
	if c.health != nil {
		counts = c.health()
	}
	// Emitted whether or not this replica leads, and emitted as 0 rather than omitted when it does not — an absent
	// series is indistinguishable from a scrape failure, which is the same reasoning as the per-kind series below.
	// Summing it across replicas is how an operator sees "nobody leads", which nothing surfaced before.
	if c.role != nil {
		lead := 0.0
		if c.role() {
			lead = 1
		}
		ch <- prometheus.MustNewConstMetric(c.roleDesc, prometheus.GaugeValue, lead)
	}
	for _, kind := range nodes.AllKinds() {
		ch <- prometheus.MustNewConstMetric(
			c.desc, prometheus.GaugeValue, float64(counts[kind]), string(kind),
		)
	}
}

// NewRegistry builds a registry carrying the fleet collector plus the Go/process collectors (heap, GC,
// goroutines, fds, CPU) — the baseline an operator needs to answer "is the control plane itself healthy",
// which is half of what this endpoint exists for. A dedicated registry (not the global default) keeps the
// exposed set explicit and testable.
// role may be nil; when supplied it emits tunnex_scheduler_leader so an operator can alert on the sum being zero
// across replicas (review #6 — leaderlessness was the safe failure direction and the invisible one).
func NewRegistry(health FleetHealthFunc, role func() bool) *prometheus.Registry {
	c := NewCollector(health)
	c.SetRole(role)
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		c,
		prometheus.NewGoCollector(),
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
	)
	return reg
}
