package k8s

import (
	"fmt"
	"sort"
)

const (
	PromoteAfterStaleTicks  = 3
	FailbackAfterFreshTicks = 5
)

// ConnectorCandidate is the current control-plane projection of one pool
// member. EndpointReady means that the source node has both a validated
// WireGuard public key and validated non-empty endpoint; it is deliberately
// not a claim about Kubernetes workload readiness.
type ConnectorCandidate struct {
	ID            string
	OrgID         string
	SiteID        string
	AdminPriority int
	Active        bool
	Revoked       bool
	EndpointReady bool
}

func (c ConnectorCandidate) eligible() bool {
	return c.ID != "" && c.Active && !c.Revoked && c.EndpointReady
}

// ConnectorHealth is a fail-closed projection of two independent current
// observations. The adapter that builds it must leave a signal false for
// missing, malformed, future, stale, or old-agent evidence. DataHealthy is the
// agent's global Kubernetes endpoint-view health, not per-Service readiness.
type ConnectorHealth struct {
	ControlHealthy bool
	DataHealthy    bool
}

func (h ConnectorHealth) Healthy() bool {
	return h.ControlHealthy && h.DataHealthy
}

// ConnectorPool is the pure control-plane state used to evaluate one health
// tick. Cluster and VIP identities are stable across a decision; this model
// neither moves a VIP nor authorizes an agent to serve it.
type ConnectorPool struct {
	OrgID                 string
	SiteID                string
	ClusterID             string
	Candidates            []ConnectorCandidate
	PreferredID           string
	ActiveID              string
	Generation            uint64
	StaleTicks            int
	PreferredFreshTicks   int
	CandidateHealthyTicks map[string]int
	VIPs                  []string
}

type Transition string

const (
	NoChange       Transition = "no_change"
	Promoted       Transition = "promoted"
	FailedBack     Transition = "failed_back"
	NeedsAttention Transition = "needs_attention"
)

// Decision is an evaluated state transition only. A promoted or failed-back
// decision still requires the persistence coordinator's expected-active and
// expected-generation CAS plus audit transaction before it becomes CP truth.
type Decision struct {
	Pool       ConnectorPool
	Transition Transition
	FromID     string
	ToID       string
	Reason     string
}

// NewConnectorPool validates the scope and eligibility boundary and establishes
// deterministic candidate order. It does not select an arbitrary member when
// the configured preferred connector is unusable.
func NewConnectorPool(orgID, siteID, clusterID, preferredID string, candidates []ConnectorCandidate, vips []string) (ConnectorPool, error) {
	if orgID == "" || siteID == "" || clusterID == "" || preferredID == "" {
		return ConnectorPool{}, fmt.Errorf("connector pool requires org, site, cluster, and preferred connector")
	}
	if len(candidates) == 0 {
		return ConnectorPool{}, fmt.Errorf("connector pool requires at least one connector")
	}

	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if candidate.ID == "" {
			return ConnectorPool{}, fmt.Errorf("connector pool contains an empty connector id")
		}
		if _, duplicate := seen[candidate.ID]; duplicate {
			return ConnectorPool{}, fmt.Errorf("connector pool contains duplicate connector %q", candidate.ID)
		}
		seen[candidate.ID] = struct{}{}
		if candidate.OrgID != orgID || candidate.SiteID != siteID {
			return ConnectorPool{}, fmt.Errorf("connector %q is outside the cluster org/site scope", candidate.ID)
		}
		if !candidate.eligible() {
			return ConnectorPool{}, fmt.Errorf("connector %q is not active, non-revoked, and WireGuard-ready", candidate.ID)
		}
	}
	if _, ok := seen[preferredID]; !ok {
		return ConnectorPool{}, fmt.Errorf("preferred connector %q is not in the pool", preferredID)
	}

	ordered := append([]ConnectorCandidate(nil), candidates...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].AdminPriority != ordered[j].AdminPriority {
			return ordered[i].AdminPriority > ordered[j].AdminPriority
		}
		return ordered[i].ID < ordered[j].ID
	})

	return ConnectorPool{
		OrgID:                 orgID,
		SiteID:                siteID,
		ClusterID:             clusterID,
		Candidates:            ordered,
		PreferredID:           preferredID,
		ActiveID:              preferredID,
		Generation:            1,
		CandidateHealthyTicks: make(map[string]int),
		VIPs:                  append([]string(nil), vips...),
	}, nil
}

// Reconcile applies one health tick without mutating its input. Candidate
// ordering is deterministic and all hysteresis is CP-owned. A transition here
// implies no scheduler activation, agent delivery, lease, fencing, or VIP move.
func Reconcile(pool ConnectorPool, health map[string]ConnectorHealth) Decision {
	next := clonePool(pool)
	if reason := invalidPoolReason(pool); reason != "" {
		return Decision{
			Pool:       next,
			Transition: NeedsAttention,
			FromID:     pool.ActiveID,
			ToID:       pool.ActiveID,
			Reason:     reason,
		}
	}

	active := candidate(pool, pool.ActiveID)
	preferred := candidate(pool, pool.PreferredID)
	activeHealthy := active.eligible() && health[active.ID].Healthy()

	if pool.ActiveID != pool.PreferredID {
		if preferred.eligible() && health[preferred.ID].Healthy() {
			next.PreferredFreshTicks++
		} else {
			next.PreferredFreshTicks = 0
		}
		if next.PreferredFreshTicks >= FailbackAfterFreshTicks {
			next.ActiveID = pool.PreferredID
			next.StaleTicks = 0
			next.PreferredFreshTicks = 0
			resetCandidateTicks(next.CandidateHealthyTicks)
			next.Generation++
			return Decision{
				Pool:       next,
				Transition: FailedBack,
				FromID:     pool.ActiveID,
				ToID:       next.ActiveID,
				Reason:     "preferred connector is healthy for the failback window",
			}
		}
	} else {
		next.PreferredFreshTicks = 0
	}

	if activeHealthy {
		next.StaleTicks = 0
		resetCandidateTicks(next.CandidateHealthyTicks)
		return Decision{
			Pool:       next,
			Transition: NoChange,
			FromID:     pool.ActiveID,
			ToID:       pool.ActiveID,
			Reason:     "active connector has current control/policy and endpoint-view health",
		}
	}

	next.StaleTicks++
	for _, standby := range pool.Candidates {
		if standby.ID == pool.ActiveID || standby.ID == pool.PreferredID {
			continue
		}
		if standby.eligible() && health[standby.ID].Healthy() {
			next.CandidateHealthyTicks[standby.ID]++
		} else {
			next.CandidateHealthyTicks[standby.ID] = 0
		}
	}
	if next.StaleTicks < PromoteAfterStaleTicks {
		return Decision{
			Pool:       next,
			Transition: NoChange,
			FromID:     pool.ActiveID,
			ToID:       pool.ActiveID,
			Reason:     "active connector has not crossed the stale threshold",
		}
	}

	for _, standby := range pool.Candidates {
		// Preferred has a separate five-tick failback contract and must never
		// enter the generic three-tick promotion path.
		if standby.ID == pool.ActiveID || standby.ID == pool.PreferredID ||
			!standby.eligible() || next.CandidateHealthyTicks[standby.ID] < PromoteAfterStaleTicks {
			continue
		}
		next.ActiveID = standby.ID
		next.StaleTicks = 0
		next.PreferredFreshTicks = 0
		resetCandidateTicks(next.CandidateHealthyTicks)
		next.Generation++
		return Decision{
			Pool:       next,
			Transition: Promoted,
			FromID:     pool.ActiveID,
			ToID:       standby.ID,
			Reason:     "active connector crossed the stale threshold; selected the highest-ranked healthy standby",
		}
	}

	return Decision{
		Pool:       next,
		Transition: NeedsAttention,
		FromID:     pool.ActiveID,
		ToID:       pool.ActiveID,
		Reason:     "active connector is stale and no eligible healthy standby exists",
	}
}

func invalidPoolReason(pool ConnectorPool) string {
	if pool.OrgID == "" || pool.SiteID == "" || pool.ClusterID == "" || pool.Generation == 0 {
		return "connector pool identity or generation is invalid"
	}
	seen := make(map[string]struct{}, len(pool.Candidates))
	for _, member := range pool.Candidates {
		if member.ID == "" || member.OrgID != pool.OrgID || member.SiteID != pool.SiteID {
			return "connector pool contains an invalid or cross-scope member"
		}
		if _, duplicate := seen[member.ID]; duplicate {
			return "connector pool contains duplicate members"
		}
		seen[member.ID] = struct{}{}
	}
	if _, ok := seen[pool.PreferredID]; !ok {
		return "preferred connector is not a pool member"
	}
	if _, ok := seen[pool.ActiveID]; !ok {
		return "active connector is not a pool member"
	}
	return ""
}

func candidate(pool ConnectorPool, id string) ConnectorCandidate {
	for _, member := range pool.Candidates {
		if member.ID == id {
			return member
		}
	}
	return ConnectorCandidate{}
}

func clonePool(pool ConnectorPool) ConnectorPool {
	pool.Candidates = append([]ConnectorCandidate(nil), pool.Candidates...)
	pool.CandidateHealthyTicks = cloneTicks(pool.CandidateHealthyTicks)
	pool.VIPs = append([]string(nil), pool.VIPs...)
	return pool
}

func cloneTicks(in map[string]int) map[string]int {
	out := make(map[string]int, len(in))
	for id, ticks := range in {
		out[id] = ticks
	}
	return out
}

func resetCandidateTicks(ticks map[string]int) {
	for id := range ticks {
		ticks[id] = 0
	}
}
