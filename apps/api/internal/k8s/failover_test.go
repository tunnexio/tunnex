package k8s

import "testing"

func makeCandidate(id string, priority int) ConnectorCandidate {
	return ConnectorCandidate{
		ID:            id,
		OrgID:         "org",
		SiteID:        "site",
		AdminPriority: priority,
		Active:        true,
		EndpointReady: true,
	}
}

func healthy(ids ...string) map[string]ConnectorHealth {
	out := make(map[string]ConnectorHealth, len(ids))
	for _, id := range ids {
		out[id] = ConnectorHealth{ControlHealthy: true, DataHealthy: true}
	}
	return out
}

func newTestPool(t *testing.T, candidates ...ConnectorCandidate) ConnectorPool {
	t.Helper()
	pool, err := NewConnectorPool("org", "site", "cluster", "primary", candidates, []string{"100.64.0.3/32"})
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestReconcilePromotesDeterministicHealthyStandbyAfterThreeStaleTicks(t *testing.T) {
	pool := newTestPool(t,
		makeCandidate("standby-b", 1),
		makeCandidate("primary", 10),
		makeCandidate("standby-a", 1),
	)
	health := healthy("standby-a", "standby-b")
	for tick := 1; tick < PromoteAfterStaleTicks; tick++ {
		decision := Reconcile(pool, health)
		if decision.Transition != NoChange || decision.Pool.ActiveID != "primary" {
			t.Fatalf("tick %d: premature transition: %+v", tick, decision)
		}
		pool = decision.Pool
	}
	decision := Reconcile(pool, health)
	if decision.Transition != Promoted || decision.Pool.ActiveID != "standby-a" {
		t.Fatalf("promotion must choose UUID-ordered standby-a: %+v", decision)
	}
	if decision.Pool.Generation != 2 || len(decision.Pool.VIPs) != 1 || decision.Pool.VIPs[0] != "100.64.0.3/32" {
		t.Fatalf("promotion must preserve generation and VIP identity: %+v", decision.Pool)
	}
}

func TestReconcileDoesNotPreAccumulateStandbyHealthWhileActiveIsHealthy(t *testing.T) {
	pool := newTestPool(t, makeCandidate("primary", 10), makeCandidate("standby", 1))
	for tick := 0; tick < PromoteAfterStaleTicks+2; tick++ {
		pool = Reconcile(pool, healthy("primary", "standby")).Pool
	}
	for tick := 1; tick < PromoteAfterStaleTicks; tick++ {
		decision := Reconcile(pool, healthy("standby"))
		if decision.Transition != NoChange {
			t.Fatalf("stale tick %d reused pre-stale standby evidence: %+v", tick, decision)
		}
		pool = decision.Pool
	}
	decision := Reconcile(pool, healthy("standby"))
	if decision.Transition != Promoted {
		t.Fatalf("standby must promote only after three healthy ticks while active is stale: %+v", decision)
	}
}

func TestReconcileNeverUsesThreeTickPromotionToBypassFailback(t *testing.T) {
	pool := newTestPool(t, makeCandidate("primary", 10), makeCandidate("standby", 1))
	pool.ActiveID = "standby"
	for tick := 1; tick <= FailbackAfterFreshTicks; tick++ {
		decision := Reconcile(pool, healthy("primary"))
		pool = decision.Pool
		if tick < FailbackAfterFreshTicks && (decision.Transition == FailedBack || decision.Pool.ActiveID != "standby") {
			t.Fatalf("preferred connector bypassed the failback window at tick %d: %+v", tick, decision)
		}
		if tick == FailbackAfterFreshTicks && (decision.Transition != FailedBack || decision.Pool.ActiveID != "primary") {
			t.Fatalf("preferred connector must fail back exactly at tick five: %+v", decision)
		}
	}
}

func TestReconcileRequiresConsecutiveStandbyHealth(t *testing.T) {
	pool := newTestPool(t, makeCandidate("primary", 10), makeCandidate("standby", 1))
	observations := []map[string]ConnectorHealth{
		healthy("standby"),
		{},
		healthy("standby"),
		healthy("standby"),
		healthy("standby"),
	}
	for index, observation := range observations {
		decision := Reconcile(pool, observation)
		pool = decision.Pool
		if index < len(observations)-1 && decision.Transition == Promoted {
			t.Fatalf("standby promoted before three post-reset healthy ticks: %+v", decision)
		}
		if index == len(observations)-1 && (decision.Transition != Promoted || decision.Pool.ActiveID != "standby") {
			t.Fatalf("standby should promote after the reset streak reaches three: %+v", decision)
		}
	}
}

func TestReconcileRequiresBothCurrentHealthSignals(t *testing.T) {
	tests := []struct {
		name   string
		health ConnectorHealth
	}{
		{name: "missing both"},
		{name: "control only", health: ConnectorHealth{ControlHealthy: true}},
		{name: "endpoint view only", health: ConnectorHealth{DataHealthy: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pool := newTestPool(t, makeCandidate("primary", 10), makeCandidate("standby", 1))
			var decision Decision
			for tick := 0; tick < PromoteAfterStaleTicks; tick++ {
				decision = Reconcile(pool, map[string]ConnectorHealth{"standby": test.health})
				pool = decision.Pool
			}
			if decision.Transition != NeedsAttention || decision.Pool.ActiveID != "primary" {
				t.Fatalf("partial or missing evidence must fail closed: %+v", decision)
			}
		})
	}
}

func TestReconcileFailsBackOnlyAfterFivePreferredHealthyTicks(t *testing.T) {
	pool := newTestPool(t, makeCandidate("primary", 10), makeCandidate("standby", 1))
	pool.ActiveID = "standby"
	pool.Generation = 2
	for tick := 1; tick < FailbackAfterFreshTicks; tick++ {
		decision := Reconcile(pool, healthy("primary", "standby"))
		if decision.Transition != NoChange {
			t.Fatalf("tick %d: failback must wait for full stability window: %+v", tick, decision)
		}
		pool = decision.Pool
	}
	decision := Reconcile(pool, healthy("primary", "standby"))
	if decision.Transition != FailedBack || decision.Pool.ActiveID != "primary" || decision.Pool.Generation != 3 {
		t.Fatalf("expected controlled failback: %+v", decision)
	}
}

func TestNewConnectorPoolRejectsInvalidCandidates(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ConnectorCandidate)
	}{
		{name: "cross org", mutate: func(candidate *ConnectorCandidate) { candidate.OrgID = "other-org" }},
		{name: "cross site", mutate: func(candidate *ConnectorCandidate) { candidate.SiteID = "other-site" }},
		{name: "inactive", mutate: func(candidate *ConnectorCandidate) { candidate.Active = false }},
		{name: "revoked", mutate: func(candidate *ConnectorCandidate) { candidate.Revoked = true }},
		{name: "wireguard unready", mutate: func(candidate *ConnectorCandidate) { candidate.EndpointReady = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			standby := makeCandidate("standby", 1)
			test.mutate(&standby)
			if _, err := NewConnectorPool("org", "site", "cluster", "primary", []ConnectorCandidate{makeCandidate("primary", 10), standby}, nil); err == nil {
				t.Fatal("invalid candidate must be rejected before entering the pool")
			}
		})
	}
}

func TestReconcileFailsClosedOnInvalidPoolScope(t *testing.T) {
	pool := newTestPool(t, makeCandidate("primary", 10), makeCandidate("standby", 1))
	pool.Candidates[1].SiteID = "other-site"
	decision := Reconcile(pool, healthy("standby"))
	if decision.Transition != NeedsAttention || decision.Pool.ActiveID != "primary" || decision.Pool.Generation != 1 {
		t.Fatalf("cross-scope retained state must not transition: %+v", decision)
	}
}

func TestReconcileDoesNotMutateInput(t *testing.T) {
	pool := newTestPool(t, makeCandidate("primary", 10), makeCandidate("standby", 1))
	pool.CandidateHealthyTicks["standby"] = 1
	decision := Reconcile(pool, healthy("standby"))
	decision.Pool.Candidates[0].AdminPriority = 99
	decision.Pool.CandidateHealthyTicks["standby"] = 99
	decision.Pool.VIPs[0] = "changed"
	if pool.Candidates[0].AdminPriority == 99 || pool.CandidateHealthyTicks["standby"] == 99 || pool.VIPs[0] == "changed" {
		t.Fatal("reconcile result aliases mutable input state")
	}
}
