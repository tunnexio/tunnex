package appaccess

import (
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"testing"
)

func TestAppEventBufferBoundsAndTenantIsolation(t *testing.T) {
	p := &EventProducer{queue: make(chan Event, 1024), stop: make(chan struct{}), tenantCounts: make(map[uuid.UUID][3]uint64)}
	a, b := uuid.New(), uuid.New()
	e := Event{OrgID: a, AppID: uuid.New(), InstallationGeneration: uuid.New(), Kind: "request_allowed", Outcome: "allowed", Reason: "none"}
	for i := 0; i < 1025; i++ {
		p.Emit(e)
	}
	if len(p.queue) != 1024 || p.dropped.Load() != 1 {
		t.Fatal("telemetry buffer did not remain bounded")
	}
	counts, available := p.TenantCounts(a)
	if !available || counts[1] != 1 {
		t.Fatal("tenant drop counter unavailable")
	}
	if _, available := p.TenantCounts(b); available {
		t.Fatal("another tenant observed activity")
	}
	e.Reason = "cookie=secret"
	p.Emit(e)
	if p.dropped.Load() != 2 {
		t.Fatal("unbounded reason was accepted")
	}
	for i := 0; i < 1024; i++ {
		p.tenantCount(uuid.New(), 0)
	}
	if len(p.tenantCounts) != 1024 {
		t.Fatal("tenant counters exceeded their bound")
	}
	if _, ok := p.TenantCounts(uuid.New()); ok {
		t.Fatal("unknown tenant counters fabricated")
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(p)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		for _, metric := range family.Metric {
			if len(metric.Label) != 0 {
				t.Fatal("operator metrics leaked tenant labels")
			}
		}
	}
}
