package nodes

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/leader"
)

func TestHandoffSchedulerServerRuntimeDefaultOffIsInert(t *testing.T) {
	runtime := NewHandoffSchedulerServerRuntime(HandoffSchedulerServerConfig{}, HandoffSchedulerServerDependencies{})
	if status := runtime.Status(); status.State != HandoffSchedulerDisabled || len(status.Reasons) != 0 {
		t.Fatalf("default status=%+v", status)
	}
	if status := runtime.Start(context.Background()); status.State != HandoffSchedulerDisabled {
		t.Fatalf("default start=%+v", status)
	}
	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestHandoffSchedulerServerRuntimeRefusesPartialDependencies(t *testing.T) {
	p := &pgxpool.Pool{}
	runtime := NewHandoffSchedulerServerRuntime(HandoffSchedulerServerConfig{
		Enabled: true, Cadence: 5 * time.Second, PerTickTimeout: time.Second, MaxBackoff: time.Minute,
		LeaderProbeInterval: time.Second, StopTimeout: time.Second, SerialBatchSize: 1,
	}, HandoffSchedulerServerDependencies{Pool: p, Elector: &leader.Elector{}})
	status := runtime.Status()
	if status.State != HandoffSchedulerBlocked || !hasHandoffSchedulerReason(status, HandoffSchedulerTickSourceMissing) ||
		!hasHandoffSchedulerReason(status, HandoffSchedulerP2IssuerMissing) || !hasHandoffSchedulerReason(status, HandoffSchedulerP2AttestationReaderMissing) {
		t.Fatalf("partial runtime status=%+v", status)
	}
	if started := runtime.Start(context.Background()); started.State != HandoffSchedulerBlocked || runtime.activation.Running() {
		t.Fatalf("partial runtime started: status=%+v running=%t", started, runtime.activation.Running())
	}
}

func TestHandoffSchedulerServerRuntimeLeadershipFailsClosed(t *testing.T) {
	p := &pgxpool.Pool{}
	runtime := NewHandoffSchedulerServerRuntime(HandoffSchedulerServerConfig{}, HandoffSchedulerServerDependencies{Pool: p, Elector: &leader.Elector{}})
	state, err := runtime.HandoffOperatorLeadership(context.Background())
	if err != nil || !state.Confirmed || state.Leader {
		t.Fatalf("follower leadership=%+v err=%v", state, err)
	}
	if _, err := (*HandoffSchedulerServerRuntime)(nil).HandoffOperatorLeadership(context.Background()); err == nil {
		t.Fatal("nil runtime leadership was accepted")
	}
}
