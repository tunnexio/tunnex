package nodes

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/leader"
)

// HandoffSchedulerServerConfig is the composition-root projection of the
// validated default-off config. It deliberately contains no environment or
// P2 protocol detail; main owns parsing and must validate it before calling
// this constructor.
type HandoffSchedulerServerConfig struct {
	Enabled             bool
	Cadence             time.Duration
	PerTickTimeout      time.Duration
	MaxBackoff          time.Duration
	LeaderProbeInterval time.Duration
	StopTimeout         time.Duration
	SerialBatchSize     int
}

// HandoffSchedulerServerDependencies are deliberately prebuilt. Supplying a
// partial set is safe but blocked; no loop can start from it.
type HandoffSchedulerServerDependencies struct {
	Pool                *pgxpool.Pool
	Elector             *leader.Elector
	HealthObserver      *PostgresHandoffHealthHistory
	MigrationGate       *PostgresHandoffSchedulerMigrationGate
	TickSource          *PostgresHandoffTickSource
	P2Issuer            k8s.P2HandoffDeliveryIssuer
	P2Reader            k8s.P2HandoffAttestationReader
	OperationProvenance k8s.HandoffOperationProvenanceFence
	CoordinatorService  *k8s.Service
}

// HandoffSchedulerServerRuntime owns the future server lifecycle boundary.
// Construction has no database reads or goroutines. Start delegates to the
// leader-aware lifecycle, which keeps followers from invoking the source and
// fences every mutating scheduler call on the exact leader session.
type HandoffSchedulerServerRuntime struct {
	activation *HandoffSchedulerActivation
	lifecycle  *HandoffSchedulerLeaderLifecycle
	elector    *leader.Elector
	pool       *pgxpool.Pool
}

func NewHandoffSchedulerServerRuntime(config HandoffSchedulerServerConfig, deps HandoffSchedulerServerDependencies) *HandoffSchedulerServerRuntime {
	timing := HandoffSchedulerTiming{Cadence: config.Cadence, PerTickTimeout: config.PerTickTimeout, MaxBackoff: config.MaxBackoff, SerialBatchSize: config.SerialBatchSize}
	activation := NewHandoffSchedulerActivation(HandoffSchedulerActivationConfig{
		Enabled: config.Enabled, Pool: deps.Pool, Elector: deps.Elector, HealthObserver: deps.HealthObserver, MigrationGate: deps.MigrationGate,
		TickSource: deps.TickSource, P2Issuer: deps.P2Issuer, P2Reader: deps.P2Reader, OperationProvenance: deps.OperationProvenance, CoordinatorService: deps.CoordinatorService, Timing: timing,
	})
	lifecycle := NewHandoffSchedulerLeaderLifecycle(HandoffSchedulerLeaderLifecycleConfig{
		Enabled: config.Enabled, Activation: activation, Leader: PostgresHandoffSchedulerLeaderProbe{Elector: deps.Elector, Pool: deps.Pool},
		Timing: HandoffSchedulerLeadershipTiming{ProbeInterval: config.LeaderProbeInterval, StopTimeout: config.StopTimeout},
	})
	return &HandoffSchedulerServerRuntime{activation: activation, lifecycle: lifecycle, elector: deps.Elector, pool: deps.Pool}
}

func (r *HandoffSchedulerServerRuntime) Status() HandoffSchedulerFeatureStatus {
	if r == nil || r.lifecycle == nil {
		return HandoffSchedulerFeatureStatus{State: HandoffSchedulerBlocked, Reasons: []HandoffSchedulerBlockReason{HandoffSchedulerConstructionFailed}}
	}
	return r.lifecycle.Status()
}

func (r *HandoffSchedulerServerRuntime) Start(ctx context.Context) HandoffSchedulerFeatureStatus {
	if r == nil || r.lifecycle == nil {
		return HandoffSchedulerFeatureStatus{State: HandoffSchedulerBlocked, Reasons: []HandoffSchedulerBlockReason{HandoffSchedulerConstructionFailed}}
	}
	return r.lifecycle.Start(ctx)
}

func (r *HandoffSchedulerServerRuntime) Stop(ctx context.Context) error {
	if r == nil || r.lifecycle == nil {
		return nil
	}
	return r.lifecycle.Stop(ctx)
}

// HandoffOperatorLeadership supplies a redacted local leadership view. A
// stale local leader bit is never emitted as leader: only PostgreSQL
// confirmation proves leadership; a local follower is a normal state.
func (r *HandoffSchedulerServerRuntime) HandoffOperatorLeadership(ctx context.Context) (HandoffOperatorLeadership, error) {
	if r == nil || r.elector == nil || r.pool == nil || ctx == nil {
		return HandoffOperatorLeadership{}, errors.New("handoff operator leadership unavailable")
	}
	if !r.elector.IsLeader() {
		return HandoffOperatorLeadership{Confirmed: true}, nil
	}
	if !r.elector.ConfirmLeader(ctx, r.pool) {
		return HandoffOperatorLeadership{}, nil
	}
	return HandoffOperatorLeadership{Confirmed: true, Leader: true}, nil
}

var _ interface {
	Status() HandoffSchedulerFeatureStatus
} = (*HandoffSchedulerServerRuntime)(nil)
