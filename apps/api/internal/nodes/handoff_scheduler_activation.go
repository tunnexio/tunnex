package nodes

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/leader"
)

// HandoffSchedulerFeatureState is a local composition status only. It does
// not register an API, read an environment variable, or start the scheduler.
type HandoffSchedulerFeatureState string

const (
	HandoffSchedulerDisabled HandoffSchedulerFeatureState = "disabled"
	HandoffSchedulerBlocked  HandoffSchedulerFeatureState = "blocked"
	HandoffSchedulerReady    HandoffSchedulerFeatureState = "ready"
)

// HandoffSchedulerBlockReason is intentionally a small, non-sensitive code
// set suitable for a future operator-status projection. It never exposes DSNs,
// node IDs, P2 identities, or dependency error text.
type HandoffSchedulerBlockReason string

const (
	HandoffSchedulerPostgresPoolMissing        HandoffSchedulerBlockReason = "postgres_pool_missing"
	HandoffSchedulerLeaderElectorMissing       HandoffSchedulerBlockReason = "leader_elector_missing"
	HandoffSchedulerHealthObserverMissing      HandoffSchedulerBlockReason = "health_observer_missing"
	HandoffSchedulerHealthObserverInvalid      HandoffSchedulerBlockReason = "health_observer_invalid"
	HandoffSchedulerMigrationStateInvalid      HandoffSchedulerBlockReason = "migration_state_invalid"
	HandoffSchedulerTickSourceMissing          HandoffSchedulerBlockReason = "tick_source_missing"
	HandoffSchedulerTickSourceInvalid          HandoffSchedulerBlockReason = "tick_source_invalid"
	HandoffSchedulerP2IssuerMissing            HandoffSchedulerBlockReason = "p2_issuer_missing"
	HandoffSchedulerP2AttestationReaderMissing HandoffSchedulerBlockReason = "p2_attestation_reader_missing"
	HandoffSchedulerOperationProvenanceMissing HandoffSchedulerBlockReason = "operation_provenance_missing"
	HandoffSchedulerCoordinatorServiceMissing  HandoffSchedulerBlockReason = "coordinator_service_missing"
	HandoffSchedulerCoordinatorServiceInvalid  HandoffSchedulerBlockReason = "coordinator_service_invalid"
	HandoffSchedulerTimingInvalid              HandoffSchedulerBlockReason = "timing_invalid"
	HandoffSchedulerConstructionFailed         HandoffSchedulerBlockReason = "construction_failed"
)

type HandoffSchedulerFeatureStatus struct {
	State   HandoffSchedulerFeatureState
	Reasons []HandoffSchedulerBlockReason
}

func (s HandoffSchedulerFeatureStatus) copy() HandoffSchedulerFeatureStatus {
	s.Reasons = append([]HandoffSchedulerBlockReason(nil), s.Reasons...)
	return s
}

// HandoffSchedulerTiming is deliberately validated rather than normalized.
// An enabled HA scheduler must reject an unsafe operator value instead of
// quietly changing the requested cadence or deadline.
type HandoffSchedulerTiming struct {
	Cadence         time.Duration
	MaxBackoff      time.Duration
	PerTickTimeout  time.Duration
	SerialBatchSize int
}

const (
	minHandoffSchedulerCadence = time.Second
	maxHandoffSchedulerCadence = 15 * time.Minute
	maxHandoffSchedulerBackoff = time.Hour
	minHandoffSchedulerTimeout = 100 * time.Millisecond
	maxHandoffSchedulerTimeout = 30 * time.Second
	minHandoffSchedulerBatch   = 1
	maxHandoffSchedulerBatch   = 256
)

func (t HandoffSchedulerTiming) valid() bool {
	return t.Cadence >= minHandoffSchedulerCadence && t.Cadence <= maxHandoffSchedulerCadence &&
		t.MaxBackoff >= t.Cadence && t.MaxBackoff <= maxHandoffSchedulerBackoff &&
		t.PerTickTimeout >= minHandoffSchedulerTimeout && t.PerTickTimeout <= maxHandoffSchedulerTimeout &&
		t.PerTickTimeout <= t.Cadence &&
		t.SerialBatchSize >= minHandoffSchedulerBatch && t.SerialBatchSize <= maxHandoffSchedulerBatch
}

func (t HandoffSchedulerTiming) schedulerConfig() k8s.HandoffSchedulerConfig {
	return k8s.HandoffSchedulerConfig{Cadence: t.Cadence, MaxBackoff: t.MaxBackoff, PerTickTimeout: t.PerTickTimeout, SerialBatchSize: t.SerialBatchSize}
}

// PostgresHandoffSchedulerMigrationGate verifies the durable P2 prerequisites
// before an enabled scheduler is permitted to start its first loop. It binds
// to the exact pool used by the observer, source, and coordinator. Version
// 0134 is the first schema with both the exact v3 delivery/P3 ledgers and the
// authority-kind discriminator consumed by the scheduler's transition reads.
// Earlier schemas remain compatible for ordinary traffic but can never
// authorize this scheduler.
type PostgresHandoffSchedulerMigrationGate struct {
	pool  *pgxpool.Pool
	check func(context.Context, *pgxpool.Pool) bool // deterministic package-test seam
}

const minHandoffSchedulerSchemaVersion int64 = 134

func NewPostgresHandoffSchedulerMigrationGate(pool *pgxpool.Pool) *PostgresHandoffSchedulerMigrationGate {
	return &PostgresHandoffSchedulerMigrationGate{pool: pool}
}

func (g *PostgresHandoffSchedulerMigrationGate) handoffSchedulerActivationReady(pool *pgxpool.Pool) bool {
	return g != nil && pool != nil && g.pool == pool
}

func (g *PostgresHandoffSchedulerMigrationGate) ready(ctx context.Context) bool {
	if g == nil || g.pool == nil || ctx == nil {
		return false
	}
	if g.check != nil {
		return g.check(ctx, g.pool)
	}
	var version int64
	var dirty bool
	if err := g.pool.QueryRow(ctx, "SELECT version, dirty FROM schema_migrations LIMIT 1").Scan(&version, &dirty); err != nil {
		return false
	}
	return !dirty && version >= minHandoffSchedulerSchemaVersion
}

// HandoffSchedulerActivationConfig is intentionally explicit. The future
// composition root must construct all CP/P2 dependencies before setting
// Enabled; this package supplies no fallback transport, receipt reader, or
// partial tick source that could look healthy.
type HandoffSchedulerActivationConfig struct {
	Enabled bool

	Pool                *pgxpool.Pool
	Elector             *leader.Elector
	HealthObserver      *PostgresHandoffHealthHistory
	MigrationGate       *PostgresHandoffSchedulerMigrationGate
	TickSource          *PostgresHandoffTickSource
	P2Issuer            k8s.P2HandoffDeliveryIssuer
	P2Reader            k8s.P2HandoffAttestationReader
	OperationProvenance k8s.HandoffOperationProvenanceFence
	CoordinatorService  *k8s.Service
	Timing              HandoffSchedulerTiming
}

type handoffSchedulerLoop interface {
	Run(context.Context)
}

type handoffSchedulerFactory func(k8s.HandoffTickSource, k8s.HandoffTickRunner, k8s.LeaderHandoffFence, k8s.HandoffSchedulerConfig) (handoffSchedulerLoop, error)

// HandoffSchedulerActivation owns at most one local scheduler Run loop. It
// does not start leader election: the existing composition root owns the
// elector lifecycle and this future opt-in merely consumes its fenced session.
type HandoffSchedulerActivation struct {
	mu          sync.Mutex
	status      HandoffSchedulerFeatureStatus
	loop        handoffSchedulerLoop
	gate        *PostgresHandoffSchedulerMigrationGate
	gateTimeout time.Duration
	cancel      context.CancelFunc
	done        chan struct{}
}

func NewHandoffSchedulerActivation(config HandoffSchedulerActivationConfig) *HandoffSchedulerActivation {
	return newHandoffSchedulerActivation(config, productionHandoffSchedulerFactory)
}

func newHandoffSchedulerActivation(config HandoffSchedulerActivationConfig, factory handoffSchedulerFactory) (activation *HandoffSchedulerActivation) {
	activation = &HandoffSchedulerActivation{}
	if !config.Enabled {
		activation.status = HandoffSchedulerFeatureStatus{State: HandoffSchedulerDisabled}
		return activation
	}
	if reasons := handoffSchedulerBlockReasons(config); len(reasons) != 0 {
		activation.status = HandoffSchedulerFeatureStatus{State: HandoffSchedulerBlocked, Reasons: reasons}
		return activation
	}

	loop, err := safelyBuildHandoffScheduler(factory, config)
	if err != nil || loop == nil {
		activation.status = HandoffSchedulerFeatureStatus{State: HandoffSchedulerBlocked, Reasons: []HandoffSchedulerBlockReason{HandoffSchedulerConstructionFailed}}
		return activation
	}
	activation.loop = loop
	activation.gate = config.MigrationGate
	activation.gateTimeout = config.Timing.PerTickTimeout
	activation.status = HandoffSchedulerFeatureStatus{State: HandoffSchedulerReady}
	return activation
}

func handoffSchedulerBlockReasons(config HandoffSchedulerActivationConfig) []HandoffSchedulerBlockReason {
	reasons := make([]HandoffSchedulerBlockReason, 0, 8)
	if config.Pool == nil {
		reasons = append(reasons, HandoffSchedulerPostgresPoolMissing)
	}
	if config.Elector == nil {
		reasons = append(reasons, HandoffSchedulerLeaderElectorMissing)
	}
	if config.HealthObserver == nil {
		reasons = append(reasons, HandoffSchedulerHealthObserverMissing)
	} else if !config.HealthObserver.handoffSchedulerActivationReady(config.Pool) {
		reasons = append(reasons, HandoffSchedulerHealthObserverInvalid)
	}
	if config.MigrationGate == nil || !config.MigrationGate.handoffSchedulerActivationReady(config.Pool) {
		reasons = append(reasons, HandoffSchedulerMigrationStateInvalid)
	}
	if config.TickSource == nil {
		reasons = append(reasons, HandoffSchedulerTickSourceMissing)
	} else if !config.TickSource.handoffSchedulerActivationReady(config.Pool, config.HealthObserver) {
		reasons = append(reasons, HandoffSchedulerTickSourceInvalid)
	}
	if !handoffActivationDependencyPresent(config.P2Issuer) {
		reasons = append(reasons, HandoffSchedulerP2IssuerMissing)
	}
	boundReader, leaderBound := config.P2Reader.(k8s.P2HandoffLeaderBoundAttestationReader)
	if !handoffActivationDependencyPresent(config.P2Reader) || !leaderBound || !handoffActivationDependencyPresent(boundReader) {
		reasons = append(reasons, HandoffSchedulerP2AttestationReaderMissing)
	}
	if !handoffActivationDependencyPresent(config.OperationProvenance) {
		reasons = append(reasons, HandoffSchedulerOperationProvenanceMissing)
	}
	if config.CoordinatorService == nil {
		reasons = append(reasons, HandoffSchedulerCoordinatorServiceMissing)
	} else if !config.CoordinatorService.HandoffCoordinatorServiceReady(config.Pool) {
		reasons = append(reasons, HandoffSchedulerCoordinatorServiceInvalid)
	}
	if !config.Timing.valid() {
		reasons = append(reasons, HandoffSchedulerTimingInvalid)
	}
	return reasons
}

func safelyBuildHandoffScheduler(factory handoffSchedulerFactory, config HandoffSchedulerActivationConfig) (loop handoffSchedulerLoop, err error) {
	defer func() {
		if recover() != nil {
			loop = nil
			err = errors.New("handoff scheduler construction panicked")
		}
	}()
	if factory == nil {
		return nil, errors.New("handoff scheduler factory is unavailable")
	}
	adapter := k8s.NewP2HandoffAdapter(config.P2Issuer, config.P2Reader)
	coordinator := k8s.NewHandoffCoordinator(config.CoordinatorService, adapter).WithHandoffOperationProvenanceFence(config.OperationProvenance)
	runner := newP2AttestingHandoffRunner(coordinator, adapter)
	fence := k8s.LeaderHandoffFence{Elector: config.Elector, Pool: config.Pool}
	return factory(config.TickSource, runner, fence, config.Timing.schedulerConfig())
}

func productionHandoffSchedulerFactory(source k8s.HandoffTickSource, runner k8s.HandoffTickRunner, fence k8s.LeaderHandoffFence, config k8s.HandoffSchedulerConfig) (handoffSchedulerLoop, error) {
	return k8s.NewHandoffScheduler(source, runner, fence, config), nil
}

func handoffActivationDependencyPresent(value any) bool {
	if value == nil {
		return false
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !v.IsNil()
	default:
		return true
	}
}

func (a *HandoffSchedulerActivation) Status() HandoffSchedulerFeatureStatus {
	if a == nil {
		return HandoffSchedulerFeatureStatus{State: HandoffSchedulerBlocked, Reasons: []HandoffSchedulerBlockReason{HandoffSchedulerConstructionFailed}}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.status.copy()
}

// Start is idempotent. It starts one scheduler loop only when construction was
// ready; disabled and blocked configurations perform no read, write, or
// goroutine creation. A cancelled parent does not start a transient loop.
func (a *HandoffSchedulerActivation) Start(parent context.Context) HandoffSchedulerFeatureStatus {
	if a == nil || parent == nil {
		return HandoffSchedulerFeatureStatus{State: HandoffSchedulerBlocked, Reasons: []HandoffSchedulerBlockReason{HandoffSchedulerConstructionFailed}}
	}
	a.mu.Lock()
	if a.status.State != HandoffSchedulerReady || a.loop == nil || a.done != nil || parent.Err() != nil {
		status := a.status.copy()
		a.mu.Unlock()
		return status
	}
	gate := a.gate
	gateTimeout := a.gateTimeout
	a.mu.Unlock()
	// This read is performed only for an enabled, structurally complete
	// activation immediately before the loop starts. Dirty or incomplete
	// durable state blocks without starting an inert-looking scheduler.
	gateCtx, cancelGate := context.WithTimeout(parent, gateTimeout)
	ready := gate.ready(gateCtx)
	cancelGate()
	if !ready {
		a.mu.Lock()
		if a.done == nil {
			a.status = HandoffSchedulerFeatureStatus{State: HandoffSchedulerBlocked, Reasons: []HandoffSchedulerBlockReason{HandoffSchedulerMigrationStateInvalid}}
		}
		status := a.status.copy()
		a.mu.Unlock()
		return status
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.status.State != HandoffSchedulerReady || a.loop == nil || a.done != nil || parent.Err() != nil {
		return a.status.copy()
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	a.cancel, a.done = cancel, done
	go func(loop handoffSchedulerLoop, done chan struct{}) {
		defer close(done)
		loop.Run(ctx)
		a.mu.Lock()
		if a.done == done {
			a.cancel = nil
			a.done = nil
		}
		a.mu.Unlock()
	}(a.loop, done)
	return a.status.copy()
}

// Stop is safe before Start and waits for an in-flight scheduler loop to exit.
// It does not mutate the configured feature status, so a future composition
// root can inspect why an activation was blocked after shutdown.
func (a *HandoffSchedulerActivation) Stop(ctx context.Context) error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	cancel, done := a.cancel, a.done
	a.mu.Unlock()
	if cancel == nil || done == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// running is package-private lifecycle coordination only. It does not expose a
// scheduler readiness/health claim: it means exactly one local Run goroutine
// has not yet returned.
// Running reports only whether the local Run goroutine has not returned. It is
// lifecycle bookkeeping, not a health, readiness, or leadership claim.
func (a *HandoffSchedulerActivation) Running() bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.done != nil
}

func (a *HandoffSchedulerActivation) running() bool { return a.Running() }
