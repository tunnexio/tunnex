package nodes

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/leader"
)

func TestHandoffSchedulerActivationDisabledDoesNothing(t *testing.T) {
	config, issuer, reader := activationConfig()
	config.Enabled = false
	var factoryCalls atomic.Int32
	activation := newHandoffSchedulerActivation(config, func(k8s.HandoffTickSource, k8s.HandoffTickRunner, k8s.LeaderHandoffFence, k8s.HandoffSchedulerConfig) (handoffSchedulerLoop, error) {
		factoryCalls.Add(1)
		return nil, errors.New("must not construct while disabled")
	})
	if status := activation.Status(); status.State != HandoffSchedulerDisabled || len(status.Reasons) != 0 {
		t.Fatalf("disabled status=%+v", status)
	}
	if status := activation.Start(context.Background()); status.State != HandoffSchedulerDisabled {
		t.Fatalf("disabled start=%+v", status)
	}
	if err := activation.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if factoryCalls.Load() != 0 || issuer.calls.Load() != 0 || reader.calls.Load() != 0 {
		t.Fatalf("disabled activation constructed/read/wrote: factory=%d issuer=%d reader=%d", factoryCalls.Load(), issuer.calls.Load(), reader.calls.Load())
	}
}

func TestPostgresHandoffSchedulerMigrationGateRequires0130(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run scheduler migration-gate PostgreSQL proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	dsn := newOwnershipDeliveryIntegrationDatabase(t, ctx, admin)
	for _, version := range []int{85, 118, 119, 120, 122, 128, 129} {
		if err := db.MigrateTo(dsn, uint(version)); err != nil {
			t.Fatalf("migrate through %04d: %v", version, err)
		}
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		if (&PostgresHandoffSchedulerMigrationGate{pool: pool}).ready(ctx) {
			pool.Close()
			t.Fatalf("schema %04d must not enable the scheduler before 0130 delivery-kind authority", version)
		}
		pool.Close()
	}
	if err := db.MigrateTo(dsn, 130); err != nil {
		t.Fatalf("migrate through 0130: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if !(&PostgresHandoffSchedulerMigrationGate{pool: pool}).ready(ctx) {
		t.Fatal("clean schema 0130 must satisfy the scheduler migration gate")
	}
}

func TestHandoffSchedulerActivationBlocksMissingDependencies(t *testing.T) {
	tests := map[string]struct {
		mutate func(*HandoffSchedulerActivationConfig)
		want   HandoffSchedulerBlockReason
	}{
		"pool":     {func(c *HandoffSchedulerActivationConfig) { c.Pool = nil }, HandoffSchedulerPostgresPoolMissing},
		"elector":  {func(c *HandoffSchedulerActivationConfig) { c.Elector = nil }, HandoffSchedulerLeaderElectorMissing},
		"observer": {func(c *HandoffSchedulerActivationConfig) { c.HealthObserver = nil }, HandoffSchedulerHealthObserverMissing},
		"source":   {func(c *HandoffSchedulerActivationConfig) { c.TickSource = nil }, HandoffSchedulerTickSourceMissing},
		"issuer":   {func(c *HandoffSchedulerActivationConfig) { c.P2Issuer = nil }, HandoffSchedulerP2IssuerMissing},
		"reader":   {func(c *HandoffSchedulerActivationConfig) { c.P2Reader = nil }, HandoffSchedulerP2AttestationReaderMissing},
		"operation provenance": {func(c *HandoffSchedulerActivationConfig) {
			c.OperationProvenance = nil
		}, HandoffSchedulerOperationProvenanceMissing},
		"typed nil issuer": {func(c *HandoffSchedulerActivationConfig) {
			var issuer *activationIssuer
			c.P2Issuer = issuer
		}, HandoffSchedulerP2IssuerMissing},
		"typed nil reader": {func(c *HandoffSchedulerActivationConfig) {
			var reader *activationReader
			c.P2Reader = reader
		}, HandoffSchedulerP2AttestationReaderMissing},
		"unbound reader": {func(c *HandoffSchedulerActivationConfig) {
			c.P2Reader = activationUnboundReader{}
		}, HandoffSchedulerP2AttestationReaderMissing},
		"observer source mismatch": {func(c *HandoffSchedulerActivationConfig) {
			c.HealthObserver = NewPostgresHandoffHealthHistory(c.Pool, activationPolicy{}, time.Minute)
		}, HandoffSchedulerTickSourceInvalid},
		"service pool mismatch": {func(c *HandoffSchedulerActivationConfig) {
			c.CoordinatorService = k8s.NewService(&pgxpool.Pool{})
		}, HandoffSchedulerCoordinatorServiceInvalid},
		"service": {func(c *HandoffSchedulerActivationConfig) { c.CoordinatorService = nil }, HandoffSchedulerCoordinatorServiceMissing},
		"timing":  {func(c *HandoffSchedulerActivationConfig) { c.Timing.Cadence = 0 }, HandoffSchedulerTimingInvalid},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			config, _, _ := activationConfig()
			test.mutate(&config)
			var calls atomic.Int32
			activation := newHandoffSchedulerActivation(config, func(k8s.HandoffTickSource, k8s.HandoffTickRunner, k8s.LeaderHandoffFence, k8s.HandoffSchedulerConfig) (handoffSchedulerLoop, error) {
				calls.Add(1)
				return &activationLoop{}, nil
			})
			status := activation.Status()
			if status.State != HandoffSchedulerBlocked || !hasHandoffSchedulerReason(status, test.want) {
				t.Fatalf("missing %s status=%+v", name, status)
			}
			if calls.Load() != 0 {
				t.Fatalf("missing %s called constructor", name)
			}
			for _, reason := range status.Reasons {
				if reason == "" || len(reason) > 64 {
					t.Fatalf("status leaked non-code reason %q", reason)
				}
			}
		})
	}
}

func TestHandoffSchedulerActivationRejectsUnsafeTimingWithoutNormalization(t *testing.T) {
	for name, mutate := range map[string]func(*HandoffSchedulerTiming){
		"cadence too fast":        func(t *HandoffSchedulerTiming) { t.Cadence = minHandoffSchedulerCadence - time.Millisecond },
		"cadence too slow":        func(t *HandoffSchedulerTiming) { t.Cadence = maxHandoffSchedulerCadence + time.Second },
		"backoff below cadence":   func(t *HandoffSchedulerTiming) { t.MaxBackoff = t.Cadence - time.Millisecond },
		"backoff too large":       func(t *HandoffSchedulerTiming) { t.MaxBackoff = maxHandoffSchedulerBackoff + time.Second },
		"timeout too short":       func(t *HandoffSchedulerTiming) { t.PerTickTimeout = minHandoffSchedulerTimeout - time.Millisecond },
		"timeout too long":        func(t *HandoffSchedulerTiming) { t.PerTickTimeout = maxHandoffSchedulerTimeout + time.Second },
		"timeout exceeds cadence": func(t *HandoffSchedulerTiming) { t.PerTickTimeout = t.Cadence + time.Millisecond },
	} {
		t.Run(name, func(t *testing.T) {
			config, _, _ := activationConfig()
			original := config.Timing
			mutate(&config.Timing)
			activation := NewHandoffSchedulerActivation(config)
			if status := activation.Status(); status.State != HandoffSchedulerBlocked || !hasHandoffSchedulerReason(status, HandoffSchedulerTimingInvalid) {
				t.Fatalf("unsafe timing status=%+v", status)
			}
			if config.Timing == original {
				t.Fatal("test did not change timing")
			}
		})
	}
}

func TestHandoffSchedulerActivationConstructionFailuresStayBlocked(t *testing.T) {
	for name, factory := range map[string]handoffSchedulerFactory{
		"error": func(k8s.HandoffTickSource, k8s.HandoffTickRunner, k8s.LeaderHandoffFence, k8s.HandoffSchedulerConfig) (handoffSchedulerLoop, error) {
			return nil, errors.New("P2 secret must not surface")
		},
		"panic": func(k8s.HandoffTickSource, k8s.HandoffTickRunner, k8s.LeaderHandoffFence, k8s.HandoffSchedulerConfig) (handoffSchedulerLoop, error) {
			panic("unexpected constructor panic")
		},
	} {
		t.Run(name, func(t *testing.T) {
			config, _, _ := activationConfig()
			activation := newHandoffSchedulerActivation(config, factory)
			if status := activation.Status(); status.State != HandoffSchedulerBlocked || len(status.Reasons) != 1 || status.Reasons[0] != HandoffSchedulerConstructionFailed {
				t.Fatalf("construction failure status=%+v", status)
			}
			if status := activation.Start(context.Background()); status.State != HandoffSchedulerBlocked {
				t.Fatalf("construction failure started: %+v", status)
			}
		})
	}
}

func TestHandoffSchedulerActivationStartsOneLoopAndWaitsForShutdown(t *testing.T) {
	config, _, _ := activationConfig()
	loop := newActivationLoop()
	activation := newHandoffSchedulerActivation(config, activationFactory(loop))
	if status := activation.Status(); status.State != HandoffSchedulerReady {
		t.Fatalf("ready status=%+v", status)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if status := activation.Start(context.Background()); status.State != HandoffSchedulerReady {
				t.Errorf("start status=%+v", status)
			}
		}()
	}
	wg.Wait()
	select {
	case <-loop.started:
	case <-time.After(time.Second):
		t.Fatal("ready activation did not start loop")
	}
	if loop.runs.Load() != 1 {
		t.Fatalf("starts=%d, want exactly one", loop.runs.Load())
	}
	if err := activation.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-loop.exited:
	case <-time.After(time.Second):
		t.Fatal("Stop returned before loop exit")
	}
}

func TestHandoffSchedulerActivationShutdownBeforeStartAndFollowerReadFence(t *testing.T) {
	config, issuer, reader := activationConfig()
	activation := NewHandoffSchedulerActivation(config)
	if err := activation.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The zero-value elector is a follower. Tick must return before touching
	// the invalid test pool, which proves the lifecycle-built scheduler makes no
	// CP source read (and no P2 reader/issuer call) for followers.
	scheduler, ok := activation.loop.(*k8s.HandoffScheduler)
	if !ok {
		t.Fatalf("production activation loop=%T", activation.loop)
	}
	result := scheduler.Tick(context.Background())
	if !result.Follower || result.SourceError != nil || issuer.calls.Load() != 0 || reader.calls.Load() != 0 {
		t.Fatalf("follower touched source/P2: result=%+v issuer=%d reader=%d", result, issuer.calls.Load(), reader.calls.Load())
	}
}

func activationConfig() (HandoffSchedulerActivationConfig, *activationIssuer, *activationReader) {
	pool := &pgxpool.Pool{}
	policy := activationPolicy{}
	history := NewPostgresHandoffHealthHistory(pool, policy, time.Minute)
	source := NewPostgresHandoffTickSource(pool, policy, history, NewPostgresHandoffPlanResolver(pool, activationProvenance{}), HandoffTickSourceConfig{ReportFreshness: time.Minute, MaxAckAge: time.Minute, ClockSkewMargin: time.Second})
	issuer, reader := &activationIssuer{}, &activationReader{}
	return HandoffSchedulerActivationConfig{
		Enabled:             true,
		Pool:                pool,
		Elector:             &leader.Elector{},
		HealthObserver:      history,
		MigrationGate:       &PostgresHandoffSchedulerMigrationGate{pool: pool, check: func(context.Context, *pgxpool.Pool) bool { return true }},
		TickSource:          source,
		P2Issuer:            issuer,
		P2Reader:            reader,
		OperationProvenance: activationProvenance{},
		CoordinatorService:  k8s.NewService(pool),
		Timing:              HandoffSchedulerTiming{Cadence: 5 * time.Second, MaxBackoff: time.Minute, PerTickTimeout: 4 * time.Second, SerialBatchSize: 32},
	}, issuer, reader
}

func hasHandoffSchedulerReason(status HandoffSchedulerFeatureStatus, want HandoffSchedulerBlockReason) bool {
	for _, reason := range status.Reasons {
		if reason == want {
			return true
		}
	}
	return false
}

type activationLoop struct {
	runs    atomic.Int32
	started chan struct{}
	exited  chan struct{}
}

func newActivationLoop() *activationLoop {
	return &activationLoop{started: make(chan struct{}), exited: make(chan struct{})}
}

func (l *activationLoop) Run(ctx context.Context) {
	l.runs.Add(1)
	select {
	case <-l.started:
	default:
		close(l.started)
	}
	<-ctx.Done()
	close(l.exited)
}

func activationFactory(loop handoffSchedulerLoop) handoffSchedulerFactory {
	return func(k8s.HandoffTickSource, k8s.HandoffTickRunner, k8s.LeaderHandoffFence, k8s.HandoffSchedulerConfig) (handoffSchedulerLoop, error) {
		return loop, nil
	}
}

type activationPolicy struct{}

func (activationPolicy) HandoffPolicyAcknowledgements(context.Context, uuid.UUID, uuid.UUID, []uuid.UUID) (map[uuid.UUID]k8s.PolicyAcknowledgement, error) {
	return map[uuid.UUID]k8s.PolicyAcknowledgement{}, nil
}

type activationPlans struct{}

func (activationPlans) ResolveHandoffPlan(context.Context, HandoffTickIntent) (k8s.DurableHandoffPlan, bool, error) {
	return k8s.DurableHandoffPlan{}, false, nil
}

type activationProvenance struct{}

func (activationProvenance) ResolveFreshHandoffPlan(context.Context, HandoffTickIntent) (k8s.DurableHandoffPlan, bool, error) {
	return k8s.DurableHandoffPlan{}, false, nil
}

func (activationProvenance) ResolveFreshHandoffPlanWithLeadership(context.Context, HandoffTickIntent, k8s.HandoffLeadershipEpoch, *pgxpool.Conn) (k8s.DurableHandoffPlan, bool, error) {
	return k8s.DurableHandoffPlan{}, false, nil
}

func (activationProvenance) ValidateHandoffOperationProvenance(context.Context, pgx.Tx, k8s.DurableHandoffPlan, k8s.HandoffLeadershipEpoch) error {
	return nil
}

type activationIssuer struct{ calls atomic.Int32 }

func (i *activationIssuer) IssueP2HandoffDelivery(context.Context, k8s.HandoffLeadershipEpoch, *pgxpool.Conn, k8s.P2HandoffDelivery) error {
	i.calls.Add(1)
	return nil
}

type activationReader struct{ calls atomic.Int32 }

func (r *activationReader) LoadP2HandoffAppliedAttestation(context.Context, k8s.P2HandoffDeliveryIdentity) (k8s.P2HandoffAppliedAttestation, bool, error) {
	r.calls.Add(1)
	return k8s.P2HandoffAppliedAttestation{}, false, nil
}

func (r *activationReader) LoadP2HandoffAppliedAttestationWithLeadership(context.Context, k8s.HandoffLeadershipEpoch, *pgxpool.Conn, k8s.P2HandoffDeliveryIdentity) (k8s.P2HandoffAppliedAttestation, bool, error) {
	r.calls.Add(1)
	return k8s.P2HandoffAppliedAttestation{}, false, nil
}

type activationUnboundReader struct{}

func (activationUnboundReader) LoadP2HandoffAppliedAttestation(context.Context, k8s.P2HandoffDeliveryIdentity) (k8s.P2HandoffAppliedAttestation, bool, error) {
	return k8s.P2HandoffAppliedAttestation{}, false, nil
}
