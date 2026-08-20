package alerts

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The condition scanner owns F11's bounded, server-observed conditions. It
// does not mutate an agent, policy, or rotation: durable outbox cooldowns own
// notification de-duplication after a condition has been observed.
const (
	offlineAfter        = time.Minute
	denialWindow        = 5 * time.Minute
	denialSpikeMinimum  = 20
	accessWarningBefore = 15 * time.Minute
)

type Condition struct {
	OrgID    uuid.UUID
	DeviceID uuid.UUID
	Name     string
	Count    int64
	Deadline time.Time
	Reason   string
}

// ConditionStore makes every producer independently testable. The production
// implementation reads only canonical control-plane state; an alert remains
// opt-in because Publisher enforces the organization setting at enqueue time.
type ConditionStore interface {
	OfflineAgents(context.Context) ([]Condition, error)
	DenialSpikes(context.Context) ([]Condition, error)
	ExpiringAccess(context.Context) ([]Condition, error)
	FailedRotations(context.Context) ([]Condition, error)
}

type ConditionScanner struct {
	store     ConditionStore
	publisher Publisher
}

func NewConditionScanner(store ConditionStore, publisher Publisher) *ConditionScanner {
	if publisher == nil {
		publisher = NoopPublisher{}
	}
	return &ConditionScanner{store: store, publisher: publisher}
}

// RunOnce publishes every currently-observed condition. Calling it every
// minute is safe: the per-destination durable cooldown suppresses duplicate
// deliveries while preserving the suppressed count.
func (s *ConditionScanner) RunOnce(ctx context.Context) error {
	if s == nil || s.store == nil {
		return fmt.Errorf("alert condition scanner is not configured")
	}
	checks := []struct {
		list func(context.Context) ([]Condition, error)
		make func(Condition) Event
	}{
		{s.store.OfflineAgents, offlineEvent},
		{s.store.DenialSpikes, denialEvent},
		{s.store.ExpiringAccess, expiryEvent},
		{s.store.FailedRotations, rotationEvent},
	}
	for _, check := range checks {
		conditions, err := check.list(ctx)
		if err != nil {
			return err
		}
		for _, condition := range conditions {
			if err := s.publisher.Publish(ctx, check.make(condition)); err != nil {
				return err
			}
		}
	}
	return nil
}

func offlineEvent(c Condition) Event {
	return Event{OrgID: c.OrgID, Key: EventAgentOffline, Severity: SeverityCritical,
		DedupKey: "agent:" + c.DeviceID.String() + ":offline",
		Subject:  "Agent " + c.Name + " has been offline for at least one minute",
		Fields:   map[string]string{"agent_id": c.DeviceID.String(), "agent_name": c.Name, "threshold_seconds": strconv.Itoa(int(offlineAfter.Seconds()))}}
}

func denialEvent(c Condition) Event {
	return Event{OrgID: c.OrgID, Key: EventAgentDenialSpike, Severity: SeverityWarning,
		DedupKey: "agent:" + c.DeviceID.String() + ":denial-spike",
		Subject:  "Agent " + c.Name + " exceeded the denied-access threshold",
		Fields:   map[string]string{"agent_id": c.DeviceID.String(), "agent_name": c.Name, "denied_count": strconv.FormatInt(c.Count, 10), "window_seconds": strconv.Itoa(int(denialWindow.Seconds()))}}
}

func expiryEvent(c Condition) Event {
	return Event{OrgID: c.OrgID, Key: EventAgentAccessExpiring, Severity: SeverityWarning,
		DedupKey: "agent-access:" + c.Reason + ":expiring",
		Subject:  "Temporary access for agent " + c.Name + " expires soon",
		Fields:   map[string]string{"agent_id": c.DeviceID.String(), "request_id": c.Reason, "expires_at": c.Deadline.UTC().Format(time.RFC3339)}}
}

func rotationEvent(c Condition) Event {
	return Event{OrgID: c.OrgID, Key: EventAgentRotationFailed, Severity: SeverityCritical,
		DedupKey: "agent:" + c.DeviceID.String() + ":rotation:" + c.Reason,
		Subject:  "Credential or WireGuard rotation for agent " + c.Name + " reached its deadline",
		Fields:   map[string]string{"agent_id": c.DeviceID.String(), "agent_name": c.Name, "rotation": c.Reason, "deadline": c.Deadline.UTC().Format(time.RFC3339)}}
}

type PostgresConditionStore struct{ pool *pgxpool.Pool }

func NewPostgresConditionStore(pool *pgxpool.Pool) *PostgresConditionStore {
	return &PostgresConditionStore{pool: pool}
}

func (s *PostgresConditionStore) OfflineAgents(ctx context.Context) ([]Condition, error) {
	return scanConditions(ctx, s.pool, `
		SELECT d.org_id,d.id,d.name,0::bigint,ars.last_seen_at,'offline'
		FROM devices d
		JOIN agent_runtime_state ars ON ars.device_id=d.id
		WHERE d.kind='agent' AND d.status='active' AND d.deleted_at IS NULL
		  AND (ars.last_seen_at IS NULL OR ars.last_seen_at < now() - ($1::bigint * interval '1 second'))
		  AND ars.created_at < now() - ($1::bigint * interval '1 second')`, int64(offlineAfter/time.Second))
}

func (s *PostgresConditionStore) DenialSpikes(ctx context.Context) ([]Condition, error) {
	return scanConditions(ctx, s.pool, `
		SELECT e.org_id,d.id,d.name,count(*)::bigint,max(e.created_at),'denial-spike'
		FROM access_events e
		JOIN devices d ON d.id=e.src_device_id AND d.org_id=e.org_id
		WHERE e.src_kind='agent' AND e.decision <> 'allow'
		  AND e.created_at >= now() - ($1::bigint * interval '1 second')
		  AND d.kind='agent' AND d.status='active' AND d.deleted_at IS NULL
		GROUP BY e.org_id,d.id,d.name
		HAVING count(*) >= $2`, int64(denialWindow/time.Second), denialSpikeMinimum)
}

func (s *PostgresConditionStore) ExpiringAccess(ctx context.Context) ([]Condition, error) {
	return scanConditions(ctx, s.pool, `
		SELECT ar.org_id,d.id,d.name,0::bigint,ar.approved_expires_at,ar.id::text
		FROM agent_access_requests ar
		JOIN devices d ON d.id=ar.device_id AND d.org_id=ar.org_id
		WHERE ar.state='approved' AND ar.approved_expires_at > now()
		  AND ar.approved_expires_at <= now() + ($1::bigint * interval '1 second')
		  AND d.kind='agent' AND d.status='active' AND d.deleted_at IS NULL`, int64(accessWarningBefore/time.Second))
}

func (s *PostgresConditionStore) FailedRotations(ctx context.Context) ([]Condition, error) {
	return scanConditions(ctx, s.pool, `
		SELECT c.org_id,d.id,d.name,0::bigint,c.rotation_deadline,'runtime-credential'
		FROM agent_runtime_credentials c
		JOIN devices d ON d.id=c.device_id AND d.org_id=c.org_id
		WHERE c.state='current' AND c.revoked_at IS NULL
		  AND c.rotation_deadline IS NOT NULL AND c.rotation_deadline <= now()
		  AND d.kind='agent' AND d.status='active' AND d.deleted_at IS NULL
		UNION ALL
		SELECT r.org_id,d.id,d.name,0::bigint,r.deadline,'wireguard'
		FROM agent_wireguard_rotations r
		JOIN devices d ON d.id=r.device_id AND d.org_id=r.org_id
		WHERE r.state <> 'current' AND r.deadline <= now()
		  AND d.kind='agent' AND d.status='active' AND d.deleted_at IS NULL`)
}

func scanConditions(ctx context.Context, pool *pgxpool.Pool, query string, args ...any) ([]Condition, error) {
	if pool == nil {
		return nil, fmt.Errorf("alert condition store is not configured")
	}
	rows, err := pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Condition
	for rows.Next() {
		var row Condition
		if err := rows.Scan(&row.OrgID, &row.DeviceID, &row.Name, &row.Count, &row.Deadline, &row.Reason); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

var _ ConditionStore = (*PostgresConditionStore)(nil)
