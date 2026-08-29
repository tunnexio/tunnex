package nodes

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	maxStoredK8sServiceUIDRetired  = 1024
	maxStoredK8sServiceUIDReceipts = 128
)

var _ K8sServiceUIDObservationStore = (*PostgresK8sServiceUIDObservationStore)(nil)

// PostgresK8sServiceUIDObservationStore owns replay, incarnation and reporter
// attribution durability for the private mTLS observation endpoint.
type PostgresK8sServiceUIDObservationStore struct {
	pool *pgxpool.Pool
}

func NewPostgresK8sServiceUIDObservationStore(pool *pgxpool.Pool) *PostgresK8sServiceUIDObservationStore {
	return &PostgresK8sServiceUIDObservationStore{pool: pool}
}

// UpdateK8sServiceUIDObservations locks the exact selected connector authority
// (legacy cluster or pool+member), its node, replay state and cluster ledger in
// one transaction. Promotion, demotion and revocation therefore cannot pass a
// check/write gap, and every changed current row is attributed to this replay
// state only after the pure validator accepts it.
func (s *PostgresK8sServiceUIDObservationStore) UpdateK8sServiceUIDObservations(ctx context.Context, agent K8sServiceUIDObservationAgent, report K8sServiceUIDObservationReport, receiptTime time.Time, validate func(K8sServiceUIDObservationScope, K8sServiceUIDObservationState, time.Time) (K8sServiceUIDObservationValidation, error)) (K8sServiceUIDObservationValidation, error) {
	if s == nil || s.pool == nil || validate == nil {
		return K8sServiceUIDObservationValidation{}, fmt.Errorf("Kubernetes Service UID observation store is not configured")
	}
	if agent.NodeID == uuid.Nil || agent.OrgID == uuid.Nil || receiptTime.IsZero() || report.Sequence > math.MaxInt64 {
		return K8sServiceUIDObservationValidation{}, fmt.Errorf("invalid Kubernetes Service UID observation principal, sequence, or receipt time")
	}
	// The receipt is durable replay identity. PostgreSQL timestamptz stores
	// microseconds, so validate and return the same canonical value that a
	// restarted store will load.
	receiptTime = receiptTime.UTC().Truncate(time.Microsecond)
	canonical, err := ValidateK8sServiceUIDObservationReport(report)
	if err != nil {
		return K8sServiceUIDObservationValidation{}, err
	}
	report = canonical

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return K8sServiceUIDObservationValidation{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	scope, err := resolveSelectedK8sServiceUIDObservationScope(ctx, tx, agent)
	if err != nil {
		return K8sServiceUIDObservationValidation{}, err
	}
	scopeIdentity := k8sServiceUIDObservationScopeIdentity(scope)
	if _, err := tx.Exec(ctx, `INSERT INTO k8s_service_uid_observation_replay_states
		(org_id,site_id,cluster_id,connector_node_id,scope_identity) VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (org_id,site_id,cluster_id,connector_node_id) DO NOTHING`, scope.OrgID, scope.SiteID, scope.ClusterID, scope.ConnectorNodeID, scopeIdentity); err != nil {
		return K8sServiceUIDObservationValidation{}, err
	}
	replayStateID, state, err := loadK8sServiceUIDObservationReplayState(ctx, tx, scope, scopeIdentity)
	if err != nil {
		return K8sServiceUIDObservationValidation{}, err
	}
	ledgerID, current, retired, err := loadK8sServiceUIDObservationLedger(ctx, tx, scope)
	if err != nil {
		return K8sServiceUIDObservationValidation{}, err
	}
	state.Current, state.Retired = current, retired
	result, err := validate(scope, state, receiptTime)
	if err != nil {
		return K8sServiceUIDObservationValidation{}, err
	}
	if err := validK8sServiceUIDObservationStoreTransition(scopeIdentity, report, state, result); err != nil {
		return K8sServiceUIDObservationValidation{}, err
	}
	if result.Duplicate {
		// A duplicate proves only that an old report was replayed. It may retain
		// existing attribution, but it must never elevate an unattributed legacy
		// row into fresh handoff authority.
		if err := tx.Commit(ctx); err != nil {
			return K8sServiceUIDObservationValidation{}, err
		}
		return result, nil
	}
	if err := persistK8sServiceUIDObservationState(ctx, tx, replayStateID, ledgerID, scope.OrgID, report, result.NextState); err != nil {
		return K8sServiceUIDObservationValidation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return K8sServiceUIDObservationValidation{}, err
	}
	return result, nil
}

func resolveSelectedK8sServiceUIDObservationScope(ctx context.Context, tx pgx.Tx, agent K8sServiceUIDObservationAgent) (K8sServiceUIDObservationScope, error) {
	var scope K8sServiceUIDObservationScope
	// Pool mode first. The globally unique member-node constraint makes this at
	// most one cluster; all mutable authority rows are locked and rechecked here.
	err := tx.QueryRow(ctx, `SELECT c.org_id,c.site_id,c.id,m.node_id
		FROM k8s_connector_pool_members m
		JOIN k8s_connector_pools p ON p.id=m.pool_id AND p.org_id=m.org_id AND p.site_id=m.site_id AND p.active_node_id=m.node_id AND p.generation>0
		JOIN k8s_clusters c ON c.id=p.cluster_id AND c.org_id=p.org_id AND c.site_id=p.site_id AND c.connector_pool_id=p.id AND c.connector_node_id IS NULL
		JOIN nodes n ON n.id=m.node_id AND n.org_id=m.org_id AND n.site_id=m.site_id
		WHERE m.node_id=$2 AND m.org_id=$1
		  AND n.status='active' AND n.revoked_at IS NULL
		  AND n.wg_public_key ~ '^[A-Za-z0-9+/]{43}=$' AND btrim(n.endpoint)<>''
		  AND NOT EXISTS (SELECT 1 FROM k8s_clusters legacy WHERE legacy.connector_node_id=m.node_id)
		FOR UPDATE OF p,c,m,n`, agent.OrgID, agent.NodeID).Scan(&scope.OrgID, &scope.SiteID, &scope.ClusterID, &scope.ConnectorNodeID)
	if err == nil {
		if validK8sServiceUIDObservationScope(scope) {
			return scope, nil
		}
		return K8sServiceUIDObservationScope{}, fmt.Errorf("selected Kubernetes connector scope is invalid")
	}
	if err != pgx.ErrNoRows {
		return K8sServiceUIDObservationScope{}, err
	}

	err = tx.QueryRow(ctx, `SELECT c.org_id,c.site_id,c.id,c.connector_node_id
		FROM k8s_clusters c
		JOIN nodes n ON n.id=c.connector_node_id AND n.org_id=c.org_id AND n.site_id=c.site_id
		WHERE c.org_id=$1 AND c.connector_node_id=$2 AND c.connector_pool_id IS NULL
		  AND n.status='active' AND n.revoked_at IS NULL
		  AND NOT EXISTS (SELECT 1 FROM k8s_connector_pool_members member WHERE member.node_id=c.connector_node_id)
		FOR UPDATE OF c,n`, agent.OrgID, agent.NodeID).Scan(&scope.OrgID, &scope.SiteID, &scope.ClusterID, &scope.ConnectorNodeID)
	if err == pgx.ErrNoRows {
		return K8sServiceUIDObservationScope{}, fmt.Errorf("authenticated node is not the active selected Kubernetes connector")
	}
	if err != nil {
		return K8sServiceUIDObservationScope{}, err
	}
	if !validK8sServiceUIDObservationScope(scope) || scope.OrgID != agent.OrgID || scope.ConnectorNodeID != agent.NodeID {
		return K8sServiceUIDObservationScope{}, fmt.Errorf("selected Kubernetes connector scope is invalid")
	}
	return scope, nil
}

func loadK8sServiceUIDObservationReplayState(ctx context.Context, tx pgx.Tx, scope K8sServiceUIDObservationScope, scopeIdentity string) (uuid.UUID, K8sServiceUIDObservationState, error) {
	var stateID uuid.UUID
	var sequence int64
	var digest, storedScopeIdentity string
	err := tx.QueryRow(ctx, `SELECT id,scope_identity,sequence,digest FROM k8s_service_uid_observation_replay_states
		WHERE org_id=$1 AND site_id=$2 AND cluster_id=$3 AND connector_node_id=$4 FOR UPDATE`, scope.OrgID, scope.SiteID, scope.ClusterID, scope.ConnectorNodeID).Scan(&stateID, &storedScopeIdentity, &sequence, &digest)
	if err != nil {
		return uuid.Nil, K8sServiceUIDObservationState{}, err
	}
	if sequence < 0 || storedScopeIdentity != scopeIdentity || !validStoredK8sServiceUIDDigest(sequence, digest) {
		return uuid.Nil, K8sServiceUIDObservationState{}, fmt.Errorf("stored Kubernetes Service UID observation state is invalid")
	}
	state := K8sServiceUIDObservationState{ScopeIdentity: storedScopeIdentity, Sequence: uint64(sequence), Seen: map[uint64]K8sServiceUIDObservationReceipt{}}
	rows, err := tx.Query(ctx, `SELECT sequence,digest,receipt_time FROM k8s_service_uid_observation_receipts WHERE replay_state_id=$1 ORDER BY sequence`, stateID)
	if err != nil {
		return uuid.Nil, K8sServiceUIDObservationState{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var receiptSequence int64
		var receipt K8sServiceUIDObservationReceipt
		if err := rows.Scan(&receiptSequence, &receipt.Digest, &receipt.ReceiptTime); err != nil || receiptSequence <= 0 || !validStoredK8sServiceUIDDigest(receiptSequence, receipt.Digest) || receipt.ReceiptTime.IsZero() {
			return uuid.Nil, K8sServiceUIDObservationState{}, fmt.Errorf("stored Kubernetes Service UID observation receipt is invalid")
		}
		state.Seen[uint64(receiptSequence)] = K8sServiceUIDObservationReceipt{Digest: receipt.Digest, ReceiptTime: receipt.ReceiptTime.UTC()}
	}
	if err := rows.Err(); err != nil {
		return uuid.Nil, K8sServiceUIDObservationState{}, err
	}
	return stateID, state, nil
}

func loadK8sServiceUIDObservationLedger(ctx context.Context, tx pgx.Tx, scope K8sServiceUIDObservationScope) (uuid.UUID, map[string]K8sServiceUIDObservation, map[string]map[string]bool, error) {
	ledgerIdentity := k8sServiceUIDObservationClusterIdentity(scope)
	if _, err := tx.Exec(ctx, `INSERT INTO k8s_service_uid_observation_ledgers (org_id,site_id,cluster_id,scope_identity)
		VALUES ($1,$2,$3,$4) ON CONFLICT (org_id,site_id,cluster_id) DO NOTHING`, scope.OrgID, scope.SiteID, scope.ClusterID, ledgerIdentity); err != nil {
		return uuid.Nil, nil, nil, err
	}
	var ledgerID uuid.UUID
	var storedIdentity string
	if err := tx.QueryRow(ctx, `SELECT id,scope_identity FROM k8s_service_uid_observation_ledgers WHERE org_id=$1 AND site_id=$2 AND cluster_id=$3 FOR UPDATE`, scope.OrgID, scope.SiteID, scope.ClusterID).Scan(&ledgerID, &storedIdentity); err != nil {
		return uuid.Nil, nil, nil, err
	}
	if storedIdentity != ledgerIdentity {
		return uuid.Nil, nil, nil, fmt.Errorf("stored Kubernetes Service UID observation ledger is invalid")
	}
	current := map[string]K8sServiceUIDObservation{}
	rows, err := tx.Query(ctx, `SELECT namespace,service,uid,state FROM k8s_service_uid_observation_current WHERE ledger_id=$1`, ledgerID)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	for rows.Next() {
		var observation K8sServiceUIDObservation
		if err := rows.Scan(&observation.Namespace, &observation.Service, &observation.UID, &observation.State); err != nil || !validK8sServiceUIDObservation(observation) {
			rows.Close()
			return uuid.Nil, nil, nil, fmt.Errorf("stored Kubernetes Service UID current incarnation is invalid")
		}
		current[observation.Namespace+"\x00"+observation.Service] = observation
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return uuid.Nil, nil, nil, err
	}
	rows.Close()
	retired := map[string]map[string]bool{}
	rows, err = tx.Query(ctx, `SELECT namespace,service,uid FROM k8s_service_uid_observation_retired WHERE ledger_id=$1`, ledgerID)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	for rows.Next() {
		var namespace, service, uid string
		if err := rows.Scan(&namespace, &service, &uid); err != nil || !validK8sServiceUIDObservation(K8sServiceUIDObservation{Namespace: namespace, Service: service, UID: uid, State: "deleted"}) {
			rows.Close()
			return uuid.Nil, nil, nil, fmt.Errorf("stored Kubernetes Service UID retired incarnation is invalid")
		}
		key := namespace + "\x00" + service
		if retired[key] == nil {
			retired[key] = map[string]bool{}
		}
		retired[key][uid] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return uuid.Nil, nil, nil, err
	}
	rows.Close()
	return ledgerID, current, retired, nil
}

func validK8sServiceUIDObservationStoreTransition(scopeIdentity string, report K8sServiceUIDObservationReport, previous K8sServiceUIDObservationState, result K8sServiceUIDObservationValidation) error {
	if result.NextState.ScopeIdentity != scopeIdentity || result.NextState.Sequence > math.MaxInt64 {
		return fmt.Errorf("invalid Kubernetes Service UID observation state transition")
	}
	if result.Duplicate {
		receipt, ok := result.NextState.Seen[report.Sequence]
		if result.NextState.Sequence != previous.Sequence || !ok || receipt.Digest != report.Digest || receipt.ReceiptTime.IsZero() || !result.ReceiptTime.Equal(receipt.ReceiptTime) {
			return fmt.Errorf("duplicate Kubernetes Service UID observation lacks original receipt")
		}
		return nil
	}
	if result.NextState.Sequence != report.Sequence {
		return fmt.Errorf("Kubernetes Service UID observation transition changed sequence")
	}
	receipt, ok := result.NextState.Seen[report.Sequence]
	if !ok || receipt.Digest != report.Digest || receipt.ReceiptTime.IsZero() || !result.ReceiptTime.Equal(receipt.ReceiptTime) || result.NextState.Sequence <= previous.Sequence {
		return fmt.Errorf("Kubernetes Service UID observation transition lacks a valid receipt")
	}
	if retainedK8sServiceUIDCount(result.NextState.Retired) > maxStoredK8sServiceUIDRetired {
		return fmt.Errorf("Kubernetes Service UID observation retired-incarnation capacity reached")
	}
	return nil
}

func persistK8sServiceUIDObservationState(ctx context.Context, tx pgx.Tx, replayStateID, ledgerID, orgID uuid.UUID, report K8sServiceUIDObservationReport, state K8sServiceUIDObservationState) error {
	receipt := state.Seen[state.Sequence]
	if _, err := tx.Exec(ctx, `UPDATE k8s_service_uid_observation_replay_states SET sequence=$2,digest=$3 WHERE id=$1`, replayStateID, int64(state.Sequence), receipt.Digest); err != nil {
		return err
	}
	for _, observation := range report.Observations {
		if _, err := tx.Exec(ctx, `INSERT INTO k8s_service_uid_observation_current
			(ledger_id,org_id,namespace,service,uid,state,replay_sequence) VALUES ($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (ledger_id,namespace,service) DO UPDATE SET uid=EXCLUDED.uid,state=EXCLUDED.state,replay_sequence=EXCLUDED.replay_sequence,updated_at=now()`,
			ledgerID, orgID, observation.Namespace, observation.Service, observation.UID, observation.State, int64(report.Sequence)); err != nil {
			return err
		}
	}
	if err := persistK8sServiceUIDObservationAttributions(ctx, tx, replayStateID, ledgerID, orgID, report); err != nil {
		return err
	}
	for _, retired := range sortedK8sServiceUIDRetired(state.Retired) {
		if _, err := tx.Exec(ctx, `INSERT INTO k8s_service_uid_observation_retired
			(ledger_id,org_id,namespace,service,uid,retired_replay_sequence,retired_at) VALUES ($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (ledger_id,namespace,service,uid) DO NOTHING`, ledgerID, orgID, retired.Namespace, retired.Service, retired.UID, int64(state.Sequence), receipt.ReceiptTime.UTC()); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO k8s_service_uid_observation_receipts (org_id,replay_state_id,sequence,digest,receipt_time) VALUES ($1,$2,$3,$4,$5)`, orgID, replayStateID, int64(state.Sequence), receipt.Digest, receipt.ReceiptTime.UTC()); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `DELETE FROM k8s_service_uid_observation_receipts WHERE replay_state_id=$1 AND sequence <= $2::bigint-$3::bigint`, replayStateID, int64(state.Sequence), int64(maxStoredK8sServiceUIDReceipts))
	return err
}

func persistK8sServiceUIDObservationAttributions(ctx context.Context, tx pgx.Tx, replayStateID, ledgerID, orgID uuid.UUID, report K8sServiceUIDObservationReport) error {
	for _, observation := range report.Observations {
		ct, err := tx.Exec(ctx, `INSERT INTO k8s_service_uid_observation_current_attributions
			(ledger_id,org_id,namespace,service,replay_state_id,replay_sequence)
			SELECT $1,$2,$3,$4,$5,$6 FROM k8s_service_uid_observation_current c
			WHERE c.ledger_id=$1 AND c.org_id=$2 AND c.namespace=$3 AND c.service=$4 AND c.uid=$7 AND c.state=$8 AND c.replay_sequence=$6
			ON CONFLICT (ledger_id,namespace,service) DO UPDATE SET replay_state_id=EXCLUDED.replay_state_id,replay_sequence=EXCLUDED.replay_sequence,updated_at=now()`,
			ledgerID, orgID, observation.Namespace, observation.Service, replayStateID, int64(report.Sequence), observation.UID, observation.State)
		if err != nil {
			return err
		}
		if ct.RowsAffected() != 1 {
			return fmt.Errorf("Kubernetes Service UID observation current row does not match reporter attribution")
		}
	}
	return nil
}

func validStoredK8sServiceUIDDigest(sequence int64, digest string) bool {
	if sequence == 0 {
		return digest == ""
	}
	if sequence < 0 || len(digest) != 64 {
		return false
	}
	for _, r := range digest {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func k8sServiceUIDObservationClusterIdentity(scope K8sServiceUIDObservationScope) string {
	return strings.Join([]string{scope.OrgID.String(), scope.SiteID.String(), scope.ClusterID.String()}, "\x1f")
}

func retainedK8sServiceUIDCount(retired map[string]map[string]bool) int {
	count := 0
	for _, values := range retired {
		count += len(values)
	}
	return count
}

func sortedK8sServiceUIDRetired(values map[string]map[string]bool) []K8sServiceUIDObservation {
	entries := make([]K8sServiceUIDObservation, 0, retainedK8sServiceUIDCount(values))
	for key, uids := range values {
		parts := strings.Split(key, "\x00")
		if len(parts) != 2 {
			continue
		}
		for uid, retired := range uids {
			if retired {
				entries = append(entries, K8sServiceUIDObservation{Namespace: parts[0], Service: parts[1], UID: uid})
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Namespace != entries[j].Namespace {
			return entries[i].Namespace < entries[j].Namespace
		}
		if entries[i].Service != entries[j].Service {
			return entries[i].Service < entries[j].Service
		}
		return entries[i].UID < entries[j].UID
	})
	return entries
}
