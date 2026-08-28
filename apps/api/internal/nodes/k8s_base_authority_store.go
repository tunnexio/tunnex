package nodes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"reflect"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
)

type KubernetesOwnershipBaseAuthorityStore interface {
	LoadPendingKubernetesOwnershipBaseAuthority(context.Context, KubernetesOwnershipBaseAuthorityAgentIdentity) (KubernetesOwnershipBaseAuthority, bool, error)
	AcknowledgeKubernetesOwnershipBaseAuthority(context.Context, KubernetesOwnershipBaseAuthorityAgentIdentity, KubernetesOwnershipBaseAuthorityAck, time.Time) (bool, error)
}

type KubernetesOwnershipBaseAuthorityIssuer interface {
	IssueKubernetesOwnershipBaseAuthorityWithLeadership(context.Context, k8s.HandoffLeadershipEpoch, *pgxpool.Conn, KubernetesOwnershipBaseAuthorityIssue) (KubernetesOwnershipBaseAuthorityIssueResult, error)
	IssueKubernetesOwnershipBaseAuthorityWithLeadershipTx(context.Context, k8s.HandoffLeadershipEpoch, pgx.Tx, KubernetesOwnershipBaseAuthorityIssue) (KubernetesOwnershipBaseAuthorityIssueResult, error)
}

type PostgresKubernetesOwnershipBaseAuthorityStore struct {
	pool                    *pgxpool.Pool
	leaderBoundPreWriteHook func(context.Context, pgx.Tx) error
}

func NewPostgresKubernetesOwnershipBaseAuthorityStore(pool *pgxpool.Pool) *PostgresKubernetesOwnershipBaseAuthorityStore {
	return &PostgresKubernetesOwnershipBaseAuthorityStore{pool: pool}
}

func (s *PostgresKubernetesOwnershipBaseAuthorityStore) IssueKubernetesOwnershipBaseAuthority(ctx context.Context, issue KubernetesOwnershipBaseAuthorityIssue) (KubernetesOwnershipBaseAuthorityIssueResult, error) {
	if s == nil || s.pool == nil {
		return KubernetesOwnershipBaseAuthorityIssueResult{}, fmt.Errorf("base-authority store is not configured")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return KubernetesOwnershipBaseAuthorityIssueResult{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	result, err := issueKubernetesOwnershipBaseAuthorityTx(ctx, tx, issue)
	if err != nil {
		return KubernetesOwnershipBaseAuthorityIssueResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return KubernetesOwnershipBaseAuthorityIssueResult{}, err
	}
	return result, nil
}

func (s *PostgresKubernetesOwnershipBaseAuthorityStore) IssueKubernetesOwnershipBaseAuthorityWithLeadership(ctx context.Context, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn, issue KubernetesOwnershipBaseAuthorityIssue) (KubernetesOwnershipBaseAuthorityIssueResult, error) {
	if s == nil || s.pool == nil || conn == nil {
		return KubernetesOwnershipBaseAuthorityIssueResult{}, fmt.Errorf("base-authority store is not configured")
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return KubernetesOwnershipBaseAuthorityIssueResult{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	result, err := s.IssueKubernetesOwnershipBaseAuthorityWithLeadershipTx(ctx, epoch, tx, issue)
	if err != nil {
		return KubernetesOwnershipBaseAuthorityIssueResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return KubernetesOwnershipBaseAuthorityIssueResult{}, err
	}
	return result, nil
}

func (s *PostgresKubernetesOwnershipBaseAuthorityStore) IssueKubernetesOwnershipBaseAuthorityWithLeadershipTx(ctx context.Context, epoch k8s.HandoffLeadershipEpoch, tx pgx.Tx, issue KubernetesOwnershipBaseAuthorityIssue) (KubernetesOwnershipBaseAuthorityIssueResult, error) {
	if s == nil || s.pool == nil || tx == nil {
		return KubernetesOwnershipBaseAuthorityIssueResult{}, fmt.Errorf("base-authority store is not configured")
	}
	if err := requireHandoffHALeaderSessionTx(ctx, tx, epoch); err != nil {
		return KubernetesOwnershipBaseAuthorityIssueResult{}, err
	}
	if s.leaderBoundPreWriteHook != nil {
		if err := s.leaderBoundPreWriteHook(ctx, tx); err != nil {
			return KubernetesOwnershipBaseAuthorityIssueResult{}, err
		}
	}
	if err := requireHandoffHALeaderSessionTx(ctx, tx, epoch); err != nil {
		return KubernetesOwnershipBaseAuthorityIssueResult{}, err
	}
	result, err := issueKubernetesOwnershipBaseAuthorityTx(ctx, tx, issue)
	if err != nil {
		return KubernetesOwnershipBaseAuthorityIssueResult{}, err
	}
	if err := requireHandoffHALeaderSessionTx(ctx, tx, epoch); err != nil {
		return KubernetesOwnershipBaseAuthorityIssueResult{}, err
	}
	return result, nil
}

func issueKubernetesOwnershipBaseAuthorityTx(ctx context.Context, tx pgx.Tx, issue KubernetesOwnershipBaseAuthorityIssue) (KubernetesOwnershipBaseAuthorityIssueResult, error) {
	if issue.Authority.AuthorityRevision != 0 || issue.TransitionRevision == 0 || issue.TransitionRevision > math.MaxInt64 ||
		issue.Authority.BaseVersion == 0 || issue.Authority.BaseVersion > math.MaxInt64 ||
		issue.ExpiresAt.IsZero() || issue.ExpiresAt.Location() != time.UTC {
		return KubernetesOwnershipBaseAuthorityIssueResult{}, ErrKubernetesOwnershipBaseAuthorityInvalid
	}
	// PostgreSQL timestamptz persists microseconds. Canonicalize before both
	// the insert and exact replay comparison so one caller-owned issue remains
	// byte-for-byte retryable after a process restart.
	issue.ExpiresAt = issue.ExpiresAt.Truncate(time.Microsecond)
	if !issue.ExpiresAt.After(time.Now().UTC()) {
		return KubernetesOwnershipBaseAuthorityIssueResult{}, ErrKubernetesOwnershipBaseAuthorityInvalid
	}
	nodeID, nodeErr := uuid.Parse(issue.Authority.NodeID)
	orgID, orgErr := uuid.Parse(issue.Authority.OrgID)
	siteID, siteErr := uuid.Parse(issue.Authority.SiteID)
	if nodeErr != nil || orgErr != nil || siteErr != nil || nodeID == uuid.Nil || orgID == uuid.Nil || siteID == uuid.Nil {
		return KubernetesOwnershipBaseAuthorityIssueResult{}, ErrKubernetesOwnershipBaseAuthorityInvalid
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO k8s_base_authority_node_states (org_id,site_id,node_id)
		VALUES ($1,$2,$3) ON CONFLICT (org_id,node_id) DO NOTHING`, orgID, siteID, nodeID); err != nil {
		return KubernetesOwnershipBaseAuthorityIssueResult{}, err
	}
	var storedSite uuid.UUID
	var nextRevision, acceptedRevision int64
	if err := tx.QueryRow(ctx, `
		SELECT site_id,next_authority_revision,accepted_authority_revision
		FROM k8s_base_authority_node_states WHERE org_id=$1 AND node_id=$2 FOR UPDATE`, orgID, nodeID).
		Scan(&storedSite, &nextRevision, &acceptedRevision); err != nil {
		return KubernetesOwnershipBaseAuthorityIssueResult{}, err
	}
	if storedSite != siteID || nextRevision <= acceptedRevision || nextRevision <= 0 {
		return KubernetesOwnershipBaseAuthorityIssueResult{}, ErrKubernetesOwnershipBaseAuthorityConflict
	}

	existing, found, err := loadKubernetesOwnershipBaseAuthorityIssueReplay(ctx, tx, orgID, siteID, nodeID, issue.TransitionRevision, issue.Pools)
	if err != nil {
		return KubernetesOwnershipBaseAuthorityIssueResult{}, err
	}
	if found {
		candidate := issue.Authority
		candidate.AuthorityRevision = existing.Authority.AuthorityRevision
		candidate, _, err = CanonicalKubernetesOwnershipBaseAuthority(candidate)
		if err != nil || !sameKubernetesOwnershipBaseAuthority(existing.Authority, candidate) || !existing.ExpiresAt.Equal(issue.ExpiresAt) ||
			!sameKubernetesOwnershipIssuePools(existing.Pools, issue.Pools) {
			return KubernetesOwnershipBaseAuthorityIssueResult{}, ErrKubernetesOwnershipBaseAuthorityConflict
		}
		existing.Duplicate = true
		return existing.KubernetesOwnershipBaseAuthorityIssueResult, nil
	}
	if nextRevision > math.MaxInt64-1 {
		return KubernetesOwnershipBaseAuthorityIssueResult{}, ErrKubernetesOwnershipBaseAuthorityConflict
	}
	authority := issue.Authority
	authority.AuthorityRevision = uint64(nextRevision)
	_, digest, err := canonicalKubernetesOwnershipBaseAuthorityJSON(authority)
	if err != nil {
		return KubernetesOwnershipBaseAuthorityIssueResult{}, err
	}
	authority, _, _ = CanonicalKubernetesOwnershipBaseAuthority(authority)
	pools, err := validateKubernetesOwnershipIssuePools(authority, issue.Pools)
	if err != nil {
		return KubernetesOwnershipBaseAuthorityIssueResult{}, err
	}
	var deliveryID uuid.UUID
	if err := tx.QueryRow(ctx, `
		INSERT INTO k8s_base_authority_deliveries
			(org_id,site_id,node_id,authority_revision,wire_version,base_version,base_hash,payload_digest,payload,transition_revision,expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING id`, orgID, siteID, nodeID, nextRevision, authority.WireVersion, int64(authority.BaseVersion), authority.BaseHash,
		digest, authority, int64(issue.TransitionRevision), issue.ExpiresAt).Scan(&deliveryID); err != nil {
		return KubernetesOwnershipBaseAuthorityIssueResult{}, err
	}
	classifications := make(map[string]KubernetesOwnershipPoolClassification, len(authority.Classifications))
	for _, item := range authority.Classifications {
		classifications[item.Scope.PoolID] = item
	}
	for poolID, generation := range pools {
		poolUUID, _ := uuid.Parse(poolID)
		clusterUUID, _ := uuid.Parse(generation.Scope.ClusterID)
		if classification, ok := classifications[poolID]; ok {
			classificationJSON, err := json.Marshal(classification)
			if err != nil {
				return KubernetesOwnershipBaseAuthorityIssueResult{}, err
			}
			sum := sha256.Sum256(classificationJSON)
			if _, err := tx.Exec(ctx, `
				INSERT INTO k8s_base_authority_delivery_pools
					(delivery_id,org_id,site_id,node_id,cluster_id,pool_id,promotion_generation,kind,disposition,classification,classification_digest)
				VALUES ($1,$2,$3,$4,$5,$6,$7,'classification',$8,$9,$10)`, deliveryID, orgID, siteID, nodeID, clusterUUID,
				poolUUID, int64(generation.PromotionGeneration), string(classification.Disposition), classification, hex.EncodeToString(sum[:])); err != nil {
				return KubernetesOwnershipBaseAuthorityIssueResult{}, err
			}
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO k8s_base_authority_delivery_pools
				(delivery_id,org_id,site_id,node_id,cluster_id,pool_id,promotion_generation,kind)
			VALUES ($1,$2,$3,$4,$5,$6,$7,'unfence')`, deliveryID, orgID, siteID, nodeID, clusterUUID, poolUUID, int64(generation.PromotionGeneration)); err != nil {
			return KubernetesOwnershipBaseAuthorityIssueResult{}, err
		}
	}
	ct, err := tx.Exec(ctx, `
		UPDATE k8s_base_authority_node_states SET next_authority_revision=$3
		WHERE org_id=$1 AND node_id=$2 AND next_authority_revision=$4`, orgID, nodeID, nextRevision+1, nextRevision)
	if err != nil || ct.RowsAffected() != 1 {
		if err == nil {
			err = ErrKubernetesOwnershipBaseAuthorityConflict
		}
		return KubernetesOwnershipBaseAuthorityIssueResult{}, err
	}
	return KubernetesOwnershipBaseAuthorityIssueResult{DeliveryID: deliveryID, Authority: authority, PayloadDigest: digest}, nil
}

func (s *PostgresKubernetesOwnershipBaseAuthorityStore) LoadPendingKubernetesOwnershipBaseAuthority(ctx context.Context, agent KubernetesOwnershipBaseAuthorityAgentIdentity) (KubernetesOwnershipBaseAuthority, bool, error) {
	if s == nil || s.pool == nil {
		return KubernetesOwnershipBaseAuthority{}, false, fmt.Errorf("base-authority store is not configured")
	}
	if agent.NodeID == uuid.Nil || agent.OrgID == uuid.Nil || agent.SiteID == uuid.Nil {
		return KubernetesOwnershipBaseAuthority{}, false, ErrKubernetesOwnershipBaseAuthorityInvalid
	}
	var payload []byte
	var digest, baseHash string
	var revision, baseVersion int64
	err := s.pool.QueryRow(ctx, `
		WITH current_delivery AS (
			SELECT d.* FROM k8s_base_authority_deliveries d
			WHERE d.org_id=$1 AND d.site_id=$2 AND d.node_id=$3
			ORDER BY d.authority_revision DESC LIMIT 1
		)
		SELECT d.payload,d.payload_digest,d.authority_revision,d.base_version,d.base_hash
		FROM current_delivery d
		LEFT JOIN k8s_base_authority_ack_receipts r ON r.delivery_id=d.id
		WHERE r.delivery_id IS NULL AND d.expires_at > clock_timestamp()`, agent.OrgID, agent.SiteID, agent.NodeID).
		Scan(&payload, &digest, &revision, &baseVersion, &baseHash)
	if err == pgx.ErrNoRows {
		return KubernetesOwnershipBaseAuthority{}, false, nil
	}
	if err != nil {
		return KubernetesOwnershipBaseAuthority{}, false, err
	}
	authority, canonicalDigest, err := decodeKubernetesOwnershipBaseAuthorityPayload(payload)
	if err != nil || canonicalDigest != digest || authority.AuthorityRevision != uint64(revision) || authority.BaseVersion != uint64(baseVersion) ||
		authority.BaseHash != baseHash || authority.NodeID != agent.NodeID.String() || authority.OrgID != agent.OrgID.String() || authority.SiteID != agent.SiteID.String() {
		return KubernetesOwnershipBaseAuthority{}, false, fmt.Errorf("%w: stored delivery", ErrKubernetesOwnershipBaseAuthorityInvalid)
	}
	return authority, true, nil
}

func (s *PostgresKubernetesOwnershipBaseAuthorityStore) AcknowledgeKubernetesOwnershipBaseAuthority(ctx context.Context, agent KubernetesOwnershipBaseAuthorityAgentIdentity, ack KubernetesOwnershipBaseAuthorityAck, receivedAt time.Time) (bool, error) {
	if s == nil || s.pool == nil || agent.NodeID == uuid.Nil || agent.OrgID == uuid.Nil || agent.SiteID == uuid.Nil ||
		receivedAt.IsZero() || receivedAt.Location() != time.UTC || ack.AuthorityRevision == 0 || ack.AuthorityRevision > math.MaxInt64 {
		return false, ErrKubernetesOwnershipBaseAuthorityInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var deliveryID uuid.UUID
	var payload []byte
	var payloadDigest string
	var expiresAt time.Time
	err = tx.QueryRow(ctx, `
		SELECT id,payload,payload_digest,expires_at
		FROM k8s_base_authority_deliveries
		WHERE wire_version=1 AND org_id=$1 AND site_id=$2 AND node_id=$3 AND authority_revision=$4
		FOR UPDATE`, agent.OrgID, agent.SiteID, agent.NodeID, int64(ack.AuthorityRevision)).
		Scan(&deliveryID, &payload, &payloadDigest, &expiresAt)
	if err == pgx.ErrNoRows {
		return false, ErrKubernetesOwnershipBaseAuthorityInvalid
	}
	if err != nil {
		return false, err
	}
	authority, digest, err := decodeKubernetesOwnershipBaseAuthorityPayload(payload)
	if err != nil || digest != payloadDigest {
		return false, ErrKubernetesOwnershipBaseAuthorityInvalid
	}
	appliedAt, err := ValidateKubernetesOwnershipBaseAuthorityAck(agent, authority, payloadDigest, ack)
	if err != nil {
		return false, err
	}
	// Keep exact ACK replay stable across the PostgreSQL timestamptz boundary.
	appliedAt = appliedAt.UTC().Truncate(time.Microsecond)
	var existingRevision, existingBaseVersion int64
	var existingDigest, existingBaseHash string
	var existingAppliedAt time.Time
	err = tx.QueryRow(ctx, `
		SELECT authority_revision,payload_digest,applied_base_version,applied_base_hash,agent_applied_at
		FROM k8s_base_authority_ack_receipts WHERE delivery_id=$1`, deliveryID).
		Scan(&existingRevision, &existingDigest, &existingBaseVersion, &existingBaseHash, &existingAppliedAt)
	if err == nil {
		if existingRevision != int64(ack.AuthorityRevision) || existingDigest != ack.AuthorityDigest || existingBaseVersion != int64(ack.BaseVersion) ||
			existingBaseHash != ack.BaseHash || !existingAppliedAt.Equal(appliedAt) {
			return false, ErrKubernetesOwnershipBaseAuthorityConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return false, err
		}
		return true, nil
	}
	if err != pgx.ErrNoRows {
		return false, err
	}
	if !expiresAt.After(receivedAt) {
		return false, ErrKubernetesOwnershipBaseAuthorityInvalid
	}
	var nextRevision, acceptedRevision int64
	var acceptedDigest *string
	if err := tx.QueryRow(ctx, `
		SELECT next_authority_revision,accepted_authority_revision,accepted_payload_digest
		FROM k8s_base_authority_node_states WHERE org_id=$1 AND node_id=$2 AND site_id=$3 FOR UPDATE`, agent.OrgID, agent.NodeID, agent.SiteID).
		Scan(&nextRevision, &acceptedRevision, &acceptedDigest); err != nil {
		return false, err
	}
	if nextRevision != int64(ack.AuthorityRevision)+1 || acceptedRevision >= int64(ack.AuthorityRevision) {
		return false, ErrKubernetesOwnershipBaseAuthorityConflict
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO k8s_base_authority_ack_receipts
			(delivery_id,org_id,site_id,node_id,authority_revision,payload_digest,applied_base_version,applied_base_hash,agent_applied_at,receipt_time)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, deliveryID, agent.OrgID, agent.SiteID, agent.NodeID, int64(ack.AuthorityRevision),
		ack.AuthorityDigest, int64(ack.BaseVersion), ack.BaseHash, appliedAt, receivedAt); err != nil {
		return false, err
	}
	ct, err := tx.Exec(ctx, `
		UPDATE k8s_base_authority_node_states
		SET accepted_authority_revision=$3,accepted_payload_digest=$4
		WHERE org_id=$1 AND node_id=$2 AND accepted_authority_revision=$5`, agent.OrgID, agent.NodeID, int64(ack.AuthorityRevision), ack.AuthorityDigest, acceptedRevision)
	if err != nil || ct.RowsAffected() != 1 {
		if err == nil {
			err = ErrKubernetesOwnershipBaseAuthorityConflict
		}
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return false, nil
}

type loadedKubernetesOwnershipIssueReplay struct {
	KubernetesOwnershipBaseAuthorityIssueResult
	ExpiresAt time.Time
	Pools     []KubernetesOwnershipBaseAuthorityPoolGeneration
}

func loadKubernetesOwnershipBaseAuthorityIssueReplay(ctx context.Context, tx pgx.Tx, orgID, siteID, nodeID uuid.UUID, transitionRevision uint64, pools []KubernetesOwnershipBaseAuthorityPoolGeneration) (loadedKubernetesOwnershipIssueReplay, bool, error) {
	poolIDs := make([]uuid.UUID, 0, len(pools))
	for _, pool := range pools {
		poolID, err := uuid.Parse(pool.Scope.PoolID)
		if err != nil || poolID == uuid.Nil {
			return loadedKubernetesOwnershipIssueReplay{}, false, ErrKubernetesOwnershipBaseAuthorityInvalid
		}
		poolIDs = append(poolIDs, poolID)
	}
	if len(poolIDs) == 0 {
		return loadedKubernetesOwnershipIssueReplay{}, false, ErrKubernetesOwnershipBaseAuthorityInvalid
	}
	rows, err := tx.Query(ctx, `
		SELECT d.id,d.payload,d.payload_digest,d.expires_at,d.authority_revision
		FROM k8s_base_authority_deliveries d
		WHERE d.org_id=$1 AND d.site_id=$2 AND d.node_id=$3 AND d.transition_revision=$4
		  AND EXISTS (SELECT 1 FROM k8s_base_authority_delivery_pools p
		    WHERE p.delivery_id=d.id AND p.org_id=d.org_id AND p.site_id=d.site_id AND p.node_id=d.node_id
		      AND p.pool_id=ANY($5))
		ORDER BY d.authority_revision FOR UPDATE OF d`, orgID, siteID, nodeID, int64(transitionRevision), poolIDs)
	if err != nil {
		return loadedKubernetesOwnershipIssueReplay{}, false, err
	}
	defer rows.Close()
	var matches []loadedKubernetesOwnershipIssueReplay
	for rows.Next() {
		var value loadedKubernetesOwnershipIssueReplay
		var payload []byte
		var authorityRevision int64
		if err := rows.Scan(&value.DeliveryID, &payload, &value.PayloadDigest, &value.ExpiresAt, &authorityRevision); err != nil {
			return loadedKubernetesOwnershipIssueReplay{}, false, err
		}
		authority, digest, err := decodeKubernetesOwnershipBaseAuthorityPayload(payload)
		if err != nil || digest != value.PayloadDigest || authorityRevision <= 0 || authority.AuthorityRevision != uint64(authorityRevision) {
			return loadedKubernetesOwnershipIssueReplay{}, false, ErrKubernetesOwnershipBaseAuthorityConflict
		}
		value.Authority = authority
		matches = append(matches, value)
	}
	if err := rows.Err(); err != nil {
		return loadedKubernetesOwnershipIssueReplay{}, false, err
	}
	if len(matches) > 1 {
		return loadedKubernetesOwnershipIssueReplay{}, false, ErrKubernetesOwnershipBaseAuthorityConflict
	}
	if len(matches) == 0 {
		return loadedKubernetesOwnershipIssueReplay{}, false, nil
	}
	rows.Close()
	matches[0].Pools, err = loadKubernetesOwnershipIssuePools(ctx, tx, matches[0].DeliveryID)
	if err != nil {
		return loadedKubernetesOwnershipIssueReplay{}, false, err
	}
	return matches[0], true, nil
}

func loadKubernetesOwnershipIssuePools(ctx context.Context, tx pgx.Tx, deliveryID uuid.UUID) ([]KubernetesOwnershipBaseAuthorityPoolGeneration, error) {
	rows, err := tx.Query(ctx, `
		SELECT org_id::text,site_id::text,cluster_id::text,pool_id::text,promotion_generation
		FROM k8s_base_authority_delivery_pools WHERE delivery_id=$1 ORDER BY pool_id`, deliveryID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KubernetesOwnershipBaseAuthorityPoolGeneration
	for rows.Next() {
		var item KubernetesOwnershipBaseAuthorityPoolGeneration
		var generation int64
		if err := rows.Scan(&item.Scope.OrgID, &item.Scope.SiteID, &item.Scope.ClusterID, &item.Scope.PoolID, &generation); err != nil || generation <= 0 {
			if err == nil {
				err = ErrKubernetesOwnershipBaseAuthorityConflict
			}
			return nil, err
		}
		item.PromotionGeneration = uint64(generation)
		out = append(out, item)
	}
	return out, rows.Err()
}

func sameKubernetesOwnershipIssuePools(a, b []KubernetesOwnershipBaseAuthorityPoolGeneration) bool {
	a, b = append([]KubernetesOwnershipBaseAuthorityPoolGeneration(nil), a...), append([]KubernetesOwnershipBaseAuthorityPoolGeneration(nil), b...)
	sort.Slice(a, func(i, j int) bool { return a[i].Scope.PoolID < a[j].Scope.PoolID })
	sort.Slice(b, func(i, j int) bool { return b[i].Scope.PoolID < b[j].Scope.PoolID })
	return reflect.DeepEqual(a, b)
}

func decodeKubernetesOwnershipBaseAuthorityPayload(payload []byte) (KubernetesOwnershipBaseAuthority, string, error) {
	var value KubernetesOwnershipBaseAuthority
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return KubernetesOwnershipBaseAuthority{}, "", err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return KubernetesOwnershipBaseAuthority{}, "", ErrKubernetesOwnershipBaseAuthorityInvalid
	}
	canonical, digest, err := CanonicalKubernetesOwnershipBaseAuthority(value)
	if err != nil {
		return KubernetesOwnershipBaseAuthority{}, "", err
	}
	return canonical, digest, nil
}

var _ KubernetesOwnershipBaseAuthorityStore = (*PostgresKubernetesOwnershipBaseAuthorityStore)(nil)
var _ KubernetesOwnershipBaseAuthorityIssuer = (*PostgresKubernetesOwnershipBaseAuthorityStore)(nil)
