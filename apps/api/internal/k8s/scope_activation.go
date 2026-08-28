package k8s

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/ipalloc"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s/scopeapproval"
	"github.com/tunnexio/tunnex/apps/api/internal/pgerr"
)

const (
	clusterScopeInventoryPageLimit = 100
	clusterScopeExposurePortLimit  = 32
	clusterScopePendingFanoutLimit = 500
	clusterScopeActiveLimit        = 20
)

type ClusterScopeSetting struct {
	Enabled             bool
	Revision            int64
	EntitlementUnlocked bool
	Effective           bool
	UpdatedAt           *time.Time
}

type ClusterScopeSource struct {
	Kind string
	ID   uuid.UUID
	CIDR string
}

type ClusterScopeRecord struct {
	RuleID                uuid.UUID
	OrgID                 uuid.UUID
	ClusterID             uuid.UUID
	Source                ClusterScopeSource
	Active                bool
	Revision              int64
	InitialCandidateCount int
	CreatedByUserID       uuid.UUID
	ExpiresAt             *time.Time
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

type CreateClusterScopeInput struct {
	OrgID               uuid.UUID
	ClusterID           uuid.UUID
	Source              ClusterScopeSource
	InitialChildIDs     []uuid.UUID
	ExpiresAt           *time.Time
	Actor               *authctx.Principal
	EntitlementUnlocked bool
	Cause               string
}

type ClusterScopeInventoryPort struct {
	PortRef     uuid.UUID
	Name        *string
	Protocol    string
	ServicePort int32
}

type ClusterScopeInventoryItem struct {
	InventoryRef uuid.UUID
	Namespace    string
	Service      string
	Ports        []ClusterScopeInventoryPort
}

type ClusterScopeInventoryPage struct {
	Items      []ClusterScopeInventoryItem
	NextCursor string
	ObservedAt time.Time
	FreshUntil time.Time
}

type ClusterScopeCandidateView struct {
	ChildID        uuid.UUID
	Namespace      string
	Service        string
	Protocol       string
	ServicePort    int32
	Selected       bool
	Current        bool
	Effective      bool
	InactiveReason string
	clusterID      uuid.UUID
	serviceUID     string
	scopeActive    bool
	orgEnabled     bool
	ruleDisabled   bool
	ruleExpired    bool
}

type ClusterScopeCandidatePage struct {
	Items      []ClusterScopeCandidateView
	NextCursor string
}

type ClusterScopeMembershipView struct {
	RuleID          uuid.UUID
	ClusterID       uuid.UUID
	ChildID         uuid.UUID
	Namespace       string
	Service         string
	Protocol        string
	ServicePort     int32
	Origin          string
	Status          string
	Current         bool
	Effective       bool
	InactiveReason  string
	DecidedByUserID *uuid.UUID
	DecidedAt       *time.Time
	CreatedAt       time.Time
	serviceUID      string
	scopeActive     bool
	orgEnabled      bool
	ruleDisabled    bool
	ruleExpired     bool
}

type ClusterScopeMembershipPage struct {
	Items      []ClusterScopeMembershipView
	NextCursor string
}

type ClusterScopeReviewQueuePage struct {
	Items      []ClusterScopeMembershipView
	NextCursor string
}

const (
	clusterScopeInactiveEditionLocked        = "edition_locked"
	clusterScopeInactiveNotSelected          = "not_selected"
	clusterScopeInactivePending              = "pending"
	clusterScopeInactiveRejected             = "rejected"
	clusterScopeInactiveScopeDisabled        = "scope_disabled"
	clusterScopeInactiveOrganizationDisabled = "organization_disabled"
	clusterScopeInactiveRuleDisabled         = "rule_disabled"
	clusterScopeInactiveRuleExpired          = "rule_expired"
	clusterScopeInactiveInventoryStale       = "inventory_stale"
	clusterScopeInactiveInventoryUnavailable = "inventory_unavailable"
	clusterScopeInactiveIdentityChanged      = "identity_changed"
)

type clusterScopeEffectInput struct {
	entitlementUnlocked bool
	selected            bool
	status              string
	scopeActive         bool
	orgEnabled          bool
	ruleDisabled        bool
	ruleExpired         bool
	current             bool
	currentReason       string
}

func projectClusterScopeEffect(in clusterScopeEffectInput) (bool, string) {
	if !in.entitlementUnlocked {
		return false, clusterScopeInactiveEditionLocked
	}
	if in.status == "" && !in.selected {
		return false, clusterScopeInactiveNotSelected
	}
	switch in.status {
	case "pending":
		return false, clusterScopeInactivePending
	case "rejected":
		return false, clusterScopeInactiveRejected
	}
	if !in.scopeActive {
		return false, clusterScopeInactiveScopeDisabled
	}
	if !in.orgEnabled {
		return false, clusterScopeInactiveOrganizationDisabled
	}
	if in.ruleDisabled {
		return false, clusterScopeInactiveRuleDisabled
	}
	if in.ruleExpired {
		return false, clusterScopeInactiveRuleExpired
	}
	if !in.current {
		if in.currentReason == "" {
			in.currentReason = clusterScopeInactiveIdentityChanged
		}
		return false, in.currentReason
	}
	return true, ""
}

type ExposeInventoryServiceInput struct {
	OrgID        uuid.UUID
	ClusterID    uuid.UUID
	InventoryRef uuid.UUID
	PortRefs     []uuid.UUID
	Actor        *authctx.Principal
	Cause        string
}

type ExposeInventoryServiceResult struct {
	ServiceChildIDs []uuid.UUID
	PendingRows     int
}

func requireClusterScopeHuman(actor *authctx.Principal) (uuid.UUID, error) {
	if actor == nil || actor.UserID == uuid.Nil || actor.IsMachine() || actor.AuthMethod == authctx.AuthAgent || actor.NodeID != uuid.Nil {
		return uuid.Nil, apierr.Forbidden("human_actor_required", "a verified human organization member is required")
	}
	if !actor.EmailVerified {
		return uuid.Nil, apierr.Forbidden("email_not_verified", "verify your email before changing Kubernetes cluster-scope access")
	}
	return actor.UserID, nil
}

func clusterScopeCause(cause string) string {
	cause = authctx.SanitizeCause(cause)
	if cause == "" {
		return "operator request"
	}
	return cause
}

func (s *Service) GetClusterScopeSetting(ctx context.Context, orgID uuid.UUID, entitlementUnlocked bool) (ClusterScopeSetting, error) {
	out := ClusterScopeSetting{EntitlementUnlocked: entitlementUnlocked}
	var updated time.Time
	err := s.pool.QueryRow(ctx, `SELECT enabled,revision,updated_at FROM k8s_cluster_scope_settings WHERE org_id=$1`, orgID).
		Scan(&out.Enabled, &out.Revision, &updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return ClusterScopeSetting{}, err
	}
	out.UpdatedAt = &updated
	out.Effective = entitlementUnlocked && out.Enabled
	return out, nil
}

// SetClusterScopeSetting uses revision zero for the missing/default-OFF state.
// Exact committed retries are no-ops and therefore emit no duplicate audit.
// Disabling remains available after entitlement loss for safe withdrawal.
func (s *Service) SetClusterScopeSetting(ctx context.Context, orgID uuid.UUID, actor *authctx.Principal, entitlementUnlocked, enabled bool, expectedRevision int64, cause string) (ClusterScopeSetting, error) {
	actorID, err := requireClusterScopeHuman(actor)
	if err != nil {
		return ClusterScopeSetting{}, err
	}
	if enabled && !entitlementUnlocked {
		return ClusterScopeSetting{}, apierr.Forbidden("edition_required", "Kubernetes cluster scopes require an entitled licence")
	}
	if expectedRevision < 0 {
		return ClusterScopeSetting{}, apierr.BadRequest("invalid_expected_revision", "expected_revision cannot be negative")
	}
	cause = clusterScopeCause(cause)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ClusterScopeSetting{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := requireClusterScopeHumanMember(ctx, tx, orgID, actorID); err != nil {
		return ClusterScopeSetting{}, err
	}

	var currentEnabled bool
	var currentRevision int64
	changed := false
	err = tx.QueryRow(ctx, `SELECT enabled,revision FROM k8s_cluster_scope_settings WHERE org_id=$1 FOR UPDATE`, orgID).
		Scan(&currentEnabled, &currentRevision)
	switch {
	case errors.Is(err, pgx.ErrNoRows) && !enabled:
		// The absent row already is the locked default-OFF state.
		currentEnabled, currentRevision = false, 0
	case errors.Is(err, pgx.ErrNoRows):
		if expectedRevision != 0 {
			return ClusterScopeSetting{}, scopeRevisionConflict("cluster-scope setting")
		}
		if _, err := tx.Exec(ctx, `INSERT INTO k8s_cluster_scope_settings(org_id,enabled,revision,actor_user_id,cause) VALUES($1,$2,1,$3,$4)`, orgID, enabled, actorID, cause); err != nil {
			return ClusterScopeSetting{}, err
		}
		currentEnabled, currentRevision, changed = enabled, 1, true
	case err != nil:
		return ClusterScopeSetting{}, err
	case currentEnabled == enabled && (expectedRevision == currentRevision || expectedRevision+1 == currentRevision):
		// Exact retry/no-op.
	default:
		if expectedRevision != currentRevision {
			return ClusterScopeSetting{}, scopeRevisionConflict("cluster-scope setting")
		}
		currentRevision++
		if _, err := tx.Exec(ctx, `UPDATE k8s_cluster_scope_settings SET enabled=$2,revision=$3,actor_user_id=$4,cause=$5 WHERE org_id=$1`, orgID, enabled, currentRevision, actorID, cause); err != nil {
			return ClusterScopeSetting{}, err
		}
		currentEnabled, changed = enabled, true
	}
	if changed {
		if err := s.audit(ctx, sqlc.New(tx), orgID, actorID, "", cause, "organization", orgID.String(), "k8s.cluster_scope_setting_changed", map[string]any{
			"enabled": currentEnabled, "revision": currentRevision,
		}); err != nil {
			return ClusterScopeSetting{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return ClusterScopeSetting{}, err
	}
	if changed {
		s.pushOrg(ctx, orgID)
	}
	return s.GetClusterScopeSetting(ctx, orgID, entitlementUnlocked)
}

func (s *Service) CreateClusterScope(ctx context.Context, in CreateClusterScopeInput) (ClusterScopeRecord, error) {
	actorID, err := requireClusterScopeHuman(in.Actor)
	if err != nil {
		return ClusterScopeRecord{}, err
	}
	if !in.EntitlementUnlocked {
		return ClusterScopeRecord{}, apierr.Forbidden("edition_required", "Kubernetes cluster scopes require an entitled licence")
	}
	source, err := validateClusterScopeSource(in.Source)
	if err != nil {
		return ClusterScopeRecord{}, err
	}
	if in.ExpiresAt != nil && !in.ExpiresAt.After(time.Now()) {
		return ClusterScopeRecord{}, apierr.BadRequest("invalid_request", "expires_at must be in the future")
	}
	cause := clusterScopeCause(in.Cause)
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return ClusterScopeRecord{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := requireClusterScopeHumanMember(ctx, tx, in.OrgID, actorID); err != nil {
		return ClusterScopeRecord{}, err
	}
	if err := requireClusterScopeOptIn(ctx, tx, in.OrgID); err != nil {
		return ClusterScopeRecord{}, err
	}
	if err := validateClusterScopeSourceExists(ctx, tx, in.OrgID, source); err != nil {
		return ClusterScopeRecord{}, err
	}
	var clusterID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM k8s_clusters WHERE id=$1 AND org_id=$2 FOR UPDATE`, in.ClusterID, in.OrgID).Scan(&clusterID); errors.Is(err, pgx.ErrNoRows) {
		return ClusterScopeRecord{}, apierr.NotFound("k8s_cluster_not_found", "Kubernetes cluster not found")
	} else if err != nil {
		return ClusterScopeRecord{}, err
	}
	if err := requireClusterScopeActiveCapacity(ctx, tx, in.OrgID, in.ClusterID, uuid.Nil); err != nil {
		return ClusterScopeRecord{}, err
	}
	report, err := currentInventoryReport(ctx, tx, in.OrgID, in.ClusterID, true)
	if err != nil {
		return ClusterScopeRecord{}, scopeActivationError(err)
	}
	children, err := currentExposedInventoryChildren(ctx, tx, report.ID, in.OrgID, in.ClusterID)
	if err != nil {
		return ClusterScopeRecord{}, err
	}
	ruleID := uuid.New()
	now := time.Now().UTC()
	domainScope, err := scopeapproval.Create(scopeapproval.CreateInput{
		RuleID: ruleID, OrgID: in.OrgID, ClusterID: in.ClusterID,
		Feature:   scopeapproval.FeatureState{EntitlementUnlocked: true, OrganizationOptInEnabled: true},
		Inventory: scopeapproval.InventoryCurrent, CurrentChildren: children,
		InitialChildIDs: in.InitialChildIDs, ActorUserID: actorID, Now: now,
	}, scopeapproval.ProductionLimits())
	if err != nil {
		return ClusterScopeRecord{}, scopeActivationError(err)
	}
	if err := insertClusterScopePolicyRule(ctx, tx, ruleID, in.OrgID, in.ClusterID, source, in.ExpiresAt); err != nil {
		if pgerr.IsUnique(err) {
			return ClusterScopeRecord{}, apierr.Conflict("k8s_cluster_scope_exists", "an identical cluster scope already exists")
		}
		return ClusterScopeRecord{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO k8s_cluster_scope_grants(rule_id,org_id,cluster_id,created_by_user_id,initial_candidate_count,active,revision) VALUES($1,$2,$3,$4,$5,true,1)`,
		ruleID, in.OrgID, in.ClusterID, actorID, len(domainScope.InitialEvidence)); err != nil {
		return ClusterScopeRecord{}, err
	}
	for _, evidence := range domainScope.InitialEvidence {
		if _, err := tx.Exec(ctx, `INSERT INTO k8s_cluster_scope_initial_candidates(rule_id,org_id,cluster_id,service_child_id,namespace,service_uid,protocol,port_low,port_high,selected,inventory_report_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8,$9,$10)`,
			ruleID, in.OrgID, in.ClusterID, evidence.Identity.ChildID, evidence.Identity.Namespace, evidence.Identity.ServiceUID, string(evidence.Identity.Protocol), evidence.Identity.ServicePort, evidence.Selected, report.ID); err != nil {
			return ClusterScopeRecord{}, err
		}
	}
	for _, membership := range domainScope.Memberships {
		if err := insertScopeMembership(ctx, tx, membership); err != nil {
			return ClusterScopeRecord{}, err
		}
	}
	if err := s.audit(ctx, sqlc.New(tx), in.OrgID, actorID, "", cause, "policy_rule", ruleID.String(), "k8s.cluster_scope_created", map[string]any{
		"cluster_id": in.ClusterID.String(), "initial_candidate_count": len(domainScope.InitialEvidence),
		"initial_selected_count": len(domainScope.Memberships),
	}); err != nil {
		return ClusterScopeRecord{}, err
	}
	for _, membership := range domainScope.Memberships {
		if err := s.audit(ctx, sqlc.New(tx), in.OrgID, actorID, "", cause, "k8s_service", membership.Identity.ChildID.String(), "k8s.cluster_scope_initial_child_approved", map[string]any{
			"rule_id": ruleID.String(), "origin": "initial",
		}); err != nil {
			return ClusterScopeRecord{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return ClusterScopeRecord{}, err
	}
	s.pushOrg(ctx, in.OrgID)
	return s.GetClusterScope(ctx, in.OrgID, ruleID)
}

func (s *Service) GetClusterScope(ctx context.Context, orgID, ruleID uuid.UUID) (ClusterScopeRecord, error) {
	return scanClusterScope(s.pool.QueryRow(ctx, clusterScopeSelect+` WHERE g.org_id=$1 AND g.rule_id=$2`, orgID, ruleID))
}

func (s *Service) ListClusterScopes(ctx context.Context, orgID uuid.UUID) ([]ClusterScopeRecord, error) {
	rows, err := s.pool.Query(ctx, clusterScopeSelect+` WHERE g.org_id=$1 ORDER BY g.created_at,g.rule_id`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ClusterScopeRecord, 0)
	for rows.Next() {
		record, err := scanClusterScope(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

func (s *Service) ListClusterScopeCandidates(ctx context.Context, orgID, ruleID uuid.UUID, entitlementUnlocked bool, cursor string, limit int) (ClusterScopeCandidatePage, error) {
	limit, err := clusterScopeReadLimit(limit)
	if err != nil {
		return ClusterScopeCandidatePage{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return ClusterScopeCandidatePage{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := requireClusterScopeExists(ctx, tx, orgID, ruleID); err != nil {
		return ClusterScopeCandidatePage{}, err
	}
	cur, err := decodeScopeReadCursor(cursor, "candidates", ruleID)
	if err != nil {
		return ClusterScopeCandidatePage{}, err
	}
	rows, err := tx.Query(ctx, `
		SELECT c.service_child_id,c.namespace,s.name,c.protocol,c.port_low,c.selected,c.cluster_id,c.service_uid,
		       g.active,COALESCE(setting.enabled,false),r.disabled,(r.expires_at IS NOT NULL AND r.expires_at<=now())
		FROM k8s_cluster_scope_initial_candidates c
		JOIN k8s_services s ON s.id=c.service_child_id AND s.org_id=c.org_id AND s.cluster_id=c.cluster_id
		JOIN k8s_cluster_scope_grants g ON g.rule_id=c.rule_id AND g.org_id=c.org_id AND g.cluster_id=c.cluster_id
		JOIN policy_rules r ON r.id=g.rule_id AND r.org_id=g.org_id
		LEFT JOIN k8s_cluster_scope_settings setting ON setting.org_id=c.org_id
		WHERE c.org_id=$1 AND c.rule_id=$2
		  AND (c.namespace,s.name,c.protocol,c.port_low,c.service_child_id)>($3,$4,$5,$6,$7)
		ORDER BY c.namespace,s.name,c.protocol,c.port_low,c.service_child_id
		LIMIT $8`, orgID, ruleID, cur.Namespace, cur.Service, cur.Protocol, cur.ServicePort, cur.ChildID, limit+1)
	if err != nil {
		return ClusterScopeCandidatePage{}, err
	}
	defer rows.Close()
	items := make([]ClusterScopeCandidateView, 0, limit+1)
	for rows.Next() {
		var item ClusterScopeCandidateView
		if err := rows.Scan(&item.ChildID, &item.Namespace, &item.Service, &item.Protocol, &item.ServicePort, &item.Selected,
			&item.clusterID, &item.serviceUID, &item.scopeActive, &item.orgEnabled, &item.ruleDisabled, &item.ruleExpired); err != nil {
			return ClusterScopeCandidatePage{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return ClusterScopeCandidatePage{}, err
	}
	rows.Close()
	if err := projectClusterScopeCandidates(ctx, tx, orgID, entitlementUnlocked, items); err != nil {
		return ClusterScopeCandidatePage{}, err
	}
	page := ClusterScopeCandidatePage{Items: items}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor, err = encodeScopeReadCursor(scopeReadCursor{
			Kind: "candidates", BoundaryID: ruleID, Namespace: last.Namespace, Service: last.Service,
			Protocol: last.Protocol, ServicePort: last.ServicePort, ChildID: last.ChildID,
		})
		if err != nil {
			return ClusterScopeCandidatePage{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return ClusterScopeCandidatePage{}, err
	}
	return page, nil
}

func (s *Service) ListClusterScopeMemberships(ctx context.Context, orgID, ruleID uuid.UUID, entitlementUnlocked bool, cursor string, limit int) (ClusterScopeMembershipPage, error) {
	limit, err := clusterScopeReadLimit(limit)
	if err != nil {
		return ClusterScopeMembershipPage{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return ClusterScopeMembershipPage{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := requireClusterScopeExists(ctx, tx, orgID, ruleID); err != nil {
		return ClusterScopeMembershipPage{}, err
	}
	cur, err := decodeScopeReadCursor(cursor, "memberships", ruleID)
	if err != nil {
		return ClusterScopeMembershipPage{}, err
	}
	rows, err := tx.Query(ctx, clusterScopeMembershipReadSelect+`
		WHERE m.org_id=$1 AND m.rule_id=$2
		  AND (m.namespace,s.name,m.protocol,m.port_low,m.service_child_id)>($3,$4,$5,$6,$7)
		ORDER BY m.namespace,s.name,m.protocol,m.port_low,m.service_child_id
		LIMIT $8`, orgID, ruleID, cur.Namespace, cur.Service, cur.Protocol, cur.ServicePort, cur.ChildID, limit+1)
	if err != nil {
		return ClusterScopeMembershipPage{}, err
	}
	defer rows.Close()
	items := make([]ClusterScopeMembershipView, 0, limit+1)
	for rows.Next() {
		item, err := scanClusterScopeMembershipView(rows)
		if err != nil {
			return ClusterScopeMembershipPage{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return ClusterScopeMembershipPage{}, err
	}
	rows.Close()
	if err := projectClusterScopeMemberships(ctx, tx, orgID, entitlementUnlocked, items); err != nil {
		return ClusterScopeMembershipPage{}, err
	}
	page := ClusterScopeMembershipPage{Items: items}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor, err = encodeScopeReadCursor(scopeReadCursor{
			Kind: "memberships", BoundaryID: ruleID, Namespace: last.Namespace, Service: last.Service,
			Protocol: last.Protocol, ServicePort: last.ServicePort, ChildID: last.ChildID,
		})
		if err != nil {
			return ClusterScopeMembershipPage{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return ClusterScopeMembershipPage{}, err
	}
	return page, nil
}

func (s *Service) ListClusterScopeReviewQueue(ctx context.Context, orgID uuid.UUID, entitlementUnlocked bool, cursor string, limit int) (ClusterScopeReviewQueuePage, error) {
	limit, err := clusterScopeReadLimit(limit)
	if err != nil {
		return ClusterScopeReviewQueuePage{}, err
	}
	cur, err := decodeScopeReadCursor(cursor, "review_queue", orgID)
	if err != nil {
		return ClusterScopeReviewQueuePage{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return ClusterScopeReviewQueuePage{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, clusterScopeMembershipReadSelect+`
		WHERE m.org_id=$1 AND m.status='pending'
		  AND (m.created_at,m.rule_id,m.service_child_id)>($2,$3,$4)
		ORDER BY m.created_at,m.rule_id,m.service_child_id
		LIMIT $5`, orgID, cur.CreatedAt, cur.RuleID, cur.ChildID, limit+1)
	if err != nil {
		return ClusterScopeReviewQueuePage{}, err
	}
	defer rows.Close()
	items := make([]ClusterScopeMembershipView, 0, limit+1)
	for rows.Next() {
		item, err := scanClusterScopeMembershipView(rows)
		if err != nil {
			return ClusterScopeReviewQueuePage{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return ClusterScopeReviewQueuePage{}, err
	}
	rows.Close()
	if err := projectClusterScopeMemberships(ctx, tx, orgID, entitlementUnlocked, items); err != nil {
		return ClusterScopeReviewQueuePage{}, err
	}
	page := ClusterScopeReviewQueuePage{Items: items}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor, err = encodeScopeReadCursor(scopeReadCursor{
			Kind: "review_queue", BoundaryID: orgID, CreatedAt: last.CreatedAt, RuleID: last.RuleID, ChildID: last.ChildID,
		})
		if err != nil {
			return ClusterScopeReviewQueuePage{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return ClusterScopeReviewQueuePage{}, err
	}
	return page, nil
}

func (s *Service) SetClusterScopeActive(ctx context.Context, orgID, ruleID uuid.UUID, actor *authctx.Principal, entitlementUnlocked, active bool, expectedRevision int64, cause string) (ClusterScopeRecord, error) {
	actorID, err := requireClusterScopeHuman(actor)
	if err != nil {
		return ClusterScopeRecord{}, err
	}
	if expectedRevision < 1 {
		return ClusterScopeRecord{}, apierr.BadRequest("invalid_expected_revision", "expected_revision must be positive")
	}
	if active && !entitlementUnlocked {
		return ClusterScopeRecord{}, apierr.Forbidden("edition_required", "Kubernetes cluster scopes require an entitled licence")
	}
	cause = clusterScopeCause(cause)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ClusterScopeRecord{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := requireClusterScopeHumanMember(ctx, tx, orgID, actorID); err != nil {
		return ClusterScopeRecord{}, err
	}
	if active {
		if err := requireClusterScopeOptIn(ctx, tx, orgID); err != nil {
			return ClusterScopeRecord{}, err
		}
	}
	var clusterID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT cluster_id FROM k8s_cluster_scope_grants WHERE rule_id=$1 AND org_id=$2`, ruleID, orgID).Scan(&clusterID); errors.Is(err, pgx.ErrNoRows) {
		return ClusterScopeRecord{}, apierr.NotFound("k8s_cluster_scope_not_found", "Kubernetes cluster scope not found")
	} else if err != nil {
		return ClusterScopeRecord{}, err
	}
	var lockedClusterID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM k8s_clusters WHERE id=$1 AND org_id=$2 FOR UPDATE`, clusterID, orgID).Scan(&lockedClusterID); errors.Is(err, pgx.ErrNoRows) {
		return ClusterScopeRecord{}, apierr.NotFound("k8s_cluster_not_found", "Kubernetes cluster not found")
	} else if err != nil {
		return ClusterScopeRecord{}, err
	}
	var currentActive bool
	var currentRevision int64
	if err := tx.QueryRow(ctx, `SELECT active,revision FROM k8s_cluster_scope_grants WHERE rule_id=$1 AND org_id=$2 FOR UPDATE`, ruleID, orgID).Scan(&currentActive, &currentRevision); errors.Is(err, pgx.ErrNoRows) {
		return ClusterScopeRecord{}, apierr.NotFound("k8s_cluster_scope_not_found", "Kubernetes cluster scope not found")
	} else if err != nil {
		return ClusterScopeRecord{}, err
	}
	changed := false
	if currentActive == active && (expectedRevision == currentRevision || expectedRevision+1 == currentRevision) {
		// Exact retry/no-op.
	} else {
		if expectedRevision != currentRevision {
			return ClusterScopeRecord{}, scopeRevisionConflict("cluster scope")
		}
		if active {
			if err := requireClusterScopeActiveCapacity(ctx, tx, orgID, clusterID, ruleID); err != nil {
				return ClusterScopeRecord{}, err
			}
		}
		currentRevision++
		if _, err := tx.Exec(ctx, `UPDATE k8s_cluster_scope_grants SET active=$3,revision=$4 WHERE rule_id=$1 AND org_id=$2`, ruleID, orgID, active, currentRevision); err != nil {
			return ClusterScopeRecord{}, err
		}
		changed = true
	}
	if changed {
		action := "k8s.cluster_scope_disabled"
		if active {
			action = "k8s.cluster_scope_enabled"
		}
		if err := s.audit(ctx, sqlc.New(tx), orgID, actorID, "", cause, "policy_rule", ruleID.String(), action, map[string]any{"revision": currentRevision}); err != nil {
			return ClusterScopeRecord{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return ClusterScopeRecord{}, err
	}
	if changed {
		s.pushOrg(ctx, orgID)
	}
	return s.GetClusterScope(ctx, orgID, ruleID)
}

func (s *Service) DeleteClusterScope(ctx context.Context, orgID, ruleID uuid.UUID, actor *authctx.Principal, expectedRevision int64, cause string) error {
	actorID, err := requireClusterScopeHuman(actor)
	if err != nil {
		return err
	}
	if expectedRevision < 1 {
		return apierr.BadRequest("invalid_expected_revision", "expected_revision must be positive")
	}
	cause = clusterScopeCause(cause)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := requireClusterScopeHumanMember(ctx, tx, orgID, actorID); err != nil {
		return err
	}
	var currentRevision int64
	var pending, approved, rejected, candidates int
	if err := tx.QueryRow(ctx, `SELECT g.revision,
		(SELECT count(*) FROM k8s_cluster_scope_memberships m WHERE m.rule_id=g.rule_id AND m.status='pending'),
		(SELECT count(*) FROM k8s_cluster_scope_memberships m WHERE m.rule_id=g.rule_id AND m.status='approved'),
		(SELECT count(*) FROM k8s_cluster_scope_memberships m WHERE m.rule_id=g.rule_id AND m.status='rejected'),
		(SELECT count(*) FROM k8s_cluster_scope_initial_candidates c WHERE c.rule_id=g.rule_id)
		FROM k8s_cluster_scope_grants g WHERE g.rule_id=$1 AND g.org_id=$2 FOR UPDATE`, ruleID, orgID).
		Scan(&currentRevision, &pending, &approved, &rejected, &candidates); errors.Is(err, pgx.ErrNoRows) {
		return apierr.NotFound("k8s_cluster_scope_not_found", "Kubernetes cluster scope not found")
	} else if err != nil {
		return err
	}
	if expectedRevision != currentRevision {
		return scopeRevisionConflict("cluster scope")
	}
	if tag, err := tx.Exec(ctx, `DELETE FROM policy_rules WHERE id=$1 AND org_id=$2 AND dst_kind='k8s_cluster_scope'`, ruleID, orgID); err != nil {
		return err
	} else if tag.RowsAffected() != 1 {
		return apierr.NotFound("k8s_cluster_scope_not_found", "Kubernetes cluster scope not found")
	}
	if err := s.audit(ctx, sqlc.New(tx), orgID, actorID, "", cause, "policy_rule", ruleID.String(), "k8s.cluster_scope_deleted", map[string]any{
		"revision": currentRevision, "pending_deleted": pending, "approved_deleted": approved,
		"rejected_deleted": rejected, "initial_candidates_deleted": candidates,
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.pushOrg(ctx, orgID)
	return nil
}

func (s *Service) DecideClusterScopeMembership(ctx context.Context, orgID, ruleID, childID uuid.UUID, actor *authctx.Principal, entitlementUnlocked bool, decision scopeapproval.Status, cause string) (ClusterScopeMembershipView, bool, error) {
	actorID, err := requireClusterScopeHuman(actor)
	if err != nil {
		return ClusterScopeMembershipView{}, false, err
	}
	if !entitlementUnlocked {
		return ClusterScopeMembershipView{}, false, apierr.Forbidden("edition_required", "Kubernetes cluster scopes require an entitled licence")
	}
	cause = clusterScopeCause(cause)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ClusterScopeMembershipView{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := requireClusterScopeHumanMember(ctx, tx, orgID, actorID); err != nil {
		return ClusterScopeMembershipView{}, false, err
	}
	if err := requireClusterScopeOptIn(ctx, tx, orgID); err != nil {
		return ClusterScopeMembershipView{}, false, err
	}
	var clusterID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT cluster_id FROM k8s_cluster_scope_grants WHERE rule_id=$1 AND org_id=$2`, ruleID, orgID).Scan(&clusterID); errors.Is(err, pgx.ErrNoRows) {
		return ClusterScopeMembershipView{}, false, apierr.NotFound("k8s_cluster_scope_not_found", "Kubernetes cluster scope not found")
	} else if err != nil {
		return ClusterScopeMembershipView{}, false, err
	}
	var lockedClusterID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM k8s_clusters WHERE id=$1 AND org_id=$2 FOR UPDATE`, clusterID, orgID).Scan(&lockedClusterID); errors.Is(err, pgx.ErrNoRows) {
		return ClusterScopeMembershipView{}, false, apierr.NotFound("k8s_cluster_not_found", "Kubernetes cluster not found")
	} else if err != nil {
		return ClusterScopeMembershipView{}, false, err
	}
	domainScope, active, err := loadDomainScopeForUpdate(ctx, tx, orgID, ruleID)
	if err != nil {
		return ClusterScopeMembershipView{}, false, err
	}
	if !active {
		return ClusterScopeMembershipView{}, false, apierr.Conflict("k8s_cluster_scope_disabled", "enable the Kubernetes cluster scope before deciding memberships")
	}
	membership, ok := findScopeMembership(domainScope.Memberships, childID)
	if !ok {
		return ClusterScopeMembershipView{}, false, apierr.NotFound("k8s_cluster_scope_membership_not_found", "Kubernetes cluster-scope membership not found")
	}
	child := scopeapproval.ExactPortChild{Identity: membership.Identity}
	if membership.Status == scopeapproval.StatusPending {
		child.Live, child.UIDAttributionCurrent, err = currentExactChildState(ctx, tx, membership.Identity)
		if err != nil {
			return ClusterScopeMembershipView{}, false, scopeActivationError(err)
		}
	}
	result, err := scopeapproval.Decide(domainScope, child, decision, scopeapproval.FeatureState{EntitlementUnlocked: true, OrganizationOptInEnabled: true}, actorID, time.Now().UTC(), scopeapproval.ProductionLimits())
	if err != nil {
		return ClusterScopeMembershipView{}, false, scopeActivationError(err)
	}
	updated, _ := findScopeMembership(result.Scope.Memberships, childID)
	if result.Changed {
		tag, err := tx.Exec(ctx, `UPDATE k8s_cluster_scope_memberships SET status=$4,decided_by_user_id=$5,decided_at=$6 WHERE rule_id=$1 AND org_id=$2 AND service_child_id=$3 AND status='pending'`,
			ruleID, orgID, childID, string(updated.Status), actorID, *updated.DecidedAt)
		if err != nil {
			return ClusterScopeMembershipView{}, false, err
		}
		if tag.RowsAffected() != 1 {
			return ClusterScopeMembershipView{}, false, apierr.Conflict("k8s_scope_decision_conflict", "the Kubernetes Service membership decision changed; reload and retry")
		}
		action := "k8s.cluster_scope_later_child_approved"
		if decision == scopeapproval.StatusRejected {
			action = "k8s.cluster_scope_later_child_rejected"
		}
		if err := s.audit(ctx, sqlc.New(tx), orgID, actorID, "", cause, "k8s_service", childID.String(), action, map[string]any{"rule_id": ruleID.String()}); err != nil {
			return ClusterScopeMembershipView{}, false, err
		}
	}
	view, err := scanClusterScopeMembershipView(tx.QueryRow(ctx, clusterScopeMembershipReadSelect+`
		WHERE m.org_id=$1 AND m.rule_id=$2 AND m.service_child_id=$3`, orgID, ruleID, childID))
	if err != nil {
		return ClusterScopeMembershipView{}, false, err
	}
	projected := []ClusterScopeMembershipView{view}
	if err := projectClusterScopeMemberships(ctx, tx, orgID, entitlementUnlocked, projected); err != nil {
		return ClusterScopeMembershipView{}, false, err
	}
	view = projected[0]
	if err := tx.Commit(ctx); err != nil {
		return ClusterScopeMembershipView{}, false, err
	}
	if result.Changed {
		s.pushOrg(ctx, orgID)
	}
	return view, result.Changed, nil
}

func (s *Service) ListClusterScopeInventory(ctx context.Context, orgID, clusterID uuid.UUID, cursor string, limit int) (ClusterScopeInventoryPage, error) {
	if limit <= 0 {
		limit = clusterScopeInventoryPageLimit
	}
	if limit > clusterScopeInventoryPageLimit {
		return ClusterScopeInventoryPage{}, apierr.BadRequest("invalid_page_limit", "inventory page limit cannot exceed 100")
	}
	report, err := currentInventoryReport(ctx, s.pool, orgID, clusterID, false)
	if err != nil {
		return ClusterScopeInventoryPage{}, scopeActivationError(err)
	}
	cur, err := decodeScopeInventoryCursor(cursor)
	if err != nil {
		return ClusterScopeInventoryPage{}, err
	}
	if cur.ReportID != uuid.Nil && cur.ReportID != report.ID {
		return ClusterScopeInventoryPage{}, apierr.Conflict("k8s_inventory_cursor_stale", "the Kubernetes inventory changed; restart paging")
	}
	rows, err := s.pool.Query(ctx, `
		SELECT i.inventory_ref,i.namespace,i.service,
		       COALESCE(jsonb_agg(jsonb_build_object('port_ref',p.port_ref,'name',p.name,'protocol',p.protocol,'service_port',p.service_port)
		                ORDER BY p.protocol,p.service_port,p.port_ref),'[]'::jsonb)
		FROM k8s_service_inventory_items i
		JOIN k8s_service_inventory_ports p ON p.report_id=i.report_id AND p.inventory_ref=i.inventory_ref
		WHERE i.report_id=$1 AND (i.namespace,i.service,i.inventory_ref)>($2,$3,$4)
		GROUP BY i.inventory_ref,i.namespace,i.service
		ORDER BY i.namespace,i.service,i.inventory_ref
		LIMIT $5`, report.ID, cur.Namespace, cur.Service, cur.InventoryRef, limit+1)
	if err != nil {
		return ClusterScopeInventoryPage{}, err
	}
	defer rows.Close()
	items := make([]ClusterScopeInventoryItem, 0, limit+1)
	for rows.Next() {
		var item ClusterScopeInventoryItem
		var portsJSON []byte
		if err := rows.Scan(&item.InventoryRef, &item.Namespace, &item.Service, &portsJSON); err != nil {
			return ClusterScopeInventoryPage{}, err
		}
		var ports []struct {
			PortRef     uuid.UUID `json:"port_ref"`
			Name        *string   `json:"name"`
			Protocol    string    `json:"protocol"`
			ServicePort int32     `json:"service_port"`
		}
		if err := json.Unmarshal(portsJSON, &ports); err != nil {
			return ClusterScopeInventoryPage{}, err
		}
		item.Ports = make([]ClusterScopeInventoryPort, len(ports))
		for i, port := range ports {
			item.Ports[i] = ClusterScopeInventoryPort(port)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return ClusterScopeInventoryPage{}, err
	}
	page := ClusterScopeInventoryPage{Items: items, ObservedAt: report.ObservedAt, FreshUntil: report.FreshUntil}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor, err = encodeScopeInventoryCursor(scopeInventoryCursor{ReportID: report.ID, Namespace: last.Namespace, Service: last.Service, InventoryRef: last.InventoryRef})
		if err != nil {
			return ClusterScopeInventoryPage{}, err
		}
	}
	return page, nil
}

// ExposeInventoryService atomically exposes every requested exact port and
// appends one pending membership per active scope. A stale ref, duplicate port,
// or fan-out overflow rolls back the entire request.
func (s *Service) ExposeInventoryService(ctx context.Context, in ExposeInventoryServiceInput) (ExposeInventoryServiceResult, error) {
	actorID, actorSystem, actorMemberID, actorCause, err := clusterScopeExposureActor(in.Actor, in.Cause)
	if err != nil {
		return ExposeInventoryServiceResult{}, err
	}
	if in.InventoryRef == uuid.Nil || len(in.PortRefs) == 0 || len(in.PortRefs) > clusterScopeExposurePortLimit {
		return ExposeInventoryServiceResult{}, apierr.BadRequest("invalid_inventory_selection", "select between 1 and 32 exact Service ports")
	}
	seen := make(map[uuid.UUID]struct{}, len(in.PortRefs))
	for _, ref := range in.PortRefs {
		if ref == uuid.Nil {
			return ExposeInventoryServiceResult{}, apierr.BadRequest("invalid_inventory_selection", "port references must be non-empty")
		}
		if _, duplicate := seen[ref]; duplicate {
			return ExposeInventoryServiceResult{}, apierr.BadRequest("duplicate_inventory_port", "each exact Service port may be selected once")
		}
		seen[ref] = struct{}{}
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return ExposeInventoryServiceResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := requireClusterScopeExposureMember(ctx, tx, in.OrgID, actorMemberID); err != nil {
		return ExposeInventoryServiceResult{}, err
	}
	var vipRange string
	var dnsVIP *string
	if err := tx.QueryRow(ctx, `SELECT vip_range::text,host(dns_vip) FROM k8s_clusters WHERE id=$1 AND org_id=$2 FOR UPDATE`, in.ClusterID, in.OrgID).Scan(&vipRange, &dnsVIP); errors.Is(err, pgx.ErrNoRows) {
		return ExposeInventoryServiceResult{}, apierr.NotFound("k8s_cluster_not_found", "Kubernetes cluster not found")
	} else if err != nil {
		return ExposeInventoryServiceResult{}, err
	}
	report, err := currentInventoryReport(ctx, tx, in.OrgID, in.ClusterID, true)
	if err != nil {
		return ExposeInventoryServiceResult{}, scopeActivationError(err)
	}
	var namespace, service, serviceUID string
	if err := tx.QueryRow(ctx, `SELECT namespace,service,service_uid FROM k8s_service_inventory_items WHERE report_id=$1 AND inventory_ref=$2 AND org_id=$3 AND cluster_id=$4`, report.ID, in.InventoryRef, in.OrgID, in.ClusterID).
		Scan(&namespace, &service, &serviceUID); errors.Is(err, pgx.ErrNoRows) {
		return ExposeInventoryServiceResult{}, apierr.Conflict("k8s_inventory_reference_stale", "the selected Kubernetes Service is not in the current inventory")
	} else if err != nil {
		return ExposeInventoryServiceResult{}, err
	}
	type selectedPort struct {
		Ref      uuid.UUID
		Protocol scopeapproval.Protocol
		Port     int32
	}
	portRows, err := tx.Query(ctx, `SELECT port_ref,protocol,service_port FROM k8s_service_inventory_ports WHERE report_id=$1 AND inventory_ref=$2 AND port_ref=ANY($3::uuid[]) ORDER BY protocol,service_port,port_ref`, report.ID, in.InventoryRef, in.PortRefs)
	if err != nil {
		return ExposeInventoryServiceResult{}, err
	}
	ports := make([]selectedPort, 0, len(in.PortRefs))
	for portRows.Next() {
		var p selectedPort
		var protocol string
		if err := portRows.Scan(&p.Ref, &protocol, &p.Port); err != nil {
			portRows.Close()
			return ExposeInventoryServiceResult{}, err
		}
		p.Protocol = scopeapproval.Protocol(protocol)
		ports = append(ports, p)
	}
	portRows.Close()
	if err := portRows.Err(); err != nil {
		return ExposeInventoryServiceResult{}, err
	}
	if len(ports) != len(in.PortRefs) {
		return ExposeInventoryServiceResult{}, apierr.Conflict("k8s_inventory_port_stale", "one or more selected Service ports are not in the current inventory")
	}
	var alreadyExposed int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM k8s_services s WHERE s.org_id=$1 AND s.cluster_id=$2 AND s.namespace=$3 AND s.name=$4 AND s.deleted_at IS NULL AND (s.protocol,s.port_low) IN (SELECT protocol,service_port FROM k8s_service_inventory_ports WHERE report_id=$5 AND inventory_ref=$6 AND port_ref=ANY($7::uuid[]))`,
		in.OrgID, in.ClusterID, namespace, service, report.ID, in.InventoryRef, in.PortRefs).Scan(&alreadyExposed); err != nil {
		return ExposeInventoryServiceResult{}, err
	}
	if alreadyExposed != 0 {
		return ExposeInventoryServiceResult{}, apierr.Conflict("k8s_service_port_already_exposed", "one or more selected Service ports are already exposed")
	}
	usedRows, err := tx.Query(ctx, `SELECT host(vip) FROM k8s_services WHERE org_id=$1 AND cluster_id=$2 AND deleted_at IS NULL`, in.OrgID, in.ClusterID)
	if err != nil {
		return ExposeInventoryServiceResult{}, err
	}
	used := make([]string, 0)
	for usedRows.Next() {
		var vip string
		if err := usedRows.Scan(&vip); err != nil {
			usedRows.Close()
			return ExposeInventoryServiceResult{}, err
		}
		used = append(used, vip)
	}
	usedRows.Close()
	if err := usedRows.Err(); err != nil {
		return ExposeInventoryServiceResult{}, err
	}
	if dnsVIP != nil {
		used = append(used, *dnsVIP)
	}
	vip, err := ipalloc.Allocate(vipRange, used)
	if errors.Is(err, ipalloc.ErrPoolExhausted) {
		return ExposeInventoryServiceResult{}, apierr.Conflict("vip_range_exhausted", "the cluster VIP range is full")
	}
	if err != nil {
		return ExposeInventoryServiceResult{}, err
	}
	activeRows, err := tx.Query(ctx, `SELECT rule_id FROM k8s_cluster_scope_grants WHERE org_id=$1 AND cluster_id=$2 AND active ORDER BY rule_id FOR UPDATE`, in.OrgID, in.ClusterID)
	if err != nil {
		return ExposeInventoryServiceResult{}, err
	}
	activeScopeIDs := make([]uuid.UUID, 0)
	for activeRows.Next() {
		var id uuid.UUID
		if err := activeRows.Scan(&id); err != nil {
			activeRows.Close()
			return ExposeInventoryServiceResult{}, err
		}
		activeScopeIDs = append(activeScopeIDs, id)
	}
	activeRows.Close()
	if err := activeRows.Err(); err != nil {
		return ExposeInventoryServiceResult{}, err
	}
	pendingRows := len(activeScopeIDs) * len(ports)
	if pendingRows > clusterScopePendingFanoutLimit {
		return ExposeInventoryServiceResult{}, apierr.Conflict("k8s_cluster_scope_pending_fanout_limit", "exposing these ports would create more than 500 pending scope reviews")
	}
	children := make([]scopeapproval.ExactPortChild, 0, len(ports))
	for _, port := range ports {
		var childID uuid.UUID
		if err := tx.QueryRow(ctx, `INSERT INTO k8s_services(org_id,cluster_id,name,namespace,protocol,port_low,port_high,vip) VALUES($1,$2,$3,$4,$5,$6,$6,$7::inet) RETURNING id`,
			in.OrgID, in.ClusterID, service, namespace, string(port.Protocol), port.Port, vip).Scan(&childID); err != nil {
			if pgerr.IsUnique(err) {
				return ExposeInventoryServiceResult{}, apierr.Conflict("k8s_service_port_already_exposed", "one or more selected Service ports are already exposed")
			}
			return ExposeInventoryServiceResult{}, err
		}
		children = append(children, scopeapproval.ExactPortChild{Identity: scopeapproval.ExactChildIdentity{
			ChildID: childID, OrgID: in.OrgID, ClusterID: in.ClusterID, Namespace: namespace,
			ServiceUID: serviceUID, Protocol: port.Protocol, ServicePort: port.Port,
		}, Live: true, UIDAttributionCurrent: true})
	}
	for _, scopeID := range activeScopeIDs {
		domainScope, active, err := loadDomainScopeForUpdate(ctx, tx, in.OrgID, scopeID)
		if err != nil {
			return ExposeInventoryServiceResult{}, err
		}
		if !active {
			return ExposeInventoryServiceResult{}, apierr.Conflict("k8s_cluster_scope_changed", "a Kubernetes cluster scope changed; retry the exposure")
		}
		for _, child := range children {
			next, err := scopeapproval.AddLaterExposure(domainScope, child, scopeapproval.ProductionLimits())
			if err != nil {
				return ExposeInventoryServiceResult{}, scopeActivationError(err)
			}
			membership, _ := findScopeMembership(next.Memberships, child.Identity.ChildID)
			if err := insertScopeMembership(ctx, tx, membership); err != nil {
				return ExposeInventoryServiceResult{}, err
			}
			if err := s.audit(ctx, sqlc.New(tx), in.OrgID, actorID, actorSystem, actorCause, "k8s_service", child.Identity.ChildID.String(), "k8s.cluster_scope_later_child_pending", map[string]any{
				"rule_id": scopeID.String(), "origin": "later",
			}); err != nil {
				return ExposeInventoryServiceResult{}, err
			}
			domainScope = next
		}
	}
	for _, child := range children {
		if err := s.audit(ctx, sqlc.New(tx), in.OrgID, actorID, actorSystem, actorCause, "k8s_service", child.Identity.ChildID.String(), "k8s.service_exposed", map[string]any{
			"cluster_id": in.ClusterID.String(), "pending_scope_reviews": len(activeScopeIDs),
		}); err != nil {
			return ExposeInventoryServiceResult{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return ExposeInventoryServiceResult{}, err
	}
	s.pushOrg(ctx, in.OrgID)
	ids := make([]uuid.UUID, len(children))
	for i, child := range children {
		ids[i] = child.Identity.ChildID
	}
	return ExposeInventoryServiceResult{ServiceChildIDs: ids, PendingRows: pendingRows}, nil
}

func clusterScopeExposureActor(actor *authctx.Principal, requestedCause string) (actorUserID uuid.UUID, actorSystem string, memberUserID uuid.UUID, cause string, err error) {
	if actor == nil || actor.AuthMethod == authctx.AuthAgent || actor.NodeID != uuid.Nil {
		return uuid.Nil, "", uuid.Nil, "", apierr.Forbidden("actor_required", "an authenticated organization operator is required")
	}
	if actor.IsMachine() {
		if actor.OwnerUserID == uuid.Nil {
			return uuid.Nil, "", uuid.Nil, "", apierr.Forbidden("actor_required", "the machine credential must have a current human owner")
		}
		actorUserID, actorSystem, cause = actor.AuditActor()
		if actorSystem == "" {
			return uuid.Nil, "", uuid.Nil, "", apierr.Forbidden("actor_required", "the machine credential audit identity is invalid")
		}
		if requestedCause != "" {
			cause = clusterScopeCause(requestedCause)
		}
		return actorUserID, actorSystem, actor.OwnerUserID, cause, nil
	}
	if actor.UserID == uuid.Nil {
		return uuid.Nil, "", uuid.Nil, "", apierr.Forbidden("actor_required", "an authenticated organization operator is required")
	}
	return actor.UserID, "", actor.UserID, clusterScopeCause(requestedCause), nil
}

const clusterScopeSelect = `
	SELECT g.rule_id,g.org_id,g.cluster_id,g.active,g.revision,g.initial_candidate_count,
	       g.created_by_user_id,g.created_at,g.updated_at,r.src_kind,r.src_group_id,
	       r.src_user_id,r.src_site_id,r.src_cidr,r.src_device_id,r.src_agent_group_id,r.expires_at
	FROM k8s_cluster_scope_grants g
	JOIN policy_rules r ON r.id=g.rule_id AND r.org_id=g.org_id
`

const clusterScopeMembershipReadSelect = `
	SELECT m.rule_id,m.cluster_id,m.service_child_id,m.namespace,s.name,m.protocol,m.port_low,
	       m.origin,m.status,m.decided_by_user_id,m.decided_at,m.created_at,m.service_uid,
	       g.active,COALESCE(setting.enabled,false),r.disabled,(r.expires_at IS NOT NULL AND r.expires_at<=now())
	FROM k8s_cluster_scope_memberships m
	JOIN k8s_services s ON s.id=m.service_child_id AND s.org_id=m.org_id AND s.cluster_id=m.cluster_id
	JOIN k8s_cluster_scope_grants g ON g.rule_id=m.rule_id AND g.org_id=m.org_id AND g.cluster_id=m.cluster_id
	JOIN policy_rules r ON r.id=g.rule_id AND r.org_id=g.org_id
	LEFT JOIN k8s_cluster_scope_settings setting ON setting.org_id=m.org_id
`

type clusterScopeScanner interface {
	Scan(dest ...any) error
}

func scanClusterScope(row clusterScopeScanner) (ClusterScopeRecord, error) {
	var out ClusterScopeRecord
	var srcGroup, srcUser, srcSite, srcDevice, srcAgentGroup pgtype.UUID
	var srcCIDR *string
	var expires pgtype.Timestamptz
	if err := row.Scan(&out.RuleID, &out.OrgID, &out.ClusterID, &out.Active, &out.Revision, &out.InitialCandidateCount,
		&out.CreatedByUserID, &out.CreatedAt, &out.UpdatedAt, &out.Source.Kind, &srcGroup,
		&srcUser, &srcSite, &srcCIDR, &srcDevice, &srcAgentGroup, &expires); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ClusterScopeRecord{}, apierr.NotFound("k8s_cluster_scope_not_found", "Kubernetes cluster scope not found")
		}
		return ClusterScopeRecord{}, err
	}
	switch out.Source.Kind {
	case "group":
		out.Source.ID = uuid.UUID(srcGroup.Bytes)
	case "user":
		out.Source.ID = uuid.UUID(srcUser.Bytes)
	case "site":
		out.Source.ID = uuid.UUID(srcSite.Bytes)
	case "agent":
		out.Source.ID = uuid.UUID(srcDevice.Bytes)
	case "agent_group":
		out.Source.ID = uuid.UUID(srcAgentGroup.Bytes)
	case "cidr":
		if srcCIDR != nil {
			out.Source.CIDR = *srcCIDR
		}
	}
	if expires.Valid {
		at := expires.Time
		out.ExpiresAt = &at
	}
	return out, nil
}

func scanClusterScopeMembershipView(row clusterScopeScanner) (ClusterScopeMembershipView, error) {
	var out ClusterScopeMembershipView
	var actor pgtype.UUID
	var decidedAt pgtype.Timestamptz
	if err := row.Scan(&out.RuleID, &out.ClusterID, &out.ChildID, &out.Namespace, &out.Service,
		&out.Protocol, &out.ServicePort, &out.Origin, &out.Status,
		&actor, &decidedAt, &out.CreatedAt, &out.serviceUID,
		&out.scopeActive, &out.orgEnabled, &out.ruleDisabled, &out.ruleExpired); err != nil {
		return ClusterScopeMembershipView{}, err
	}
	if actor.Valid {
		id := uuid.UUID(actor.Bytes)
		out.DecidedByUserID = &id
	}
	if decidedAt.Valid {
		at := decidedAt.Time
		out.DecidedAt = &at
	}
	return out, nil
}

func validateClusterScopeSource(source ClusterScopeSource) (ClusterScopeSource, error) {
	switch source.Kind {
	case "group", "user", "site", "agent":
		if source.ID == uuid.Nil || source.CIDR != "" {
			return ClusterScopeSource{}, apierr.BadRequest("invalid_request", "the selected source kind requires exactly one source id")
		}
	case "cidr":
		if source.ID != uuid.Nil || source.CIDR == "" {
			return ClusterScopeSource{}, apierr.BadRequest("invalid_request", "src_kind=cidr requires exactly one source CIDR")
		}
		prefix, err := netip.ParsePrefix(source.CIDR)
		if err != nil {
			return ClusterScopeSource{}, apierr.BadRequest("invalid_request", "src_cidr must be a valid CIDR")
		}
		source.CIDR = prefix.Masked().String()
	default:
		return ClusterScopeSource{}, apierr.BadRequest("invalid_request", "src_kind must be group, user, site, cidr, or agent")
	}
	return source, nil
}

func validateClusterScopeSourceExists(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, source ClusterScopeSource) error {
	var found uuid.UUID
	var err error
	switch source.Kind {
	case "group":
		err = tx.QueryRow(ctx, `SELECT id FROM user_groups WHERE id=$1 AND org_id=$2`, source.ID, orgID).Scan(&found)
	case "user":
		err = tx.QueryRow(ctx, `SELECT user_id FROM memberships WHERE user_id=$1 AND org_id=$2 AND access_revoked_at IS NULL`, source.ID, orgID).Scan(&found)
	case "site":
		err = tx.QueryRow(ctx, `SELECT id FROM sites WHERE id=$1 AND org_id=$2`, source.ID, orgID).Scan(&found)
	case "agent":
		err = tx.QueryRow(ctx, `SELECT id FROM devices WHERE id=$1 AND org_id=$2 AND kind='agent' AND deleted_at IS NULL`, source.ID, orgID).Scan(&found)
	case "agent_group":
		err = tx.QueryRow(ctx, `SELECT id FROM agent_groups WHERE id=$1 AND org_id=$2`, source.ID, orgID).Scan(&found)
	case "cidr":
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return apierr.BadRequest("scope_source_not_found", "the cluster-scope source does not exist in this organization")
	}
	return err
}

func insertClusterScopePolicyRule(ctx context.Context, tx pgx.Tx, ruleID, orgID, clusterID uuid.UUID, source ClusterScopeSource, expiresAt *time.Time) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO policy_rules(id,org_id,src_kind,src_group_id,src_user_id,src_site_id,src_cidr,src_device_id,src_agent_group_id,dst_kind,dst_k8s_cluster_id,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'k8s_cluster_scope',$10,$11)`,
		ruleID, orgID, source.Kind,
		pgUUID(source.ID, source.Kind == "group"), pgUUID(source.ID, source.Kind == "user"),
		pgUUID(source.ID, source.Kind == "site"), nullableString(source.CIDR, source.Kind == "cidr"),
		pgUUID(source.ID, source.Kind == "agent"), pgUUID(source.ID, source.Kind == "agent_group"), clusterID,
		pgTime(expiresAt))
	return err
}

func pgUUID(id uuid.UUID, valid bool) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: valid}
}

func pgTime(at *time.Time) pgtype.Timestamptz {
	if at == nil {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: at.UTC(), Valid: true}
}

func nullableString(value string, valid bool) *string {
	if !valid {
		return nil
	}
	return &value
}

func requireClusterScopeHumanMember(ctx context.Context, tx pgx.Tx, orgID, actorID uuid.UUID) error {
	var exists int
	if err := tx.QueryRow(ctx, `SELECT 1 FROM memberships WHERE org_id=$1 AND user_id=$2 AND access_revoked_at IS NULL FOR SHARE`, orgID, actorID).Scan(&exists); errors.Is(err, pgx.ErrNoRows) {
		return apierr.Forbidden("human_actor_required", "a verified human organization member is required")
	} else if err != nil {
		return err
	}
	return nil
}

func requireClusterScopeExposureMember(ctx context.Context, tx pgx.Tx, orgID, memberUserID uuid.UUID) error {
	var exists int
	if err := tx.QueryRow(ctx, `SELECT 1 FROM memberships WHERE org_id=$1 AND user_id=$2 AND access_revoked_at IS NULL FOR SHARE`, orgID, memberUserID).Scan(&exists); errors.Is(err, pgx.ErrNoRows) {
		return apierr.Forbidden("actor_required", "the operator or machine owner must be a current organization member")
	} else if err != nil {
		return err
	}
	return nil
}

func requireClusterScopeOptIn(ctx context.Context, tx pgx.Tx, orgID uuid.UUID) error {
	var enabled bool
	if err := tx.QueryRow(ctx, `SELECT enabled FROM k8s_cluster_scope_settings WHERE org_id=$1 FOR SHARE`, orgID).Scan(&enabled); errors.Is(err, pgx.ErrNoRows) || err == nil && !enabled {
		return apierr.Conflict("k8s_cluster_scope_opt_in_required", "enable Kubernetes cluster scopes for the organization first")
	} else if err != nil {
		return err
	}
	return nil
}

func requireClusterScopeActiveCapacity(ctx context.Context, tx pgx.Tx, orgID, clusterID, excludeRuleID uuid.UUID) error {
	var activeCount int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM k8s_cluster_scope_grants WHERE org_id=$1 AND cluster_id=$2 AND active AND rule_id<>$3`, orgID, clusterID, excludeRuleID).Scan(&activeCount); err != nil {
		return err
	}
	if activeCount >= clusterScopeActiveLimit {
		return apierr.Conflict("k8s_cluster_scope_active_limit", "a cluster cannot have more than 20 active Kubernetes scopes")
	}
	return nil
}

func scopeRevisionConflict(subject string) error {
	return apierr.Conflict("k8s_cluster_scope_revision_conflict", "the "+subject+" changed; reload and retry")
}

type scopeDB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type inventoryReport struct {
	ID         uuid.UUID
	ObservedAt time.Time
	FreshUntil time.Time
}

func currentInventoryReport(ctx context.Context, db scopeDB, orgID, clusterID uuid.UUID, lock bool) (inventoryReport, error) {
	query := `
		SELECT report.id,report.observed_at,report.fresh_until
		FROM k8s_service_inventory_reports report
		JOIN k8s_service_uid_observation_replay_states replay
		  ON replay.id=report.replay_state_id AND replay.org_id=report.org_id
		 AND replay.site_id=report.site_id AND replay.cluster_id=report.cluster_id
		 AND replay.connector_node_id=report.connector_node_id AND replay.sequence=report.replay_sequence
		JOIN k8s_clusters cluster
		  ON cluster.id=report.cluster_id AND cluster.org_id=report.org_id AND cluster.site_id=report.site_id
		JOIN nodes connector
		  ON connector.id=report.connector_node_id AND connector.org_id=report.org_id AND connector.site_id=report.site_id
		 AND connector.status='active' AND connector.revoked_at IS NULL
		WHERE report.org_id=$1 AND report.cluster_id=$2 AND report.fresh_until>now()
		  AND (
		    (cluster.connector_pool_id IS NULL AND cluster.connector_node_id=report.connector_node_id AND report.promotion_generation=0)
		    OR
		    (cluster.connector_node_id IS NULL AND EXISTS (
		      SELECT 1 FROM k8s_connector_pools pool
		      JOIN k8s_connector_pool_members member
		        ON member.pool_id=pool.id AND member.org_id=pool.org_id AND member.site_id=pool.site_id
		       AND member.node_id=pool.active_node_id
		      WHERE pool.id=cluster.connector_pool_id AND pool.org_id=cluster.org_id
		        AND pool.site_id=cluster.site_id AND pool.cluster_id=cluster.id
		        AND pool.active_node_id=report.connector_node_id
		        AND pool.generation=report.promotion_generation AND pool.generation>0
		    ))
		  )
		ORDER BY report.replay_sequence DESC,report.received_at DESC,report.id DESC
		LIMIT 1`
	if lock {
		query += ` FOR SHARE OF report,replay,cluster,connector`
	}
	var out inventoryReport
	err := db.QueryRow(ctx, query, orgID, clusterID).Scan(&out.ID, &out.ObservedAt, &out.FreshUntil)
	if err == nil {
		return out, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return inventoryReport{}, err
	}
	var latest time.Time
	err = db.QueryRow(ctx, `SELECT fresh_until FROM k8s_service_inventory_reports WHERE org_id=$1 AND cluster_id=$2 ORDER BY replay_sequence DESC,received_at DESC,id DESC LIMIT 1`, orgID, clusterID).Scan(&latest)
	if errors.Is(err, pgx.ErrNoRows) {
		return inventoryReport{}, scopeapproval.ErrInventoryUnavailable
	}
	if err != nil {
		return inventoryReport{}, err
	}
	if !latest.After(time.Now()) {
		return inventoryReport{}, scopeapproval.ErrInventoryStale
	}
	return inventoryReport{}, scopeapproval.ErrInventoryUnavailable
}

func currentExposedInventoryChildren(ctx context.Context, db scopeDB, reportID, orgID, clusterID uuid.UUID) ([]scopeapproval.ExactPortChild, error) {
	rows, err := db.Query(ctx, `
		SELECT service_child.id,service_child.org_id,service_child.cluster_id,item.namespace,item.service_uid,
		       port.protocol,port.service_port
		FROM k8s_service_inventory_reports report
		JOIN k8s_service_inventory_items item ON item.report_id=report.id AND item.org_id=report.org_id AND item.cluster_id=report.cluster_id
		JOIN k8s_service_inventory_ports port ON port.report_id=item.report_id AND port.inventory_ref=item.inventory_ref
		JOIN k8s_service_identities identity
		  ON identity.org_id=item.org_id AND identity.cluster_id=item.cluster_id
		 AND identity.namespace=item.namespace AND identity.name=item.service AND identity.deleted_at IS NULL
		JOIN k8s_services service_child
		  ON service_child.identity_id=identity.id AND service_child.org_id=identity.org_id
		 AND service_child.cluster_id=identity.cluster_id AND service_child.namespace=identity.namespace
		 AND service_child.name=identity.name AND service_child.protocol=port.protocol
		 AND service_child.port_low=port.service_port AND service_child.port_high=port.service_port
		 AND service_child.deleted_at IS NULL
		JOIN k8s_service_uid_observation_ledgers ledger ON ledger.org_id=report.org_id AND ledger.cluster_id=report.cluster_id
		JOIN k8s_service_uid_observation_current current_uid
		  ON current_uid.ledger_id=ledger.id AND current_uid.org_id=ledger.org_id
		 AND current_uid.namespace=item.namespace AND current_uid.service=item.service
		 AND current_uid.uid=item.service_uid AND current_uid.state='live'
		 AND current_uid.replay_sequence=report.replay_sequence
		JOIN k8s_service_uid_observation_current_attributions attribution
		  ON attribution.ledger_id=current_uid.ledger_id AND attribution.org_id=current_uid.org_id
		 AND attribution.namespace=current_uid.namespace AND attribution.service=current_uid.service
		 AND attribution.replay_state_id=report.replay_state_id AND attribution.replay_sequence=report.replay_sequence
		WHERE report.id=$1 AND report.org_id=$2 AND report.cluster_id=$3
		ORDER BY item.namespace,item.service_uid,port.protocol,port.service_port,service_child.id`, reportID, orgID, clusterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]scopeapproval.ExactPortChild, 0)
	for rows.Next() {
		var child scopeapproval.ExactPortChild
		var protocol string
		if err := rows.Scan(&child.Identity.ChildID, &child.Identity.OrgID, &child.Identity.ClusterID,
			&child.Identity.Namespace, &child.Identity.ServiceUID, &protocol, &child.Identity.ServicePort); err != nil {
			return nil, err
		}
		child.Identity.Protocol = scopeapproval.Protocol(protocol)
		child.Live, child.UIDAttributionCurrent = true, true
		out = append(out, child)
	}
	return out, rows.Err()
}

type clusterScopeCurrentChildren struct {
	byID   map[uuid.UUID]scopeapproval.ExactChildIdentity
	reason string
}

func loadClusterScopeCurrentChildren(ctx context.Context, db scopeDB, orgID, clusterID uuid.UUID) (clusterScopeCurrentChildren, error) {
	report, err := currentInventoryReport(ctx, db, orgID, clusterID, false)
	if errors.Is(err, scopeapproval.ErrInventoryStale) {
		return clusterScopeCurrentChildren{reason: clusterScopeInactiveInventoryStale}, nil
	}
	if errors.Is(err, scopeapproval.ErrInventoryUnavailable) {
		return clusterScopeCurrentChildren{reason: clusterScopeInactiveInventoryUnavailable}, nil
	}
	if err != nil {
		return clusterScopeCurrentChildren{}, err
	}
	children, err := currentExposedInventoryChildren(ctx, db, report.ID, orgID, clusterID)
	if err != nil {
		return clusterScopeCurrentChildren{}, err
	}
	out := clusterScopeCurrentChildren{byID: make(map[uuid.UUID]scopeapproval.ExactChildIdentity, len(children))}
	for _, child := range children {
		out.byID[child.Identity.ChildID] = child.Identity
	}
	return out, nil
}

func clusterScopeIdentityCurrent(state clusterScopeCurrentChildren, childID uuid.UUID, namespace, serviceUID, protocol string, servicePort int32) (bool, string) {
	if state.reason != "" {
		return false, state.reason
	}
	identity, ok := state.byID[childID]
	if !ok || identity.Namespace != namespace || identity.ServiceUID != serviceUID ||
		string(identity.Protocol) != protocol || identity.ServicePort != servicePort {
		return false, clusterScopeInactiveIdentityChanged
	}
	return true, ""
}

func projectClusterScopeCandidates(ctx context.Context, db scopeDB, orgID uuid.UUID, entitlementUnlocked bool, items []ClusterScopeCandidateView) error {
	states := make(map[uuid.UUID]clusterScopeCurrentChildren)
	for i := range items {
		state, ok := states[items[i].clusterID]
		if !ok {
			var err error
			state, err = loadClusterScopeCurrentChildren(ctx, db, orgID, items[i].clusterID)
			if err != nil {
				return err
			}
			states[items[i].clusterID] = state
		}
		items[i].Current, items[i].InactiveReason = clusterScopeIdentityCurrent(state, items[i].ChildID, items[i].Namespace, items[i].serviceUID, items[i].Protocol, items[i].ServicePort)
		status := ""
		if items[i].Selected {
			status = "approved"
		}
		items[i].Effective, items[i].InactiveReason = projectClusterScopeEffect(clusterScopeEffectInput{
			entitlementUnlocked: entitlementUnlocked, selected: items[i].Selected, status: status,
			scopeActive: items[i].scopeActive, orgEnabled: items[i].orgEnabled,
			ruleDisabled: items[i].ruleDisabled, ruleExpired: items[i].ruleExpired,
			current: items[i].Current, currentReason: items[i].InactiveReason,
		})
	}
	return nil
}

func projectClusterScopeMemberships(ctx context.Context, db scopeDB, orgID uuid.UUID, entitlementUnlocked bool, items []ClusterScopeMembershipView) error {
	states := make(map[uuid.UUID]clusterScopeCurrentChildren)
	for i := range items {
		state, ok := states[items[i].ClusterID]
		if !ok {
			var err error
			state, err = loadClusterScopeCurrentChildren(ctx, db, orgID, items[i].ClusterID)
			if err != nil {
				return err
			}
			states[items[i].ClusterID] = state
		}
		items[i].Current, items[i].InactiveReason = clusterScopeIdentityCurrent(state, items[i].ChildID, items[i].Namespace, items[i].serviceUID, items[i].Protocol, items[i].ServicePort)
		items[i].Effective, items[i].InactiveReason = projectClusterScopeEffect(clusterScopeEffectInput{
			entitlementUnlocked: entitlementUnlocked, selected: true, status: items[i].Status,
			scopeActive: items[i].scopeActive, orgEnabled: items[i].orgEnabled,
			ruleDisabled: items[i].ruleDisabled, ruleExpired: items[i].ruleExpired,
			current: items[i].Current, currentReason: items[i].InactiveReason,
		})
	}
	return nil
}

func currentExactChildState(ctx context.Context, db scopeDB, identity scopeapproval.ExactChildIdentity) (bool, bool, error) {
	report, err := currentInventoryReport(ctx, db, identity.OrgID, identity.ClusterID, true)
	if err != nil {
		return false, false, err
	}
	var found int
	err = db.QueryRow(ctx, `
		SELECT 1
		FROM k8s_service_inventory_reports report
		JOIN k8s_service_inventory_items item ON item.report_id=report.id AND item.org_id=report.org_id AND item.cluster_id=report.cluster_id
		JOIN k8s_service_inventory_ports port ON port.report_id=item.report_id AND port.inventory_ref=item.inventory_ref
		JOIN k8s_service_uid_observation_ledgers ledger ON ledger.org_id=report.org_id AND ledger.cluster_id=report.cluster_id
		JOIN k8s_service_uid_observation_current current_uid
		  ON current_uid.ledger_id=ledger.id AND current_uid.org_id=ledger.org_id
		 AND current_uid.namespace=item.namespace AND current_uid.service=item.service
		JOIN k8s_service_uid_observation_current_attributions attribution
		  ON attribution.ledger_id=current_uid.ledger_id AND attribution.org_id=current_uid.org_id
		 AND attribution.namespace=current_uid.namespace AND attribution.service=current_uid.service
		 AND attribution.replay_state_id=report.replay_state_id AND attribution.replay_sequence=report.replay_sequence
		JOIN k8s_services service_child ON service_child.id=$2 AND service_child.org_id=report.org_id AND service_child.cluster_id=report.cluster_id AND service_child.deleted_at IS NULL
		WHERE report.id=$1 AND item.namespace=$3 AND item.service_uid=$4 AND current_uid.uid=$4
		  AND current_uid.state='live' AND current_uid.replay_sequence=report.replay_sequence
		  AND port.protocol=$5 AND port.service_port=$6
		  AND service_child.namespace=$3 AND service_child.name=item.service AND service_child.protocol=$5
		  AND service_child.port_low=$6 AND service_child.port_high=$6`,
		report.ID, identity.ChildID, identity.Namespace, identity.ServiceUID, string(identity.Protocol), identity.ServicePort).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, true, nil
	}
	if err != nil {
		return false, false, err
	}
	return true, true, nil
}

func loadDomainScopeForUpdate(ctx context.Context, tx pgx.Tx, orgID, ruleID uuid.UUID) (scopeapproval.Scope, bool, error) {
	var scope scopeapproval.Scope
	var active bool
	if err := tx.QueryRow(ctx, `SELECT rule_id,org_id,cluster_id,active FROM k8s_cluster_scope_grants WHERE rule_id=$1 AND org_id=$2 FOR UPDATE`, ruleID, orgID).
		Scan(&scope.RuleID, &scope.OrgID, &scope.ClusterID, &active); errors.Is(err, pgx.ErrNoRows) {
		return scopeapproval.Scope{}, false, apierr.NotFound("k8s_cluster_scope_not_found", "Kubernetes cluster scope not found")
	} else if err != nil {
		return scopeapproval.Scope{}, false, err
	}
	evidenceRows, err := tx.Query(ctx, `SELECT service_child_id,org_id,cluster_id,namespace,service_uid,protocol,port_low,selected FROM k8s_cluster_scope_initial_candidates WHERE rule_id=$1 ORDER BY service_child_id`, ruleID)
	if err != nil {
		return scopeapproval.Scope{}, false, err
	}
	for evidenceRows.Next() {
		var evidence scopeapproval.InitialCandidateEvidence
		var protocol string
		if err := evidenceRows.Scan(&evidence.Identity.ChildID, &evidence.Identity.OrgID, &evidence.Identity.ClusterID,
			&evidence.Identity.Namespace, &evidence.Identity.ServiceUID, &protocol,
			&evidence.Identity.ServicePort, &evidence.Selected); err != nil {
			evidenceRows.Close()
			return scopeapproval.Scope{}, false, err
		}
		evidence.Identity.Protocol = scopeapproval.Protocol(protocol)
		scope.InitialEvidence = append(scope.InitialEvidence, evidence)
	}
	evidenceRows.Close()
	if err := evidenceRows.Err(); err != nil {
		return scopeapproval.Scope{}, false, err
	}
	membershipRows, err := tx.Query(ctx, `SELECT service_child_id,org_id,cluster_id,namespace,service_uid,protocol,port_low,origin,status,decided_by_user_id,decided_at FROM k8s_cluster_scope_memberships WHERE rule_id=$1 ORDER BY service_child_id FOR UPDATE`, ruleID)
	if err != nil {
		return scopeapproval.Scope{}, false, err
	}
	for membershipRows.Next() {
		var membership scopeapproval.Membership
		var origin pgtype.Text
		var protocol, status string
		var actor pgtype.UUID
		var decidedAt pgtype.Timestamptz
		membership.RuleID = ruleID
		if err := membershipRows.Scan(&membership.Identity.ChildID, &membership.Identity.OrgID, &membership.Identity.ClusterID,
			&membership.Identity.Namespace, &membership.Identity.ServiceUID, &protocol,
			&membership.Identity.ServicePort, &origin, &status, &actor, &decidedAt); err != nil {
			membershipRows.Close()
			return scopeapproval.Scope{}, false, err
		}
		membership.Identity.Protocol = scopeapproval.Protocol(protocol)
		membership.Status = scopeapproval.Status(status)
		if origin.Valid {
			membership.Origin = scopeapproval.Origin(origin.String)
		}
		if actor.Valid {
			id := uuid.UUID(actor.Bytes)
			membership.DecidedByUserID = &id
		}
		if decidedAt.Valid {
			at := decidedAt.Time
			membership.DecidedAt = &at
		}
		scope.Memberships = append(scope.Memberships, membership)
	}
	membershipRows.Close()
	if err := membershipRows.Err(); err != nil {
		return scopeapproval.Scope{}, false, err
	}
	return scope, active, nil
}

func insertScopeMembership(ctx context.Context, tx pgx.Tx, membership scopeapproval.Membership) error {
	_, err := tx.Exec(ctx, `INSERT INTO k8s_cluster_scope_memberships(rule_id,org_id,cluster_id,service_child_id,namespace,service_uid,protocol,port_low,port_high,status,decided_by_user_id,decided_at,origin) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8,$9,$10,$11,$12)`,
		membership.RuleID, membership.Identity.OrgID, membership.Identity.ClusterID, membership.Identity.ChildID,
		membership.Identity.Namespace, membership.Identity.ServiceUID, string(membership.Identity.Protocol), membership.Identity.ServicePort,
		string(membership.Status), membership.DecidedByUserID, membership.DecidedAt, string(membership.Origin))
	return err
}

func findScopeMembership(memberships []scopeapproval.Membership, childID uuid.UUID) (scopeapproval.Membership, bool) {
	for _, membership := range memberships {
		if membership.Identity.ChildID == childID {
			return membership, true
		}
	}
	return scopeapproval.Membership{}, false
}

type scopeInventoryCursor struct {
	ReportID     uuid.UUID `json:"r"`
	Namespace    string    `json:"n"`
	Service      string    `json:"s"`
	InventoryRef uuid.UUID `json:"i"`
}

type scopeReadCursor struct {
	Kind        string    `json:"k"`
	BoundaryID  uuid.UUID `json:"b"`
	Namespace   string    `json:"n,omitempty"`
	Service     string    `json:"s,omitempty"`
	Protocol    string    `json:"p,omitempty"`
	ServicePort int32     `json:"o,omitempty"`
	CreatedAt   time.Time `json:"t,omitempty"`
	RuleID      uuid.UUID `json:"r,omitempty"`
	ChildID     uuid.UUID `json:"c"`
}

func clusterScopeReadLimit(limit int) (int, error) {
	if limit <= 0 {
		return clusterScopeInventoryPageLimit, nil
	}
	if limit > clusterScopeInventoryPageLimit {
		return 0, apierr.BadRequest("invalid_page_limit", "scope page limit cannot exceed 100")
	}
	return limit, nil
}

func requireClusterScopeExists(ctx context.Context, db scopeDB, orgID, ruleID uuid.UUID) error {
	var exists int
	if err := db.QueryRow(ctx, `SELECT 1 FROM k8s_cluster_scope_grants WHERE org_id=$1 AND rule_id=$2`, orgID, ruleID).Scan(&exists); errors.Is(err, pgx.ErrNoRows) {
		return apierr.NotFound("k8s_cluster_scope_not_found", "Kubernetes cluster scope not found")
	} else if err != nil {
		return err
	}
	return nil
}

func encodeScopeReadCursor(cursor scopeReadCursor) (string, error) {
	raw, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeScopeReadCursor(encoded, kind string, boundaryID uuid.UUID) (scopeReadCursor, error) {
	if encoded == "" {
		return scopeReadCursor{}, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return scopeReadCursor{}, apierr.BadRequest("invalid_scope_cursor", "scope cursor is invalid")
	}
	var cursor scopeReadCursor
	if err := json.Unmarshal(raw, &cursor); err != nil || cursor.Kind != kind || cursor.BoundaryID != boundaryID || cursor.ChildID == uuid.Nil {
		return scopeReadCursor{}, apierr.BadRequest("invalid_scope_cursor", "scope cursor is invalid")
	}
	switch kind {
	case "candidates", "memberships":
		if cursor.Namespace == "" || cursor.Service == "" ||
			(cursor.Protocol != string(scopeapproval.ProtocolTCP) && cursor.Protocol != string(scopeapproval.ProtocolUDP)) ||
			cursor.ServicePort < 1 || cursor.ServicePort > 65535 {
			return scopeReadCursor{}, apierr.BadRequest("invalid_scope_cursor", "scope cursor is invalid")
		}
	case "review_queue":
		if cursor.CreatedAt.IsZero() || cursor.RuleID == uuid.Nil {
			return scopeReadCursor{}, apierr.BadRequest("invalid_scope_cursor", "scope cursor is invalid")
		}
	default:
		return scopeReadCursor{}, apierr.BadRequest("invalid_scope_cursor", "scope cursor is invalid")
	}
	return cursor, nil
}

func encodeScopeInventoryCursor(cursor scopeInventoryCursor) (string, error) {
	raw, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeScopeInventoryCursor(encoded string) (scopeInventoryCursor, error) {
	if encoded == "" {
		return scopeInventoryCursor{}, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return scopeInventoryCursor{}, apierr.BadRequest("invalid_inventory_cursor", "inventory cursor is invalid")
	}
	var cursor scopeInventoryCursor
	if err := json.Unmarshal(raw, &cursor); err != nil || cursor.ReportID == uuid.Nil || cursor.Namespace == "" || cursor.Service == "" || cursor.InventoryRef == uuid.Nil {
		return scopeInventoryCursor{}, apierr.BadRequest("invalid_inventory_cursor", "inventory cursor is invalid")
	}
	return cursor, nil
}

func scopeActivationError(err error) error {
	if err == nil {
		return nil
	}
	var apiError *apierr.Error
	if errors.As(err, &apiError) {
		return err
	}
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) && (pgError.Code == "40001" || pgError.Code == "40P01") {
		return apierr.Conflict("k8s_cluster_scope_changed", "Kubernetes cluster-scope state changed; reload and retry")
	}
	switch {
	case errors.Is(err, scopeapproval.ErrInventoryStale):
		return apierr.Conflict("k8s_inventory_stale", "the Kubernetes inventory is stale; wait for the active connector to refresh it")
	case errors.Is(err, scopeapproval.ErrInventoryUnavailable):
		return apierr.Conflict("k8s_inventory_unavailable", "current attributed Kubernetes inventory is unavailable")
	case errors.Is(err, scopeapproval.ErrEntitlementUnavailable):
		return apierr.Forbidden("edition_required", "Kubernetes cluster scopes require an entitled licence")
	case errors.Is(err, scopeapproval.ErrOptInDisabled):
		return apierr.Conflict("k8s_cluster_scope_opt_in_required", "enable Kubernetes cluster scopes for the organization first")
	case errors.Is(err, scopeapproval.ErrCandidateLimitReached), errors.Is(err, scopeapproval.ErrSelectionLimitReached), errors.Is(err, scopeapproval.ErrMembershipLimitReached):
		return apierr.Conflict("k8s_cluster_scope_limit_reached", err.Error())
	case errors.Is(err, scopeapproval.ErrInvalidDecision), errors.Is(err, scopeapproval.ErrScopeMismatch), errors.Is(err, scopeapproval.ErrCurrentIdentityMismatch):
		return apierr.Conflict("k8s_scope_decision_conflict", "the Kubernetes Service membership changed or already has a terminal decision")
	case errors.Is(err, scopeapproval.ErrExposureNotLive), errors.Is(err, scopeapproval.ErrUIDAttributionNotCurrent):
		return apierr.Conflict("k8s_scope_membership_stale", "the Kubernetes Service identity is no longer current and attributed")
	case errors.Is(err, scopeapproval.ErrUnknownChildID):
		return apierr.BadRequest("k8s_scope_unknown_child", "one or more selected exact Service children are unavailable")
	default:
		return err
	}
}
