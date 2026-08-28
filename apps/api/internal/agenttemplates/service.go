package agenttemplates

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

var (
	ErrInvalid      = errors.New("invalid agent policy template input")
	ErrNotFound     = errors.New("agent policy template object not found")
	ErrStalePreview = errors.New("agent policy template preview is stale")
	ErrConflict     = errors.New("agent policy template mutation conflicts with current state")
)

type Pusher interface {
	PushOrgNodes(context.Context, uuid.UUID)
}

type Service struct {
	pool   *pgxpool.Pool
	pusher Pusher
}

func New(pool *pgxpool.Pool, pusher Pusher) *Service { return &Service{pool: pool, pusher: pusher} }

func (s *Service) ListGroups(ctx context.Context, orgID uuid.UUID) ([]sqlc.ListAgentGroupsRow, error) {
	if s == nil || s.pool == nil {
		return nil, ErrInvalid
	}
	return sqlc.New(s.pool).ListAgentGroups(ctx, orgID)
}

func (s *Service) ListMembers(ctx context.Context, orgID, groupID uuid.UUID) ([]sqlc.ListAgentGroupMembersRow, error) {
	if s == nil || s.pool == nil {
		return nil, ErrInvalid
	}
	q := sqlc.New(s.pool)
	if _, err := q.GetAgentGroup(ctx, sqlc.GetAgentGroupParams{ID: groupID, OrgID: orgID}); err != nil {
		return nil, classifyNotFound(err)
	}
	return q.ListAgentGroupMembers(ctx, sqlc.ListAgentGroupMembersParams{OrgID: orgID, AgentGroupID: groupID})
}

func (s *Service) ListTemplates(ctx context.Context, orgID uuid.UUID) ([]sqlc.AgentPolicyTemplate, error) {
	if s == nil || s.pool == nil {
		return nil, ErrInvalid
	}
	return sqlc.New(s.pool).ListAgentPolicyTemplates(ctx, orgID)
}

func (s *Service) ListVersions(ctx context.Context, orgID, templateID uuid.UUID) ([]sqlc.AgentPolicyTemplateVersion, error) {
	if s == nil || s.pool == nil {
		return nil, ErrInvalid
	}
	q := sqlc.New(s.pool)
	if _, err := q.GetAgentPolicyTemplate(ctx, sqlc.GetAgentPolicyTemplateParams{ID: templateID, OrgID: orgID}); err != nil {
		return nil, classifyNotFound(err)
	}
	return q.ListAgentPolicyTemplateVersions(ctx, sqlc.ListAgentPolicyTemplateVersionsParams{OrgID: orgID, TemplateID: templateID})
}

func (s *Service) SetEnabled(ctx context.Context, orgID, actor uuid.UUID, enabled bool) (bool, error) {
	if s == nil || s.pool == nil || actor == uuid.Nil {
		return false, ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var lockedOrg uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, orgID).Scan(&lockedOrg); err != nil {
		return false, classifyNotFound(err)
	}
	if !enabled {
		var live int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM agent_policy_template_assignments WHERE org_id=$1 AND state='active'`, orgID).Scan(&live); err != nil {
			return false, err
		}
		if live != 0 {
			return false, ErrConflict
		}
	}
	q := sqlc.New(tx)
	updated, err := q.SetOrganizationAgentPolicyTemplatesEnabled(ctx, sqlc.SetOrganizationAgentPolicyTemplatesEnabledParams{ID: orgID, AgentPolicyTemplatesEnabled: enabled})
	if err != nil {
		return false, classifyNotFound(err)
	}
	if err := audit(ctx, tx, orgID, actor, "org.agent_policy_templates_enabled", "organization", orgID, map[string]any{"enabled": enabled}); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return updated, nil
}

type ItemInput struct {
	DestinationKind string
	DestinationID   uuid.UUID
}

type Preview struct {
	Digest          string
	AffectedAgents  int
	CreatedRules    int
	ReusedRules     int
	RemovedRules    int
	ChangedGateways int
	Added           []Tuple
	Removed         []Tuple
}

type Tuple struct {
	DeviceID uuid.UUID
	NodeID   uuid.UUID
	CIDR     string
	Protocol string
	PortLow  int
	PortHigh int
}

type ApplyResult struct {
	AssignmentID uuid.UUID
	NoOp         bool
	Preview      Preview
}

type Assignment struct {
	ID                uuid.UUID
	GroupID           uuid.UUID
	GroupName         string
	TemplateID        uuid.UUID
	TemplateName      string
	TemplateVersionID uuid.UUID
	Version           int
	RuleCount         int
	AppliedAt         time.Time
}

type RemovalImpact struct {
	Members         int
	Assignments     int
	MCPAssignments  int
	GeneratedRules  int
	WithdrawnTuples int
	ChangedGateways int
}

func (s *Service) CreateGroup(ctx context.Context, orgID, actor uuid.UUID, name, description string) (sqlc.AgentGroup, error) {
	if s == nil || s.pool == nil || actor == uuid.Nil || strings.TrimSpace(name) == "" {
		return sqlc.AgentGroup{}, ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return sqlc.AgentGroup{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := requireEnabledTx(ctx, tx, orgID); err != nil {
		return sqlc.AgentGroup{}, err
	}
	row, err := sqlc.New(tx).CreateAgentGroup(ctx, sqlc.CreateAgentGroupParams{OrgID: orgID, Name: strings.TrimSpace(name), Description: strings.TrimSpace(description)})
	if err != nil {
		return sqlc.AgentGroup{}, err
	}
	if err := audit(ctx, tx, orgID, actor, "agent_group.created", "agent_group", row.ID, map[string]any{"name": row.Name}); err != nil {
		return sqlc.AgentGroup{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return sqlc.AgentGroup{}, err
	}
	return row, nil
}

func (s *Service) UpdateGroup(ctx context.Context, orgID, groupID, actor uuid.UUID, name, description string) (sqlc.AgentGroup, error) {
	if s == nil || s.pool == nil || actor == uuid.Nil || strings.TrimSpace(name) == "" {
		return sqlc.AgentGroup{}, ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return sqlc.AgentGroup{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := requireEnabledTx(ctx, tx, orgID); err != nil {
		return sqlc.AgentGroup{}, err
	}
	if _, err := sqlc.New(tx).GetAgentGroupForUpdate(ctx, sqlc.GetAgentGroupForUpdateParams{ID: groupID, OrgID: orgID}); err != nil {
		return sqlc.AgentGroup{}, classifyNotFound(err)
	}
	var row sqlc.AgentGroup
	err = tx.QueryRow(ctx, `UPDATE agent_groups SET name=$3,description=$4 WHERE id=$1 AND org_id=$2 AND archived_at IS NULL RETURNING id,org_id,name,description,archived_at,created_at,updated_at`, groupID, orgID, strings.TrimSpace(name), strings.TrimSpace(description)).Scan(&row.ID, &row.OrgID, &row.Name, &row.Description, &row.ArchivedAt, &row.CreatedAt, &row.UpdatedAt)
	if err != nil {
		return sqlc.AgentGroup{}, classifyNotFound(err)
	}
	if err := audit(ctx, tx, orgID, actor, "agent_group.updated", "agent_group", groupID, map[string]any{"name": row.Name}); err != nil {
		return sqlc.AgentGroup{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return sqlc.AgentGroup{}, err
	}
	return row, nil
}

func (s *Service) ArchiveGroup(ctx context.Context, orgID, groupID, actor uuid.UUID) (RemovalImpact, error) {
	if s == nil || s.pool == nil || actor == uuid.Nil {
		return RemovalImpact{}, ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return RemovalImpact{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := requireEnabledTx(ctx, tx, orgID); err != nil {
		return RemovalImpact{}, err
	}
	if _, err := sqlc.New(tx).GetAgentGroupForUpdate(ctx, sqlc.GetAgentGroupForUpdateParams{ID: groupID, OrgID: orgID}); err != nil {
		return RemovalImpact{}, classifyNotFound(err)
	}
	impact := RemovalImpact{}
	if err := tx.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM agent_group_members WHERE org_id=$1 AND agent_group_id=$2),
		(SELECT count(*) FROM agent_policy_template_assignments WHERE org_id=$1 AND agent_group_id=$2 AND state='active'),
		(SELECT count(*) FROM agent_mcp_profile_assignments WHERE org_id=$1 AND agent_group_id=$2 AND state='active'),
		(SELECT count(DISTINCT b.policy_rule_id) FROM agent_policy_template_assignments a JOIN agent_policy_template_rule_bindings b ON b.org_id=a.org_id AND b.assignment_id=a.id WHERE a.org_id=$1 AND a.agent_group_id=$2 AND a.state='active')`, orgID, groupID).Scan(&impact.Members, &impact.Assignments, &impact.MCPAssignments, &impact.GeneratedRules); err != nil {
		return RemovalImpact{}, err
	}
	if impact.Members != 0 || impact.Assignments != 0 || impact.MCPAssignments != 0 {
		return impact, ErrConflict
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_groups SET archived_at=now() WHERE id=$1 AND org_id=$2 AND archived_at IS NULL`, groupID, orgID); err != nil {
		return RemovalImpact{}, err
	}
	if err := audit(ctx, tx, orgID, actor, "agent_group.archived", "agent_group", groupID, map[string]any{}); err != nil {
		return RemovalImpact{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RemovalImpact{}, err
	}
	return impact, nil
}

func (s *Service) AddMember(ctx context.Context, orgID, groupID, deviceID, actor uuid.UUID) (bool, error) {
	if s == nil || s.pool == nil || actor == uuid.Nil {
		return false, ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := requireEnabledTx(ctx, tx, orgID); err != nil {
		return false, err
	}
	q := sqlc.New(tx)
	if _, err := q.GetAgentGroupForUpdate(ctx, sqlc.GetAgentGroupForUpdateParams{ID: groupID, OrgID: orgID}); err != nil {
		return false, classifyNotFound(err)
	}
	changed, err := q.AddAgentGroupMember(ctx, sqlc.AddAgentGroupMemberParams{OrgID: orgID, AgentGroupID: groupID, DeviceID: deviceID, CreatedByUserID: actor})
	if err != nil {
		return false, err
	}
	if changed == 0 {
		return false, tx.Commit(ctx)
	}
	var assigned, mcpAssigned bool
	if err := tx.QueryRow(ctx, `SELECT
		EXISTS (SELECT 1 FROM agent_policy_template_assignments WHERE org_id=$1 AND agent_group_id=$2 AND state='active'),
		EXISTS (SELECT 1 FROM agent_mcp_profile_assignments WHERE org_id=$1 AND agent_group_id=$2 AND state='active')`, orgID, groupID).Scan(&assigned, &mcpAssigned); err != nil {
		return false, err
	}
	if err := audit(ctx, tx, orgID, actor, "agent_group.member_added", "agent_group", groupID, map[string]any{"device_id": deviceID, "mcp_inheritance_gained": mcpAssigned}); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	if (assigned || mcpAssigned) && s.pusher != nil {
		s.pusher.PushOrgNodes(ctx, orgID)
	}
	return true, nil
}

func (s *Service) RemoveMember(ctx context.Context, orgID, groupID, deviceID, actor uuid.UUID) (RemovalImpact, error) {
	if s == nil || s.pool == nil || actor == uuid.Nil {
		return RemovalImpact{}, ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return RemovalImpact{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := requireEnabledTx(ctx, tx, orgID); err != nil {
		return RemovalImpact{}, err
	}
	q := sqlc.New(tx)
	if _, err := q.GetAgentGroupForUpdate(ctx, sqlc.GetAgentGroupForUpdateParams{ID: groupID, OrgID: orgID}); err != nil {
		return RemovalImpact{}, classifyNotFound(err)
	}
	var present bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_group_members WHERE org_id=$1 AND agent_group_id=$2 AND device_id=$3 FOR UPDATE)`, orgID, groupID, deviceID).Scan(&present); err != nil {
		return RemovalImpact{}, err
	}
	if !present {
		return RemovalImpact{}, ErrNotFound
	}
	beforeSnapshot, err := policy.BuildSnapshotWithQueries(ctx, q, orgID)
	if err != nil {
		return RemovalImpact{}, err
	}
	var assignments, generated int
	if err := tx.QueryRow(ctx, `SELECT count(DISTINCT a.id), count(DISTINCT b.policy_rule_id)
		FROM agent_policy_template_assignments a
		LEFT JOIN agent_policy_template_rule_bindings b ON b.org_id=a.org_id AND b.assignment_id=a.id
		WHERE a.org_id=$1 AND a.agent_group_id=$2 AND a.state='active'`, orgID, groupID).Scan(&assignments, &generated); err != nil {
		return RemovalImpact{}, err
	}
	if changed, err := q.RemoveAgentGroupMember(ctx, sqlc.RemoveAgentGroupMemberParams{OrgID: orgID, AgentGroupID: groupID, DeviceID: deviceID}); err != nil || changed != 1 {
		if err != nil {
			return RemovalImpact{}, err
		}
		return RemovalImpact{}, ErrConflict
	}
	afterSnapshot, err := policy.BuildSnapshotWithQueries(ctx, q, orgID)
	if err != nil {
		return RemovalImpact{}, err
	}
	_, removed, gateways := compiledDelta(policy.Compile(beforeSnapshot), policy.Compile(afterSnapshot))
	withdrawn := 0
	for _, tuple := range removed {
		if tuple.DeviceID == deviceID {
			withdrawn++
		}
	}
	impact := RemovalImpact{Assignments: assignments, GeneratedRules: generated, WithdrawnTuples: withdrawn, ChangedGateways: gateways}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM agent_mcp_profile_assignments WHERE org_id=$1 AND agent_group_id=$2 AND state='active'`, orgID, groupID).Scan(&impact.MCPAssignments); err != nil {
		return RemovalImpact{}, err
	}
	if err := audit(ctx, tx, orgID, actor, "agent_group.member_removed", "agent_group", groupID, map[string]any{"device_id": deviceID, "assignments": assignments, "mcp_inheritance_lost": impact.MCPAssignments != 0, "generated_rules": generated, "withdrawn_tuples": withdrawn, "changed_gateways": gateways}); err != nil {
		return RemovalImpact{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RemovalImpact{}, err
	}
	if (assignments != 0 || impact.MCPAssignments != 0) && s.pusher != nil {
		s.pusher.PushOrgNodes(ctx, orgID)
	}
	return impact, nil
}

func (s *Service) CreateTemplate(ctx context.Context, orgID, actor uuid.UUID, name, description string) (sqlc.AgentPolicyTemplate, error) {
	if s == nil || s.pool == nil || actor == uuid.Nil || strings.TrimSpace(name) == "" {
		return sqlc.AgentPolicyTemplate{}, ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return sqlc.AgentPolicyTemplate{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := requireEnabledTx(ctx, tx, orgID); err != nil {
		return sqlc.AgentPolicyTemplate{}, err
	}
	row, err := sqlc.New(tx).CreateAgentPolicyTemplate(ctx, sqlc.CreateAgentPolicyTemplateParams{OrgID: orgID, Name: strings.TrimSpace(name), Description: strings.TrimSpace(description)})
	if err != nil {
		return sqlc.AgentPolicyTemplate{}, err
	}
	if err := audit(ctx, tx, orgID, actor, "agent_policy_template.created", "agent_policy_template", row.ID, map[string]any{"name": row.Name}); err != nil {
		return sqlc.AgentPolicyTemplate{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return sqlc.AgentPolicyTemplate{}, err
	}
	return row, nil
}

func (s *Service) UpdateTemplate(ctx context.Context, orgID, templateID, actor uuid.UUID, name, description string) (sqlc.AgentPolicyTemplate, error) {
	if s == nil || s.pool == nil || actor == uuid.Nil || strings.TrimSpace(name) == "" {
		return sqlc.AgentPolicyTemplate{}, ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return sqlc.AgentPolicyTemplate{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := requireEnabledTx(ctx, tx, orgID); err != nil {
		return sqlc.AgentPolicyTemplate{}, err
	}
	if _, err := sqlc.New(tx).GetAgentPolicyTemplateForUpdate(ctx, sqlc.GetAgentPolicyTemplateForUpdateParams{ID: templateID, OrgID: orgID}); err != nil {
		return sqlc.AgentPolicyTemplate{}, classifyNotFound(err)
	}
	var row sqlc.AgentPolicyTemplate
	err = tx.QueryRow(ctx, `UPDATE agent_policy_templates SET name=$3,description=$4 WHERE id=$1 AND org_id=$2 AND archived_at IS NULL RETURNING id,org_id,name,description,archived_at,created_at,updated_at`, templateID, orgID, strings.TrimSpace(name), strings.TrimSpace(description)).Scan(&row.ID, &row.OrgID, &row.Name, &row.Description, &row.ArchivedAt, &row.CreatedAt, &row.UpdatedAt)
	if err != nil {
		return sqlc.AgentPolicyTemplate{}, classifyNotFound(err)
	}
	if err := audit(ctx, tx, orgID, actor, "agent_policy_template.updated", "agent_policy_template", templateID, map[string]any{"name": row.Name}); err != nil {
		return sqlc.AgentPolicyTemplate{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return sqlc.AgentPolicyTemplate{}, err
	}
	return row, nil
}

func (s *Service) ArchiveTemplate(ctx context.Context, orgID, templateID, actor uuid.UUID) error {
	if s == nil || s.pool == nil || actor == uuid.Nil {
		return ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := requireEnabledTx(ctx, tx, orgID); err != nil {
		return err
	}
	if _, err := sqlc.New(tx).GetAgentPolicyTemplateForUpdate(ctx, sqlc.GetAgentPolicyTemplateForUpdateParams{ID: templateID, OrgID: orgID}); err != nil {
		return classifyNotFound(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_policy_templates SET archived_at=now() WHERE id=$1 AND org_id=$2 AND archived_at IS NULL`, templateID, orgID); err != nil {
		return err
	}
	if err := audit(ctx, tx, orgID, actor, "agent_policy_template.archived", "agent_policy_template", templateID, map[string]any{"live_assignments_preserved": true}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) CreateVersion(ctx context.Context, orgID, templateID, actor uuid.UUID, items []ItemInput) (sqlc.AgentPolicyTemplateVersion, error) {
	if s == nil || s.pool == nil || actor == uuid.Nil || len(items) == 0 || len(items) > 100 {
		return sqlc.AgentPolicyTemplateVersion{}, ErrInvalid
	}
	if err := validateItems(items); err != nil {
		return sqlc.AgentPolicyTemplateVersion{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return sqlc.AgentPolicyTemplateVersion{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := requireEnabledTx(ctx, tx, orgID); err != nil {
		return sqlc.AgentPolicyTemplateVersion{}, err
	}
	q := sqlc.New(tx)
	if _, err := q.GetAgentPolicyTemplateForUpdate(ctx, sqlc.GetAgentPolicyTemplateForUpdateParams{ID: templateID, OrgID: orgID}); err != nil {
		return sqlc.AgentPolicyTemplateVersion{}, classifyNotFound(err)
	}
	next, err := q.NextAgentPolicyTemplateVersion(ctx, sqlc.NextAgentPolicyTemplateVersionParams{OrgID: orgID, TemplateID: templateID})
	if err != nil || next < 1 || next > 2147483647 {
		return sqlc.AgentPolicyTemplateVersion{}, ErrConflict
	}
	version, err := q.CreateAgentPolicyTemplateVersion(ctx, sqlc.CreateAgentPolicyTemplateVersionParams{OrgID: orgID, TemplateID: templateID, Version: int32(next), CreatedByUserID: actor})
	if err != nil {
		return sqlc.AgentPolicyTemplateVersion{}, err
	}
	for i, item := range items {
		params := sqlc.CreateAgentPolicyTemplateVersionItemParams{OrgID: orgID, TemplateVersionID: version.ID, Ordinal: int32(i + 1), DstKind: item.DestinationKind}
		setDestination(&params, item)
		if _, err := q.CreateAgentPolicyTemplateVersionItem(ctx, params); err != nil {
			return sqlc.AgentPolicyTemplateVersion{}, err
		}
	}
	if err := audit(ctx, tx, orgID, actor, "agent_policy_template.version_created", "agent_policy_template", templateID, map[string]any{"version_id": version.ID, "version": version.Version, "item_count": len(items)}); err != nil {
		return sqlc.AgentPolicyTemplateVersion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return sqlc.AgentPolicyTemplateVersion{}, err
	}
	return version, nil
}

func (s *Service) Preview(ctx context.Context, orgID, groupID, versionID uuid.UUID) (Preview, error) {
	if s == nil || s.pool == nil {
		return Preview{}, ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return Preview{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	p, err := previewWithQueries(ctx, tx, sqlc.New(tx), orgID, groupID, versionID)
	if err != nil {
		return Preview{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Preview{}, err
	}
	return p, nil
}

func (s *Service) Apply(ctx context.Context, orgID, groupID, versionID, actor uuid.UUID, digest, idempotencyKey string) (ApplyResult, error) {
	if s == nil || s.pool == nil || actor == uuid.Nil || len(idempotencyKey) < 1 || len(idempotencyKey) > 128 {
		return ApplyResult{}, ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return ApplyResult{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := requireEnabledTx(ctx, tx, orgID); err != nil {
		return ApplyResult{}, err
	}
	q := sqlc.New(tx)
	if _, err := q.GetAgentGroupForUpdate(ctx, sqlc.GetAgentGroupForUpdateParams{ID: groupID, OrgID: orgID}); err != nil {
		return ApplyResult{}, classifyNotFound(err)
	}
	version, err := q.GetAgentPolicyTemplateVersion(ctx, sqlc.GetAgentPolicyTemplateVersionParams{ID: versionID, OrgID: orgID})
	if err != nil {
		return ApplyResult{}, classifyNotFound(err)
	}
	if _, err := q.GetAgentPolicyTemplateForUpdate(ctx, sqlc.GetAgentPolicyTemplateForUpdateParams{ID: version.TemplateID, OrgID: orgID}); err != nil {
		return ApplyResult{}, classifyNotFound(err)
	}
	var priorID, priorGroup, priorVersion uuid.UUID
	var priorDigest string
	err = tx.QueryRow(ctx, `SELECT id,agent_group_id,template_version_id,preview_digest FROM agent_policy_template_assignments WHERE org_id=$1 AND idempotency_key=$2`, orgID, idempotencyKey).Scan(&priorID, &priorGroup, &priorVersion, &priorDigest)
	if err == nil {
		if priorGroup != groupID || priorVersion != versionID || priorDigest != digest {
			return ApplyResult{}, ErrConflict
		}
		p, err := previewWithQueries(ctx, tx, q, orgID, groupID, versionID)
		return ApplyResult{AssignmentID: priorID, NoOp: true, Preview: p}, err
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return ApplyResult{}, err
	}
	_, lockErr := q.GetActiveAgentPolicyTemplateAssignmentForUpdate(ctx, sqlc.GetActiveAgentPolicyTemplateAssignmentForUpdateParams{OrgID: orgID, AgentGroupID: groupID, TemplateID: version.TemplateID})
	if lockErr != nil && !errors.Is(lockErr, pgx.ErrNoRows) {
		return ApplyResult{}, lockErr
	}
	p, err := previewWithQueries(ctx, tx, q, orgID, groupID, versionID)
	if err != nil {
		return ApplyResult{}, err
	}
	if !strings.EqualFold(p.Digest, digest) {
		return ApplyResult{}, ErrStalePreview
	}

	var previousID *uuid.UUID
	current, currentErr := q.GetActiveAgentPolicyTemplateAssignmentForUpdate(ctx, sqlc.GetActiveAgentPolicyTemplateAssignmentForUpdateParams{OrgID: orgID, AgentGroupID: groupID, TemplateID: version.TemplateID})
	if currentErr == nil {
		previousID = &current.ID
		if _, err := tx.Exec(ctx, `UPDATE agent_policy_template_assignments SET state='superseded',ended_at=now() WHERE id=$1 AND org_id=$2`, current.ID, orgID); err != nil {
			return ApplyResult{}, err
		}
	} else if !errors.Is(currentErr, pgx.ErrNoRows) {
		return ApplyResult{}, currentErr
	}
	var assignmentID uuid.UUID
	if err := tx.QueryRow(ctx, `INSERT INTO agent_policy_template_assignments (org_id,agent_group_id,template_id,template_version_id,preview_digest,idempotency_key,applied_by_user_id,previous_assignment_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`, orgID, groupID, version.TemplateID, versionID, p.Digest, idempotencyKey, actor, previousID).Scan(&assignmentID); err != nil {
		return ApplyResult{}, err
	}
	items, err := q.ListAgentPolicyTemplateVersionItems(ctx, sqlc.ListAgentPolicyTemplateVersionItemsParams{OrgID: orgID, TemplateVersionID: versionID})
	if err != nil {
		return ApplyResult{}, err
	}
	for _, item := range items {
		ruleID, err := ensureRule(ctx, tx, orgID, groupID, item)
		if err != nil {
			return ApplyResult{}, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO agent_policy_template_rule_bindings (org_id,assignment_id,template_version_item_id,policy_rule_id) VALUES ($1,$2,$3,$4)`, orgID, assignmentID, item.ID, ruleID); err != nil {
			return ApplyResult{}, err
		}
	}
	if previousID != nil {
		if _, err := tx.Exec(ctx, `DELETE FROM agent_policy_template_rule_bindings WHERE org_id=$1 AND assignment_id=$2`, orgID, *previousID); err != nil {
			return ApplyResult{}, err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM policy_rules r WHERE r.org_id=$1 AND r.src_kind='agent_group' AND r.src_agent_group_id=$2 AND NOT EXISTS (SELECT 1 FROM agent_policy_template_rule_bindings b WHERE b.org_id=r.org_id AND b.policy_rule_id=r.id)`, orgID, groupID); err != nil {
			return ApplyResult{}, err
		}
	}
	if err := audit(ctx, tx, orgID, actor, "agent_policy_template.applied", "agent_policy_template_assignment", assignmentID, map[string]any{"group_id": groupID, "template_id": version.TemplateID, "template_version_id": versionID, "preview_digest": p.Digest, "created_rules": p.CreatedRules, "reused_rules": p.ReusedRules, "removed_rules": p.RemovedRules}); err != nil {
		return ApplyResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ApplyResult{}, err
	}
	if p.ChangedGateways != 0 && s.pusher != nil {
		s.pusher.PushOrgNodes(ctx, orgID)
	}
	return ApplyResult{AssignmentID: assignmentID, Preview: p}, nil
}

func (s *Service) ListAssignments(ctx context.Context, orgID uuid.UUID) ([]Assignment, error) {
	if s == nil || s.pool == nil {
		return nil, ErrInvalid
	}
	rows, err := s.pool.Query(ctx, `SELECT a.id,a.agent_group_id,g.name,a.template_id,t.name,a.template_version_id,v.version,
		count(DISTINCT b.policy_rule_id),a.applied_at
		FROM agent_policy_template_assignments a
		JOIN agent_groups g ON g.id=a.agent_group_id AND g.org_id=a.org_id
		JOIN agent_policy_templates t ON t.id=a.template_id AND t.org_id=a.org_id
		JOIN agent_policy_template_versions v ON v.id=a.template_version_id AND v.org_id=a.org_id
		LEFT JOIN agent_policy_template_rule_bindings b ON b.assignment_id=a.id AND b.org_id=a.org_id
		WHERE a.org_id=$1 AND a.state='active'
		GROUP BY a.id,g.name,t.name,v.version
		ORDER BY lower(g.name),lower(t.name),a.id`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Assignment{}
	for rows.Next() {
		var row Assignment
		if err := rows.Scan(&row.ID, &row.GroupID, &row.GroupName, &row.TemplateID, &row.TemplateName, &row.TemplateVersionID, &row.Version, &row.RuleCount, &row.AppliedAt); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (s *Service) RemoveAssignment(ctx context.Context, orgID, assignmentID, actor uuid.UUID) (RemovalImpact, error) {
	if s == nil || s.pool == nil || actor == uuid.Nil {
		return RemovalImpact{}, ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return RemovalImpact{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := requireEnabledTx(ctx, tx, orgID); err != nil {
		return RemovalImpact{}, err
	}
	q := sqlc.New(tx)
	var groupID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT agent_group_id FROM agent_policy_template_assignments WHERE id=$1 AND org_id=$2 AND state='active' FOR UPDATE`, assignmentID, orgID).Scan(&groupID); err != nil {
		return RemovalImpact{}, classifyNotFound(err)
	}
	beforeSnapshot, err := policy.BuildSnapshotWithQueries(ctx, q, orgID)
	if err != nil {
		return RemovalImpact{}, err
	}
	var bindings, deletedRules int
	removedBindings, err := tx.Exec(ctx, `DELETE FROM agent_policy_template_rule_bindings WHERE org_id=$1 AND assignment_id=$2`, orgID, assignmentID)
	if err != nil {
		return RemovalImpact{}, err
	}
	bindings = int(removedBindings.RowsAffected())
	removedRules, err := tx.Exec(ctx, `DELETE FROM policy_rules r
		WHERE r.org_id=$1 AND r.src_kind='agent_group' AND r.src_agent_group_id=$2
		  AND NOT EXISTS (SELECT 1 FROM agent_policy_template_rule_bindings b WHERE b.org_id=r.org_id AND b.policy_rule_id=r.id)`, orgID, groupID)
	if err != nil {
		return RemovalImpact{}, err
	}
	deletedRules = int(removedRules.RowsAffected())
	if _, err := tx.Exec(ctx, `UPDATE agent_policy_template_assignments SET state='removed',ended_at=now() WHERE id=$1 AND org_id=$2`, assignmentID, orgID); err != nil {
		return RemovalImpact{}, err
	}
	afterSnapshot, err := policy.BuildSnapshotWithQueries(ctx, q, orgID)
	if err != nil {
		return RemovalImpact{}, err
	}
	_, removed, gateways := compiledDelta(policy.Compile(beforeSnapshot), policy.Compile(afterSnapshot))
	impact := RemovalImpact{Assignments: 1, GeneratedRules: deletedRules, WithdrawnTuples: len(removed), ChangedGateways: gateways}
	if err := audit(ctx, tx, orgID, actor, "agent_policy_template.assignment_removed", "agent_policy_template_assignment", assignmentID, map[string]any{"group_id": groupID, "bindings": bindings, "deleted_rules": deletedRules, "withdrawn_tuples": len(removed), "changed_gateways": gateways}); err != nil {
		return RemovalImpact{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RemovalImpact{}, err
	}
	if impact.ChangedGateways != 0 && s.pusher != nil {
		s.pusher.PushOrgNodes(ctx, orgID)
	}
	return impact, nil
}

func previewWithQueries(ctx context.Context, tx pgx.Tx, q *sqlc.Queries, orgID, groupID, versionID uuid.UUID) (Preview, error) {
	if _, err := q.GetAgentGroup(ctx, sqlc.GetAgentGroupParams{ID: groupID, OrgID: orgID}); err != nil {
		return Preview{}, classifyNotFound(err)
	}
	version, err := q.GetAgentPolicyTemplateVersion(ctx, sqlc.GetAgentPolicyTemplateVersionParams{ID: versionID, OrgID: orgID})
	if err != nil {
		return Preview{}, classifyNotFound(err)
	}
	items, err := q.ListAgentPolicyTemplateVersionItems(ctx, sqlc.ListAgentPolicyTemplateVersionItemsParams{OrgID: orgID, TemplateVersionID: versionID})
	if err != nil || len(items) == 0 {
		return Preview{}, ErrInvalid
	}
	base, err := policy.BuildSnapshotWithQueries(ctx, q, orgID)
	if err != nil {
		return Preview{}, err
	}
	before := policy.Compile(base)
	oldIDs := map[uuid.UUID]bool{}
	oldBindings := []sqlc.ListAgentPolicyTemplateRuleBindingsRow{}
	current, err := q.GetActiveAgentPolicyTemplateAssignment(ctx, sqlc.GetActiveAgentPolicyTemplateAssignmentParams{OrgID: orgID, AgentGroupID: groupID, TemplateID: version.TemplateID})
	if err == nil {
		oldBindings, err = q.ListAgentPolicyTemplateRuleBindings(ctx, sqlc.ListAgentPolicyTemplateRuleBindingsParams{OrgID: orgID, AssignmentID: current.ID})
		if err != nil {
			return Preview{}, err
		}
		for _, binding := range oldBindings {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM agent_policy_template_rule_bindings WHERE org_id=$1 AND policy_rule_id=$2`, orgID, binding.PolicyRuleID).Scan(&n); err != nil {
				return Preview{}, err
			}
			if n == 1 {
				oldIDs[binding.PolicyRuleID] = true
			}
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return Preview{}, err
	}
	p := Preview{}
	proposed := make([]policy.Rule, 0, len(items))
	for _, item := range items {
		candidate := ruleFromItem(item, groupID)
		if existingID, ok := matchingRuleID(base.Rules, candidate); ok {
			p.ReusedRules++
			delete(oldIDs, existingID) // replacement retains this canonical rule
			continue
		}
		p.CreatedRules++
		proposed = append(proposed, candidate)
	}
	filtered := base.Rules[:0]
	for _, rule := range base.Rules {
		if !oldIDs[rule.ID] {
			filtered = append(filtered, rule)
		}
	}
	base.Rules = append(filtered, proposed...)
	for range oldIDs {
		p.RemovedRules++
	}
	after := policy.Compile(base)
	p.Added, p.Removed, p.ChangedGateways = compiledDelta(before, after)
	members, err := q.ListAgentGroupMembers(ctx, sqlc.ListAgentGroupMembersParams{OrgID: orgID, AgentGroupID: groupID})
	if err != nil {
		return Preview{}, err
	}
	for _, member := range members {
		if member.Status == "active" && member.AssignedIp != nil {
			p.AffectedAgents++
		}
	}
	canonical := struct {
		OrgID, GroupID, VersionID uuid.UUID
		Snapshot                  policy.Snapshot
		Preview                   struct {
			Created, Reused, Removed int
		}
	}{OrgID: orgID, GroupID: groupID, VersionID: versionID, Snapshot: base}
	canonical.Preview.Created, canonical.Preview.Reused, canonical.Preview.Removed = p.CreatedRules, p.ReusedRules, p.RemovedRules
	b, err := json.Marshal(canonical)
	if err != nil {
		return Preview{}, err
	}
	h := sha256.Sum256(b)
	p.Digest = hex.EncodeToString(h[:])
	return p, nil
}

func ensureRule(ctx context.Context, tx pgx.Tx, orgID, groupID uuid.UUID, item sqlc.AgentPolicyTemplateVersionItem) (uuid.UUID, error) {
	var id uuid.UUID
	err := tx.QueryRow(ctx, `INSERT INTO policy_rules (org_id,src_kind,src_agent_group_id,dst_kind,dst_resource_id,dst_group_id,dst_site_id,dst_k8s_service_id) VALUES ($1,'agent_group',$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING RETURNING id`, orgID, groupID, item.DstKind, item.DstResourceID, item.DstGroupID, item.DstSiteID, item.DstK8sServiceID).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, err
	}
	query, destination := destinationLookup(item)
	err = tx.QueryRow(ctx, query, orgID, groupID, destination).Scan(&id)
	return id, err
}

func destinationLookup(item sqlc.AgentPolicyTemplateVersionItem) (string, uuid.UUID) {
	switch item.DstKind {
	case "resource":
		return `SELECT id FROM policy_rules WHERE org_id=$1 AND src_kind='agent_group' AND src_agent_group_id=$2 AND dst_kind='resource' AND dst_resource_id=$3`, item.DstResourceID.Bytes
	case "group":
		return `SELECT id FROM policy_rules WHERE org_id=$1 AND src_kind='agent_group' AND src_agent_group_id=$2 AND dst_kind='group' AND dst_group_id=$3`, item.DstGroupID.Bytes
	case "site":
		return `SELECT id FROM policy_rules WHERE org_id=$1 AND src_kind='agent_group' AND src_agent_group_id=$2 AND dst_kind='site' AND dst_site_id=$3`, item.DstSiteID.Bytes
	default:
		return `SELECT id FROM policy_rules WHERE org_id=$1 AND src_kind='agent_group' AND src_agent_group_id=$2 AND dst_kind='k8s_service' AND dst_k8s_service_id=$3`, item.DstK8sServiceID.Bytes
	}
}

func ruleFromItem(item sqlc.AgentPolicyTemplateVersionItem, groupID uuid.UUID) policy.Rule {
	return policy.Rule{ID: item.ID, SrcKind: "agent_group", SrcAgentGroupID: groupID, DstKind: item.DstKind, DstResourceID: pgUUID(item.DstResourceID), DstGroupID: pgUUID(item.DstGroupID), DstSiteID: pgUUID(item.DstSiteID), DstK8sServiceID: pgUUID(item.DstK8sServiceID)}
}

func matchingRuleID(rules []policy.Rule, want policy.Rule) (uuid.UUID, bool) {
	for _, got := range rules {
		if got.SrcKind == want.SrcKind && got.SrcAgentGroupID == want.SrcAgentGroupID && got.DstKind == want.DstKind && got.DstResourceID == want.DstResourceID && got.DstGroupID == want.DstGroupID && got.DstSiteID == want.DstSiteID && got.DstK8sServiceID == want.DstK8sServiceID {
			return got.ID, true
		}
	}
	return uuid.Nil, false
}

func compiledDelta(before, after map[uuid.UUID]policyspec.Compiled) (added, removed []Tuple, gateways int) {
	nodes := map[uuid.UUID]bool{}
	all := map[uuid.UUID]bool{}
	for id := range before {
		all[id] = true
	}
	for id := range after {
		all[id] = true
	}
	for id := range all {
		b, a := tupleSet(before[id]), tupleSet(after[id])
		changed := false
		for key, tuple := range a {
			if _, ok := b[key]; !ok {
				added = append(added, tuple)
				changed = true
			}
		}
		for key, tuple := range b {
			if _, ok := a[key]; !ok {
				removed = append(removed, tuple)
				changed = true
			}
		}
		if changed {
			nodes[id] = true
		}
	}
	sortTuples(added)
	sortTuples(removed)
	return added, removed, len(nodes)
}

func tupleSet(compiled policyspec.Compiled) map[string]Tuple {
	out := map[string]Tuple{}
	for _, allow := range compiled.Allow {
		deviceID, _ := uuid.Parse(allow.SrcDeviceID)
		nodeID, _ := uuid.Parse(compiled.NodeID)
		t := Tuple{DeviceID: deviceID, NodeID: nodeID, CIDR: allow.DstCIDR, Protocol: string(allow.Protocol), PortLow: allow.PortLow, PortHigh: allow.PortHigh}
		out[fmt.Sprintf("%s|%s|%s|%d|%d", t.DeviceID, t.CIDR, t.Protocol, t.PortLow, t.PortHigh)] = t
	}
	return out
}

func sortTuples(in []Tuple) {
	sort.Slice(in, func(i, j int) bool {
		a, b := in[i], in[j]
		return fmt.Sprint(a.DeviceID, a.NodeID, a.CIDR, a.Protocol, a.PortLow, a.PortHigh) < fmt.Sprint(b.DeviceID, b.NodeID, b.CIDR, b.Protocol, b.PortLow, b.PortHigh)
	})
}

func validateItems(items []ItemInput) error {
	seen := map[string]bool{}
	for _, item := range items {
		if item.DestinationID == uuid.Nil || (item.DestinationKind != "resource" && item.DestinationKind != "group" && item.DestinationKind != "site" && item.DestinationKind != "k8s_service") {
			return ErrInvalid
		}
		key := item.DestinationKind + ":" + item.DestinationID.String()
		if seen[key] {
			return ErrInvalid
		}
		seen[key] = true
	}
	return nil
}

func setDestination(params *sqlc.CreateAgentPolicyTemplateVersionItemParams, item ItemInput) {
	v := pgtype.UUID{Bytes: item.DestinationID, Valid: true}
	switch item.DestinationKind {
	case "resource":
		params.DstResourceID = v
	case "group":
		params.DstGroupID = v
	case "site":
		params.DstSiteID = v
	case "k8s_service":
		params.DstK8sServiceID = v
	}
}

func pgUUID(v pgtype.UUID) uuid.UUID {
	if v.Valid {
		return v.Bytes
	}
	return uuid.Nil
}

func classifyNotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func requireEnabledTx(ctx context.Context, tx pgx.Tx, orgID uuid.UUID) error {
	enabled, err := sqlc.New(tx).GetOrganizationAgentPolicyTemplatesEnabled(ctx, orgID)
	if err != nil {
		return classifyNotFound(err)
	}
	if !enabled {
		return ErrConflict
	}
	return nil
}

func audit(ctx context.Context, tx pgx.Tx, orgID, actor uuid.UUID, action, targetType string, targetID uuid.UUID, metadata map[string]any) error {
	b, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_logs (org_id,actor_user_id,action,target_type,target_id,metadata) VALUES ($1,$2,$3,$4,$5,$6)`, orgID, actor, action, targetType, targetID.String(), b)
	return err
}
