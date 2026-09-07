package aigateway

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

type policyBinding struct {
	team       uuid.UUID
	id, sealed string
	revision   int64
}

func (s *Policies) Reconcile(ctx context.Context, org, device uuid.UUID) (Assignment, error) {
	return s.reconcileTeamDevice(ctx, org, device, uuid.Nil)
}

func (s *Policies) reconcileTeamDevice(ctx context.Context, org, device, expectedTeam uuid.UUID) (Assignment, error) {
	if s == nil || s.pool == nil || s.engine == nil || s.sealer == nil {
		return Assignment{}, aiUnavailable()
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Assignment{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	if err = lockPolicyDevice(ctx, tx, org, device); err != nil {
		return Assignment{}, err
	}
	a, err := scanAssignment(tx.QueryRow(ctx, `SELECT `+assignmentColumns+` FROM ai_gateway_assignments WHERE org_id=$1 AND device_id=$2`, org, device))
	if err != nil {
		return Assignment{}, policyNotFound()
	}
	if expectedTeam != uuid.Nil && a.TeamID != expectedTeam {
		return a, nil
	}
	p, err := scanTeam(tx.QueryRow(ctx, `SELECT `+teamColumns+` FROM ai_gateway_team_policies WHERE org_id=$1 AND team_id=$2 FOR SHARE`, org, a.TeamID))
	if err != nil {
		return Assignment{}, policyNotFound()
	}
	providerEligible := s.validateProviderAccess(ctx, tx, org, p.KeyIDs, p.Models) == nil
	// Device -> team-policy -> provider -> org is the sole allocation lock order. Team
	// writes never wait on devices or orgs while holding their policy row.
	var orgEnabled bool
	if err = tx.QueryRow(ctx, `SELECT ai_gateway_enabled FROM organizations WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, org).Scan(&orgEnabled); err != nil {
		return Assignment{}, policyNotFound()
	}
	var deviceLive bool
	if err = tx.QueryRow(ctx, `SELECT status='active' AND deleted_at IS NULL AND NOT health_blocked FROM devices WHERE org_id=$1 AND id=$2`, org, device).Scan(&deviceLive); err != nil {
		return Assignment{}, aiUnavailable()
	}
	rows, err := tx.Query(ctx, `SELECT team_id,native_key_id,binding_revision,sealed_key FROM ai_gateway_key_bindings WHERE org_id=$1 AND device_id=$2 ORDER BY team_id`, org, device)
	if err != nil {
		return Assignment{}, aiUnavailable()
	}
	bindings := []policyBinding{}
	for rows.Next() {
		var b policyBinding
		if rows.Scan(&b.team, &b.id, &b.revision, &b.sealed) != nil {
			rows.Close()
			return Assignment{}, aiUnavailable()
		}
		bindings = append(bindings, b)
	}
	rows.Close()
	if rows.Err() != nil {
		return Assignment{}, aiUnavailable()
	}
	finish := func(status string, applied bool) (Assignment, error) {
		a.Status = status
		if applied {
			a.AppliedRevision = a.Revision
			a.AppliedTeamRevision = p.Revision
		}
		_, e := tx.Exec(ctx, `UPDATE ai_gateway_assignments SET status=$3,applied_revision=$4,applied_team_revision=$5,last_reconcile_at=statement_timestamp() WHERE org_id=$1 AND device_id=$2`, org, device, a.Status, a.AppliedRevision, a.AppliedTeamRevision)
		if e != nil || tx.Commit(ctx) != nil {
			return Assignment{}, aiUnavailable()
		}
		return a, nil
	}
	member := liveTeamMember(ctx, tx, org, a.TeamID, device)
	models, subset := effectiveModels(p.Models, a.ModelsOverride)
	active := a.Enabled && orgEnabled && deviceLive && member && subset && providerEligible
	var current *policyBinding
	for i := range bindings {
		b := &bindings[i]
		if b.team == a.TeamID {
			current = b
		}
		if !active || b.team != a.TeamID {
			if s.engine.DisableKey(ctx, b.id) != nil {
				return finish("error", false)
			}
		}
	}
	if !active {
		if !a.Enabled || !orgEnabled {
			return finish("disabled", true)
		}
		return finish("error", false)
	}
	if current == nil {
		var count int
		if tx.QueryRow(ctx, `SELECT count(*) FROM ai_gateway_key_bindings WHERE org_id=$1`, org).Scan(&count) != nil {
			return Assignment{}, aiUnavailable()
		}
		if count >= 64 {
			result, err := finish("error", false)
			if err != nil {
				return result, err
			}
			return result, apierr.New(429, "ai_binding_limit", "AI gateway retains at most 64 native identity bindings per organization")
		}
	}
	nativeModels := make([]string, len(models))
	for i, v := range models {
		nativeModels[i] = strings.TrimPrefix(v, "openrouter/")
	}
	key, err := s.engine.EnsureKey(ctx, "ai-"+org.String()+"-"+device.String()+"-"+a.TeamID.String(), "openrouter", nativeModels, p.KeyIDs)
	if err != nil || key.ID == "" || key.Value == "" {
		return finish("error", false)
	}
	// Native deletion/recreation under the same name must not reset accounting.
	if current != nil && current.id != key.ID {
		return finish("error", false)
	}
	revision := int64(1)
	if current != nil {
		revision = current.revision + 1
		if revision <= 0 {
			return finish("error", false)
		}
	}
	sealed, err := SealKey(s.sealer, org, device, key.ID, revision, key.Value)
	if err != nil {
		return finish("error", false)
	}
	_, err = tx.Exec(ctx, `INSERT INTO ai_gateway_key_bindings(org_id,device_id,team_id,native_key_id,sealed_key,binding_revision) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(org_id,device_id,team_id) DO UPDATE SET sealed_key=$5,binding_revision=$6,updated_at=statement_timestamp()`, org, device, a.TeamID, key.ID, sealed, revision)
	if err != nil {
		return Assignment{}, aiUnavailable()
	}
	return finish("applied", true)
}

// ReconcileTeam is the bounded management-write fast path. Its authoritative
// selection never crosses the requested organization or team; the periodic
// worker remains the fallback for work beyond the limit or request deadline.
func (s *Policies) ReconcileTeam(ctx context.Context, org, team uuid.UUID, limit int) error {
	if s == nil || s.pool == nil {
		return aiUnavailable()
	}
	if org == uuid.Nil || team == uuid.Nil || limit < 1 || limit > 64 {
		return policyInvalid()
	}
	rows, err := s.pool.Query(ctx, `SELECT device_id FROM ai_gateway_assignments WHERE org_id=$1 AND team_id=$2 ORDER BY last_reconcile_at NULLS FIRST,device_id LIMIT $3`, org, team, limit)
	if err != nil {
		return aiUnavailable()
	}
	targets := []uuid.UUID{}
	for rows.Next() {
		var device uuid.UUID
		if rows.Scan(&device) != nil {
			rows.Close()
			return aiUnavailable()
		}
		targets = append(targets, device)
	}
	rows.Close()
	if rows.Err() != nil {
		return aiUnavailable()
	}
	var failures []error
	for _, device := range targets {
		// Recheck the team on the timestamp write: an assignment may move after
		// selection. Reconcile itself rereads under the canonical device lock.
		result, err := s.pool.Exec(ctx, `UPDATE ai_gateway_assignments SET last_reconcile_at=statement_timestamp() WHERE org_id=$1 AND device_id=$2 AND team_id=$3`, org, device, team)
		if err != nil {
			failures = append(failures, aiUnavailable())
			continue
		}
		if result.RowsAffected() == 0 {
			continue
		}
		if _, err = s.reconcileTeamDevice(ctx, org, device, team); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// ReconcilePending retries only bounded known assignments. It does not scan
// unknown tenants or create assignments. Each engine failure remains visible
// in its assignment; the worker never turns it into an applied revision.
func (s *Policies) ReconcilePending(ctx context.Context, limit int) error {
	if s == nil || s.pool == nil {
		return aiUnavailable()
	}
	if limit < 1 || limit > 64 {
		return policyInvalid()
	}
	rows, err := s.pool.Query(ctx, `SELECT a.org_id,a.device_id FROM ai_gateway_assignments a
 JOIN ai_gateway_team_policies p ON p.org_id=a.org_id AND p.team_id=a.team_id
 JOIN organizations o ON o.id=a.org_id
 JOIN devices d ON d.org_id=a.org_id AND d.id=a.device_id
 WHERE o.deleted_at IS NULL AND (a.status IN ('pending','error') OR a.applied_revision<>a.revision OR a.applied_team_revision<>p.revision
 OR (a.enabled AND o.ai_gateway_enabled AND a.status='disabled')
 OR (a.status='applied' AND (NOT o.ai_gateway_enabled OR NOT a.enabled OR d.status<>'active' OR d.deleted_at IS NOT NULL OR d.health_blocked
 OR NOT EXISTS(SELECT 1 FROM agent_group_members m JOIN agent_groups g ON g.org_id=m.org_id AND g.id=m.agent_group_id WHERE m.org_id=a.org_id AND m.device_id=a.device_id AND m.agent_group_id=a.team_id AND g.archived_at IS NULL))))
 ORDER BY a.last_reconcile_at NULLS FIRST,a.org_id,a.device_id LIMIT $1`, limit)
	if err != nil {
		return aiUnavailable()
	}
	type target struct{ org, device uuid.UUID }
	targets := []target{}
	for rows.Next() {
		var v target
		if rows.Scan(&v.org, &v.device) != nil {
			rows.Close()
			return aiUnavailable()
		}
		targets = append(targets, v)
	}
	rows.Close()
	if rows.Err() != nil {
		return aiUnavailable()
	}
	var failures []error
	for _, v := range targets {
		// Persist scheduling progress before external work. A native timeout
		// rolls back its authorization transaction; it must not also erase the
		// retry timestamp and pin the same failing target at the queue head.
		// This short independent update changes no desired/applied authority.
		if _, err := s.pool.Exec(ctx, `UPDATE ai_gateway_assignments SET last_reconcile_at=statement_timestamp() WHERE org_id=$1 AND device_id=$2`, v.org, v.device); err != nil {
			failures = append(failures, aiUnavailable())
			continue
		}
		if _, err := s.Reconcile(ctx, v.org, v.device); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

var _ PolicyResolver = (*Policies)(nil)
var _ PolicyEngine = (*Engine)(nil)
