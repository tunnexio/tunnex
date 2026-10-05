package sandboxes

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"time"
)

type SetupSettings struct {
	Enabled    bool  `json:"enabled"`
	MaxPerUser int32 `json:"max_per_user"`
	MaxTotal   int32 `json:"max_total"`
}
type SetupStatus struct {
	Settings                   SetupSettings
	PolicyMode                 string
	CanAdmin, CanManageCatalog bool
	BlockedReasons             []string
	Catalog                    []CatalogEntry
	RuntimeLimits              *BoundedRuntimeLimits
	RequiresTerminalDevice     bool
	TerminalGatewayID          *uuid.UUID
}

// Read-only runtime limits distinguish the nonreusable reservation from work.
type BoundedRuntimeLimits struct {
	MaxRetained, MaxWorkloads int32
	Retained, Workloads       int64
	ReservationID             *uuid.UUID
	ReservationState          string
}
type CatalogEntry struct {
	Template                   Template
	Enabled, RuntimeCompatible bool
}

func (s *Store) runtimeOrgAvailable(org uuid.UUID) bool {
	if s.boundedRuntime != nil {
		b := s.boundedRuntime
		return b.OrgID == org && b.available(time.Now())
	}
	return s.qualificationOrg == uuid.Nil || s.qualificationOrg == org
}
func (s *Store) templateCompatible(org uuid.UUID, t Template) bool {
	if !s.runtimeOrgAvailable(org) {
		return false
	}
	if s.boundedRuntime == nil {
		return true
	}
	b := s.boundedRuntime
	p, ok := b.profile(t.ID)
	return ok && (!b.Persistent() || len(t.MaximumScope) == 0) && t.ImageDigest == p.ConfigDigest && int(t.MemoryMiB) == b.MemoryMiB && t.MaxTTLSeconds <= b.MaxTTLSeconds
}
func (s *Store) Setup(ctx context.Context, org, actor uuid.UUID) (SetupStatus, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return SetupStatus{}, err
	}
	defer tx.Rollback(ctx)
	roles, err := authorize(ctx, tx, org, actor, rbac.PermSandboxView)
	if err != nil {
		return SetupStatus{}, err
	}
	out := SetupStatus{BlockedReasons: []string{}, Catalog: []CatalogEntry{}, CanAdmin: rbac.CanAny(roles, rbac.PermSandboxAdmin), CanManageCatalog: rbac.CanAny(roles, rbac.PermSandboxTemplateManage)}
	if err = tx.QueryRow(ctx, `SELECT sandboxes_enabled,max_sandboxes_per_user,max_sandboxes,zero_trust_mode FROM organizations WHERE id=$1`, org).Scan(&out.Settings.Enabled, &out.Settings.MaxPerUser, &out.Settings.MaxTotal, &out.PolicyMode); err != nil {
		return out, err
	}
	if !out.Settings.Enabled {
		out.BlockedReasons = append(out.BlockedReasons, "organization_disabled")
	}
	if out.PolicyMode != "enforcing" {
		out.BlockedReasons = append(out.BlockedReasons, "policy_not_enforcing")
	}
	if !rbac.CanAny(roles, rbac.PermSandboxCreate) {
		out.BlockedReasons = append(out.BlockedReasons, "permission_denied")
	}
	if !s.CreationAvailable(org, actor) {
		out.BlockedReasons = append(out.BlockedReasons, "runtime_binding_unavailable")
	}
	rows, err := tx.Query(ctx, `SELECT id,name,image_digest,maximum_scope,memory_mib,max_ttl_seconds,enabled FROM sandbox_templates WHERE org_id=$1 AND (enabled OR $2) ORDER BY name,id LIMIT 101`, org, out.CanAdmin || out.CanManageCatalog)
	if err != nil {
		return out, err
	}
	enabled, compatible := 0, 0
	for rows.Next() {
		var entry CatalogEntry
		var raw []byte
		t := &entry.Template
		if err = rows.Scan(&t.ID, &t.Name, &t.ImageDigest, &raw, &t.MemoryMiB, &t.MaxTTLSeconds, &entry.Enabled); err != nil {
			rows.Close()
			return out, err
		}
		if err = json.Unmarshal(raw, &t.MaximumScope); err != nil {
			rows.Close()
			return out, ErrInvalid
		}
		entry.RuntimeCompatible = s.templateCompatible(org, *t)
		if entry.Enabled {
			enabled++
			if entry.RuntimeCompatible {
				compatible++
			}
		}
		out.Catalog = append(out.Catalog, entry)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if len(out.Catalog) > 100 {
		return out, ErrQuota
	}
	if enabled == 0 {
		out.BlockedReasons = append(out.BlockedReasons, "no_published_templates")
	} else if compatible == 0 {
		out.BlockedReasons = append(out.BlockedReasons, "no_compatible_templates")
	}
	own, total, workloads, err := s.retainedCounts(ctx, tx, org, actor)
	if err != nil {
		return out, err
	}
	perUser, totalCap := out.Settings.MaxPerUser, out.Settings.MaxTotal
	if s.boundedRuntime != nil {
		b := s.boundedRuntime
		perUser, totalCap = b.quotas(perUser, totalCap)
		if b.OrgID == org {
			out.RequiresTerminalDevice = b.OrganizationScoped()
			gateway := b.terminalGatewayID()
			out.TerminalGatewayID = &gateway
			out.RuntimeLimits = &BoundedRuntimeLimits{MaxRetained: b.retainedLimit(), MaxWorkloads: 1, Retained: total, Workloads: workloads}
			if b.DevReservation != nil {
				id := b.reservedID()
				out.RuntimeLimits.ReservationID = &id
				state, e := b.reservationState(ctx, tx)
				if e != nil && !errors.Is(e, ErrDisabled) {
					return out, e
				}
				out.RuntimeLimits.ReservationState = state
				if e != nil {
					out.BlockedReasons = append(out.BlockedReasons, "historical_reservation_invalid")
				}
				if out.Settings.Enabled && (out.Settings.MaxPerUser != 2 || out.Settings.MaxTotal != 2) {
					out.BlockedReasons = append(out.BlockedReasons, "runtime_limits_mismatch")
				}
			}
		}
		if b.Persistent() && workloads >= 1 {
			out.BlockedReasons = append(out.BlockedReasons, "runtime_workload_quota_reached")
		}
	}
	if own >= int64(perUser) {
		out.BlockedReasons = append(out.BlockedReasons, "user_quota_reached")
	}
	if total >= int64(totalCap) {
		out.BlockedReasons = append(out.BlockedReasons, "organization_quota_reached")
	}
	if s.boundedRuntime != nil && !s.boundedRuntime.Persistent() {
		var lifetime int64
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM sandboxes WHERE org_id=$1`, org).Scan(&lifetime); err != nil {
			return out, err
		}
		if lifetime > 0 {
			out.BlockedReasons = append(out.BlockedReasons, "runtime_launch_budget_used")
		}
	}
	return out, tx.Commit(ctx)
}
func (s *Store) UpdateSetup(ctx context.Context, org, actor uuid.UUID, expected, next SetupSettings, runtimeReady bool) error {
	// Legacy qualification retains its exact settings contract. Organization
	// admission enforces the separate runtime ceiling at every quota check.
	if b := s.boundedRuntime; b != nil && b.Persistent() && !b.OrganizationScoped() && next.Enabled && (next.MaxPerUser != b.retainedLimit() || next.MaxTotal != b.retainedLimit()) {
		return ErrInvalid
	}
	if next.MaxPerUser < 1 || next.MaxPerUser > 100 || next.MaxTotal < 1 || next.MaxTotal > 10000 || next.MaxPerUser > next.MaxTotal {
		return ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = authorize(ctx, tx, org, actor, rbac.PermSandboxAdmin); err != nil {
		return err
	}
	var current SetupSettings
	var mode string
	if err = tx.QueryRow(ctx, `SELECT sandboxes_enabled,max_sandboxes_per_user,max_sandboxes,zero_trust_mode FROM organizations WHERE id=$1 FOR UPDATE`, org).Scan(&current.Enabled, &current.MaxPerUser, &current.MaxTotal, &mode); err != nil {
		return err
	}
	if current != expected {
		return ErrConflict
	}
	if next.Enabled {
		if err = s.reservationAdmission(ctx, tx, org); err != nil {
			return err
		}
	}
	if current == next {
		return tx.Commit(ctx)
	}
	if next.Enabled && !current.Enabled {
		if !runtimeReady || !s.runtimeOrgAvailable(org) || mode != "enforcing" {
			return ErrDisabled
		}
		var count int
		if s.boundedRuntime != nil {
			b := s.boundedRuntime
			for _, id := range b.templateIDs() {
				p, _ := b.profile(id)
				var matched int
				err = tx.QueryRow(ctx, `SELECT count(*) FROM sandbox_templates WHERE org_id=$1 AND enabled AND id=$2 AND image_digest=$3 AND memory_mib=$4 AND max_ttl_seconds<=$5 AND (NOT $6 OR maximum_scope='[]'::jsonb)`, org, id, p.ConfigDigest, b.MemoryMiB, b.MaxTTLSeconds, b.Persistent()).Scan(&matched)
				if err != nil {
					break
				}
				count += matched
			}
		} else {
			err = tx.QueryRow(ctx, `SELECT count(*) FROM sandbox_templates WHERE org_id=$1 AND enabled`, org).Scan(&count)
		}
		if err != nil {
			return err
		}
		if count == 0 {
			return ErrDisabled
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE organizations SET sandboxes_enabled=$2,max_sandboxes_per_user=$3,max_sandboxes=$4 WHERE id=$1`, org, next.Enabled, next.MaxPerUser, next.MaxTotal); err != nil {
		return err
	}
	before, _ := json.Marshal(current)
	after, _ := json.Marshal(next)
	if _, err = tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata) VALUES($1,$2,'sandbox.settings_update','organization',$3,jsonb_build_object('before',$4::jsonb,'after',$5::jsonb))`, org, actor, org.String(), before, after); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	s.notifyPolicy(ctx, org)
	return nil
}
func (s *Store) PublishTemplate(ctx context.Context, org, actor, id uuid.UUID, expected, enabled bool) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = authorize(ctx, tx, org, actor, rbac.PermSandboxTemplateManage); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, org); err != nil {
		return err
	}
	var current bool
	err = tx.QueryRow(ctx, `SELECT enabled FROM sandbox_templates WHERE org_id=$1 AND id=$2 FOR UPDATE`, org, id).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if current != expected {
		return ErrConflict
	}
	if current == enabled {
		return tx.Commit(ctx)
	}
	if _, err = tx.Exec(ctx, `UPDATE sandbox_templates SET enabled=$3 WHERE org_id=$1 AND id=$2`, org, id, enabled); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata) VALUES($1,$2,'sandbox.template_publication','sandbox_template',$3,jsonb_build_object('enabled',$4::boolean))`, org, actor, id.String(), enabled); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	s.notifyPolicy(ctx, org)
	return nil
}
