package aigateway

import (
	"context"
	"errors"
	"math"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/agentruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/aiegress"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
)

type PolicyEngine interface {
	EnsureKey(context.Context, string, string, []string, []string) (EngineKey, error)
	DisableKey(context.Context, string) error
	Price(context.Context, string, string) (Price, error)
	Usage(context.Context, []string, time.Time, time.Time) (Usage, error)
}
type TeamPolicy struct {
	TeamID         uuid.UUID
	Models, KeyIDs []string
	DailyCostLimit *float64
	Revision       int64
}
type Assignment struct {
	DeviceID, TeamID                               uuid.UUID
	Enabled                                        bool
	ModelsOverride                                 []string
	Revision, AppliedRevision, AppliedTeamRevision int64
	Status                                         string
}
type Policies struct {
	vpnIngress         *VPNIngress
	pool               *pgxpool.Pool
	sealer             *crypto.Sealer
	engine             PolicyEngine
	providerManagement bool
	customPolicy       *aiegress.Policy
	bridge             *providerBridge
}

func NewPolicies(pool *pgxpool.Pool, sealer *crypto.Sealer, engine PolicyEngine) *Policies {
	return &Policies{pool: pool, sealer: sealer, engine: engine}
}
func policyInvalid() error {
	return apierr.New(400, "invalid_ai_policy", "AI policy is not acceptable")
}
func policyConflict() error {
	return apierr.New(409, "ai_policy_revision_conflict", "AI policy changed; refresh and retry")
}
func policyNotFound() error {
	return apierr.New(404, "ai_policy_not_found", "AI policy target is unavailable")
}
func policyDenied() error {
	return apierr.New(403, "ai_policy_denied", "AI access is not available under the current policy")
}
func canonicalModels(values []string, empty bool) ([]string, bool) {
	if len(values) > 32 || (!empty && len(values) == 0) {
		return nil, false
	}
	out := append([]string{}, values...)
	for _, v := range out {
		if _, _, ok := splitProviderModel(v); !ok {
			return nil, false
		}
	}
	slices.Sort(out)
	if len(slices.Compact(append([]string{}, out...))) != len(out) {
		return nil, false
	}
	return out, true
}
func canonicalKeys(values []string) ([]string, bool) {
	if len(values) < 1 || len(values) > 8 || !validEngineList(values, false) {
		return nil, false
	}
	out := append([]string{}, values...)
	slices.Sort(out)
	return out, true
}
func effectiveModels(team, override []string) ([]string, bool) {
	if len(override) == 0 {
		return team, true
	}
	for _, v := range override {
		if !slices.Contains(team, v) {
			return nil, false
		}
	}
	return override, true
}
func scanTeam(row pgx.Row) (TeamPolicy, error) {
	var v TeamPolicy
	err := row.Scan(&v.TeamID, &v.Models, &v.KeyIDs, &v.DailyCostLimit, &v.Revision)
	return v, err
}
func scanAssignment(row pgx.Row) (Assignment, error) {
	var a Assignment
	err := row.Scan(&a.DeviceID, &a.TeamID, &a.Enabled, &a.ModelsOverride, &a.Revision, &a.AppliedRevision, &a.AppliedTeamRevision, &a.Status)
	return a, err
}

const teamColumns = `team_id,models,key_ids,daily_cost_limit,revision`
const assignmentColumns = `device_id,team_id,enabled,models_override,revision,applied_revision,applied_team_revision,status`

func (s *Policies) ListTeams(ctx context.Context, org uuid.UUID) ([]TeamPolicy, error) {
	if s == nil || s.pool == nil {
		return nil, aiUnavailable()
	}
	rows, err := s.pool.Query(ctx, `SELECT `+teamColumns+` FROM ai_gateway_team_policies WHERE org_id=$1 ORDER BY team_id`, org)
	if err != nil {
		return nil, aiUnavailable()
	}
	defer rows.Close()
	out := []TeamPolicy{}
	for rows.Next() {
		v, e := scanTeam(rows)
		if e != nil {
			return nil, aiUnavailable()
		}
		out = append(out, v)
	}
	if rows.Err() != nil {
		return nil, aiUnavailable()
	}
	return out, nil
}
func (s *Policies) ListAssignments(ctx context.Context, org uuid.UUID) ([]Assignment, error) {
	if s == nil || s.pool == nil {
		return nil, aiUnavailable()
	}
	rows, err := s.pool.Query(ctx, `SELECT a.device_id,a.team_id,a.enabled,a.models_override,a.revision,a.applied_revision,a.applied_team_revision,CASE WHEN a.status='applied' AND a.applied_team_revision<>p.revision THEN 'pending' ELSE a.status END FROM ai_gateway_assignments a JOIN ai_gateway_team_policies p ON p.org_id=a.org_id AND p.team_id=a.team_id WHERE a.org_id=$1 ORDER BY a.device_id`, org)
	if err != nil {
		return nil, aiUnavailable()
	}
	defer rows.Close()
	out := []Assignment{}
	for rows.Next() {
		v, e := scanAssignment(rows)
		if e != nil {
			return nil, aiUnavailable()
		}
		out = append(out, v)
	}
	if rows.Err() != nil {
		return nil, aiUnavailable()
	}
	return out, nil
}
func auditPolicy(ctx context.Context, tx pgx.Tx, org, actor, target uuid.UUID, action string, revision int64) error {
	_, err := tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata) VALUES($1,$2,$3,'ai_policy',$4,jsonb_build_object('revision',$5::bigint))`, org, actor, action, target.String(), revision)
	return err
}
func (s *Policies) PutTeam(ctx context.Context, org, actor, teamID uuid.UUID, models, keyIDs []string, limit *float64, expectedRev int64) (TeamPolicy, error) {
	if s == nil || s.pool == nil {
		return TeamPolicy{}, aiUnavailable()
	}
	models, ok := canonicalModels(models, false)
	if !ok {
		return TeamPolicy{}, policyInvalid()
	}
	keyIDs, ok = canonicalKeys(keyIDs)
	if !ok || org == uuid.Nil || actor == uuid.Nil || teamID == uuid.Nil || expectedRev < 0 || expectedRev == math.MaxInt64 {
		return TeamPolicy{}, policyInvalid()
	}
	if limit != nil && (math.IsNaN(*limit) || math.IsInf(*limit, 0) || *limit <= 0 || *limit > 100000) {
		return TeamPolicy{}, policyInvalid()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return TeamPolicy{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	var live bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_groups WHERE org_id=$1 AND id=$2 AND archived_at IS NULL)`, org, teamID).Scan(&live); err != nil || !live {
		return TeamPolicy{}, policyNotFound()
	}
	previous, err := scanTeam(tx.QueryRow(ctx, `SELECT `+teamColumns+` FROM ai_gateway_team_policies WHERE org_id=$1 AND team_id=$2 FOR UPDATE`, org, teamID))
	if errors.Is(err, pgx.ErrNoRows) {
		if expectedRev != 0 {
			return TeamPolicy{}, policyConflict()
		}
	} else if err != nil {
		return TeamPolicy{}, aiUnavailable()
	} else if previous.Revision != expectedRev {
		return TeamPolicy{}, policyConflict()
	}
	if err = s.validateProviderAccess(ctx, tx, org, keyIDs, models); err != nil {
		return TeamPolicy{}, err
	}
	var out TeamPolicy
	if expectedRev == 0 {
		out, err = scanTeam(tx.QueryRow(ctx, `INSERT INTO ai_gateway_team_policies(org_id,team_id,models,key_ids,daily_cost_limit,revision) VALUES($1,$2,$3,$4,$5,1) ON CONFLICT DO NOTHING RETURNING `+teamColumns, org, teamID, models, keyIDs, limit))
	} else {
		out, err = scanTeam(tx.QueryRow(ctx, `UPDATE ai_gateway_team_policies SET models=$3,key_ids=$4,daily_cost_limit=$5,revision=revision+1 WHERE org_id=$1 AND team_id=$2 RETURNING `+teamColumns, org, teamID, models, keyIDs, limit))
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return TeamPolicy{}, policyConflict()
	}
	if err != nil || auditPolicy(ctx, tx, org, actor, teamID, "ai_gateway.team_updated", out.Revision) != nil {
		return TeamPolicy{}, aiUnavailable()
	}
	if tx.Commit(ctx) != nil {
		return TeamPolicy{}, aiUnavailable()
	}
	return out, nil
}
func lockPolicyDevice(ctx context.Context, tx pgx.Tx, org, device uuid.UUID) error {
	var v uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM devices WHERE org_id=$1 AND id=$2 AND kind='agent' FOR UPDATE`, org, device).Scan(&v); err != nil {
		return policyNotFound()
	}
	return nil
}
func liveTeamMember(ctx context.Context, tx pgx.Tx, org, team, device uuid.UUID) bool {
	var live bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_group_members m JOIN agent_groups g ON g.org_id=m.org_id AND g.id=m.agent_group_id WHERE m.org_id=$1 AND m.agent_group_id=$2 AND m.device_id=$3 AND g.archived_at IS NULL)`, org, team, device).Scan(&live)
	return err == nil && live
}
func (s *Policies) PutAssignment(ctx context.Context, org, actor, device, team uuid.UUID, enabled bool, override []string, expectedRev int64) (Assignment, error) {
	if s == nil || s.pool == nil {
		return Assignment{}, aiUnavailable()
	}
	override, ok := canonicalModels(override, true)
	if !ok || org == uuid.Nil || actor == uuid.Nil || device == uuid.Nil || team == uuid.Nil || expectedRev < 0 || expectedRev == math.MaxInt64 {
		return Assignment{}, policyInvalid()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Assignment{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	if err = lockPolicyDevice(ctx, tx, org, device); err != nil {
		return Assignment{}, err
	}
	old, err := scanAssignment(tx.QueryRow(ctx, `SELECT `+assignmentColumns+` FROM ai_gateway_assignments WHERE org_id=$1 AND device_id=$2`, org, device))
	if errors.Is(err, pgx.ErrNoRows) {
		if expectedRev != 0 {
			return Assignment{}, policyConflict()
		}
	} else if err != nil {
		return Assignment{}, aiUnavailable()
	} else if old.Revision != expectedRev {
		return Assignment{}, policyConflict()
	}
	p, err := scanTeam(tx.QueryRow(ctx, `SELECT `+teamColumns+` FROM ai_gateway_team_policies WHERE org_id=$1 AND team_id=$2 FOR SHARE`, org, team))
	if err != nil {
		return Assignment{}, policyNotFound()
	}
	// Explicit revocation stays available after group removal/archive. Only an
	// existing assignment to the same team can take this non-granting path.
	disableExisting := !enabled && old.Revision > 0 && old.TeamID == team
	if !disableExisting && !liveTeamMember(ctx, tx, org, team, device) {
		return Assignment{}, policyNotFound()
	}
	if _, ok = effectiveModels(p.Models, override); !ok && !disableExisting {
		return Assignment{}, policyInvalid()
	}
	out, err := scanAssignment(tx.QueryRow(ctx, `INSERT INTO ai_gateway_assignments(org_id,device_id,team_id,enabled,models_override,revision) VALUES($1,$2,$3,$4,$5,1) ON CONFLICT(org_id,device_id) DO UPDATE SET team_id=$3,enabled=$4,models_override=$5,revision=ai_gateway_assignments.revision+1,status='pending' RETURNING `+assignmentColumns, org, device, team, enabled, override))
	if err != nil || auditPolicy(ctx, tx, org, actor, device, "ai_gateway.assignment_updated", out.Revision) != nil {
		return Assignment{}, aiUnavailable()
	}
	if tx.Commit(ctx) != nil {
		return Assignment{}, aiUnavailable()
	}
	return out, nil
}

// authorizedPolicy uses the caller's device-locked transaction. The shared
// team lock serializes tightening against accepted requests, without borrowing
// a second connection from the pool.
func (s *Policies) authorizedPolicy(ctx context.Context, tx pgx.Tx, id agentruntime.Identity) (Assignment, TeamPolicy, string, int64, string, error) {
	if s == nil || s.engine == nil || s.sealer == nil || tx == nil {
		return Assignment{}, TeamPolicy{}, "", 0, "", policyDenied()
	}
	a, err := scanAssignment(tx.QueryRow(ctx, `SELECT `+assignmentColumns+` FROM ai_gateway_assignments WHERE org_id=$1 AND device_id=$2`, id.OrgID, id.DeviceID))
	if err != nil || !a.Enabled || a.Status != "applied" || a.Revision != a.AppliedRevision {
		return Assignment{}, TeamPolicy{}, "", 0, "", policyDenied()
	}
	p, err := scanTeam(tx.QueryRow(ctx, `SELECT `+teamColumns+` FROM ai_gateway_team_policies WHERE org_id=$1 AND team_id=$2 FOR SHARE`, id.OrgID, a.TeamID))
	if err != nil || p.Revision != a.AppliedTeamRevision || !liveTeamMember(ctx, tx, id.OrgID, a.TeamID, id.DeviceID) {
		return Assignment{}, TeamPolicy{}, "", 0, "", policyDenied()
	}
	if err = s.validateProviderAccess(ctx, tx, id.OrgID, p.KeyIDs, p.Models); err != nil {
		return Assignment{}, TeamPolicy{}, "", 0, "", err
	}
	var keyID, sealed string
	var rev int64
	err = tx.QueryRow(ctx, `SELECT native_key_id,binding_revision,sealed_key FROM ai_gateway_key_bindings WHERE org_id=$1 AND device_id=$2 AND team_id=$3`, id.OrgID, id.DeviceID, a.TeamID).Scan(&keyID, &rev, &sealed)
	if err != nil {
		return Assignment{}, TeamPolicy{}, "", 0, "", policyDenied()
	}
	return a, p, keyID, rev, sealed, nil
}
func (s *Policies) CanIssue(ctx context.Context, tx pgx.Tx, id agentruntime.Identity) error {
	_, _, _, _, _, err := s.authorizedPolicy(ctx, tx, id)
	return err
}
func (s *Policies) Resolve(ctx context.Context, tx pgx.Tx, id agentruntime.Identity, model string) (Grant, error) {
	a, p, keyID, rev, sealed, err := s.authorizedPolicy(ctx, tx, id)
	if err != nil {
		return Grant{}, err
	}
	models, ok := effectiveModels(p.Models, a.ModelsOverride)
	if !ok || !slices.Contains(models, model) {
		return Grant{}, policyDenied()
	}
	mode, err := selectedModelMode(ctx, tx, id.OrgID, p.KeyIDs, model)
	if err != nil {
		return Grant{}, err
	}
	if err = s.enforceCostMode(ctx, tx, id.OrgID, a.TeamID, model, mode, p.DailyCostLimit); err != nil {
		return Grant{}, err
	}
	value, err := OpenKey(s.sealer, id.OrgID, id.DeviceID, keyID, rev, sealed)
	if err != nil {
		return Grant{}, policyDenied()
	}
	return Grant{Mode: mode, Tenant: id.OrgID.String(), Agent: id.DeviceID.String(), VirtualKey: value, Expires: time.Now().Add(30 * time.Second)}, nil
}
