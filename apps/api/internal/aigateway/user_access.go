package aigateway

import (
	"context"
	"errors"
	"math"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

type UserModelGrant struct {
	ID, ConnectionID          uuid.UUID
	GroupID                   *uuid.UUID
	GroupName, Model, Status  string
	Mode                      ModelMode
	Enabled                   bool
	Revision, AppliedRevision int64
	native, sealed            string
	bindingRevision           int64
}

type UserGroup struct {
	ID                uuid.UUID
	Name              string
	Members           int
	DailyUsdThreshold *float64
	LimitRevision     int64
}
type UserModel struct {
	Model string
	Mode  ModelMode
}

const userGrantColumns = `id,group_id,group_name,connection_id,model,mode,enabled,revision,applied_revision,status,native_key_id,sealed_key,binding_revision`

func scanUserGrant(row pgx.Row) (UserModelGrant, error) {
	var g UserModelGrant
	err := row.Scan(&g.ID, &g.GroupID, &g.GroupName, &g.ConnectionID, &g.Model, &g.Mode, &g.Enabled, &g.Revision, &g.AppliedRevision, &g.Status, &g.native, &g.sealed, &g.bindingRevision)
	return g, err
}

// userGroupQuery lists groups with member counts and their optional shared
// daily cost limit. $2 NULL lists every group of the organization.
const userGroupQuery = `SELECT g.id,g.name,count(u.id),l.daily_usd_threshold,COALESCE(l.revision,0) FROM user_groups g
 LEFT JOIN ai_user_group_cost_limits l ON l.org_id=g.org_id AND l.group_id=g.id
 LEFT JOIN group_members gm ON gm.org_id=g.org_id AND gm.group_id=g.id
 LEFT JOIN memberships m ON m.org_id=gm.org_id AND m.user_id=gm.user_id AND m.access_revoked_at IS NULL
 LEFT JOIN users u ON u.id=m.user_id AND u.status='active' AND u.deleted_at IS NULL
 WHERE g.org_id=$1 AND ($2::uuid IS NULL OR g.id=$2) GROUP BY g.id,g.name,l.daily_usd_threshold,l.revision ORDER BY g.name,g.id LIMIT 512`

func (s *Policies) ListUserGroups(ctx context.Context, org uuid.UUID) ([]UserGroup, error) {
	if s == nil || s.pool == nil {
		return nil, aiUnavailable()
	}
	return s.queryUserGroups(ctx, org, nil)
}

func (s *Policies) queryUserGroups(ctx context.Context, org uuid.UUID, group *uuid.UUID) ([]UserGroup, error) {
	rows, err := s.pool.Query(ctx, userGroupQuery, org, group)
	if err != nil {
		return nil, aiUnavailable()
	}
	defer rows.Close()
	out := []UserGroup{}
	for rows.Next() {
		var v UserGroup
		if rows.Scan(&v.ID, &v.Name, &v.Members, &v.DailyUsdThreshold, &v.LimitRevision) != nil {
			return nil, aiUnavailable()
		}
		out = append(out, v)
	}
	if rows.Err() != nil {
		return nil, aiUnavailable()
	}
	return out, nil
}

func validDailyUsdThreshold(limit *float64) bool {
	return limit == nil || (*limit > 0 && *limit <= 100000 && !math.IsNaN(*limit) && !math.IsInf(*limit, 0))
}

// PutUserGroupCostLimit sets or removes (nil) the daily USD soft threshold
// shared by all members of a user group. Removal keeps the row so the revision
// only increases and a stale editor always conflicts.
func (s *Policies) PutUserGroupCostLimit(ctx context.Context, org, actor, group uuid.UUID, limit *float64, expected int64) (UserGroup, error) {
	if s == nil || s.pool == nil {
		return UserGroup{}, aiUnavailable()
	}
	if org == uuid.Nil || actor == uuid.Nil || group == uuid.Nil || expected < 0 || expected == math.MaxInt64 || !validDailyUsdThreshold(limit) {
		return UserGroup{}, policyInvalid()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return UserGroup{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	var found uuid.UUID
	if tx.QueryRow(ctx, `SELECT id FROM user_groups WHERE org_id=$1 AND id=$2 FOR SHARE`, org, group).Scan(&found) != nil {
		return UserGroup{}, policyNotFound()
	}
	var current int64
	err = tx.QueryRow(ctx, `SELECT revision FROM ai_user_group_cost_limits WHERE org_id=$1 AND group_id=$2 FOR UPDATE`, org, group).Scan(&current)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return UserGroup{}, aiUnavailable()
	}
	if current != expected {
		return UserGroup{}, policyConflict()
	}
	var revision int64
	if current == 0 {
		// A concurrent first save inserts the same key; the loser conflicts.
		err = tx.QueryRow(ctx, `INSERT INTO ai_user_group_cost_limits(org_id,group_id,daily_usd_threshold) VALUES($1,$2,$3) ON CONFLICT DO NOTHING RETURNING revision`, org, group, limit).Scan(&revision)
		if errors.Is(err, pgx.ErrNoRows) {
			return UserGroup{}, policyConflict()
		}
	} else {
		err = tx.QueryRow(ctx, `UPDATE ai_user_group_cost_limits SET daily_usd_threshold=$3,revision=revision+1 WHERE org_id=$1 AND group_id=$2 RETURNING revision`, org, group, limit).Scan(&revision)
	}
	if err != nil {
		return UserGroup{}, aiUnavailable()
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata) VALUES($1,$2,'ai_user_group.cost_limit_changed','ai_policy',$3,jsonb_build_object('revision',$4::bigint,'daily_usd_threshold',$5::double precision))`, org, actor, group.String(), revision, limit); err != nil {
		return UserGroup{}, aiUnavailable()
	}
	if tx.Commit(ctx) != nil {
		return UserGroup{}, aiUnavailable()
	}
	groups, err := s.queryUserGroups(ctx, org, &group)
	if err != nil {
		return UserGroup{}, err
	}
	if len(groups) != 1 {
		return UserGroup{}, policyNotFound()
	}
	return groups[0], nil
}

func (s *Policies) ListUserModelGrants(ctx context.Context, org uuid.UUID) ([]UserModelGrant, error) {
	if s == nil || s.pool == nil {
		return nil, aiUnavailable()
	}
	rows, err := s.pool.Query(ctx, `SELECT `+userGrantColumns+` FROM ai_user_model_grants WHERE org_id=$1 ORDER BY created_at,id LIMIT 65`, org)
	if err != nil {
		return nil, aiUnavailable()
	}
	defer rows.Close()
	out := []UserModelGrant{}
	for rows.Next() {
		v, err := scanUserGrant(rows)
		if err != nil {
			return nil, aiUnavailable()
		}
		out = append(out, v)
	}
	if rows.Err() != nil || len(out) > 64 {
		return nil, aiUnavailable()
	}
	return out, nil
}

// PutUserModelGrant persists desired access before touching the private engine.
// Revocation therefore denies new requests even if the engine is unavailable.
func (s *Policies) PutUserModelGrant(ctx context.Context, org, actor, group, connection uuid.UUID, model string, enabled bool, expected int64) (UserModelGrant, error) {
	if s == nil || s.pool == nil || s.engine == nil || s.sealer == nil {
		return UserModelGrant{}, aiUnavailable()
	}
	if org == uuid.Nil || actor == uuid.Nil || group == uuid.Nil || connection == uuid.Nil || expected < 0 || expected == math.MaxInt64 {
		return UserModelGrant{}, policyInvalid()
	}
	if _, _, ok := splitProviderModel(model); !ok {
		return UserModelGrant{}, policyInvalid()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return UserModelGrant{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	// Serialize same-org creates and retained-binding capacity without reversing
	// the existing provider -> organization lock order.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,150))`, org.String()); err != nil {
		return UserModelGrant{}, aiUnavailable()
	}
	var name string
	if tx.QueryRow(ctx, `SELECT name FROM user_groups WHERE org_id=$1 AND id=$2 FOR SHARE`, org, group).Scan(&name) != nil {
		return UserModelGrant{}, policyNotFound()
	}
	g, err := scanUserGrant(tx.QueryRow(ctx, `SELECT `+userGrantColumns+` FROM ai_user_model_grants WHERE org_id=$1 AND group_id=$2 AND connection_id=$3 AND model=$4 FOR UPDATE`, org, group, connection, model))
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return UserModelGrant{}, aiUnavailable()
	}
	creating := errors.Is(err, pgx.ErrNoRows)
	if (creating && expected != 0) || (!creating && g.Revision != expected) {
		return UserModelGrant{}, policyConflict()
	}
	if creating && !enabled {
		return UserModelGrant{}, policyInvalid()
	}
	mode := g.Mode
	if enabled {
		p, err := scanProvider(tx.QueryRow(ctx, `SELECT `+providerColumns+` FROM ai_provider_connections WHERE org_id=$1 AND id=$2 FOR SHARE`, org, connection))
		if err != nil {
			return UserModelGrant{}, policyNotFound()
		}
		if err := s.validateProviderAccess(ctx, tx, org, []string{p.KeyID}, []string{model}); err != nil {
			return UserModelGrant{}, err
		}
		mode = DefaultModelMode(p.ModelModes[model])
	}
	if creating {
		var locked uuid.UUID
		if tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, org).Scan(&locked) != nil {
			return UserModelGrant{}, aiUnavailable()
		}
		var count int
		if tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM ai_user_model_grants WHERE org_id=$1)+(SELECT count(*) FROM ai_workloads WHERE org_id=$1)+(SELECT count(*) FROM ai_gateway_key_bindings WHERE org_id=$1)`, org).Scan(&count) != nil {
			return UserModelGrant{}, aiUnavailable()
		}
		if count >= maxAIUsageBindings {
			return UserModelGrant{}, policyInvalid()
		}
		g, err = scanUserGrant(tx.QueryRow(ctx, `INSERT INTO ai_user_model_grants(id,org_id,group_id,group_ref,group_name,connection_id,model,mode) VALUES($1,$2,$3,$3,$4,$5,$6,$7) RETURNING `+userGrantColumns, uuid.New(), org, group, name, connection, model, mode))
	} else {
		g, err = scanUserGrant(tx.QueryRow(ctx, `UPDATE ai_user_model_grants SET enabled=$3,revision=revision+1,status='pending',group_name=$4,mode=$5 WHERE org_id=$1 AND id=$2 RETURNING `+userGrantColumns, org, g.ID, enabled, name, mode))
	}
	if err != nil || auditPolicy(ctx, tx, org, actor, g.ID, "ai_user_model.grant_changed", g.Revision) != nil || tx.Commit(ctx) != nil {
		return UserModelGrant{}, aiUnavailable()
	}
	return s.ReconcileUserGrant(ctx, org, g.ID)
}

func (s *Policies) ReconcileUserGrant(ctx context.Context, org, id uuid.UUID) (UserModelGrant, error) {
	if s == nil || s.pool == nil || s.engine == nil || s.sealer == nil {
		return UserModelGrant{}, aiUnavailable()
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return UserModelGrant{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	g, err := scanUserGrant(tx.QueryRow(ctx, `SELECT `+userGrantColumns+` FROM ai_user_model_grants WHERE org_id=$1 AND id=$2 FOR UPDATE`, org, id))
	if err != nil {
		return UserModelGrant{}, policyNotFound()
	}
	finish := func(status string) (UserModelGrant, error) {
		g.Status = status
		if status != "error" {
			g.AppliedRevision = g.Revision
		}
		_, err := tx.Exec(ctx, `UPDATE ai_user_model_grants SET status=$3,applied_revision=$4,native_key_id=$5,sealed_key=$6,binding_revision=$7,enabled=$8,last_reconcile_at=now() WHERE org_id=$1 AND id=$2`, org, id, g.Status, g.AppliedRevision, g.native, g.sealed, g.bindingRevision, g.Enabled)
		if err != nil || tx.Commit(ctx) != nil {
			return UserModelGrant{}, aiUnavailable()
		}
		return g, nil
	}
	if !g.Enabled || g.GroupID == nil {
		// Group deletion is already authoritative for admission. Persist that
		// desired revocation even if native cleanup must be retried; retain the
		// binding and group snapshot for historical usage attribution.
		g.Enabled = false
		if g.native != "" && s.engine.DisableKey(ctx, g.native) != nil {
			return finish("error")
		}
		return finish("revoked")
	}
	p, err := scanProvider(tx.QueryRow(ctx, `SELECT `+providerColumns+` FROM ai_provider_connections WHERE org_id=$1 AND id=$2 FOR SHARE`, org, g.ConnectionID))
	if err != nil {
		return finish("error")
	}
	scopes, err := s.providerScopes(ctx, tx, org, []string{p.KeyID}, []string{g.Model})
	if err != nil || len(scopes) != 1 || DefaultModelMode(p.ModelModes[g.Model]) != g.Mode {
		return finish("error")
	}
	name := "ai-user-group-" + org.String() + "-" + g.ID.String()
	var key EngineKey
	if engine, ok := s.engine.(ScopedPolicyEngine); ok {
		key, err = engine.EnsureScopedKey(ctx, name, scopes)
	} else {
		key, err = s.engine.EnsureKey(ctx, name, scopes[0].Provider, scopes[0].Models, scopes[0].KeyIDs)
	}
	if err != nil || key.ID == "" || key.Value == "" || (g.native != "" && g.native != key.ID) {
		return finish("error")
	}
	sealed, err := sealBoundKey(s.sealer, userGrantKeyPurpose, org, g.ID, key.ID, g.Revision, key.Value)
	if err != nil {
		return finish("error")
	}
	g.native, g.sealed, g.bindingRevision = key.ID, sealed, g.Revision
	return finish("applied")
}

const userGrantKeyPurpose = "tunnex-ai-user-group-key"

// ResolveUserModel never treats an organization role as inference authority.
// All identity, membership, provider and opt-in facts are read for this request.
func (s *Policies) ResolveUserModel(ctx context.Context, org, user uuid.UUID, model string) (Grant, error) {
	return s.resolveUserModel(ctx, org, user, model, nil, true)
}

// resolveUserModel admits through the first usable grant. With cost set, a
// grant whose group has a daily cost limit is usable only while the group's
// observed spend today is under it; grants of unlimited groups are tried first.
func (s *Policies) resolveUserModel(ctx context.Context, org, user uuid.UUID, model string, vpnUser func(pgx.Tx) (uuid.UUID, error), cost bool) (Grant, error) {
	return s.resolveUserGrant(ctx, org, user, model, vpnUser, cost, uuid.Nil)
}

// resolveUserGrant resolves a user's model grant. pin, when set, restricts the
// resolution to that grant: lease renewal re-checks the grant the request was
// admitted with (the same virtual key), without repeating cost admission.
func (s *Policies) resolveUserGrant(ctx context.Context, org, user uuid.UUID, model string, vpnUser func(pgx.Tx) (uuid.UUID, error), cost bool, pin uuid.UUID) (Grant, error) {
	if s == nil || s.pool == nil || s.sealer == nil || org == uuid.Nil || (user == uuid.Nil && vpnUser == nil) {
		return Grant{}, policyDenied()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Grant{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	user, err = liveAIUser(ctx, tx, org, user, vpnUser)
	if err != nil {
		return Grant{}, err
	}
	rows, err := tx.Query(ctx, `SELECT `+userGrantColumns+` FROM ai_user_model_grants g WHERE g.org_id=$1 AND g.model=$3 AND g.enabled AND g.status='applied' AND g.revision=g.applied_revision AND EXISTS(SELECT 1 FROM group_members m JOIN user_groups ug ON ug.id=m.group_id AND ug.org_id=m.org_id WHERE m.org_id=g.org_id AND m.group_id=g.group_id AND m.user_id=$2) ORDER BY g.id LIMIT 64`, org, user, model)
	if err != nil {
		return Grant{}, aiUnavailable()
	}
	grants := []UserModelGrant{}
	for rows.Next() {
		g, err := scanUserGrant(rows)
		if err != nil {
			rows.Close()
			return Grant{}, aiUnavailable()
		}
		grants = append(grants, g)
	}
	rows.Close()
	if rows.Err() != nil {
		return Grant{}, aiUnavailable()
	}
	limits := map[uuid.UUID]*float64{}
	if cost && len(grants) > 0 {
		if limits, err = userGroupLimits(ctx, tx, org, grants); err != nil {
			return Grant{}, err
		}
		// Stable: unlimited groups first, grant id order within each set.
		slices.SortStableFunc(grants, func(a, b UserModelGrant) int {
			la, lb := a.GroupID != nil && limits[*a.GroupID] != nil, b.GroupID != nil && limits[*b.GroupID] != nil
			switch {
			case la == lb:
				return 0
			case lb:
				return -1
			default:
				return 1
			}
		})
	}
	var costErr error
	for _, g := range grants {
		if pin != uuid.Nil && g.ID != pin {
			continue
		}
		p, err := scanProvider(tx.QueryRow(ctx, `SELECT `+providerColumns+` FROM ai_provider_connections WHERE org_id=$1 AND id=$2 FOR SHARE`, org, g.ConnectionID))
		if err != nil {
			continue
		}
		if s.validateProviderAccess(ctx, tx, org, []string{p.KeyID}, []string{model}) != nil || DefaultModelMode(p.ModelModes[model]) != g.Mode {
			continue
		}
		value, err := openBoundKey(s.sealer, userGrantKeyPurpose, org, g.ID, g.native, g.bindingRevision, g.sealed)
		if err != nil {
			continue
		}
		if g.GroupID != nil && limits[*g.GroupID] != nil {
			group := *g.GroupID
			if err := s.enforceCostFor(ctx, tx, org, costSubject{Kind: "user_group", ID: group}, model, g.Mode, limits[group], func() ([]string, error) {
				return userGroupUsageIDs(ctx, tx, org, group)
			}); err != nil {
				costErr = strongerCostError(costErr, err)
				continue
			}
		}
		if tx.Commit(ctx) != nil {
			return Grant{}, aiUnavailable()
		}
		if g.GroupID != nil {
			noteRequestGroup(ctx, "user_group", *g.GroupID)
		}
		// Renewal repeats this resolution (including any VPN peer evidence
		// check) for the same user, model and grant; there is no bearer or
		// cost step (cost admission is per request).
		renewUser, pinned := user, g.ID
		renew := func(ctx context.Context) (Grant, error) {
			if vpnUser != nil {
				return s.resolveUserGrant(ctx, org, uuid.Nil, model, vpnUser, false, pinned)
			}
			return s.resolveUserGrant(ctx, org, renewUser, model, nil, false, pinned)
		}
		return Grant{Tenant: org.String(), Agent: user.String(), SubjectKind: "user", VirtualKey: value, Mode: g.Mode, Expires: time.Now().Add(30 * time.Second), Renew: renew}, nil
	}
	if costErr != nil {
		return Grant{}, costErr
	}
	return Grant{}, policyDenied()
}

// userGroupLimits reads the daily cost limits of the candidate grants' groups.
func userGroupLimits(ctx context.Context, tx pgx.Tx, org uuid.UUID, grants []UserModelGrant) (map[uuid.UUID]*float64, error) {
	ids := make([]uuid.UUID, 0, len(grants))
	for _, g := range grants {
		if g.GroupID != nil {
			ids = append(ids, *g.GroupID)
		}
	}
	out := map[uuid.UUID]*float64{}
	rows, err := tx.Query(ctx, `SELECT group_id,daily_usd_threshold FROM ai_user_group_cost_limits WHERE org_id=$1 AND group_id=ANY($2::uuid[]) AND daily_usd_threshold IS NOT NULL`, org, ids)
	if err != nil {
		return nil, aiUnavailable()
	}
	defer rows.Close()
	for rows.Next() {
		var group uuid.UUID
		var limit float64
		if rows.Scan(&group, &limit) != nil {
			return nil, aiUnavailable()
		}
		out[group] = &limit
	}
	if rows.Err() != nil {
		return nil, aiUnavailable()
	}
	return out, nil
}

// userGroupUsageIDs is the group's retained attribution: every grant it holds
// or held (revoked included), each with its own native key. Grants of a
// deleted group lose group_id and with it the limit.
func userGroupUsageIDs(ctx context.Context, tx pgx.Tx, org, group uuid.UUID) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT native_key_id FROM ai_user_model_grants WHERE org_id=$1 AND group_id=$2 AND native_key_id<>'' ORDER BY native_key_id LIMIT 65`, org, group)
	if err != nil {
		return nil, aiUnavailable()
	}
	defer rows.Close()
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			return nil, aiUnavailable()
		}
		ids = append(ids, id)
	}
	if rows.Err() != nil || len(ids) > maxAIUsageBindings || (len(ids) > 0 && !validEngineList(ids, false)) {
		return nil, aiUnavailable()
	}
	return ids, nil
}

// strongerCostError keeps the most specific refusal across candidate grants:
// threshold reached, then price unavailable, then anything else (unavailable).
func strongerCostError(current, next error) error {
	rank := func(err error) int {
		var e *apierr.Error
		if !errors.As(err, &e) {
			return 0
		}
		switch e.Code {
		case "ai_daily_threshold_reached":
			return 3
		case "ai_price_unavailable":
			return 2
		default:
			return 1
		}
	}
	if current == nil || rank(next) > rank(current) {
		return next
	}
	return current
}

// liveAIUser is the identity step shared by inference and the VPN model list:
// an optional VPN evidence resolver, then the current live-user/org check.
func liveAIUser(ctx context.Context, tx pgx.Tx, org, user uuid.UUID, vpnUser func(pgx.Tx) (uuid.UUID, error)) (uuid.UUID, error) {
	if vpnUser != nil {
		var err error
		user, err = vpnUser(tx)
		if err != nil {
			return uuid.Nil, err
		}
	}
	if user == uuid.Nil {
		return uuid.Nil, policyDenied()
	}
	var live bool
	if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM memberships m JOIN users u ON u.id=m.user_id JOIN organizations o ON o.id=m.org_id WHERE m.org_id=$1 AND m.user_id=$2 AND m.access_revoked_at IS NULL AND u.status='active' AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL AND NOT (u.must_change_password AND u.password_hash IS NOT NULL) AND o.deleted_at IS NULL AND o.ai_gateway_enabled)`, org, user).Scan(&live) != nil {
		return uuid.Nil, aiUnavailable()
	}
	if !live {
		return uuid.Nil, policyDenied()
	}
	return user, nil
}

// resolveVPNUser runs the shared identity step in its own transaction for the
// VPN model list. Each listed model is then re-resolved by UserModels.
func (s *Policies) resolveVPNUser(ctx context.Context, org uuid.UUID, vpnUser func(pgx.Tx) (uuid.UUID, error)) (uuid.UUID, error) {
	if s == nil || s.pool == nil || s.sealer == nil || org == uuid.Nil || vpnUser == nil {
		return uuid.Nil, policyDenied()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, aiUnavailable()
	}
	defer rollbackAI(tx)
	user, err := liveAIUser(ctx, tx, org, uuid.Nil, vpnUser)
	if err != nil {
		return uuid.Nil, err
	}
	if tx.Commit(ctx) != nil {
		return uuid.Nil, aiUnavailable()
	}
	return user, nil
}

func (s *Policies) UserModels(ctx context.Context, org, user uuid.UUID) ([]UserModel, error) {
	if s == nil || s.pool == nil {
		return nil, aiUnavailable()
	}
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT g.model FROM ai_user_model_grants g JOIN group_members m ON m.org_id=g.org_id AND m.group_id=g.group_id WHERE g.org_id=$1 AND m.user_id=$2 AND g.enabled AND g.status='applied' ORDER BY g.model LIMIT 64`, org, user)
	if err != nil {
		return nil, aiUnavailable()
	}
	models := []string{}
	for rows.Next() {
		var m string
		if rows.Scan(&m) != nil {
			rows.Close()
			return nil, aiUnavailable()
		}
		models = append(models, m)
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, aiUnavailable()
	}
	out := []UserModel{}
	for _, model := range models {
		// Listing skips the cost check: an over-limit model stays listed and the
		// call itself is refused with the threshold message.
		grant, err := s.resolveUserModel(ctx, org, user, model, nil, false)
		if err == nil {
			out = append(out, UserModel{Model: model, Mode: grant.Mode})
		} else {
			var domain *apierr.Error
			if !errors.As(err, &domain) || domain.Status != 403 {
				return nil, aiUnavailable()
			}
		}
	}
	slices.SortFunc(out, func(a, b UserModel) int {
		if a.Model < b.Model {
			return -1
		}
		if a.Model > b.Model {
			return 1
		}
		return 0
	})
	return out, nil
}

func (s *Policies) reconcileUserGrants(ctx context.Context, limit int) error {
	// lint:cross-org bounded desired-state worker retries known grants only.
	rows, err := s.pool.Query(ctx, `SELECT org_id,id FROM ai_user_model_grants WHERE status IN ('pending','error') OR (group_id IS NULL AND status<>'revoked') ORDER BY last_reconcile_at NULLS FIRST,id LIMIT $1`, limit)
	if err != nil {
		return aiUnavailable()
	}
	type target struct{ org, id uuid.UUID }
	targets := []target{}
	for rows.Next() {
		var t target
		if rows.Scan(&t.org, &t.id) != nil {
			rows.Close()
			return aiUnavailable()
		}
		targets = append(targets, t)
	}
	rows.Close()
	if rows.Err() != nil {
		return aiUnavailable()
	}
	var failures []error
	for _, t := range targets {
		if _, err := s.pool.Exec(ctx, `UPDATE ai_user_model_grants SET last_reconcile_at=statement_timestamp() WHERE org_id=$1 AND id=$2`, t.org, t.id); err != nil {
			failures = append(failures, aiUnavailable())
			continue
		}
		if _, err := s.ReconcileUserGrant(ctx, t.org, t.id); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
