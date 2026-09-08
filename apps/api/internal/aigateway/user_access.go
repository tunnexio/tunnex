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
	ID      uuid.UUID
	Name    string
	Members int
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

func (s *Policies) ListUserGroups(ctx context.Context, org uuid.UUID) ([]UserGroup, error) {
	if s == nil || s.pool == nil {
		return nil, aiUnavailable()
	}
	rows, err := s.pool.Query(ctx, `SELECT g.id,g.name,count(u.id) FROM user_groups g
 LEFT JOIN group_members gm ON gm.org_id=g.org_id AND gm.group_id=g.id
 LEFT JOIN memberships m ON m.org_id=gm.org_id AND m.user_id=gm.user_id AND m.access_revoked_at IS NULL
 LEFT JOIN users u ON u.id=m.user_id AND u.status='active' AND u.deleted_at IS NULL
 WHERE g.org_id=$1 GROUP BY g.id,g.name ORDER BY g.name,g.id LIMIT 512`, org)
	if err != nil {
		return nil, aiUnavailable()
	}
	defer rows.Close()
	out := []UserGroup{}
	for rows.Next() {
		var v UserGroup
		if rows.Scan(&v.ID, &v.Name, &v.Members) != nil {
			return nil, aiUnavailable()
		}
		out = append(out, v)
	}
	if rows.Err() != nil {
		return nil, aiUnavailable()
	}
	return out, nil
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
		if tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM ai_user_model_grants WHERE org_id=$1)+(SELECT count(*) FROM ai_gateway_key_bindings WHERE org_id=$1)`, org).Scan(&count) != nil {
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
	if s == nil || s.pool == nil || s.sealer == nil || org == uuid.Nil || user == uuid.Nil {
		return Grant{}, policyDenied()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Grant{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	var live bool
	if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM memberships m JOIN users u ON u.id=m.user_id JOIN organizations o ON o.id=m.org_id WHERE m.org_id=$1 AND m.user_id=$2 AND m.access_revoked_at IS NULL AND u.status='active' AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL AND NOT (u.must_change_password AND u.password_hash IS NOT NULL) AND o.deleted_at IS NULL AND o.ai_gateway_enabled)`, org, user).Scan(&live) != nil {
		return Grant{}, aiUnavailable()
	}
	if !live {
		return Grant{}, policyDenied()
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
	for _, g := range grants {
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
		if tx.Commit(ctx) != nil {
			return Grant{}, aiUnavailable()
		}
		return Grant{Tenant: org.String(), Agent: user.String(), SubjectKind: "user", VirtualKey: value, Mode: g.Mode, Expires: time.Now().Add(30 * time.Second)}, nil
	}
	return Grant{}, policyDenied()
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
		grant, err := s.ResolveUserModel(ctx, org, user, model)
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
