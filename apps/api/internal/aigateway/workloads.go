package aigateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math"
	"net"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

const workloadKeyPurpose = "tunnex-ai-workload-key"
const workloadTokenPrefix = "tnx_wai_"
const workloadEnrollmentPrefix = "tnx_we_"

// Workloads share only the gateway's provider/policy engine. They never create
// users, memberships, network devices or WireGuard peers.
type Workloads struct {
	policies        *Policies
	base            string
	maintenanceMu   sync.Mutex
	recoverySince   time.Time
	lastMaintenance time.Time
}

func NewWorkloads(p *Policies, base string) (*Workloads, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("invalid workload public base URL")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || ip != nil && ip.IsLoopback())) {
		return nil, errors.New("workload public base URL requires HTTPS")
	}
	return &Workloads{policies: p, base: strings.TrimSuffix(base, "/"), recoverySince: time.Now()}, nil
}
func (s *Workloads) ready() bool {
	return s != nil && s.policies != nil && s.policies.pool != nil && s.policies.engine != nil && s.policies.sealer != nil
}

type workloadRecord struct {
	api.AIWorkload
	epoch           int64
	native, sealed  string
	bindingRevision int64
}

const workloadColumns = `id,name,enabled,revision,credential_epoch,daily_usd_threshold,applied_revision,status,native_key_id,sealed_key,binding_revision,created_at`

func scanWorkload(row pgx.Row) (workloadRecord, error) {
	var w workloadRecord
	err := row.Scan(&w.Id, &w.Name, &w.Enabled, &w.Revision, &w.epoch, &w.DailyUsdThreshold, &w.AppliedRevision, &w.Status, &w.native, &w.sealed, &w.bindingRevision, &w.CreatedAt)
	w.Models = []api.AIWorkloadModel{}
	return w, err
}
func loadWorkloadModels(ctx context.Context, tx pgx.Tx, org, id uuid.UUID) ([]api.AIWorkloadModel, error) {
	rows, err := tx.Query(ctx, `SELECT connection_id,model,mode FROM ai_workload_models WHERE org_id=$1 AND workload_id=$2 ORDER BY model LIMIT 33`, org, id)
	if err != nil {
		return nil, aiUnavailable()
	}
	defer rows.Close()
	out := []api.AIWorkloadModel{}
	for rows.Next() {
		var v api.AIWorkloadModel
		if rows.Scan(&v.ConnectionId, &v.Model, &v.Mode) != nil {
			return nil, aiUnavailable()
		}
		out = append(out, v)
	}
	if rows.Err() != nil || len(out) > 32 {
		return nil, aiUnavailable()
	}
	return out, nil
}
func (s *Workloads) List(ctx context.Context, org uuid.UUID) ([]api.AIWorkload, error) {
	if !s.ready() {
		return nil, aiUnavailable()
	}
	tx, err := s.policies.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, aiUnavailable()
	}
	defer rollbackAI(tx)
	rows, err := tx.Query(ctx, `SELECT `+workloadColumns+` FROM ai_workloads WHERE org_id=$1 ORDER BY created_at,id LIMIT 65`, org)
	if err != nil {
		return nil, aiUnavailable()
	}
	out := []api.AIWorkload{}
	for rows.Next() {
		v, e := scanWorkload(rows)
		if e != nil {
			rows.Close()
			return nil, aiUnavailable()
		}
		out = append(out, v.AIWorkload)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(out) > 64 {
		return nil, aiUnavailable()
	}
	for i := range out {
		out[i].Models, err = loadWorkloadModels(ctx, tx, org, out[i].Id)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func validWorkloadName(name string) bool {
	return name == strings.TrimSpace(name) && len(name) > 0 && len(name) <= 100 && !strings.ContainsAny(name, "\r\n\x00")
}
func validateWorkloadInput(in api.AIWorkloadInput) error {
	if !validWorkloadName(in.Name) || in.ExpectedRevision < 0 || in.ExpectedRevision == math.MaxInt64 || len(in.Models) > 32 {
		return policyInvalid()
	}
	if in.DailyUsdThreshold != nil && (*in.DailyUsdThreshold <= 0 || *in.DailyUsdThreshold > 100000 || math.IsNaN(*in.DailyUsdThreshold) || math.IsInf(*in.DailyUsdThreshold, 0)) {
		return policyInvalid()
	}
	seen := map[string]bool{}
	connections := map[uuid.UUID]bool{}
	for _, m := range in.Models {
		if _, _, ok := splitProviderModel(m.Model); !ok || m.ConnectionId == uuid.Nil || seen[m.Model] || !ValidModelMode(ModelMode(m.Mode)) {
			return policyInvalid()
		}
		seen[m.Model] = true
		connections[m.ConnectionId] = true
	}
	if len(connections) > 8 {
		return policyInvalid()
	}
	return nil
}

// Put records desired policy before external reconciliation. The workload lock
// fences enrollment, token issuance, revocation and request authorization.
func (s *Workloads) Put(ctx context.Context, org, actor, id uuid.UUID, in api.AIWorkloadInput) (api.AIWorkload, error) {
	if !s.ready() {
		return api.AIWorkload{}, aiUnavailable()
	}
	if org == uuid.Nil || actor == uuid.Nil {
		return api.AIWorkload{}, policyInvalid()
	}
	if err := validateWorkloadInput(in); err != nil {
		return api.AIWorkload{}, err
	}
	creating := id == uuid.Nil
	if creating && in.ExpectedRevision != 0 {
		return api.AIWorkload{}, policyConflict()
	}
	if creating {
		id = uuid.New()
	}
	tx, err := s.policies.pool.Begin(ctx)
	if err != nil {
		return api.AIWorkload{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	// Same advisory lock as human-grant allocation; organization row below also
	// serializes legacy allocation. Never lock organization before providers.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,150))`, org.String()); err != nil {
		return api.AIWorkload{}, aiUnavailable()
	}
	var old workloadRecord
	if !creating {
		old, err = scanWorkload(tx.QueryRow(ctx, `SELECT `+workloadColumns+` FROM ai_workloads WHERE org_id=$1 AND id=$2 FOR UPDATE`, org, id))
		if err != nil {
			return api.AIWorkload{}, policyNotFound()
		}
		if old.Revision != in.ExpectedRevision {
			return api.AIWorkload{}, policyConflict()
		}
	}
	// Stable ordering prevents two multi-provider updates locking oppositely.
	models := slices.Clone(in.Models)
	slices.SortFunc(models, func(a, b api.AIWorkloadModel) int {
		return strings.Compare(a.ConnectionId.String()+a.Model, b.ConnectionId.String()+b.Model)
	})
	for _, m := range models {
		p, e := scanProvider(tx.QueryRow(ctx, `SELECT `+providerColumns+` FROM ai_provider_connections WHERE org_id=$1 AND id=$2 FOR SHARE`, org, m.ConnectionId))
		if e != nil {
			return api.AIWorkload{}, policyNotFound()
		}
		if in.Enabled {
			if e = s.policies.validateProviderAccess(ctx, tx, org, []string{p.KeyID}, []string{m.Model}); e != nil {
				return api.AIWorkload{}, e
			}
			if DefaultModelMode(p.ModelModes[m.Model]) != ModelMode(m.Mode) {
				return api.AIWorkload{}, policyInvalid()
			}
		}
	}
	if creating {
		var locked uuid.UUID
		if tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, org).Scan(&locked) != nil {
			return api.AIWorkload{}, policyNotFound()
		}
		var count int
		if tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM ai_workloads WHERE org_id=$1)+(SELECT count(*) FROM ai_user_model_grants WHERE org_id=$1)+(SELECT count(*) FROM ai_gateway_key_bindings WHERE org_id=$1)`, org).Scan(&count) != nil {
			return api.AIWorkload{}, aiUnavailable()
		}
		if count >= maxAIUsageBindings {
			return api.AIWorkload{}, apierr.BadRequest("ai_binding_capacity", "AI gateway binding capacity reached")
		}
		_, err = tx.Exec(ctx, `INSERT INTO ai_workloads(id,org_id,name,enabled,daily_usd_threshold) VALUES($1,$2,$3,$4,$5)`, id, org, in.Name, in.Enabled, in.DailyUsdThreshold)
	} else {
		_, err = tx.Exec(ctx, `UPDATE ai_workloads SET name=$3,enabled=$4,daily_usd_threshold=$5,revision=revision+1,status='pending',credential_epoch=credential_epoch+CASE WHEN enabled AND NOT $4 THEN 1 ELSE 0 END WHERE org_id=$1 AND id=$2`, org, id, in.Name, in.Enabled, in.DailyUsdThreshold)
	}
	if err != nil {
		return api.AIWorkload{}, policyConflict()
	}
	if !in.Enabled {
		// Re-enabling a workload cannot revive revoked introductions or old tokens.
		if _, err = tx.Exec(ctx, `UPDATE ai_workload_enrollment_keys SET revoked_at=coalesce(revoked_at,now()) WHERE org_id=$1 AND workload_id=$2`, org, id); err != nil {
			return api.AIWorkload{}, aiUnavailable()
		}
	}
	if _, err = tx.Exec(ctx, `DELETE FROM ai_workload_models WHERE org_id=$1 AND workload_id=$2`, org, id); err != nil {
		return api.AIWorkload{}, aiUnavailable()
	}
	for _, m := range models {
		if _, err = tx.Exec(ctx, `INSERT INTO ai_workload_models(org_id,workload_id,connection_id,model,mode) VALUES($1,$2,$3,$4,$5)`, org, id, m.ConnectionId, m.Model, m.Mode); err != nil {
			return api.AIWorkload{}, aiUnavailable()
		}
	}
	if auditPolicy(ctx, tx, org, actor, id, "ai_workload.policy_changed", in.ExpectedRevision+1) != nil || tx.Commit(ctx) != nil {
		return api.AIWorkload{}, aiUnavailable()
	}
	return s.Reconcile(ctx, org, id)
}

func (s *Workloads) Reconcile(ctx context.Context, org, id uuid.UUID) (api.AIWorkload, error) {
	if !s.ready() {
		return api.AIWorkload{}, aiUnavailable()
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tx, err := s.policies.pool.Begin(ctx)
	if err != nil {
		return api.AIWorkload{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	w, err := scanWorkload(tx.QueryRow(ctx, `SELECT `+workloadColumns+` FROM ai_workloads WHERE org_id=$1 AND id=$2 FOR UPDATE`, org, id))
	if err != nil {
		return api.AIWorkload{}, policyNotFound()
	}
	w.Models, err = loadWorkloadModels(ctx, tx, org, id)
	if err != nil {
		return api.AIWorkload{}, err
	}
	finish := func(status string) (api.AIWorkload, error) {
		w.Status = api.AIWorkloadStatus(status)
		if status != "error" {
			w.AppliedRevision = w.Revision
		}
		_, e := tx.Exec(ctx, `UPDATE ai_workloads SET status=$3,applied_revision=$4,native_key_id=$5,sealed_key=$6,binding_revision=$7,last_reconcile_at=now() WHERE org_id=$1 AND id=$2`, org, id, status, w.AppliedRevision, w.native, w.sealed, w.bindingRevision)
		if e != nil || tx.Commit(ctx) != nil {
			return api.AIWorkload{}, aiUnavailable()
		}
		return w.AIWorkload, nil
	}
	if !w.Enabled || len(w.Models) == 0 {
		if w.native != "" && s.policies.engine.DisableKey(ctx, w.native) != nil {
			return finish("error")
		}
		if !w.Enabled {
			return finish("revoked")
		}
		return finish("applied")
	}
	scopes := []EngineProviderScope{}
	for _, m := range w.Models {
		p, e := scanProvider(tx.QueryRow(ctx, `SELECT `+providerColumns+` FROM ai_provider_connections WHERE org_id=$1 AND id=$2 FOR SHARE`, org, m.ConnectionId))
		if e != nil || DefaultModelMode(p.ModelModes[m.Model]) != ModelMode(m.Mode) {
			return finish("error")
		}
		v, e := s.policies.providerScopes(ctx, tx, org, []string{p.KeyID}, []string{m.Model})
		if e != nil {
			return finish("error")
		}
		scopes = append(scopes, v...)
	}
	scopes = mergeWorkloadScopes(scopes)
	name := "ai-workload-" + org.String() + "-" + id.String()
	var key EngineKey
	if engine, ok := s.policies.engine.(ScopedPolicyEngine); ok {
		key, err = engine.EnsureScopedKey(ctx, name, scopes)
	} else if len(scopes) == 1 {
		key, err = s.policies.engine.EnsureKey(ctx, name, scopes[0].Provider, scopes[0].Models, scopes[0].KeyIDs)
	} else {
		return finish("error")
	}
	if err != nil || key.ID == "" || key.Value == "" || w.native != "" && w.native != key.ID {
		return finish("error")
	}
	sealed, err := sealBoundKey(s.policies.sealer, workloadKeyPurpose, org, id, key.ID, w.Revision, key.Value)
	if err != nil {
		return finish("error")
	}
	w.native, w.sealed, w.bindingRevision = key.ID, sealed, w.Revision
	return finish("applied")
}

func mergeWorkloadScopes(in []EngineProviderScope) []EngineProviderScope {
	out := []EngineProviderScope{}
	for _, v := range in {
		found := -1
		for i := range out {
			if out[i].Provider == v.Provider {
				found = i
				break
			}
		}
		if found < 0 {
			out = append(out, v)
		} else {
			out[found].Models = append(out[found].Models, v.Models...)
			out[found].KeyIDs = append(out[found].KeyIDs, v.KeyIDs...)
		}
	}
	for i := range out {
		slices.Sort(out[i].Models)
		out[i].Models = slices.Compact(out[i].Models)
		slices.Sort(out[i].KeyIDs)
		out[i].KeyIDs = slices.Compact(out[i].KeyIDs)
	}
	slices.SortFunc(out, func(a, b EngineProviderScope) int { return strings.Compare(a.Provider, b.Provider) })
	return out
}

func randomWorkloadSecret(prefix string) (string, []byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	raw := prefix + base64.RawURLEncoding.EncodeToString(b)
	hash := sha256.Sum256([]byte(raw))
	return raw, hash[:], nil
}

const workloadEnrollmentColumns = `id,name,reusable,ephemeral,max_uses,uses,expires_at,revoked_at,created_at`

func scanWorkloadKey(row pgx.Row) (api.AIWorkloadEnrollmentKey, error) {
	var k api.AIWorkloadEnrollmentKey
	err := row.Scan(&k.Id, &k.Name, &k.Reusable, &k.Ephemeral, &k.MaxUses, &k.Uses, &k.ExpiresAt, &k.RevokedAt, &k.CreatedAt)
	return k, err
}

func (s *Workloads) CreateKey(ctx context.Context, org, actor, id uuid.UUID, in api.AIWorkloadKeyInput) (api.AIWorkloadKeySecret, error) {
	if !s.ready() {
		return api.AIWorkloadKeySecret{}, aiUnavailable()
	}
	now := time.Now()
	maxTTL := 90 * 24 * time.Hour
	if !in.Reusable {
		maxTTL = 24 * time.Hour
	}
	if !validWorkloadName(in.Name) || !in.ExpiresAt.After(now) || in.ExpiresAt.After(now.Add(maxTTL)) || in.MaxUses < 0 || !in.Reusable && in.MaxUses != 1 {
		return api.AIWorkloadKeySecret{}, policyInvalid()
	}
	tx, err := s.policies.pool.Begin(ctx)
	if err != nil {
		return api.AIWorkloadKeySecret{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	var enabled bool
	if tx.QueryRow(ctx, `SELECT enabled FROM ai_workloads WHERE org_id=$1 AND id=$2 FOR UPDATE`, org, id).Scan(&enabled) != nil {
		return api.AIWorkloadKeySecret{}, policyNotFound()
	}
	if !enabled {
		return api.AIWorkloadKeySecret{}, policyDenied()
	}
	var count int
	if tx.QueryRow(ctx, `SELECT count(*) FROM ai_workload_enrollment_keys WHERE org_id=$1 AND workload_id=$2 AND revoked_at IS NULL AND expires_at>now()`, org, id).Scan(&count) != nil {
		return api.AIWorkloadKeySecret{}, aiUnavailable()
	}
	if count >= 32 {
		return api.AIWorkloadKeySecret{}, apierr.BadRequest("enrollment_key_capacity", "Revoke unused enrollment keys before creating another")
	}
	raw, hash, err := randomWorkloadSecret(workloadEnrollmentPrefix)
	if err != nil {
		return api.AIWorkloadKeySecret{}, aiUnavailable()
	}
	key, err := scanWorkloadKey(tx.QueryRow(ctx, `INSERT INTO ai_workload_enrollment_keys(id,org_id,workload_id,secret_hash,name,reusable,ephemeral,max_uses,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING `+workloadEnrollmentColumns, uuid.New(), org, id, hash, in.Name, in.Reusable, in.Ephemeral, in.MaxUses, in.ExpiresAt))
	if err != nil || auditPolicy(ctx, tx, org, actor, key.Id, "ai_workload.enrollment_key_created", 1) != nil || tx.Commit(ctx) != nil {
		return api.AIWorkloadKeySecret{}, aiUnavailable()
	}
	return api.AIWorkloadKeySecret{Key: key, Secret: raw}, nil
}

func (s *Workloads) ListKeys(ctx context.Context, org, id, after uuid.UUID, limit int) (api.AIWorkloadKeyPage, error) {
	out := api.AIWorkloadKeyPage{Items: []api.AIWorkloadEnrollmentKey{}}
	if !s.ready() {
		return out, aiUnavailable()
	}
	if limit < 1 || limit > 100 {
		return out, policyInvalid()
	}
	rows, err := s.policies.pool.Query(ctx, `SELECT `+workloadEnrollmentColumns+` FROM ai_workload_enrollment_keys WHERE org_id=$1 AND workload_id=$2 AND id>$3 ORDER BY id LIMIT $4`, org, id, after, limit+1)
	if err != nil {
		return out, aiUnavailable()
	}
	defer rows.Close()
	for rows.Next() {
		k, e := scanWorkloadKey(rows)
		if e != nil {
			return out, aiUnavailable()
		}
		out.Items = append(out.Items, k)
	}
	if rows.Err() != nil {
		return out, aiUnavailable()
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		last := out.Items[limit-1].Id
		out.NextCursor = &last
	}
	return out, nil
}
func (s *Workloads) RevokeKey(ctx context.Context, org, actor, id, key uuid.UUID, instances bool) error {
	if !s.ready() {
		return aiUnavailable()
	}
	tx, err := s.policies.pool.Begin(ctx)
	if err != nil {
		return aiUnavailable()
	}
	defer rollbackAI(tx)
	var locked uuid.UUID
	if tx.QueryRow(ctx, `SELECT id FROM ai_workloads WHERE org_id=$1 AND id=$2 FOR UPDATE`, org, id).Scan(&locked) != nil {
		return policyNotFound()
	}
	res, err := tx.Exec(ctx, `UPDATE ai_workload_enrollment_keys SET revoked_at=coalesce(revoked_at,now()) WHERE org_id=$1 AND workload_id=$2 AND id=$3`, org, id, key)
	if err != nil {
		return aiUnavailable()
	}
	if res.RowsAffected() != 1 {
		return policyNotFound()
	}
	action := "ai_workload.enrollment_key_revoked"
	if instances {
		if _, err = tx.Exec(ctx, `UPDATE ai_workload_instances SET state='revoked' WHERE org_id=$1 AND workload_id=$2 AND enrollment_key_id=$3 AND state='active'`, org, id, key); err != nil {
			return aiUnavailable()
		}
		action = "ai_workload.enrollment_key_and_instances_revoked"
	}
	if auditPolicy(ctx, tx, org, actor, key, action, 1) != nil || tx.Commit(ctx) != nil {
		return aiUnavailable()
	}
	return nil
}

func (s *Workloads) ListInstances(ctx context.Context, org, id, after uuid.UUID, limit int) (api.AIWorkloadInstancePage, error) {
	out := api.AIWorkloadInstancePage{Items: []api.AIWorkloadInstance{}}
	if !s.ready() {
		return out, aiUnavailable()
	}
	if limit < 1 || limit > 100 {
		return out, policyInvalid()
	}
	rows, err := s.policies.pool.Query(ctx, `SELECT id,enrollment_key_id,ephemeral,CASE WHEN state='active' AND last_contact_at<now()-interval '10 minutes' THEN 'offline' ELSE state END,key_generation,last_contact_at,created_at FROM ai_workload_instances WHERE org_id=$1 AND workload_id=$2 AND id>$3 ORDER BY id LIMIT $4`, org, id, after, limit+1)
	if err != nil {
		return out, aiUnavailable()
	}
	defer rows.Close()
	for rows.Next() {
		var v api.AIWorkloadInstance
		if rows.Scan(&v.Id, &v.EnrollmentKeyId, &v.Ephemeral, &v.State, &v.KeyGeneration, &v.LastContactAt, &v.CreatedAt) != nil {
			return out, aiUnavailable()
		}
		out.Items = append(out.Items, v)
	}
	if rows.Err() != nil {
		return out, aiUnavailable()
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		last := out.Items[limit-1].Id
		out.NextCursor = &last
	}
	return out, nil
}
func (s *Workloads) RevokeInstance(ctx context.Context, org, actor, id, instance uuid.UUID) error {
	if !s.ready() {
		return aiUnavailable()
	}
	tx, err := s.policies.pool.Begin(ctx)
	if err != nil {
		return aiUnavailable()
	}
	defer rollbackAI(tx)
	var locked uuid.UUID
	if tx.QueryRow(ctx, `SELECT id FROM ai_workloads WHERE org_id=$1 AND id=$2 FOR UPDATE`, org, id).Scan(&locked) != nil {
		return policyNotFound()
	}
	res, err := tx.Exec(ctx, `UPDATE ai_workload_instances SET state='revoked' WHERE org_id=$1 AND workload_id=$2 AND id=$3`, org, id, instance)
	if err != nil {
		return aiUnavailable()
	}
	if res.RowsAffected() != 1 {
		return policyNotFound()
	}
	if auditPolicy(ctx, tx, org, actor, instance, "ai_workload.instance_revoked", 1) != nil || tx.Commit(ctx) != nil {
		return aiUnavailable()
	}
	return nil
}
