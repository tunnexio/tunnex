package aigateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
)

type workloadInstance struct {
	id, org, workload, key, request uuid.UUID
	public, previous                []byte
	generation                      int64
	rotation                        *uuid.UUID
	state                           string
}

const workloadInstanceColumns = `id,org_id,workload_id,enrollment_key_id,enrollment_request_id,public_key,previous_public_key,key_generation,rotation_id,state`

func scanWorkloadInstance(row pgx.Row) (workloadInstance, error) {
	var i workloadInstance
	err := row.Scan(&i.id, &i.org, &i.workload, &i.key, &i.request, &i.public, &i.previous, &i.generation, &i.rotation, &i.state)
	return i, err
}

func (s *Workloads) receipt(i workloadInstance) api.AIWorkloadReceipt {
	return api.AIWorkloadReceipt{InstanceId: i.id, WorkloadId: i.workload, OrganizationId: i.org, KeyGeneration: i.generation, TokenEndpoint: s.base + "/api/v1/workload/token", GatewayBase: s.base + "/ai/v1"}
}

// Missing records retain the caller's no-oracle refusal. A failed storage read
// cannot establish invalid authority and must remain retryable.
func workloadLookupError(err, refusal error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return refusal
	}
	return aiUnavailable()
}

// This lock order is shared by every authentication and administrative action:
// workload -> instance/enrollment key -> provider (if any) -> organization.
func liveWorkload(ctx context.Context, tx pgx.Tx, org, id uuid.UUID) (workloadRecord, error) {
	w, err := scanWorkload(tx.QueryRow(ctx, `SELECT `+workloadColumns+` FROM ai_workloads WHERE org_id=$1 AND id=$2 FOR SHARE`, org, id))
	if err != nil {
		return workloadRecord{}, workloadLookupError(err, aiUnauthorized())
	}
	if !w.Enabled {
		return workloadRecord{}, aiUnauthorized()
	}
	return w, nil
}
func liveWorkloadOrg(ctx context.Context, tx pgx.Tx, org uuid.UUID) (int64, error) {
	var enabled bool
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT ai_gateway_enabled,ai_gateway_revision FROM organizations WHERE id=$1 AND deleted_at IS NULL FOR SHARE`, org).Scan(&enabled, &revision); err != nil {
		return 0, workloadLookupError(err, aiUnauthorized())
	}
	if !enabled {
		return 0, aiUnauthorized()
	}
	return revision, nil
}
func auditWorkloadSystem(ctx context.Context, tx pgx.Tx, i workloadInstance, action string) error {
	_, err := tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_system,action,target_type,target_id,metadata) VALUES($1,'workload-identity',$2,'ai_workload_instance',$3,jsonb_build_object('cause',$2::text,'workload_id',$4::text,'key_generation',$5::bigint))`, i.org, action, i.id.String(), i.workload.String(), i.generation)
	return err
}

func (s *Workloads) Enroll(ctx context.Context, in api.AIWorkloadEnrollInput) (api.AIWorkloadReceipt, error) {
	if !s.ready() {
		return api.AIWorkloadReceipt{}, aiUnavailable()
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(in.PublicKey)
	hash := sha256.Sum256([]byte(in.EnrollmentKey))
	if err != nil || in.RequestId == uuid.Nil || !strings.HasPrefix(in.EnrollmentKey, workloadEnrollmentPrefix) || len(in.EnrollmentKey) > 128 {
		return api.AIWorkloadReceipt{}, aiUnauthorized()
	}
	proof, err := verifyWorkloadProof(in.Proof, public, s.base+"/api/v1/workload/enroll", "enrollment", time.Now())
	if err != nil || proof.RequestID != in.RequestId.String() || proof.EnrollmentHash != hex.EncodeToString(hash[:]) {
		return api.AIWorkloadReceipt{}, aiUnauthorized()
	}
	tx, err := s.policies.pool.Begin(ctx)
	if err != nil {
		return api.AIWorkloadReceipt{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	var org, workload, key uuid.UUID
	// lint:cross-org keyed bootstrap lookup; org is obtained from an unguessable
	// hashed introduction and is then mandatory on every subsequent query.
	if err = tx.QueryRow(ctx, `SELECT org_id,workload_id,id FROM ai_workload_enrollment_keys WHERE secret_hash=$1`, hash[:]).Scan(&org, &workload, &key); err != nil {
		return api.AIWorkloadReceipt{}, workloadLookupError(err, aiUnauthorized())
	}
	if _, err = liveWorkload(ctx, tx, org, workload); err != nil {
		return api.AIWorkloadReceipt{}, err
	}
	k, err := scanWorkloadKey(tx.QueryRow(ctx, `SELECT `+workloadEnrollmentColumns+` FROM ai_workload_enrollment_keys WHERE org_id=$1 AND workload_id=$2 AND id=$3 FOR UPDATE`, org, workload, key))
	if err != nil {
		return api.AIWorkloadReceipt{}, workloadLookupError(err, aiUnauthorized())
	}
	i, err := scanWorkloadInstance(tx.QueryRow(ctx, `SELECT `+workloadInstanceColumns+` FROM ai_workload_instances WHERE org_id=$1 AND workload_id=$2 AND enrollment_key_id=$3 AND enrollment_request_id=$4`, org, workload, key, in.RequestId))
	if err == nil {
		// A receipt retry is not a new enrollment, even after key expiry/use. A
		// revoked/rotated identity cannot regain its initial key through this path.
		if i.state != "active" || !bytes.Equal(i.public, public) || i.generation != 1 {
			return api.AIWorkloadReceipt{}, aiUnauthorized()
		}
		if _, err = liveWorkloadOrg(ctx, tx, org); err != nil {
			return api.AIWorkloadReceipt{}, err
		}
		return s.receipt(i), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return api.AIWorkloadReceipt{}, aiUnavailable()
	}
	if k.RevokedAt != nil || !k.ExpiresAt.After(time.Now()) || k.MaxUses > 0 && k.Uses >= k.MaxUses || !k.Reusable && k.Uses > 0 {
		return api.AIWorkloadReceipt{}, aiUnauthorized()
	}
	if _, err = liveWorkloadOrg(ctx, tx, org); err != nil {
		return api.AIWorkloadReceipt{}, err
	}
	i, err = scanWorkloadInstance(tx.QueryRow(ctx, `INSERT INTO ai_workload_instances(id,org_id,workload_id,enrollment_key_id,enrollment_request_id,public_key,ephemeral) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING `+workloadInstanceColumns, uuid.New(), org, workload, key, in.RequestId, public, k.Ephemeral))
	if err != nil {
		return api.AIWorkloadReceipt{}, aiUnavailable()
	}
	if _, err = tx.Exec(ctx, `UPDATE ai_workload_enrollment_keys SET uses=uses+1 WHERE org_id=$1 AND workload_id=$2 AND id=$3`, org, workload, key); err != nil {
		return api.AIWorkloadReceipt{}, aiUnavailable()
	}
	if auditWorkloadSystem(ctx, tx, i, "ai_workload.instance_enrolled") != nil || tx.Commit(ctx) != nil {
		return api.AIWorkloadReceipt{}, aiUnavailable()
	}
	return s.receipt(i), nil
}

func (s *Workloads) lockInstance(ctx context.Context, tx pgx.Tx, id uuid.UUID) (workloadRecord, workloadInstance, error) {
	var org, workload uuid.UUID
	// lint:cross-org client ID locates the registered public key, never authority;
	// the signed proof is verified by callers before any mutation is committed.
	if err := tx.QueryRow(ctx, `SELECT org_id,workload_id FROM ai_workload_instances WHERE id=$1`, id).Scan(&org, &workload); err != nil {
		return workloadRecord{}, workloadInstance{}, workloadLookupError(err, aiUnauthorized())
	}
	w, err := liveWorkload(ctx, tx, org, workload)
	if err != nil {
		return workloadRecord{}, workloadInstance{}, err
	}
	i, err := scanWorkloadInstance(tx.QueryRow(ctx, `SELECT `+workloadInstanceColumns+` FROM ai_workload_instances WHERE org_id=$1 AND workload_id=$2 AND id=$3 FOR UPDATE`, org, workload, id))
	if err != nil {
		return workloadRecord{}, workloadInstance{}, workloadLookupError(err, aiUnauthorized())
	}
	if i.state != "active" {
		return workloadRecord{}, workloadInstance{}, aiUnauthorized()
	}
	return w, i, nil
}
func recordWorkloadProof(ctx context.Context, tx pgx.Tx, i workloadInstance, proof workloadProof) error {
	// Replay fencing spans API processes and survives process restarts. Keep the
	// JTI through the full verifier leeway, not only the nominal JWT expiry.
	res, err := tx.Exec(ctx, `INSERT INTO ai_workload_assertions(instance_id,jti,expires_at) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, i.id, proof.ID, proof.Expires.Add(30*time.Second))
	if err != nil {
		return aiUnavailable()
	}
	if res.RowsAffected() != 1 {
		return aiUnauthorized()
	}
	return nil
}
func (s *Workloads) Token(ctx context.Context, in api.AIWorkloadTokenInput) (api.AIWorkloadToken, error) {
	if !s.ready() {
		return api.AIWorkloadToken{}, aiUnavailable()
	}
	if in.GrantType != "client_credentials" || in.ClientAssertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" || in.ClientId == uuid.Nil {
		return api.AIWorkloadToken{}, aiUnauthorized()
	}
	tx, err := s.policies.pool.Begin(ctx)
	if err != nil {
		return api.AIWorkloadToken{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	w, i, err := s.lockInstance(ctx, tx, in.ClientId)
	if err != nil {
		return api.AIWorkloadToken{}, err
	}
	proof, err := verifyWorkloadProof(in.ClientAssertion, i.public, s.base+"/api/v1/workload/token", i.id.String(), time.Now())
	if err != nil {
		return api.AIWorkloadToken{}, aiUnauthorized()
	}
	if err = recordWorkloadProof(ctx, tx, i, proof); err != nil {
		return api.AIWorkloadToken{}, err
	}
	orgRevision, err := liveWorkloadOrg(ctx, tx, i.org)
	if err != nil {
		return api.AIWorkloadToken{}, err
	}
	raw, hash, err := randomWorkloadSecret(workloadTokenPrefix)
	if err != nil {
		return api.AIWorkloadToken{}, aiUnavailable()
	}
	// Keep one preceding token for overlapping in-flight requests. Only the
	// instance lock holder can mint, so concurrent exchanges cannot exceed two.
	if _, err = tx.Exec(ctx, `DELETE FROM ai_workload_tokens WHERE org_id=$1 AND instance_id=$2 AND (expires_at<=now() OR token_hash NOT IN (SELECT token_hash FROM ai_workload_tokens WHERE org_id=$1 AND instance_id=$2 ORDER BY created_at DESC,token_hash LIMIT 1))`, i.org, i.id); err != nil {
		return api.AIWorkloadToken{}, aiUnavailable()
	}
	if _, err = tx.Exec(ctx, `INSERT INTO ai_workload_tokens(token_hash,org_id,workload_id,instance_id,audience,key_generation,workload_epoch,org_revision,expires_at) VALUES($1,$2,$3,$4,'tunnex-ai',$5,$6,$7,now()+interval '5 minutes')`, hash, i.org, i.workload, i.id, i.generation, w.epoch, orgRevision); err != nil {
		return api.AIWorkloadToken{}, aiUnavailable()
	}
	if _, err = tx.Exec(ctx, `UPDATE ai_workload_instances SET last_contact_at=now() WHERE org_id=$1 AND workload_id=$2 AND id=$3`, i.org, i.workload, i.id); err != nil || tx.Commit(ctx) != nil {
		return api.AIWorkloadToken{}, aiUnavailable()
	}
	return api.AIWorkloadToken{AccessToken: raw, TokenType: "Bearer", ExpiresIn: 300, Scope: "tunnex-ai"}, nil
}

type workloadBearer struct {
	instance    workloadInstance
	workload    workloadRecord
	expires     time.Time
	orgRevision int64
}

func (s *Workloads) authenticate(ctx context.Context, tx pgx.Tx, raw string, exclusive bool) (workloadBearer, error) {
	if !strings.HasPrefix(raw, workloadTokenPrefix) || len(raw) > 128 {
		return workloadBearer{}, aiUnauthorized()
	}
	hash := sha256.Sum256([]byte(raw))
	var org, id, instance uuid.UUID
	var generation, epoch, orgRevision int64
	var expires time.Time
	// lint:cross-org hashed bearer lookup; all authority reads are scoped to the
	// stored tenant and workload, never to a caller-provided organization.
	if err := tx.QueryRow(ctx, `SELECT org_id,workload_id,instance_id,key_generation,workload_epoch,org_revision,expires_at FROM ai_workload_tokens WHERE token_hash=$1 AND audience='tunnex-ai' AND expires_at>now()`, hash[:]).Scan(&org, &id, &instance, &generation, &epoch, &orgRevision, &expires); err != nil {
		return workloadBearer{}, workloadLookupError(err, aiUnauthorized())
	}
	w, err := liveWorkload(ctx, tx, org, id)
	if err != nil {
		return workloadBearer{}, err
	}
	if w.epoch != epoch {
		return workloadBearer{}, aiUnauthorized()
	}
	lock := " FOR SHARE"
	if exclusive {
		lock = " FOR UPDATE"
	}
	i, err := scanWorkloadInstance(tx.QueryRow(ctx, `SELECT `+workloadInstanceColumns+` FROM ai_workload_instances WHERE org_id=$1 AND workload_id=$2 AND id=$3`+lock, org, id, instance))
	if err != nil {
		return workloadBearer{}, workloadLookupError(err, aiUnauthorized())
	}
	if i.state != "active" || i.generation != generation {
		return workloadBearer{}, aiUnauthorized()
	}
	// No organization lock here: provider locks must precede it. The final
	// opt-in check below and in callers is repeated after policy/provider reads.
	var live bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1 AND deleted_at IS NULL AND ai_gateway_enabled AND ai_gateway_revision=$2)`, org, orgRevision).Scan(&live); err != nil {
		return workloadBearer{}, workloadLookupError(err, aiUnauthorized())
	}
	if !live {
		return workloadBearer{}, aiUnauthorized()
	}
	return workloadBearer{i, w, expires, orgRevision}, nil
}
func (s *Workloads) Authorize(ctx context.Context, raw, model string) (Grant, error) {
	if !s.ready() {
		return Grant{}, aiUnavailable()
	}
	tx, err := s.policies.pool.Begin(ctx)
	if err != nil {
		return Grant{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	b, err := s.authenticate(ctx, tx, raw, false)
	if err != nil {
		return Grant{}, err
	}
	return s.resolve(ctx, tx, b, model, true)
}
func (s *Workloads) resolve(ctx context.Context, tx pgx.Tx, b workloadBearer, model string, cost bool) (Grant, error) {
	w, i := b.workload, b.instance
	if w.Status != "applied" || w.AppliedRevision != w.Revision {
		return Grant{}, policyDenied()
	}
	var connection uuid.UUID
	var mode ModelMode
	if err := tx.QueryRow(ctx, `SELECT connection_id,mode FROM ai_workload_models WHERE org_id=$1 AND workload_id=$2 AND model=$3`, i.org, i.workload, model).Scan(&connection, &mode); err != nil {
		return Grant{}, workloadLookupError(err, policyDenied())
	}
	p, err := scanProvider(tx.QueryRow(ctx, `SELECT `+providerColumns+` FROM ai_provider_connections WHERE org_id=$1 AND id=$2 FOR SHARE`, i.org, connection))
	if err != nil {
		return Grant{}, workloadLookupError(err, policyDenied())
	}
	if err = s.policies.validateProviderAccess(ctx, tx, i.org, []string{p.KeyID}, []string{model}); err != nil {
		return Grant{}, err
	}
	if DefaultModelMode(p.ModelModes[model]) != mode {
		return Grant{}, policyDenied()
	}
	revision, err := liveWorkloadOrg(ctx, tx, i.org)
	if err != nil {
		return Grant{}, err
	}
	if revision != b.orgRevision {
		return Grant{}, aiUnauthorized()
	}
	if cost {
		if err = s.policies.enforceCostBindings(ctx, tx, i.org, model, mode, w.DailyUsdThreshold, func() ([]string, error) {
			if w.native == "" {
				return nil, aiUnavailable()
			}
			return []string{w.native}, nil
		}); err != nil {
			return Grant{}, err
		}
	}
	key, err := openBoundKey(s.policies.sealer, workloadKeyPurpose, i.org, i.workload, w.native, w.bindingRevision, w.sealed)
	if err != nil {
		return Grant{}, aiUnavailable()
	}
	expires := time.Now().Add(30 * time.Second)
	if b.expires.Before(expires) {
		expires = b.expires
	}
	return Grant{Tenant: i.org.String(), Agent: i.workload.String(), SubjectKind: "workload", Instance: i.id.String(), Mode: mode, VirtualKey: key, Expires: expires}, nil
}
func (s *Workloads) Models(ctx context.Context, raw string) ([]UserModel, error) {
	if !s.ready() {
		return nil, aiUnavailable()
	}
	tx, err := s.policies.pool.Begin(ctx)
	if err != nil {
		return nil, aiUnavailable()
	}
	defer rollbackAI(tx)
	b, err := s.authenticate(ctx, tx, raw, false)
	if err != nil {
		return nil, err
	}
	models, err := loadWorkloadModels(ctx, tx, b.instance.org, b.instance.workload)
	if err != nil {
		return nil, err
	}
	out := []UserModel{}
	for _, m := range models {
		g, e := s.resolve(ctx, tx, b, m.Model, false)
		if e == nil {
			out = append(out, UserModel{Model: m.Model, Mode: g.Mode})
		} else {
			return nil, e
		}
	}
	revision, err := liveWorkloadOrg(ctx, tx, b.instance.org)
	if err != nil {
		return nil, err
	}
	if revision != b.orgRevision {
		return nil, aiUnauthorized()
	}
	return out, nil
}

func (s *Workloads) Rotate(ctx context.Context, in api.AIWorkloadRotationInput) (api.AIWorkloadReceipt, error) {
	if !s.ready() {
		return api.AIWorkloadReceipt{}, aiUnavailable()
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(in.PublicKey)
	if err != nil || len(public) != 32 || in.RequestId == uuid.Nil {
		return api.AIWorkloadReceipt{}, aiUnauthorized()
	}
	tx, err := s.policies.pool.Begin(ctx)
	if err != nil {
		return api.AIWorkloadReceipt{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	_, i, err := s.lockInstance(ctx, tx, in.InstanceId)
	if err != nil {
		return api.AIWorkloadReceipt{}, err
	}
	retry := i.rotation != nil && *i.rotation == in.RequestId
	old := i.public
	if retry {
		old = i.previous
		if !bytes.Equal(i.public, public) {
			return api.AIWorkloadReceipt{}, aiUnauthorized()
		}
	} else if bytes.Equal(i.public, public) {
		return api.AIWorkloadReceipt{}, aiUnauthorized()
	}
	audience := s.base + "/api/v1/workload/rotate"
	a, err := verifyWorkloadProof(in.OldProof, old, audience, i.id.String(), time.Now())
	if err != nil {
		return api.AIWorkloadReceipt{}, aiUnauthorized()
	}
	b, err := verifyWorkloadProof(in.NewProof, public, audience, i.id.String(), time.Now())
	if err != nil || a.RequestID != in.RequestId.String() || b.RequestID != a.RequestID || a.NextKey != in.PublicKey || b.NextKey != in.PublicKey || a.ID == b.ID {
		return api.AIWorkloadReceipt{}, aiUnauthorized()
	}
	if _, err = liveWorkloadOrg(ctx, tx, i.org); err != nil {
		return api.AIWorkloadReceipt{}, err
	}
	if retry {
		return s.receipt(i), nil
	}
	if err = recordWorkloadProof(ctx, tx, i, a); err != nil {
		return api.AIWorkloadReceipt{}, err
	}
	if err = recordWorkloadProof(ctx, tx, i, b); err != nil {
		return api.AIWorkloadReceipt{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE ai_workload_instances SET previous_public_key=public_key,public_key=$4,key_generation=key_generation+1,rotation_id=$5,last_contact_at=now() WHERE org_id=$1 AND workload_id=$2 AND id=$3`, i.org, i.workload, i.id, public, in.RequestId); err != nil {
		return api.AIWorkloadReceipt{}, aiUnavailable()
	}
	i.generation++
	if auditWorkloadSystem(ctx, tx, i, "ai_workload.instance_key_rotated") != nil || tx.Commit(ctx) != nil {
		return api.AIWorkloadReceipt{}, aiUnavailable()
	}
	return s.receipt(i), nil
}
func (s *Workloads) Retire(ctx context.Context, raw string) error {
	if !s.ready() {
		return aiUnavailable()
	}
	tx, err := s.policies.pool.Begin(ctx)
	if err != nil {
		return aiUnavailable()
	}
	defer rollbackAI(tx)
	b, err := s.authenticate(ctx, tx, raw, true)
	if err != nil {
		return err
	}
	// The exclusive instance lock fences renewal and simultaneous retirement.
	if _, err = tx.Exec(ctx, `UPDATE ai_workload_instances SET state='retired' WHERE org_id=$1 AND workload_id=$2 AND id=$3 AND state='active'`, b.instance.org, b.instance.workload, b.instance.id); err != nil {
		return aiUnavailable()
	}
	if auditWorkloadSystem(ctx, tx, b.instance, "ai_workload.instance_retired") != nil || tx.Commit(ctx) != nil {
		return aiUnavailable()
	}
	return nil
}
