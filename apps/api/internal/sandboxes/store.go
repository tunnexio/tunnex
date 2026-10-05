package sandboxes

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxscope"
)

var (
	ErrForbidden = errors.New("sandbox operation forbidden")
	ErrDisabled  = errors.New("sandbox provisioning unavailable")
	ErrConflict  = errors.New("sandbox operation conflicts with current state")
	ErrQuota     = errors.New("sandbox quota exceeded")
	ErrNotFound  = errors.New("sandbox not found")
	ErrInvalid   = errors.New("invalid sandbox request")
)

type Store struct {
	pool             *pgxpool.Pool
	policyNotify     func(context.Context, uuid.UUID)
	qualificationOrg uuid.UUID
	boundedRuntime   *BoundedRuntimeBinding
}

func NewStore(pool *pgxpool.Pool) *Store                   { return &Store{pool: pool} }
func (s *Store) WithQualificationOrg(org uuid.UUID) *Store { s.qualificationOrg = org; return s }
func (s *Store) WithPolicyNotify(notify func(context.Context, uuid.UUID)) *Store {
	s.policyNotify = notify
	return s
}
func (s *Store) notifyPolicy(ctx context.Context, org uuid.UUID) {
	if s.policyNotify != nil {
		s.policyNotify(ctx, org)
	}
}

type CreateInput struct {
	TemplateID       uuid.UUID        `json:"template_id"`
	TerminalDeviceID *uuid.UUID       `json:"terminal_device_id,omitempty"`
	Name             string           `json:"name"`
	SelectedSkills   []SkillSelection `json:"selected_skills"`
	SSHPublicKeys    []string         `json:"ssh_public_keys"`
	Requested        []Scope          `json:"requested_scope"`
	TTLSeconds       int32            `json:"ttl_seconds"`
	IdempotencyKey   string           `json:"-"`
}

// authorize always loads current membership; neither supplied role nor creator
// fields are accepted. Machine principals cannot turn themselves into users.
func authorize(ctx context.Context, tx pgx.Tx, org, actor uuid.UUID, permission rbac.Permission) ([]string, error) {
	if org == uuid.Nil || actor == uuid.Nil {
		return nil, ErrForbidden
	}
	var roles []string
	var verified bool
	err := tx.QueryRow(ctx, `SELECT COALESCE(m.roles,ARRAY[m.role]),u.email_verified_at IS NOT NULL FROM memberships m
 JOIN users u ON u.id=m.user_id JOIN organizations o ON o.id=m.org_id
 WHERE m.org_id=$1 AND m.user_id=$2 AND m.access_revoked_at IS NULL AND u.status='active' AND u.deleted_at IS NULL AND NOT u.must_change_password AND o.deleted_at IS NULL
 FOR SHARE OF m,u`, org, actor).Scan(&roles, &verified)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrForbidden
	}
	if err != nil {
		return nil, err
	}
	if !rbac.CanAny(roles, permission) || (rbac.IsMutating(permission) && !verified) {
		return nil, ErrForbidden
	}
	d, err := delegationForUse(ctx, tx, org, actor)
	if err != nil {
		return nil, err
	}
	if d != nil {
		if permission != rbac.PermSandboxCreate && permission != rbac.PermSandboxView && permission != rbac.PermSandboxManage {
			return nil, ErrForbidden
		}
		return []string{rbac.RoleMember}, nil
	}
	return roles, nil
}

const sandboxColumns = `id,org_id,creator_id,template_id,name,requested_scope,peer_id,desired_state,observed_state,generation,created_at,expires_at,selected_skills,ssh_public_keys`

func scanSandbox(row pgx.Row) (Sandbox, error) {
	var out Sandbox
	var raw, skillsRaw, keysRaw []byte
	var peer pgtype.UUID
	err := row.Scan(&out.Identity.ID, &out.Identity.OrgID, &out.Identity.CreatorID, &out.TemplateVersionID, &out.Name, &raw, &peer, &out.DesiredState, &out.State, &out.Revision, &out.CreatedAt, &out.ExpiresAt, &skillsRaw, &keysRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return Sandbox{}, ErrNotFound
	}
	if err != nil {
		return Sandbox{}, err
	}
	if err = json.Unmarshal(raw, &out.RequestedScope); err != nil {
		return Sandbox{}, ErrInvalid
	}
	if json.Unmarshal(skillsRaw, &out.SelectedSkills) != nil {
		return Sandbox{}, ErrInvalid
	}
	if json.Unmarshal(keysRaw, &out.SSHPublicKeys) != nil {
		return Sandbox{}, ErrInvalid
	}
	if peer.Valid {
		id := uuid.UUID(peer.Bytes)
		out.PeerID = &id
	}
	return out, nil
}

func (s *Store) Create(ctx context.Context, org, actor uuid.UUID, in CreateInput) (Sandbox, bool, error) {
	if s != nil && s.qualificationOrg != uuid.Nil && s.qualificationOrg != org {
		return Sandbox{}, false, ErrDisabled
	}
	if s == nil || s.pool == nil {
		return Sandbox{}, false, ErrDisabled
	}
	if err := s.boundedCreate(ctx, org, actor, in); err != nil {
		return Sandbox{}, false, err
	}
	in.Name = strings.TrimSpace(in.Name)
	normalized, err := sandboxscope.NormalizeScope(in.Requested)
	if err != nil || in.TemplateID == uuid.Nil || len(in.Name) == 0 || len(in.Name) > 80 || in.TTLSeconds < 300 || in.TTLSeconds > 86400 || len(in.IdempotencyKey) == 0 || len(in.IdempotencyKey) > 128 {
		return Sandbox{}, false, ErrInvalid
	}
	in.Requested = normalized
	in.SSHPublicKeys, err = NormalizeSSHPublicKeys(in.SSHPublicKeys, 7)
	if err != nil {
		return Sandbox{}, false, err
	}
	in.SelectedSkills, err = normalizeSkills(in.SelectedSkills)
	if err != nil {
		return Sandbox{}, false, err
	}
	if p, ok := authctx.PrincipalFrom(ctx); ok && p.IsMachine() {
		key := sha256.Sum256([]byte(p.MachineID.String() + ":" + in.IdempotencyKey))
		in.IdempotencyKey = fmt.Sprintf("delegated:%x", key)
	}
	intent, _ := json.Marshal(in)
	hash := sha256.Sum256(intent)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Sandbox{}, false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// One org lock orders quota, idempotency and org policy mode/opt-in changes.
	var enabled bool
	var mode string
	var perUser, total int32
	err = tx.QueryRow(ctx, `SELECT sandboxes_enabled,zero_trust_mode,max_sandboxes_per_user,max_sandboxes FROM organizations WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, org).Scan(&enabled, &mode, &perUser, &total)
	if errors.Is(err, pgx.ErrNoRows) {
		return Sandbox{}, false, ErrForbidden
	}
	if err != nil {
		return Sandbox{}, false, err
	}
	if _, err = authorize(ctx, tx, org, actor, rbac.PermSandboxCreate); err != nil {
		return Sandbox{}, false, err
	}
	d, err := delegationForUse(ctx, tx, org, actor)
	if err != nil {
		return Sandbox{}, false, err
	}
	if d != nil {
		if err = d.admit(in); err != nil {
			return Sandbox{}, false, err
		}
	}
	var selectedTerminal uuid.UUID
	if b := s.boundedRuntime; b != nil {
		selectedTerminal, err = b.terminalDevice(in.TerminalDeviceID)
		if err != nil {
			return Sandbox{}, false, err
		}
		if err = b.validateTerminalDevice(ctx, tx, actor, selectedTerminal); err != nil {
			return Sandbox{}, false, err
		}
	} else if in.TerminalDeviceID != nil {
		return Sandbox{}, false, ErrInvalid
	}
	if err = s.reservationAdmission(ctx, tx, org); err != nil {
		return Sandbox{}, false, err
	}
	if b := s.boundedRuntime; b != nil && b.DevReservation != nil && (perUser != 2 || total != 2) {
		return Sandbox{}, false, ErrDisabled
	}
	var existingID uuid.UUID
	var existingHash []byte
	err = tx.QueryRow(ctx, `SELECT id,request_hash FROM sandboxes WHERE org_id=$1 AND creator_id=$2 AND idempotency_key=$3`, org, actor, in.IdempotencyKey).Scan(&existingID, &existingHash)
	if err == nil {
		if !equalHash(existingHash, hash[:]) {
			return Sandbox{}, false, ErrConflict
		}
		out, err := scanSandbox(tx.QueryRow(ctx, `SELECT `+sandboxColumns+` FROM sandboxes WHERE org_id=$1 AND id=$2`, org, existingID))
		if err != nil {
			return Sandbox{}, false, err
		}
		if err = delegatedInstance(ctx, tx, d, out); err != nil {
			return Sandbox{}, false, err
		}
		return out, true, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Sandbox{}, false, err
	}
	if d != nil {
		var count int32
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM sandboxes s JOIN sandbox_delegated_instances i ON i.sandbox_id=s.id WHERE i.delegation_id=$1 AND s.observed_state<>'deleted'`, d.ID).Scan(&count); err != nil {
			return Sandbox{}, false, err
		}
		if count >= d.MaxActive {
			return Sandbox{}, false, ErrQuota
		}
	}
	if !enabled || mode != policy.ModeEnforcing {
		return Sandbox{}, false, ErrDisabled
	}
	var capRaw []byte
	var ttlMax int32
	err = tx.QueryRow(ctx, `SELECT maximum_scope,max_ttl_seconds FROM sandbox_templates WHERE org_id=$1 AND id=$2 AND enabled FOR SHARE`, org, in.TemplateID).Scan(&capRaw, &ttlMax)
	if errors.Is(err, pgx.ErrNoRows) {
		return Sandbox{}, false, ErrDisabled
	}
	if err != nil {
		return Sandbox{}, false, err
	}
	if in.TTLSeconds > ttlMax {
		return Sandbox{}, false, ErrInvalid
	}
	var cap []Scope
	if json.Unmarshal(capRaw, &cap) != nil {
		return Sandbox{}, false, ErrInvalid
	}
	snapshot, err := policy.BuildSnapshotWithQueries(ctx, sqlc.New(tx), org)
	if err != nil {
		return Sandbox{}, false, err
	}
	if err = sandboxscope.AdmitScope(in.Requested, policy.CreatorStaticScope(snapshot, actor), cap); err != nil {
		return Sandbox{}, false, err
	}
	if err = admitSkills(ctx, tx, org, actor, in.TemplateID, in.SelectedSkills, in.Requested, cap); err != nil {
		return Sandbox{}, false, err
	}
	ownCount, orgCount, workloads, err := s.retainedCounts(ctx, tx, org, actor)
	if err != nil {
		return Sandbox{}, false, err
	}
	if s.boundedRuntime != nil {
		if !s.boundedRuntime.Persistent() {
			// One accepted sandbox per binding, including tombstones: deleting it cannot
			// silently authorize another launch during this bounded qualification.
			var accepted int
			if err = tx.QueryRow(ctx, `SELECT count(*) FROM sandboxes WHERE org_id=$1`, org).Scan(&accepted); err != nil {
				return Sandbox{}, false, err
			}
			if accepted > 0 {
				return Sandbox{}, false, ErrQuota
			}
		}
		perUser, total = s.boundedRuntime.quotas(perUser, total)
		if s.boundedRuntime.Persistent() && workloads >= 1 {
			return Sandbox{}, false, ErrQuota
		}
	}
	if ownCount >= int64(perUser) || orgCount >= int64(total) {
		return Sandbox{}, false, ErrQuota
	}
	var terminalDevice, localTerminalGateway any
	if s.boundedRuntime != nil {
		terminalDevice = selectedTerminal
		if len(in.Requested) == 0 && s.boundedRuntime.RemoteTerminal != nil {
			if err = s.boundedRuntime.validateRemoteTerminal(ctx, tx, actor, selectedTerminal); err != nil {
				return Sandbox{}, false, err
			}
		} else if len(in.Requested) == 0 {
			var local bool
			if err = tx.QueryRow(ctx, `SELECT node_id=$2 FROM devices WHERE id=$1`, selectedTerminal, s.boundedRuntime.GatewayID).Scan(&local); err != nil || !local {
				return Sandbox{}, false, ErrForbidden
			}
			localTerminalGateway = s.boundedRuntime.GatewayID
		}

	}
	raw, _ := json.Marshal(in.Requested)
	skillsRaw, _ := json.Marshal(in.SelectedSkills)
	keysRaw, _ := json.Marshal(in.SSHPublicKeys)
	out, err := scanSandbox(tx.QueryRow(ctx, `INSERT INTO sandboxes(org_id,creator_id,template_id,name,requested_scope,idempotency_key,request_hash,expires_at,selected_skills,ssh_public_keys,terminal_device_id,local_terminal_gateway_id)
 VALUES($1,$2,$3,$4,$5,$6,$7,now()+make_interval(secs=>$8),$9,$10,$11,$12) RETURNING `+sandboxColumns, org, actor, in.TemplateID, in.Name, raw, in.IdempotencyKey, hash[:], in.TTLSeconds, skillsRaw, keysRaw, terminalDevice, localTerminalGateway))
	if err != nil {
		return Sandbox{}, false, err
	}
	if s.boundedRuntime != nil && s.boundedRuntime.Persistent() {
		if err = s.boundedRuntime.persistRemoteTerminal(ctx, tx, out.Identity.ID, selectedTerminal); err != nil {
			return Sandbox{}, false, err
		}
		p, _ := s.boundedRuntime.profile(in.TemplateID)
		spec := sandboxruntime.Spec{ID: out.Identity.ID, ImageDigest: p.ConfigDigest, Architecture: p.Architecture, MemoryMiB: 128, CPUs: 1, PIDs: p.PIDs}
		hash, _ := sandboxruntime.Fingerprint(spec)
		if _, err = tx.Exec(ctx, `INSERT INTO sandbox_runtime_bindings(sandbox_id,org_id,spec_hash,image_digest,memory_mib,cpus,pids) VALUES($1,$2,$3,$4,128,1,$5)`, out.Identity.ID, org, hash, p.ConfigDigest, p.PIDs); err != nil {
			return Sandbox{}, false, err
		}
	}
	if d != nil {
		if _, err = tx.Exec(ctx, `INSERT INTO sandbox_delegated_instances(sandbox_id,delegation_id) VALUES ($1,$2)`, out.Identity.ID, d.ID); err != nil {
			return Sandbox{}, false, err
		}
	}
	if err = auditSandbox(ctx, tx, org, actor, out, "sandbox.create"); err != nil {
		return Sandbox{}, false, err
	}
	return out, false, tx.Commit(ctx)
}
func equalHash(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (s *Store) Get(ctx context.Context, org, actor, id uuid.UUID) (Sandbox, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Sandbox{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	roles, err := authorize(ctx, tx, org, actor, rbac.PermSandboxView)
	if err != nil {
		return Sandbox{}, err
	}
	out, err := scanSandbox(tx.QueryRow(ctx, `SELECT `+sandboxColumns+` FROM sandboxes WHERE org_id=$1 AND id=$2 AND (creator_id=$3 OR $4)`, org, id, actor, rbac.CanAny(roles, rbac.PermSandboxAdmin)))
	if err != nil {
		return Sandbox{}, err
	}
	d, err := delegationForUse(ctx, tx, org, actor)
	if err != nil {
		return Sandbox{}, err
	}
	if err = delegatedInstance(ctx, tx, d, out); err != nil {
		return Sandbox{}, err
	}
	if err = loadConnection(ctx, tx, &out); err != nil {
		return Sandbox{}, err
	}
	return out, tx.Commit(ctx)
}

// SetDesired advances one CAS generation. Runtime observation is reconciler-only.
// Stale clients cannot resurrect a deleted instance or cancel pending deletion.
func (s *Store) SetDesired(ctx context.Context, org, actor, id uuid.UUID, generation int64, desired string) (Sandbox, error) {
	if desired == "started" && !s.CreationAvailable(org, actor) {
		return Sandbox{}, ErrDisabled
	}
	if desired != "started" && desired != "stopped" && desired != "deleted" {
		return Sandbox{}, ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Sandbox{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	roles, err := authorize(ctx, tx, org, actor, rbac.PermSandboxManage)
	if err != nil {
		return Sandbox{}, err
	}
	out, err := scanSandbox(tx.QueryRow(ctx, `SELECT `+sandboxColumns+` FROM sandboxes WHERE org_id=$1 AND id=$2 AND (creator_id=$3 OR $4) FOR UPDATE`, org, id, actor, rbac.CanAny(roles, rbac.PermSandboxAdmin)))
	if err != nil {
		return Sandbox{}, err
	}
	d, err := delegationForUse(ctx, tx, org, actor)
	if err != nil {
		return Sandbox{}, err
	}
	if err = delegatedInstance(ctx, tx, d, out); err != nil {
		return Sandbox{}, err
	}
	if out.Revision != generation || (out.DesiredState == "deleted" && desired != "deleted") || (desired == "started" && time.Now().After(out.ExpiresAt)) {
		return Sandbox{}, ErrConflict
	}
	if desired == "started" && out.DesiredState == "stopped" && out.State != StateStopped && (s.qualificationOrg != uuid.Nil || s.boundedRuntime != nil) {
		return Sandbox{}, ErrConflict
	}
	if desired == "started" {
		if eligible, e := sandboxEligible(ctx, tx, id); e != nil {
			return Sandbox{}, e
		} else if !eligible {
			return Sandbox{}, ErrForbidden
		}
		var enabled bool
		var mode string
		if err = tx.QueryRow(ctx, `SELECT sandboxes_enabled,zero_trust_mode FROM organizations WHERE id=$1`, org).Scan(&enabled, &mode); err != nil {
			return Sandbox{}, err
		}
		if !enabled || mode != policy.ModeEnforcing {
			return Sandbox{}, ErrDisabled
		}
		var capRaw []byte
		if err = tx.QueryRow(ctx, `SELECT maximum_scope FROM sandbox_templates WHERE org_id=$1 AND id=$2 AND enabled FOR SHARE`, org, out.TemplateVersionID).Scan(&capRaw); errors.Is(err, pgx.ErrNoRows) {
			return Sandbox{}, ErrDisabled
		} else if err != nil {
			return Sandbox{}, err
		}
		var cap []Scope
		if json.Unmarshal(capRaw, &cap) != nil {
			return Sandbox{}, ErrInvalid
		}
		snapshot, e := policy.BuildSnapshotWithQueries(ctx, sqlc.New(tx), org)
		if e != nil {
			return Sandbox{}, e
		}
		if e = sandboxscope.AdmitScope(out.RequestedScope, policy.CreatorStaticScope(snapshot, out.Identity.CreatorID), cap); e != nil {
			return Sandbox{}, e
		}
	}
	if desired == "started" {
		var capRaw []byte
		if err = tx.QueryRow(ctx, `SELECT maximum_scope FROM sandbox_templates WHERE org_id=$1 AND id=$2`, org, out.TemplateVersionID).Scan(&capRaw); err != nil {
			return Sandbox{}, err
		}
		var cap []Scope
		if json.Unmarshal(capRaw, &cap) != nil {
			return Sandbox{}, ErrInvalid
		}
		if err = admitSkills(ctx, tx, org, out.Identity.CreatorID, out.TemplateVersionID, out.SelectedSkills, out.RequestedScope, cap); err != nil {
			return Sandbox{}, err
		}
	}
	if out.DesiredState == desired {
		return out, tx.Commit(ctx)
	}
	out, err = scanSandbox(tx.QueryRow(ctx, `UPDATE sandboxes SET desired_state=$3,generation=generation+1 WHERE org_id=$1 AND id=$2 RETURNING `+sandboxColumns, org, id, desired))
	if err != nil {
		return Sandbox{}, err
	}
	if err = auditSandbox(ctx, tx, org, actor, out, "sandbox."+desired); err != nil {
		return Sandbox{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Sandbox{}, err
	}
	s.notifyPolicy(ctx, org)
	return out, nil
}

func auditSandbox(ctx context.Context, tx pgx.Tx, org, actor uuid.UUID, sandbox Sandbox, action string) error {
	targetType, targetID := "sandbox", sandbox.Identity.ID.String()
	metadata, _ := json.Marshal(map[string]any{"generation": sandbox.Revision, "desired_state": sandbox.DesiredState, "template_id": sandbox.TemplateVersionID})
	if p, ok := authctx.PrincipalFrom(ctx); ok && p.IsMachine() {
		system := "operator:" + p.MachineName
		var grant uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT delegation_id FROM sandbox_delegated_instances WHERE sandbox_id=$1`, sandbox.Identity.ID).Scan(&grant); err != nil {
			return err
		}
		_, _, cause := p.AuditActor()
		metadata, _ = json.Marshal(map[string]any{"generation": sandbox.Revision, "desired_state": sandbox.DesiredState, "template_id": sandbox.TemplateVersionID, "owner_id": actor, "machine_id": p.MachineID, "delegation_id": grant, "cause": cause})
		_, err := sqlc.New(tx).InsertSystemAuditLog(ctx, sqlc.InsertSystemAuditLogParams{OrgID: pgtype.UUID{Bytes: org, Valid: true}, ActorSystem: &system, Action: action, TargetType: &targetType, TargetID: &targetID, Metadata: metadata})
		return err
	}
	_, err := sqlc.New(tx).InsertAuditLog(ctx, sqlc.InsertAuditLogParams{OrgID: pgtype.UUID{Bytes: org, Valid: true}, ActorUserID: pgtype.UUID{Bytes: actor, Valid: true}, Action: action, TargetType: &targetType, TargetID: &targetID, Metadata: metadata})
	return err
}
