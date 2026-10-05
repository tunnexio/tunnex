package sandboxes

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxscope"
)

type startTarget struct {
	authorization *RuntimeAuthorization
	sandbox       Sandbox
	spec          sandboxruntime.Spec
	runtimeID     *string
}

// StartBoundRuntime starts only the already bound provider resource, under the
// shared lifecycle lease. Quarantine/network and bootstrap composition remain
// separate; this method cannot enroll a peer or report Ready.
func (s *Store) StartBoundRuntime(ctx context.Context, id uuid.UUID, provider sandboxruntime.Provider) error {
	if provider == nil {
		return ErrDisabled
	}
	conn, release, err := s.acquireLifecycle(ctx, id)
	if err != nil {
		return err
	}
	defer release()
	target, err := s.prepareStart(ctx, conn, id)
	if err != nil {
		return err
	}
	if target.runtimeID == nil {
		return ErrConflict
	}
	status, err := provider.Inspect(ctx, id)
	if err != nil {
		return err
	}
	if err = sandboxruntime.Matches(target.spec, status); err != nil {
		return err
	}
	if status.RuntimeID != *target.runtimeID {
		return ErrConflict
	}
	if !status.Running {
		if err = provider.Start(ctx, id); err != nil {
			return err
		}
	}
	status, err = provider.Inspect(ctx, id)
	if err != nil {
		return err
	}
	if err = sandboxruntime.Matches(target.spec, status); err != nil {
		return err
	}
	if status.RuntimeID != *target.runtimeID || !status.Running {
		return ErrConflict
	}
	// Revalidate admission as well as generation after external start. A human
	// stop or entitlement withdrawal can change durable state during that call.
	current, err := s.prepareStart(ctx, conn, id)
	if err == nil && current.sandbox.Revision != target.sandbox.Revision {
		err = ErrConflict
	}
	if err == nil {
		err = bindStart(ctx, conn, target, status.RuntimeID)
	}
	if err != nil {
		stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		return errors.Join(err, provider.Stop(stopCtx, id))
	}
	return nil
}

// ReconcileQuarantinedStart creates/adopts only the quarantined provider
// resource. It does not open networking, enroll a peer or report Ready. No
// production worker calls this until qualified composition is available.
func (s *Store) ReconcileQuarantinedStart(ctx context.Context, id uuid.UUID, provider sandboxruntime.Provider) error {
	if provider == nil {
		return ErrInvalid
	}
	conn, release, err := s.acquireLifecycle(ctx, id)
	if err != nil {
		return err
	}
	defer release()
	target, err := s.prepareStart(ctx, conn, id)
	if err != nil {
		return err
	}
	status, err := provider.Inspect(ctx, id)
	if errors.Is(err, sandboxruntime.ErrMissing) {
		// Once a provider identity or peer exists, missing cannot mean permission
		// to silently replace its keys, workspace or uncertain enrollment.
		if target.runtimeID != nil || target.sandbox.PeerID != nil {
			return ErrConflict
		}
		if err = provider.Create(ctx, target.spec); err != nil {
			return err
		}
		status, err = provider.Inspect(ctx, id)
	}
	if err != nil {
		return err
	}
	if err = sandboxruntime.Matches(target.spec, status); err != nil {
		return err
	}
	if target.runtimeID != nil && *target.runtimeID != status.RuntimeID {
		return ErrConflict
	}
	// Adoption is durable before any start. A lost create response can recover
	// only the same spec/image-owned resource, never mint another resource.
	return bindStart(ctx, conn, target, status.RuntimeID)
}

func (s *Store) prepareStart(ctx context.Context, conn *pgxpool.Conn, id uuid.UUID) (startTarget, error) {
	if s.boundedRuntime != nil && s.boundedRuntime.deniesRuntimeID(id) {
		return startTarget{}, ErrForbidden
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return startTarget{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	out, err := scanSandbox(tx.QueryRow(ctx, `SELECT `+sandboxColumns+` FROM sandboxes WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		return startTarget{}, err
	}
	if out.DesiredState != "started" || (out.State != StateCreating && out.State != StateStarting && out.State != StateStopped) {
		return startTarget{}, ErrConflict
	}
	if err = s.reservationAdmission(ctx, tx, out.Identity.OrgID); err != nil {
		return startTarget{}, err
	}
	if _, err = NormalizeSSHPublicKeys(out.SSHPublicKeys, 7); err != nil {
		return startTarget{}, ErrDisabled
	}
	if _, err = authorize(ctx, tx, out.Identity.OrgID, out.Identity.CreatorID, rbac.PermSandboxCreate); err != nil {
		return startTarget{}, err
	}
	var delegationValid bool
	if err = tx.QueryRow(ctx, `SELECT sandbox_delegation_valid($1)`, id).Scan(&delegationValid); err != nil {
		return startTarget{}, err
	}
	if !delegationValid {
		return startTarget{}, ErrForbidden
	}
	if eligible, e := sandboxEligible(ctx, tx, id); e != nil {
		return startTarget{}, e
	} else if !eligible {
		return startTarget{}, ErrForbidden
	}
	var raw []byte
	spec := sandboxruntime.Spec{ID: id, CPUs: 1, PIDs: 128}
	if s.qualificationOrg != uuid.Nil {
		if out.Identity.OrgID != s.qualificationOrg {
			return startTarget{}, ErrDisabled
		}
		spec.PIDs = 64
	}
	err = tx.QueryRow(ctx, `SELECT t.image_digest,t.memory_mib,t.maximum_scope FROM sandbox_templates t JOIN organizations o ON o.id=t.org_id AND o.sandboxes_enabled AND o.zero_trust_mode='enforcing' JOIN sandboxes s ON s.template_id=t.id AND s.org_id=t.org_id WHERE s.id=$1 AND s.expires_at>now() AND t.enabled FOR SHARE OF t,o`, id).Scan(&spec.ImageDigest, &spec.MemoryMiB, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return startTarget{}, ErrDisabled
	}
	if err != nil {
		return startTarget{}, err
	}
	var terminalDevice uuid.UUID
	if b := s.boundedRuntime; b != nil {
		if err = tx.QueryRow(ctx, `SELECT terminal_device_id FROM sandboxes WHERE id=$1`, id).Scan(&terminalDevice); err != nil {
			return startTarget{}, ErrForbidden
		}
		if _, err = b.terminalDevice(&terminalDevice); err != nil {
			return startTarget{}, err
		}
		if err = b.validateTerminalDevice(ctx, tx, out.Identity.CreatorID, terminalDevice); err != nil {
			return startTarget{}, err
		}
		p, ok := b.profile(out.TemplateVersionID)
		if !b.Allows(out.Identity.OrgID, out.Identity.CreatorID, time.Now()) || !ok || spec.ImageDigest != p.ConfigDigest || spec.MemoryMiB != b.MemoryMiB || (b.Persistent() && len(out.RequestedScope) != 0) {
			return startTarget{}, ErrDisabled
		}
		if b.Persistent() && b.RemoteTerminal != nil {
			if err = b.validateRemoteTerminal(ctx, tx, out.Identity.CreatorID, terminalDevice); err != nil {
				return startTarget{}, err
			}
			var pinned bool
			if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sandbox_remote_terminal_routes WHERE sandbox_id=$1 AND org_id=$2 AND terminal_device_id=$3 AND terminal_gateway_id=$4 AND runtime_gateway_id=$5 AND terminal_gateway_endpoint=$6 AND runtime_gateway_endpoint=$7)`, id, b.OrgID, terminalDevice, b.RemoteTerminal.GatewayID, b.GatewayID, b.RemoteTerminal.GatewayEndpoint, b.RemoteTerminal.RuntimeGatewayEndpoint).Scan(&pinned); err != nil {
				return startTarget{}, err
			}
			if !pinned {
				return startTarget{}, ErrForbidden
			}
		} else if b.Persistent() {
			var deviceValid bool
			if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sandboxes s JOIN devices d ON d.id=s.terminal_device_id AND d.org_id=s.org_id AND d.user_id=s.creator_id WHERE s.id=$1 AND d.id=$2 AND d.kind='human' AND d.status='active' AND d.deleted_at IS NULL AND NOT d.health_blocked AND d.node_id=$3 AND s.local_terminal_gateway_id=$3)`, id, terminalDevice, b.GatewayID).Scan(&deviceValid); err != nil {
				return startTarget{}, err
			}
			if !deviceValid {
				return startTarget{}, ErrForbidden
			}
		}
		spec.PIDs = p.PIDs
		spec.Architecture = p.Architecture
	}
	var cap []Scope
	if json.Unmarshal(raw, &cap) != nil {
		return startTarget{}, ErrInvalid
	}
	if s.boundedRuntime != nil && s.boundedRuntime.Persistent() && len(cap) != 0 {
		return startTarget{}, ErrDisabled
	}
	snapshot, err := policy.BuildSnapshotWithQueries(ctx, sqlc.New(tx), out.Identity.OrgID)
	if err != nil {
		return startTarget{}, err
	}
	if err = sandboxscope.AdmitScope(out.RequestedScope, policy.CreatorStaticScope(snapshot, out.Identity.CreatorID), cap); err != nil {
		return startTarget{}, err
	}
	if err = admitSkills(ctx, tx, out.Identity.OrgID, out.Identity.CreatorID, out.TemplateVersionID, out.SelectedSkills, out.RequestedScope, cap); err != nil {
		return startTarget{}, err
	}
	hash, err := sandboxruntime.Fingerprint(spec)
	if err != nil {
		return startTarget{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO sandbox_runtime_bindings(sandbox_id,org_id,spec_hash,image_digest,memory_mib,cpus,pids) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, id, out.Identity.OrgID, hash, spec.ImageDigest, spec.MemoryMiB, spec.CPUs, spec.PIDs); err != nil {
		return startTarget{}, err
	}
	var storedHash string
	var runtimeID *string
	if err = tx.QueryRow(ctx, `SELECT spec_hash,runtime_id FROM sandbox_runtime_bindings WHERE sandbox_id=$1 AND org_id=$2 FOR UPDATE`, id, out.Identity.OrgID).Scan(&storedHash, &runtimeID); err != nil {
		return startTarget{}, err
	}
	if storedHash != hash {
		return startTarget{}, ErrConflict
	}
	target := startTarget{sandbox: out, spec: spec, runtimeID: runtimeID}
	if b := s.boundedRuntime; b != nil && b.Persistent() {
		p, _ := b.profile(out.TemplateVersionID)
		target.authorization = &RuntimeAuthorization{SandboxID: id, OrgID: out.Identity.OrgID, CreatorID: out.Identity.CreatorID, GatewayID: b.GatewayID, TerminalDeviceID: terminalDevice, TemplateID: out.TemplateVersionID, Profile: p, Generation: out.Revision, Desired: out.DesiredState, CreatedAt: out.CreatedAt, ExpiresAt: out.ExpiresAt}
	}
	return target, tx.Commit(ctx)
}

func bindStart(ctx context.Context, conn *pgxpool.Conn, target startTarget, runtimeID string) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var generation int64
	var desired string
	var eligible bool
	if err = tx.QueryRow(ctx, `SELECT generation,desired_state,expires_at>now() AND (`+sandboxEligibilitySQL+`) FROM sandboxes s WHERE id=$1 FOR UPDATE OF s`, target.sandbox.Identity.ID).Scan(&generation, &desired, &eligible); err != nil {
		return err
	}
	if generation != target.sandbox.Revision || desired != "started" || !eligible {
		return ErrConflict
	}
	result, err := tx.Exec(ctx, `UPDATE sandbox_runtime_bindings SET runtime_id=$2 WHERE sandbox_id=$1 AND (runtime_id IS NULL OR runtime_id=$2)`, target.sandbox.Identity.ID, runtimeID)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE sandboxes SET observed_state='starting' WHERE id=$1`, target.sandbox.Identity.ID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
