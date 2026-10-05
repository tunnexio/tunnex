package sandboxes

import (
	"context"
	"encoding/json"
	"golang.org/x/crypto/ssh"
	"os"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
)

// WorkspacePlan is an internal delivery binding. Bodies are private worker
// inputs; it must never be served as human inventory or logged. The coordinator
// must recheck the generation/current eligibility before accepting its receipt.
type WorkspacePlan struct {
	Authorization *RuntimeAuthorization
	SandboxID     uuid.UUID
	OrgID         uuid.UUID
	Generation    int64
	RuntimeID     string
	SpecHash      string
	Files         []SkillFile
}

func (s *Store) PrepareWorkspace(ctx context.Context, id uuid.UUID) (WorkspacePlan, error) {
	conn, release, err := s.acquireLifecycle(ctx, id)
	if err != nil {
		return WorkspacePlan{}, err
	}
	defer release()
	target, err := s.prepareStart(ctx, conn, id)
	if err != nil {
		return WorkspacePlan{}, err
	}
	if target.runtimeID == nil {
		return WorkspacePlan{}, ErrConflict
	}
	return prepareWorkspace(ctx, conn, target)
}

// PrepareCreationAssets publishes trusted immutable mounts before provider
// creation, while holding the lifecycle lease and rechecking current admission.
// The root is exclusively worker-owned; keys are approved public keys only.
func (s *Store) PrepareCreationAssets(ctx context.Context, id uuid.UUID, root *os.Root, probePublicKey string) (sandboxruntime.RuntimeAssets, TerminalDelivery, error) {
	return s.PrepareCreationAssetsWithTransport(ctx, id, probePublicKey, CreationAssetMaterializerFunc(func(_ context.Context, plan WorkspacePlan, keys []string) (sandboxruntime.RuntimeAssets, TerminalDelivery, error) {
		return MaterializeRuntimeAssets(root, plan, keys)
	}))
}

// CreationAssetMaterializer accepts only an API-authorized immutable plan.
// Remote implementations return public terminal identity; private keys and
// worker paths stay under the worker's control.
type CreationAssetMaterializer interface {
	MaterializeCreationAssets(context.Context, WorkspacePlan, []string) (sandboxruntime.RuntimeAssets, TerminalDelivery, error)
}
type CreationAssetMaterializerFunc func(context.Context, WorkspacePlan, []string) (sandboxruntime.RuntimeAssets, TerminalDelivery, error)

func (f CreationAssetMaterializerFunc) MaterializeCreationAssets(ctx context.Context, p WorkspacePlan, k []string) (sandboxruntime.RuntimeAssets, TerminalDelivery, error) {
	return f(ctx, p, k)
}

func (s *Store) PrepareCreationAssetsWithTransport(ctx context.Context, id uuid.UUID, probePublicKey string, transport CreationAssetMaterializer) (sandboxruntime.RuntimeAssets, TerminalDelivery, error) {
	if transport == nil {
		return sandboxruntime.RuntimeAssets{}, TerminalDelivery{}, ErrDisabled
	}
	conn, release, err := s.acquireLifecycle(ctx, id)
	if err != nil {
		return sandboxruntime.RuntimeAssets{}, TerminalDelivery{}, err
	}
	defer release()
	target, err := s.prepareStart(ctx, conn, id)
	if err != nil {
		return sandboxruntime.RuntimeAssets{}, TerminalDelivery{}, err
	}
	if target.runtimeID != nil {
		return sandboxruntime.RuntimeAssets{}, TerminalDelivery{}, ErrConflict
	}
	plan, err := prepareWorkspace(ctx, conn, target)
	if err != nil {
		return sandboxruntime.RuntimeAssets{}, TerminalDelivery{}, err
	}
	keys := append(append([]string(nil), target.sandbox.SSHPublicKeys...), probePublicKey)
	assets, terminal, err := transport.MaterializeCreationAssets(ctx, plan, keys)
	if err != nil {
		return sandboxruntime.RuntimeAssets{}, TerminalDelivery{}, err
	}
	if assets.SandboxID != id || assets.SpecHash != plan.SpecHash || len(assets.Digest) != 64 {
		return sandboxruntime.RuntimeAssets{}, TerminalDelivery{}, ErrConflict
	}
	publicKey, _, _, _, parseErr := ssh.ParseAuthorizedKey([]byte(terminal.HostPublicKey))
	if parseErr != nil || ssh.FingerprintSHA256(publicKey) != terminal.HostKeyFingerprint {
		return sandboxruntime.RuntimeAssets{}, TerminalDelivery{}, ErrConflict
	}
	current, err := s.prepareStart(ctx, conn, id)
	if err != nil || current.sandbox.Revision != plan.Generation || current.runtimeID != nil {
		return sandboxruntime.RuntimeAssets{}, TerminalDelivery{}, ErrConflict
	}
	if _, err = conn.Exec(ctx, `INSERT INTO sandbox_terminal_identities(sandbox_id,org_id,host_public_key,host_key_fingerprint) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, id, target.sandbox.Identity.OrgID, terminal.HostPublicKey, terminal.HostKeyFingerprint); err != nil {
		return sandboxruntime.RuntimeAssets{}, TerminalDelivery{}, err
	}
	var public, fingerprint string
	if err = conn.QueryRow(ctx, `SELECT host_public_key,host_key_fingerprint FROM sandbox_terminal_identities WHERE sandbox_id=$1 AND org_id=$2`, id, target.sandbox.Identity.OrgID).Scan(&public, &fingerprint); err != nil || public != terminal.HostPublicKey || fingerprint != terminal.HostKeyFingerprint {
		return sandboxruntime.RuntimeAssets{}, TerminalDelivery{}, ErrConflict
	}
	return assets, terminal, nil
}

func prepareWorkspace(ctx context.Context, conn *pgxpool.Conn, target startTarget) (WorkspacePlan, error) {
	id := target.sandbox.Identity.ID
	tx, err := conn.Begin(ctx)
	if err != nil {
		return WorkspacePlan{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var raw []byte
	var specHash string
	if err = tx.QueryRow(ctx, `SELECT t.maximum_scope,r.spec_hash FROM sandbox_templates t JOIN sandbox_runtime_bindings r ON r.org_id=t.org_id JOIN sandboxes s ON s.id=r.sandbox_id AND s.template_id=t.id WHERE s.id=$1 AND s.generation=$2 AND s.desired_state='started' AND s.expires_at>now() AND (t.enabled OR sandbox_qualification_trial_valid(s.id)) AND sandbox_qualification_trial_authority(s.id) FOR SHARE OF s,t,r`, id, target.sandbox.Revision).Scan(&raw, &specHash); err != nil {
		return WorkspacePlan{}, err
	}
	var cap []Scope
	if json.Unmarshal(raw, &cap) != nil {
		return WorkspacePlan{}, ErrInvalid
	}
	revisions, err := selectedSkillRevisions(ctx, tx, target.sandbox.Identity.OrgID, target.sandbox.Identity.CreatorID, target.sandbox.TemplateVersionID, target.sandbox.SelectedSkills, target.sandbox.RequestedScope, cap)
	if err != nil {
		return WorkspacePlan{}, err
	}
	files, err := PrepareSkillBundle(target.sandbox.SelectedSkills, revisions, target.sandbox.RequestedScope, cap)
	if err != nil {
		return WorkspacePlan{}, err
	}
	runtimeID := ""
	if target.runtimeID != nil {
		runtimeID = *target.runtimeID
	}
	plan := WorkspacePlan{SandboxID: id, OrgID: target.sandbox.Identity.OrgID, Generation: target.sandbox.Revision, RuntimeID: runtimeID, SpecHash: specHash, Files: files}
	if s := target.authorization; s != nil {
		plan.Authorization = s
	}
	return plan, tx.Commit(ctx)
}
