package sandboxes

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"golang.org/x/crypto/ssh"
)

// PrivateNetworkTarget contains trusted immutable control metadata, never a
// token, command, browser-selected address or path.
type PrivateNetworkTarget struct {
	OperationID, OrgID, SandboxID, GatewayID, PeerID uuid.UUID
	EnrollmentOperationID                            uuid.UUID
	Generation                                       int64
	RuntimeID, SpecHash, PublicKey                   string
	Address                                          netip.Addr
}

// PrivateNetworkObservation must come from inspection of the actual isolated
// runtime network namespace, not from workload telemetry. A concrete Linux
// implementation still requires separate qualification before production use.
type PrivateNetworkObservation struct {
	Target     PrivateNetworkTarget
	ObservedAt time.Time
}

type PrivateNetworkInspector interface {
	InspectPrivateNetwork(context.Context, PrivateNetworkTarget) (PrivateNetworkObservation, error)
}

// TerminalAssetVerifier verifies immutable worker-local files and returns only
// the host public key. The API compares it with its stored terminal identity.
type TerminalAssetVerifier interface {
	VerifyTerminalAssets(context.Context, sandboxruntime.RuntimeAssets) (ssh.PublicKey, error)
}

type TargetSSHProber interface {
	ProbePrivateTerminal(context.Context, PrivateNetworkTarget, ssh.PublicKey, ssh.Signer) (sandboxruntime.SSHProbeResult, error)
}
type targetSSHProbe func(context.Context, PrivateNetworkTarget, ssh.PublicKey, ssh.Signer) (sandboxruntime.SSHProbeResult, error)

type privateSSHProbe func(context.Context, netip.Addr, ssh.PublicKey, ssh.Signer) (sandboxruntime.SSHProbeResult, error)

// VerifyPrivateReadiness is deliberately unwired: missing adapters keep creation
// closed. Running, bootstrap persistence and a runtime's own report cannot mark
// Ready. The dedicated probe identity belongs to the trusted worker.
func (s *Store) VerifyPrivateReadiness(ctx context.Context, id uuid.UUID, provider sandboxruntime.Provider, policies canonicalPolicyReader, network PrivateNetworkInspector, assets sandboxruntime.AssetResolver, probeIdentity ssh.Signer) error {
	return s.verifyPrivateReadiness(ctx, id, provider, policies, network, assets, probeIdentity, sandboxruntime.ProbePrivateSSH)
}

// VerifyPrivateReadinessWithTransport uses an independent trusted gateway route.
// The supplied target is the exact confirmed launch, never workload metadata.
func (s *Store) VerifyPrivateReadinessWithTransport(ctx context.Context, id uuid.UUID, provider sandboxruntime.Provider, policies canonicalPolicyReader, network PrivateNetworkInspector, assets sandboxruntime.AssetResolver, probeIdentity ssh.Signer, transport TargetSSHProber) error {
	if transport == nil {
		return ErrDisabled
	}
	return s.verifyTargetReadiness(ctx, id, provider, policies, network, assets, probeIdentity, transport.ProbePrivateTerminal)
}

func (s *Store) verifyPrivateReadiness(ctx context.Context, id uuid.UUID, provider sandboxruntime.Provider, policies canonicalPolicyReader, network PrivateNetworkInspector, assets sandboxruntime.AssetResolver, probeIdentity ssh.Signer, probe privateSSHProbe) error {
	if probe == nil {
		return ErrDisabled
	}
	return s.verifyTargetReadiness(ctx, id, provider, policies, network, assets, probeIdentity, func(ctx context.Context, target PrivateNetworkTarget, host ssh.PublicKey, identity ssh.Signer) (sandboxruntime.SSHProbeResult, error) {
		return probe(ctx, target.Address, host, identity)
	})
}
func (s *Store) verifyTargetReadiness(ctx context.Context, id uuid.UUID, provider sandboxruntime.Provider, policies canonicalPolicyReader, network PrivateNetworkInspector, assets sandboxruntime.AssetResolver, probeIdentity ssh.Signer, probe targetSSHProbe) (failure error) {
	stage := "readiness-admission"
	defer func() {
		if failure != nil {
			failure = &LaunchStageError{Stage: stage, Cause: failure}
		}
	}()
	if provider == nil || policies == nil || network == nil || assets == nil || probeIdentity == nil || probe == nil {
		return ErrDisabled
	}
	conn, release, err := s.acquireLifecycle(ctx, id)
	if err != nil {
		return err
	}
	defer release()
	start, err := s.prepareStart(ctx, conn, id)
	if err != nil {
		return err
	}
	if start.sandbox.State != StateStarting || start.runtimeID == nil || start.sandbox.PeerID == nil {
		return ErrConflict
	}
	target, launchedAt, err := confirmedNetworkTarget(ctx, conn, id, start.sandbox.Revision, false)
	if err != nil {
		return err
	}
	if target.RuntimeID != *start.runtimeID || target.PeerID != *start.sandbox.PeerID {
		return ErrConflict
	}
	status, err := provider.Inspect(ctx, id)
	if err != nil {
		return err
	}
	if err = sandboxruntime.Matches(start.spec, status); err != nil {
		return err
	}
	if !status.Running || status.RuntimeID != target.RuntimeID {
		return ErrConflict
	}
	stage = "readiness-policy-before"
	before, err := s.CurrentSandboxPolicyAcknowledgements(ctx, target, policies)
	if err != nil {
		return err
	}
	stage = "readiness-network-before"
	observation, err := network.InspectPrivateNetwork(ctx, target)
	if err != nil {
		return err
	}
	if !validNetworkObservation(time.Now().UTC(), launchedAt, target, observation) {
		return ErrConflict
	}
	// Resolve and verify persisted workload assets; derive the pin only from the
	// immutable terminal identity whose content digest the provider verifies.
	stage = "readiness-terminal-assets"
	materialized, err := assets.ResolveAssets(ctx, id)
	if err != nil {
		return err
	}
	if materialized.SandboxID != id || materialized.SpecHash != target.SpecHash {
		return ErrConflict
	}
	var hostPublic ssh.PublicKey
	if verifier, ok := assets.(TerminalAssetVerifier); ok {
		hostPublic, err = verifier.VerifyTerminalAssets(ctx, materialized)
	} else {
		hostPublic, err = verifyLocalTerminalAssets(materialized)
	}
	if err != nil || hostPublic == nil {
		return ErrConflict
	}
	var storedPublic, previousFingerprint string
	if err = conn.QueryRow(ctx, `SELECT host_public_key,host_key_fingerprint FROM sandbox_terminal_identities WHERE sandbox_id=$1 AND org_id=$2`, id, target.OrgID).Scan(&storedPublic, &previousFingerprint); (err != nil && !errors.Is(err, pgx.ErrNoRows)) || (err == nil && (storedPublic != string(ssh.MarshalAuthorizedKey(hostPublic)) || previousFingerprint != ssh.FingerprintSHA256(hostPublic))) {
		return ErrConflict
	}
	stage = "readiness-terminal-probe"
	probeResult, err := probe(ctx, target, hostPublic, probeIdentity)
	if err != nil {
		return err
	}
	if probeResult.UID != 1001 || probeResult.HostKeyFingerprint != ssh.FingerprintSHA256(hostPublic) || !freshEvidence(time.Now().UTC(), probeResult.ObservedAt, 10*time.Second) {
		return ErrConflict
	}
	stage = "readiness-network-after"
	observation, err = network.InspectPrivateNetwork(ctx, target)
	if err != nil {
		return err
	}
	if !validNetworkObservation(time.Now().UTC(), launchedAt, target, observation) {
		return ErrConflict
	}
	stage = "readiness-gateway-handshake"
	var handshake, reportedAt time.Time
	err = conn.QueryRow(ctx, `SELECT ds.last_handshake_at,ds.updated_at FROM device_status ds JOIN devices d ON d.id=ds.device_id WHERE d.id=$1 AND d.node_id=$2 AND d.public_key=$3 AND d.kind='sandbox' AND ds.last_handshake_at IS NOT NULL`, target.PeerID, target.GatewayID, target.PublicKey).Scan(&handshake, &reportedAt)
	// Gateway reports use Unix seconds. Compare at that resolution; subsecond
	// launch timestamps must not reject a valid first handshake in that second.
	if err != nil || handshake.Before(launchedAt.Truncate(time.Second)) || !freshEvidence(time.Now().UTC(), handshake, 180*time.Second) || !freshEvidence(time.Now().UTC(), reportedAt, 30*time.Second) {
		return ErrConflict
	}
	stage = "readiness-policy-after"
	after, err := s.CurrentSandboxPolicyAcknowledgements(ctx, target, policies)
	if err != nil {
		return err
	}
	if !samePolicyAcknowledgements(before, after) || (start.sandbox.Revision > target.Generation && (!acknowledgementsAfter(before, launchedAt) || !acknowledgementsAfter(after, launchedAt))) {
		return ErrConflict
	}
	stage = "readiness-ready-cas"
	current, err := s.prepareStart(ctx, conn, id)
	if err != nil {
		return err
	}
	if current.sandbox.Revision != start.sandbox.Revision || current.runtimeID == nil || *current.runtimeID != target.RuntimeID || current.sandbox.PeerID == nil || *current.sandbox.PeerID != target.PeerID {
		return ErrConflict
	}
	status, err = provider.Inspect(ctx, id)
	if err != nil {
		return err
	}
	if err = sandboxruntime.Matches(current.spec, status); err != nil {
		return err
	}
	now := time.Now().UTC()
	if !status.Running || status.RuntimeID != target.RuntimeID || !freshEvidence(now, probeResult.ObservedAt, 10*time.Second) || !validNetworkObservation(now, launchedAt, target, observation) || !freshEvidence(now, handshake, 180*time.Second) || !freshEvidence(now, reportedAt, 30*time.Second) {
		return ErrConflict
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// Recover public delivery metadata even if asset publication succeeded before
	// its database response was lost. The verified immutable host identity is
	// authoritative; an existing conflicting pin must never be replaced.
	publicHostKey := string(ssh.MarshalAuthorizedKey(hostPublic))
	fingerprint := ssh.FingerprintSHA256(hostPublic)
	if _, err = tx.Exec(ctx, `INSERT INTO sandbox_terminal_identities(sandbox_id,org_id,host_public_key,host_key_fingerprint) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, id, target.OrgID, publicHostKey, fingerprint); err != nil {
		return err
	}
	var storedKey, storedFingerprint string
	if err = tx.QueryRow(ctx, `SELECT host_public_key,host_key_fingerprint FROM sandbox_terminal_identities WHERE sandbox_id=$1 AND org_id=$2`, id, target.OrgID).Scan(&storedKey, &storedFingerprint); err != nil || storedKey != publicHostKey || storedFingerprint != fingerprint {
		return ErrConflict
	}
	result, err := tx.Exec(ctx, `UPDATE sandboxes s SET observed_state='ready' WHERE s.id=$1 AND s.org_id=$2 AND s.generation=$3 AND s.peer_id=$4 AND s.desired_state='started' AND s.observed_state='starting' AND s.expires_at>now() AND (`+sandboxEligibilitySQL+`) AND EXISTS(SELECT 1 FROM devices d JOIN sandbox_runtime_credentials c ON c.peer_id=d.id AND c.sandbox_id=s.id AND c.org_id=s.org_id WHERE d.id=s.peer_id AND d.org_id=s.org_id AND d.kind='sandbox' AND d.status='active' AND d.deleted_at IS NULL AND NOT d.health_blocked AND c.revoked_at IS NULL)`, id, target.OrgID, start.sandbox.Revision, target.PeerID)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrConflict
	}
	trialCode := "initial_ready"
	if start.sandbox.Revision != 1 {
		trialCode = "resume_ready"
	}
	if err = recordRunnerTrialEvent(ctx, tx, id, trialCode, start.sandbox.Revision, map[string]any{
		"target": target, "launched_at": launchedAt, "policy_before": before, "policy_after": after,
		"network_observed_at": observation.ObservedAt, "gateway_handshake_at": handshake,
		"gateway_reported_at": reportedAt, "terminal_probe": probeResult, "ssh_origin": "runner",
	}); err != nil {
		return err
	}
	if err = auditSandbox(ctx, tx, target.OrgID, current.sandbox.Identity.CreatorID, current.sandbox, "sandbox.ready"); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func freshEvidence(now, at time.Time, window time.Duration) bool {
	age := now.Sub(at)
	return !at.IsZero() && age >= 0 && age < window
}
func validNetworkObservation(now, launchedAt time.Time, target PrivateNetworkTarget, observation PrivateNetworkObservation) bool {
	return observation.Target == target && !observation.ObservedAt.Before(launchedAt) && freshEvidence(now, observation.ObservedAt, 10*time.Second)
}
func samePolicyAcknowledgements(before, after []PolicyAcknowledgement) bool {
	if len(before) == 0 || len(before) != len(after) {
		return false
	}
	hashes := map[uuid.UUID]string{}
	for _, ack := range before {
		hashes[ack.NodeID] = ack.Hash
	}
	for _, ack := range after {
		if hashes[ack.NodeID] != ack.Hash || strings.TrimSpace(ack.Hash) == "" {
			return false
		}
		delete(hashes, ack.NodeID)
	}
	return len(hashes) == 0
}

func verifyLocalTerminalAssets(materialized sandboxruntime.RuntimeAssets) (ssh.PublicKey, error) {
	digest, err := sandboxruntime.AssetContentDigest(materialized.Skills, materialized.SSH)
	if err != nil || digest != materialized.Digest {
		return nil, ErrConflict
	}
	root, err := os.OpenRoot(materialized.SSH)
	if err != nil {
		return nil, ErrConflict
	}
	defer root.Close()
	key, err := readControlFile(root, "host_key", 65536)
	if err != nil {
		return nil, err
	}
	identity, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, ErrConflict
	}
	return identity.PublicKey(), nil
}
