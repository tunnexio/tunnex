package sandboxes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
)

type PrivateNetworkControl interface {
	PrivateNetworkInspector
	ApplyPrivateNetwork(context.Context, PrivateNetworkTarget, []byte) error
	RemovePrivateNetwork(context.Context, PrivateNetworkTarget, []byte) error
}

func parsePrivateAddress(value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || !address.IsPrivate() {
		return netip.Addr{}, ErrConflict
	}
	return address, nil
}

func networkHandoff(target PrivateNetworkTarget) LaunchHandoff {
	return LaunchHandoff{OperationID: enrollmentOperation(target), OrgID: target.OrgID, SandboxID: target.SandboxID, GatewayID: target.GatewayID, Generation: target.Generation, RuntimeID: target.RuntimeID, SpecHash: target.SpecHash}
}

// ReadPrivateNetworkConfig reads only this exact already-confirmed protected
// operation. Credentials remain outside workloads; no token is minted/redeemed.
func (t *FileBootstrapTransport) ReadPrivateNetworkConfig(ctx context.Context, target PrivateNetworkTarget) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	h := networkHandoff(target)
	owned, err := openPrivateControlChild(t.root, target.SandboxID.String())
	if err != nil {
		return nil, err
	}
	defer owned.Close()
	job, err := openPrivateControlChild(owned, h.OperationID.String())
	if err != nil {
		return nil, err
	}
	defer job.Close()
	stored, err := readControlFile(job, "binding.json", 16384)
	expected, _ := json.Marshal(t.binding(h))
	if err != nil || !bytes.Equal(stored, expected) {
		return nil, ErrConflict
	}
	receipt, err := readPersistedLaunch(job, h, t.server)
	if err != nil || receipt.Handoff.PeerID != target.PeerID || receipt.WireGuardPublicKey != target.PublicKey {
		return nil, ErrConflict
	}
	enrollment, err := job.OpenRoot("enrollment")
	if err != nil {
		return nil, ErrConflict
	}
	defer enrollment.Close()
	return readControlFile(enrollment, "wireguard.conf", 65536)
}
func openPrivateControlChild(root *os.Root, name string) (*os.Root, error) {
	if root == nil {
		return nil, ErrDisabled
	}
	if _, err := uuid.Parse(name); err != nil {
		return nil, ErrInvalid
	}
	info, err := root.Lstat(name)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrConflict
	}
	return root.OpenRoot(name)
}

// ActivatePrivateNetwork holds the existing lifecycle lease across actual
// helper setup. Network activation alone remains Starting. A stop/admission
// race removes the exact just-applied owned interface before returning.
func (s *Store) ActivatePrivateNetwork(ctx context.Context, id uuid.UUID, network PrivateNetworkControl, files LaunchControlTransport) error {
	if network == nil || files == nil {
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
	target, _, err := confirmedNetworkTarget(ctx, conn, id, start.sandbox.Revision, false)
	if err != nil {
		return err
	}
	hash, err := sandboxruntime.Fingerprint(start.spec)
	if err != nil || start.runtimeID == nil || *start.runtimeID != target.RuntimeID || hash != target.SpecHash {
		return ErrConflict
	}
	config, err := files.ReadPrivateNetworkConfig(ctx, target)
	if err != nil {
		return err
	}
	if err = network.ApplyPrivateNetwork(ctx, target, config); err != nil {
		return err
	}
	current, err := s.prepareStart(ctx, conn, id)
	if err == nil && (current.sandbox.Revision != start.sandbox.Revision || current.runtimeID == nil || *current.runtimeID != target.RuntimeID) {
		err = ErrConflict
	}
	if err != nil {
		withdrawCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		return errors.Join(err, network.RemovePrivateNetwork(withdrawCtx, target, config))
	}
	return nil
}

func confirmedNetworkTarget(ctx context.Context, conn *pgxpool.Conn, id uuid.UUID, generation int64, cleanup bool) (PrivateNetworkTarget, time.Time, error) {
	var target PrivateNetworkTarget
	var address string
	var launchedAt time.Time
	var enrolledOperation uuid.UUID
	// Cleanup must recover the original confirmed operation after a desired stop
	// increments generation/revokes credentials. It cannot create a new operation.
	query := `SELECT COALESCE(e.id,l.id),l.org_id,l.sandbox_id,l.gateway_node_id,d.id,l.generation,l.runtime_id,l.spec_hash,d.public_key,d.assigned_ip,COALESCE(e.created_at,l.created_at),l.id FROM sandbox_launch_operations l JOIN sandboxes s ON s.id=l.sandbox_id AND s.org_id=l.org_id JOIN devices d ON d.id=s.peer_id AND d.org_id=s.org_id AND d.node_id=l.gateway_node_id JOIN sandbox_bootstrap_tokens t ON t.id=l.bootstrap_token_id LEFT JOIN sandbox_start_epochs e ON e.sandbox_id=s.id AND e.org_id=s.org_id AND e.generation=(SELECT max(epoch.generation) FROM sandbox_start_epochs epoch WHERE epoch.sandbox_id=s.id AND epoch.org_id=s.org_id AND epoch.operation_id=l.id AND epoch.generation<=$2) AND e.operation_id=l.id WHERE l.sandbox_id=$1 AND l.generation<=$2 AND l.handoff_ciphertext IS NULL AND t.consumed_at IS NOT NULL AND d.kind='sandbox'`
	if !cleanup {
		query += ` AND s.generation=$2 AND (l.generation=$2 OR e.generation=$2) AND d.status='active' AND d.deleted_at IS NULL AND NOT d.health_blocked AND EXISTS(SELECT 1 FROM sandbox_runtime_credentials c WHERE c.peer_id=d.id AND c.sandbox_id=s.id AND c.org_id=s.org_id AND c.revoked_at IS NULL)`
	}
	query += ` ORDER BY l.generation DESC LIMIT 1`
	err := conn.QueryRow(ctx, query, id, generation).Scan(&target.OperationID, &target.OrgID, &target.SandboxID, &target.GatewayID, &target.PeerID, &target.Generation, &target.RuntimeID, &target.SpecHash, &target.PublicKey, &address, &launchedAt, &enrolledOperation)
	if errors.Is(err, pgx.ErrNoRows) {
		return target, launchedAt, ErrConflict
	}
	if err != nil {
		return target, launchedAt, err
	}
	if enrolledOperation != target.OperationID {
		target.EnrollmentOperationID = enrolledOperation
	}
	target.Address, err = parsePrivateAddress(address)
	if err != nil {
		return target, launchedAt, err
	}
	return target, launchedAt, nil
}

// Network operation identity is per-start namespace. Enrollment files and peer
// credentials stay bound to the original operation across all start epochs.
func enrollmentOperation(target PrivateNetworkTarget) uuid.UUID {
	if target.EnrollmentOperationID != uuid.Nil {
		return target.EnrollmentOperationID
	}
	return target.OperationID
}
func networkEpoch(target PrivateNetworkTarget) any {
	if target.EnrollmentOperationID != uuid.Nil {
		return target.OperationID
	}
	return nil
}
