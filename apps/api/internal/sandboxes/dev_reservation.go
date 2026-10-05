package sandboxes

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// DevHistoricalReservation is an opt-in operator attestation for ONE physically
// erased historical trial. It grants no effects on that trial and supplies no
// withdrawal or retirement proof. The two unsaved fields require fresh operator
// verification before activation; neither is inferred from the current gateway.
type DevHistoricalReservation struct {
	PeerStatus              string
	LaunchGatewayID         uuid.UUID
	PhysicalCleanupEvidence string
}

var (
	devReservedSandbox    = uuid.MustParse("01a100f3-a3c6-7ac3-b35c-e27419d997d5")
	devReservedOrg        = uuid.MustParse("01a0fa92-f690-79e6-aa7d-99de6871e3dc")
	devReservedCreator    = uuid.MustParse("01a0fa92-f68d-7829-9e1b-cf2ce0fc798e")
	devReservedDevice     = uuid.MustParse("01a0fc79-f210-7ac6-a6cb-c643de185657")
	devCurrentDevice      = uuid.MustParse("01a104ce-a4ea-7578-ac6f-2b400c367a91")
	devOperationalGateway = uuid.MustParse("01a0fa96-28af-73d2-9cca-45d6218ebcd8")
	devReservedTemplate   = uuid.MustParse("75184b8b-c24a-56e1-8601-67b878965c97")
	devReservedPeer       = uuid.MustParse("01a10106-7c77-7bd8-bcc2-6a08d7a51acb")
	devReservedCreated    = time.Date(2026, 10, 3, 8, 48, 49, 531245000, time.UTC)
	devReservedExpiry     = devReservedCreated.Add(time.Hour)
)

const (
	devReservedRuntime = "697eb38eb76b1a0c14e8e37c9fd8f9b44ff018aa2bdd5b4c46b9a9f3c20a6fec"
	devReservedSpec    = "eb7fcc449a6a779ece22ae30b6bd61a2352165d652c2ea60df5f5f7f77d8ea59"
	devReservedImage   = "sha256:956864613a2e5356b9da8afe8a7ceef90c5cdcc0bca911957df98fb59f4914f1"
)

func (b BoundedRuntimeBinding) validDevReservation() bool {
	r := b.DevReservation
	if r == nil || !b.Persistent() || b.OrgID != devReservedOrg || b.CreatorID != devReservedCreator || (b.TerminalDeviceID != devReservedDevice && b.TerminalDeviceID != devCurrentDevice) || b.terminalGatewayID() != devOperationalGateway || r.LaunchGatewayID == uuid.Nil || (r.PeerStatus != "active" && r.PeerStatus != "revoked") || strings.TrimSpace(r.PhysicalCleanupEvidence) == "" || len(r.PhysicalCleanupEvidence) > 512 {
		return false
	}
	for _, p := range b.Profiles {
		if p.TemplateID == devReservedTemplate {
			return false
		}
	}
	return true
}
func (b BoundedRuntimeBinding) reservedID() uuid.UUID {
	if b.DevReservation != nil {
		return devReservedSandbox
	}
	return uuid.Nil
}

// Persistent authority can NEVER adopt the old trial, even without the allowance.
func (b BoundedRuntimeBinding) deniesRuntimeID(id uuid.UUID) bool {
	return b.Persistent() && id == devReservedSandbox
}
func (b BoundedRuntimeBinding) retainedLimit() int32 {
	if b.DevReservation != nil {
		return 2
	}
	return 1
}

type reservationReader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// These exact existing rows are held for share through admission/Setup mutation.
// There is no historical write path. Completion is accepted only with its own
// genuine matching withdrawal; NULL retirement still counts as retained.
func (b BoundedRuntimeBinding) reservationState(ctx context.Context, q reservationReader) (string, error) {
	if b.DevReservation == nil {
		return "", nil
	}
	if !b.validDevReservation() {
		return "invalid", ErrDisabled
	}
	var pending, completed bool
	err := q.QueryRow(ctx, `SELECT
 (s.observed_state='deleting' AND d.status=$13 AND d.assigned_ip='10.99.0.10' AND d.deleted_at IS NULL
  AND (d.status<>'revoked' OR d.revoked_at IS NOT NULL) AND r.worker_retired_at IS NULL
  AND NOT EXISTS(SELECT 1 FROM sandbox_network_withdrawals w WHERE w.sandbox_id=s.id)),
 (s.observed_state='deleted' AND d.status='revoked' AND d.revoked_at IS NOT NULL AND d.assigned_ip IS NULL
  AND EXISTS(SELECT 1 FROM sandbox_network_withdrawals w WHERE w.sandbox_id=s.id AND w.org_id=s.org_id
   AND w.generation=2 AND w.operation_id=l.id AND COALESCE(w.network_epoch_id,w.operation_id)=l.id
   AND w.network_generation=1 AND w.peer_id=d.id AND w.runtime_id=r.runtime_id AND w.spec_hash=r.spec_hash))
 FROM sandboxes s
 JOIN sandbox_runtime_bindings r ON r.sandbox_id=s.id AND r.org_id=s.org_id
 JOIN sandbox_templates t ON t.id=s.template_id AND t.org_id=s.org_id
 JOIN devices d ON d.id=s.peer_id AND d.org_id=s.org_id AND d.user_id=s.creator_id
 JOIN sandbox_runtime_credentials c ON c.sandbox_id=s.id AND c.org_id=s.org_id AND c.peer_id=d.id
 JOIN sandbox_launch_operations l ON l.sandbox_id=s.id AND l.org_id=s.org_id AND l.generation=1
 WHERE s.id=$1 AND s.org_id=$2 AND s.creator_id=$3 AND s.template_id=$4 AND s.peer_id=$5
 AND s.generation=2 AND s.desired_state='deleted' AND s.requested_scope='[]'::jsonb
 AND s.created_at=$6 AND s.expires_at=$7 AND s.expires_at<=now()
 AND s.terminal_device_id=$8 AND s.local_terminal_gateway_id IS NULL
 AND r.runtime_id=$9 AND r.spec_hash=$10 AND r.image_digest=$11 AND r.memory_mib=128 AND r.cpus=1 AND r.pids=128
 AND t.image_digest=$11 AND t.memory_mib=128 AND t.max_ttl_seconds=3600 AND t.maximum_scope='[]'::jsonb
 AND d.kind='sandbox' AND d.health_blocked AND d.node_id=$12
 AND l.gateway_node_id=$12 AND l.runtime_id=r.runtime_id AND l.spec_hash=r.spec_hash AND l.confirmed_at IS NOT NULL
 AND c.revoked_at IS NOT NULL
 AND NOT EXISTS(SELECT 1 FROM sandbox_runtime_credentials c2 WHERE c2.sandbox_id=s.id AND c2.revoked_at IS NULL)
 AND NOT EXISTS(SELECT 1 FROM sandbox_bootstrap_tokens bt WHERE bt.sandbox_id=s.id AND bt.consumed_at IS NULL AND bt.expires_at>now())
 FOR SHARE OF s,r,t,d,c,l`, devReservedSandbox, b.OrgID, b.CreatorID, devReservedTemplate, devReservedPeer,
		devReservedCreated, devReservedExpiry, devReservedDevice, devReservedRuntime, devReservedSpec, devReservedImage,
		b.DevReservation.LaunchGatewayID, b.DevReservation.PeerStatus).Scan(&pending, &completed)
	if err == pgx.ErrNoRows {
		return "invalid", ErrDisabled
	}
	if err != nil {
		return "invalid", err
	}
	if pending {
		return "pending", nil
	}
	if completed {
		return "completed", nil
	}
	return "invalid", ErrDisabled
}

// Counts ALL retained org records, including creators/templates the worker cannot
// operate. The reserved identity is the sole exception to the one-workload cap.
func (s *Store) retainedCounts(ctx context.Context, q reservationReader, org, actor uuid.UUID) (own, total, workloads int64, err error) {
	reserved := uuid.Nil
	if s.boundedRuntime != nil {
		reserved = s.boundedRuntime.reservedID()
	}
	err = q.QueryRow(ctx, `SELECT count(*) FILTER(WHERE creator_id=$2),count(*),count(*) FILTER(WHERE id<>$3) FROM sandboxes WHERE org_id=$1 AND `+s.retainedPredicate(), org, actor, reserved).Scan(&own, &total, &workloads)
	return
}
func (s *Store) reservationAdmission(ctx context.Context, q reservationReader, org uuid.UUID) error {
	b := s.boundedRuntime
	if b == nil || b.DevReservation == nil {
		return nil
	}
	if org != b.OrgID {
		return ErrDisabled
	}
	_, err := b.reservationState(ctx, q)
	return err
}
