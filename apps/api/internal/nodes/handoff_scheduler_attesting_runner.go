package nodes

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
)

// p2AttestingHandoffRunner is the production scheduler boundary between the
// durable request source and the coordinator. It accepts no source-supplied
// acknowledgement. For a resumed operation it reads only the artifact named
// by the stored phase, through the exact leader session, immediately before
// the coordinator rechecks that phase and mutates state.
type p2AttestingHandoffRunner struct {
	coordinator k8s.HandoffFencedTickRunner
	adapter     *k8s.P2HandoffAdapter
}

var _ k8s.HandoffTickRunner = (*p2AttestingHandoffRunner)(nil)
var _ k8s.HandoffFencedTickRunner = (*p2AttestingHandoffRunner)(nil)

func newP2AttestingHandoffRunner(coordinator k8s.HandoffFencedTickRunner, adapter *k8s.P2HandoffAdapter) *p2AttestingHandoffRunner {
	return &p2AttestingHandoffRunner{coordinator: coordinator, adapter: adapter}
}

func (r *p2AttestingHandoffRunner) Tick(context.Context, k8s.HandoffCoordinatorRequest) (k8s.HandoffCoordinatorResult, error) {
	return k8s.HandoffCoordinatorResult{}, k8s.ErrHandoffLeadershipUnavailable
}

func (r *p2AttestingHandoffRunner) TickWithLeadership(ctx context.Context, req k8s.HandoffCoordinatorRequest, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn) (k8s.HandoffCoordinatorResult, error) {
	if r == nil || r.coordinator == nil || r.adapter == nil || conn == nil {
		return k8s.HandoffCoordinatorResult{}, k8s.ErrHandoffLeadershipUnavailable
	}
	if req.PreparedAck != nil || req.WithdrawalAck != nil || req.ServingAck != nil {
		return k8s.HandoffCoordinatorResult{}, fmt.Errorf("%w: scheduler source supplied phase acknowledgement", k8s.ErrInvalidHandoffCoordinatorRequest)
	}
	if req.CurrentPhase != "" {
		acks, err := r.adapter.AcknowledgementsForPhaseWithLeadership(ctx, req.Plan, req.CurrentPhase, req.Now, req.MaxAckAge, epoch, conn)
		if err != nil {
			return k8s.HandoffCoordinatorResult{}, err
		}
		req.PreparedAck, req.WithdrawalAck, req.ServingAck = acks.Prepared, acks.Withdrawal, acks.Serving
	}
	return r.coordinator.TickWithLeadership(ctx, req, epoch, conn)
}
