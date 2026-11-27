package mcpdecision

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/mcptoolapproval"
	"github.com/tunnexio/tunnex/packages/apptransport/mcpwire"
)

// Wait holds a gateway's question "has this request been answered?" open until an approver answers, the
// request's lifetime ends, or the hold runs out, whichever comes first. The agent is identified exactly
// as for a decision, from the tunnel evidence the gateway observed, and only that agent's own request is
// answered for: any other is ErrNotFound.
//
// Wait changes nothing. On "approved" the gateway asks for the decision again, and that decision is what
// spends the approval, with every check run again.
//
// The state is re-read on a ticker rather than signalled in process, so an approval given through any
// control-plane replica is seen.
func (s *Service) Wait(ctx context.Context, ev Evidence, req mcpwire.WaitRequest) (mcpwire.WaitResponse, error) {
	requestID, err := uuid.Parse(req.RequestID)
	if err != nil {
		return mcpwire.WaitResponse{}, ErrInvalid
	}
	if s.approvals == nil {
		return mcpwire.WaitResponse{}, ErrNotFound
	}
	deviceID, ok := s.resolveDevice(ctx, ev)
	if !ok {
		return mcpwire.WaitResponse{}, ErrNotFound
	}
	hold, tick := s.waitHold, s.waitTick
	if hold <= 0 {
		hold = mcpwire.MaxHoldSeconds * time.Second
	}
	if tick <= 0 {
		tick = time.Second
	}
	read := func() (string, error) {
		state, err := s.approvals.State(ctx, ev.OrgID, deviceID, requestID)
		switch {
		case errors.Is(err, mcptoolapproval.ErrNotFound):
			return "", ErrNotFound
		case errors.Is(err, mcptoolapproval.ErrInvalid):
			return "", ErrInvalid
		}
		return state, err
	}
	state, err := read()
	if err != nil {
		return mcpwire.WaitResponse{}, err
	}
	timer := time.NewTimer(hold)
	defer timer.Stop()
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for state == mcptoolapproval.StatePending {
		select {
		case <-ctx.Done():
			return mcpwire.WaitResponse{}, ctx.Err()
		case <-timer.C:
			return mcpwire.WaitResponse{State: mcpwire.WaitPending}, nil
		case <-ticker.C:
			if state, err = read(); err != nil {
				return mcpwire.WaitResponse{}, err
			}
		}
	}
	switch state {
	case mcptoolapproval.StateApproved:
		return mcpwire.WaitResponse{State: mcpwire.WaitApproved}, nil
	case mcptoolapproval.StateDenied:
		return mcpwire.WaitResponse{State: mcpwire.WaitDenied}, nil
	}
	return mcpwire.WaitResponse{State: mcpwire.WaitExpired}, nil
}
