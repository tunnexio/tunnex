package nodes

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
)

// HandoffHAOperatorStatusSource is the narrow public projection adapter. It
// aggregates the existing pool statuses without exposing node, operation,
// artifact, P2, or database identities through the organization settings API.
type HandoffHAOperatorStatusSource struct {
	runtime    *HandoffSchedulerServerRuntime
	projection *PostgresHandoffOperatorStatusProjection
}

func NewHandoffHAOperatorStatusSource(runtime *HandoffSchedulerServerRuntime, projection *PostgresHandoffOperatorStatusProjection) *HandoffHAOperatorStatusSource {
	return &HandoffHAOperatorStatusSource{runtime: runtime, projection: projection}
}

func (s *HandoffHAOperatorStatusSource) HandoffHAOperatorStatus(ctx context.Context, orgID uuid.UUID) (k8s.HAOperatorStatus, error) {
	if s == nil || s.runtime == nil || s.projection == nil || ctx == nil || orgID == uuid.Nil {
		return k8s.HAOperatorStatus{}, errors.New("handoff HA operator status unavailable")
	}
	activation := s.runtime.Status()
	out := k8s.HAOperatorStatus{DeploymentReady: activation.State == HandoffSchedulerReady}
	switch activation.State {
	case HandoffSchedulerDisabled:
		out.SchedulerState = string(HandoffOperatorDisabled)
		out.SchedulerReasonCodes = []string{string(HandoffOperatorActivationDisabled)}
		return out, nil
	case HandoffSchedulerBlocked:
		out.SchedulerState = string(HandoffOperatorBlocked)
		for _, reason := range operatorActivationReasons(activation) {
			out.SchedulerReasonCodes = append(out.SchedulerReasonCodes, string(reason))
		}
		return out, nil
	case HandoffSchedulerReady:
	default:
		return k8s.HAOperatorStatus{SchedulerState: string(HandoffOperatorDegraded), SchedulerReasonCodes: []string{string(HandoffOperatorActivationUnknown)}}, nil
	}

	leadership, err := s.runtime.HandoffOperatorLeadership(ctx)
	if err != nil {
		return k8s.HAOperatorStatus{DeploymentReady: true, SchedulerState: string(HandoffOperatorDegraded), SchedulerReasonCodes: []string{string(HandoffOperatorLeadershipUnknown)}}, nil
	}
	statuses, err := s.projection.HandoffOperatorStatuses(ctx, orgID, time.Now().UTC(), activation, leadership)
	if err != nil {
		return k8s.HAOperatorStatus{DeploymentReady: true, SchedulerState: string(HandoffOperatorDegraded), SchedulerReasonCodes: []string{"status_projection_unavailable"}}, nil
	}
	if len(statuses) == 0 {
		if !leadership.Confirmed {
			out.SchedulerState = string(HandoffOperatorDegraded)
			out.SchedulerReasonCodes = []string{string(HandoffOperatorLeadershipUnknown)}
		} else if leadership.Leader {
			out.SchedulerState = string(HandoffOperatorLeaderIdle)
		} else {
			out.SchedulerState = string(HandoffOperatorFollower)
		}
		return out, nil
	}

	state := HandoffOperatorLeaderIdle
	reasons := make([]string, 0)
	for _, status := range statuses {
		for _, reason := range status.Reasons {
			reasons = appendUniqueString(reasons, string(reason))
		}
		switch status.State {
		case HandoffOperatorDegraded:
			state = HandoffOperatorDegraded
		case HandoffOperatorBlocked:
			if state != HandoffOperatorDegraded {
				state = HandoffOperatorBlocked
			}
		case HandoffOperatorLeaderOperating:
			if state != HandoffOperatorDegraded && state != HandoffOperatorBlocked {
				state = HandoffOperatorLeaderOperating
			}
		case HandoffOperatorFollower:
			if state == HandoffOperatorLeaderIdle {
				state = HandoffOperatorFollower
			}
		}
	}
	out.SchedulerState, out.SchedulerReasonCodes = string(state), reasons
	return out, nil
}

func appendUniqueString(values []string, value string) []string {
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

var _ k8s.HAOperatorStatusSource = (*HandoffHAOperatorStatusSource)(nil)
