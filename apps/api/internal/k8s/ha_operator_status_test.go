package k8s

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

type fakeHAOperatorStatusSource struct {
	status HAOperatorStatus
	err    error
}

func (f fakeHAOperatorStatusSource) HandoffHAOperatorStatus(context.Context, uuid.UUID) (HAOperatorStatus, error) {
	return f.status, f.err
}

func TestHAOperatorStatusIsFiniteAndFailClosed(t *testing.T) {
	service := &Service{}
	missing := service.loadHAOperatorStatus(context.Background(), uuid.New())
	if missing.DeploymentReady || missing.SchedulerState != "blocked" || len(missing.SchedulerReasonCodes) != 1 || missing.SchedulerReasonCodes[0] != "status_projection_unavailable" {
		t.Fatalf("missing source must be blocked and finite: %+v", missing)
	}
	service.SetHAOperatorStatusSource(fakeHAOperatorStatusSource{status: HAOperatorStatus{DeploymentReady: true, SchedulerState: "leader_operating", SchedulerReasonCodes: []string{"working"}}})
	valid := service.loadHAOperatorStatus(context.Background(), uuid.New())
	if !valid.DeploymentReady || valid.SchedulerState != "leader_operating" || len(valid.SchedulerReasonCodes) != 1 || valid.SchedulerReasonCodes[0] != "working" {
		t.Fatalf("valid source not preserved: %+v", valid)
	}
	service.SetHAOperatorStatusSource(fakeHAOperatorStatusSource{status: HAOperatorStatus{DeploymentReady: true, SchedulerState: "invented"}})
	invalid := service.loadHAOperatorStatus(context.Background(), uuid.New())
	if invalid.DeploymentReady || invalid.SchedulerState != "degraded" {
		t.Fatalf("invalid source must degrade without claiming readiness: %+v", invalid)
	}
	service.SetHAOperatorStatusSource(fakeHAOperatorStatusSource{err: errors.New("database details")})
	failed := service.loadHAOperatorStatus(context.Background(), uuid.New())
	if failed.SchedulerState != "degraded" || len(failed.SchedulerReasonCodes) != 1 || failed.SchedulerReasonCodes[0] != "status_projection_unavailable" {
		t.Fatalf("provider errors must be redacted: %+v", failed)
	}
}
