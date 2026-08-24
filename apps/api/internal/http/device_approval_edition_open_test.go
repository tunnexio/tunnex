//go:build !enterprise

package http

import (
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// Device approval is wired in the one binary for Community and every paid plan.
// Authorization and service integration tests exercise the handlers themselves;
// this wire test prevents the old build-edition seam returning as an entitlement.
func TestDeviceApprovalIsWiredInTheOneBinary(t *testing.T) {
	if !NewDeviceApprovalEdition() {
		t.Fatal("device approval must not be disabled by a build or edition switch")
	}
}

// RBAC deliberate-red: a MEMBER-role caller lacks device:approve, so authorize()
// refuses before the handler can touch device state.
func TestDeviceApprovalRefusesMemberRole(t *testing.T) {
	s := apiServer{}
	org, dev := uuid.New(), uuid.New()
	ctx := principalWithRole(org, rbac.RoleMember)

	if _, err := s.ApproveDevice(ctx, api.ApproveDeviceRequestObject{OrgId: org, DeviceId: dev}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member ApproveDevice: want 403 forbidden (RBAC), got %v", err)
	}
	if _, err := s.RejectDevice(ctx, api.RejectDeviceRequestObject{OrgId: org, DeviceId: dev}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member RejectDevice: want 403 forbidden, got %v", err)
	}
	mode := api.DeviceApprovalMode("on")
	if _, err := s.SetDeviceApproval(ctx, api.SetDeviceApprovalRequestObject{OrgId: org, Body: &api.DeviceApproval{Mode: mode}}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member SetDeviceApproval: want 403 forbidden, got %v", err)
	}
	if _, err := s.ListPendingDevices(ctx, api.ListPendingDevicesRequestObject{OrgId: org}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member ListPendingDevices: want 403 forbidden, got %v", err)
	}
}
