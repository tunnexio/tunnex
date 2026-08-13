//go:build !enterprise

package http

import (
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// Device posture (S7.3) is enterprise-only. In the open build deviceApprovalEnabled is
// false (its own NAMED wire file — NOT a proxy behind s.policy), so an authenticated +
// authorized owner still gets 403 edition_required on every device-posture endpoint —
// server-side enforcement, not a hidden UI. authorize() runs FIRST (sessionless -> 401,
// covered by the spec-walk); the edition gate fires for authenticated callers.
func TestDeviceApprovalEditionGatedInOpenBuild(t *testing.T) {
	s := apiServer{} // open build: deviceApprovalEnabled defaults to false
	org, dev := uuid.New(), uuid.New()
	ctx := principalWithRole(org, rbac.RoleOwner)

	if _, err := s.ListPendingDevices(ctx, api.ListPendingDevicesRequestObject{OrgId: org}); !hasCode(err, 403, "edition_required") {
		t.Fatalf("ListPendingDevices: want 403 edition_required, got %v", err)
	}
	if _, err := s.ApproveDevice(ctx, api.ApproveDeviceRequestObject{OrgId: org, DeviceId: dev}); !hasCode(err, 403, "edition_required") {
		t.Fatalf("ApproveDevice: want 403 edition_required, got %v", err)
	}
	if _, err := s.RejectDevice(ctx, api.RejectDeviceRequestObject{OrgId: org, DeviceId: dev}); !hasCode(err, 403, "edition_required") {
		t.Fatalf("RejectDevice: want 403 edition_required, got %v", err)
	}
	if _, err := s.GetDeviceApproval(ctx, api.GetDeviceApprovalRequestObject{OrgId: org}); !hasCode(err, 403, "edition_required") {
		t.Fatalf("GetDeviceApproval: want 403 edition_required, got %v", err)
	}
	mode := api.DeviceApprovalMode("on")
	if _, err := s.SetDeviceApproval(ctx, api.SetDeviceApprovalRequestObject{OrgId: org, Body: &api.DeviceApproval{Mode: mode}}); !hasCode(err, 403, "edition_required") {
		t.Fatalf("SetDeviceApproval: want 403 edition_required, got %v", err)
	}
}

// RBAC deliberate-red: a MEMBER-role caller lacks device:approve, so authorize() refuses
// BEFORE the edition gate — 403 forbidden, not edition_required. Proves the endpoints are
// RBAC-gated at the owner/admin grain (a member cannot approve devices even in enterprise).
func TestDeviceApprovalRefusesMemberRole(t *testing.T) {
	s := apiServer{deviceApprovalEnabled: true} // pretend enterprise so the gate isn't what refuses
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
