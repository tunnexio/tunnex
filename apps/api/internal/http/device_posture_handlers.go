package http

import (
	"context"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// ListPendingDevices GET .../devices/pending — the Community approval queue.
func (s apiServer) ListPendingDevices(ctx context.Context, req api.ListPendingDevicesRequestObject) (api.ListPendingDevicesResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermDeviceApprove); err != nil {
		return nil, err
	}
	list, err := s.devices.ListPending(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	out := make([]api.Device, 0, len(list))
	for _, d := range list {
		out = append(out, toAPIDeviceWithStatus(d))
	}
	return api.ListPendingDevices200JSONResponse{Body: out, Headers: api.ListPendingDevices200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// ApproveDevice POST .../devices/{deviceId}/approve.
func (s apiServer) ApproveDevice(ctx context.Context, req api.ApproveDeviceRequestObject) (api.ApproveDeviceResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermDeviceApprove); err != nil {
		return nil, err
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if err := s.devices.Approve(ctx, req.OrgId, p.UserID, req.DeviceId); err != nil {
		return nil, err
	}
	return api.ApproveDevice204Response{Headers: api.ApproveDevice204ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// RejectDevice POST .../devices/{deviceId}/reject.
func (s apiServer) RejectDevice(ctx context.Context, req api.RejectDeviceRequestObject) (api.RejectDeviceResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermDeviceApprove); err != nil {
		return nil, err
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if err := s.devices.Reject(ctx, req.OrgId, p.UserID, req.DeviceId); err != nil {
		return nil, err
	}
	return api.RejectDevice204Response{Headers: api.RejectDevice204ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// GetDeviceApproval GET .../device-approval.
func (s apiServer) GetDeviceApproval(ctx context.Context, req api.GetDeviceApprovalRequestObject) (api.GetDeviceApprovalResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermDeviceApprove); err != nil {
		return nil, err
	}
	mode, err := s.devices.GetDeviceApproval(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	return api.GetDeviceApproval200JSONResponse{
		Body:    api.DeviceApproval{Mode: api.DeviceApprovalMode(mode)},
		Headers: api.GetDeviceApproval200ResponseHeaders{XRequestId: reqID(ctx)},
	}, nil
}

// SetDeviceApproval PUT .../device-approval — flip the gate; returns the grandfathered
// count when enabling (best-effort; a committed flip never fails on the count).
func (s apiServer) SetDeviceApproval(ctx context.Context, req api.SetDeviceApprovalRequestObject) (api.SetDeviceApprovalResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermDeviceApprove); err != nil {
		return nil, err
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	mode := string(req.Body.Mode)
	grandfathered, err := s.devices.SetDeviceApproval(ctx, p.UserID, req.OrgId, mode)
	if err != nil {
		return nil, err
	}
	body := api.DeviceApproval{Mode: api.DeviceApprovalMode(mode)}
	if mode == "on" {
		n := int(grandfathered)
		body.GrandfatheredCount = &n
	}
	return api.SetDeviceApproval200JSONResponse{
		Body:    body,
		Headers: api.SetDeviceApproval200ResponseHeaders{XRequestId: reqID(ctx)},
	}, nil
}
