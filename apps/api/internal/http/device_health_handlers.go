package http

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// deviceHealthEditionRequired is the open-build 403 for the device-health
// endpoints. NAMED per feature (s.deviceHealthEnabled) — the standing discipline
// (F2 / S12.1): device health, device approval, and Zero Trust policy unlock
// independently.
func deviceHealthEditionRequired() error {
	return apierr.New(http.StatusForbidden, "edition_required", "Device posture checks are a Tunnex Enterprise feature")
}

// ListHealthChecks GET .../health-checks — the org's configured (opted-in) checks.
func (s apiServer) ListHealthChecks(ctx context.Context, req api.ListHealthChecksRequestObject) (api.ListHealthChecksResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermDeviceHealthManage); err != nil {
		return nil, err
	}
	if !s.deviceHealthEnabled {
		return nil, deviceHealthEditionRequired()
	}
	checks, err := s.devices.ListHealthChecks(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	out := make([]api.HealthCheck, 0, len(checks))
	for _, c := range checks {
		out = append(out, toAPIHealthCheck(c))
	}
	return api.ListHealthChecks200JSONResponse{Body: out, Headers: api.ListHealthChecks200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// PutHealthCheck PUT .../health-checks/{checkKind} — opt in / reconfigure one
// check. The write itself never flips a device gate (D4 grandfather); the
// response carries the best-effort would-fail blast radius.
func (s apiServer) PutHealthCheck(ctx context.Context, req api.PutHealthCheckRequestObject) (api.PutHealthCheckResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermDeviceHealthManage); err != nil {
		return nil, err
	}
	if !s.deviceHealthEnabled {
		return nil, deviceHealthEditionRequired()
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	var param json.RawMessage
	if req.Body.Param != nil {
		b, err := json.Marshal(req.Body.Param)
		if err != nil {
			return nil, apierr.BadRequest("invalid_request", "param must be a JSON object")
		}
		param = b
	}
	wouldFail, err := s.devices.SetHealthCheck(ctx, p.UserID, req.OrgId, req.CheckKind, string(req.Body.Mode), param)
	if err != nil {
		return nil, err
	}
	body := toAPIHealthCheck(devices.HealthCheckConfig{Kind: req.CheckKind, Mode: string(req.Body.Mode), Param: param})
	n := int(wouldFail)
	body.WouldFailCount = &n
	return api.PutHealthCheck200JSONResponse{Body: body, Headers: api.PutHealthCheck200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// DeleteHealthCheck DELETE .../health-checks/{checkKind} — turn the check off
// (idempotent). Devices it blocked unblock on their next report.
func (s apiServer) DeleteHealthCheck(ctx context.Context, req api.DeleteHealthCheckRequestObject) (api.DeleteHealthCheckResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermDeviceHealthManage); err != nil {
		return nil, err
	}
	if !s.deviceHealthEnabled {
		return nil, deviceHealthEditionRequired()
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if err := s.devices.DeleteHealthCheck(ctx, p.UserID, req.OrgId, req.CheckKind); err != nil {
		return nil, err
	}
	return api.DeleteHealthCheck204Response{Headers: api.DeleteHealthCheck204ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// ReportDeviceHealth POST .../devices/{deviceId}/health — the device OWNER
// self-reports posture facts (org membership here; owner-match in the service).
// No manage perm: the same ownership rule as device creation.
func (s apiServer) ReportDeviceHealth(ctx context.Context, req api.ReportDeviceHealthRequestObject) (api.ReportDeviceHealthResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	if !s.deviceHealthEnabled {
		return nil, deviceHealthEditionRequired()
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	facts := devices.HealthFacts{
		Platform:      string(req.Body.Platform),
		OSVersion:     req.Body.OsVersion,
		DiskEncrypted: req.Body.DiskEncrypted,
		CollectedAt:   req.Body.CollectedAt,
	}
	ev, err := s.devices.ReportHealth(ctx, req.OrgId, p.UserID, req.DeviceId, facts)
	if err != nil {
		return nil, err
	}
	body := api.DeviceHealthResult{
		State:   api.DeviceHealthResultState(ev.State),
		Blocked: ev.Blocked,
		FailedChecks: make([]struct {
			Kind api.DeviceHealthResultFailedChecksKind `json:"kind"`
			Mode api.DeviceHealthResultFailedChecksMode `json:"mode"`
		}, 0, len(ev.FailedChecks)),
	}
	for _, f := range ev.FailedChecks {
		body.FailedChecks = append(body.FailedChecks, struct {
			Kind api.DeviceHealthResultFailedChecksKind `json:"kind"`
			Mode api.DeviceHealthResultFailedChecksMode `json:"mode"`
		}{Kind: api.DeviceHealthResultFailedChecksKind(f.Kind), Mode: api.DeviceHealthResultFailedChecksMode(f.Mode)})
	}
	return api.ReportDeviceHealth200JSONResponse{Body: body, Headers: api.ReportDeviceHealth200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func toAPIHealthCheck(c devices.HealthCheckConfig) api.HealthCheck {
	out := api.HealthCheck{Kind: api.HealthCheckKind(c.Kind), Mode: api.HealthCheckMode(c.Mode)}
	if len(c.Param) > 0 && string(c.Param) != "null" {
		var m map[string]interface{}
		if json.Unmarshal(c.Param, &m) == nil {
			out.Param = &m
		}
	}
	return out
}
