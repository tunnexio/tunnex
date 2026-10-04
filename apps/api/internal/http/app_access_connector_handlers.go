package http

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
)

type appAccessCheckPort interface {
	RequestCheck(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, int64, bool) (appaccess.Check, error)
	GetCheck(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (appaccess.Check, error)
	GetGatewayRuntime(context.Context, uuid.UUID, uuid.UUID) (appaccess.GatewayRuntime, error)
}

func (s apiServer) appAccessChecks() (appAccessCheckPort, error) {
	service, ok := s.appAccess.(appAccessCheckPort)
	if !ok {
		return nil, apierr.New(http.StatusServiceUnavailable, "app_access_unavailable", "App Access connector service is unavailable")
	}
	return service, nil
}
func appAccessCheck(r appaccess.Check) api.AppAccessCheck {
	return api.AppAccessCheck{Id: r.ID, OrgId: r.OrgID, AppId: r.AppID, GatewayId: r.GatewayID, Generation: r.Generation, Revision: r.Revision, Digest: r.Digest, Purpose: api.AppAccessCheckPurpose(r.Purpose), Status: api.AppAccessCheckStatus(r.Status), CreatedAt: r.CreatedAt, Deadline: r.Deadline, CompletedAt: r.CompletedAt, DnsStatus: api.AppAccessCheckDnsStatus(r.DNSStatus), ConnectStatus: api.AppAccessCheckConnectStatus(r.ConnectStatus), TlsStatus: api.AppAccessCheckTlsStatus(r.TLSStatus), ErrorCode: api.AppAccessCheckErrorCode(r.ErrorCode)}
}
func appAccessGatewayRuntime(r appaccess.GatewayRuntime) api.AppAccessGatewayRuntime {
	return api.AppAccessGatewayRuntime{OrgId: r.OrgID, GatewayId: r.GatewayID, CapabilityVersion: int(r.CapabilityVersion), ReportedAt: r.ReportedAt, Status: api.AppAccessGatewayRuntimeStatus(r.Status)}
}
func (s apiServer) RequestAppAccessCheck(ctx context.Context, req api.RequestAppAccessCheckRequestObject) (api.RequestAppAccessCheckResponseObject, error) {
	ctx, actor, err := s.appAccessContext(ctx, req.OrgId, true)
	if err != nil {
		return nil, err
	}
	if req.Body == nil || req.Body.ExpectedVersion < 1 {
		return nil, apierr.BadRequest("invalid_request", "positive expected version required")
	}
	if err = s.requireAppAccessEntitlement(); err != nil {
		return nil, err
	}
	service, err := s.appAccessChecks()
	if err != nil {
		return nil, err
	}
	out, err := service.RequestCheck(ctx, req.OrgId, actor, req.AppId, req.Body.ExpectedVersion, s.appAccessEntitled())
	if err != nil {
		return nil, err
	}
	return api.RequestAppAccessCheck202JSONResponse{Body: appAccessCheck(out), Headers: api.RequestAppAccessCheck202ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) GetAppAccessCheck(ctx context.Context, req api.GetAppAccessCheckRequestObject) (api.GetAppAccessCheckResponseObject, error) {
	ctx, _, err := s.appAccessContext(ctx, req.OrgId, false)
	if err != nil {
		return nil, err
	}
	service, err := s.appAccessChecks()
	if err != nil {
		return nil, err
	}
	out, err := service.GetCheck(ctx, req.OrgId, req.AppId, req.CheckId)
	if err != nil {
		return nil, err
	}
	return api.GetAppAccessCheck200JSONResponse{Body: appAccessCheck(out), Headers: api.GetAppAccessCheck200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) GetAppAccessGatewayStatus(ctx context.Context, req api.GetAppAccessGatewayStatusRequestObject) (api.GetAppAccessGatewayStatusResponseObject, error) {
	ctx, _, err := s.appAccessContext(ctx, req.OrgId, false)
	if err != nil {
		return nil, err
	}
	service, err := s.appAccessChecks()
	if err != nil {
		return nil, err
	}
	out, err := service.GetGatewayRuntime(ctx, req.OrgId, req.GatewayId)
	if err != nil {
		return nil, err
	}
	return api.GetAppAccessGatewayStatus200JSONResponse{Body: appAccessGatewayRuntime(out), Headers: api.GetAppAccessGatewayStatus200ResponseHeaders{CacheControl: "no-store"}}, nil
}
