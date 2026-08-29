package http

import (
	"context"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	k8ssvc "github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func toAPIK8sHASettings(in k8ssvc.HASettings) api.K8sHASettings {
	return api.K8sHASettings{
		Enabled: in.Enabled, Revision: in.Revision,
		ActualState: api.K8sHASettingsActualState(in.ActualState),
		ReasonCode:  in.ReasonCode, UpdatedAt: in.UpdatedAt,
		DeploymentReady:      in.DeploymentReady,
		SchedulerState:       api.K8sHASettingsSchedulerState(in.SchedulerState),
		SchedulerReasonCodes: append([]string(nil), in.SchedulerReasonCodes...),
	}
}

func toAPIK8sConnectorPoolHAStatus(in k8ssvc.ConnectorPoolHAStatus) api.K8sConnectorPoolHAStatus {
	return api.K8sConnectorPoolHAStatus{
		PoolId: in.PoolID, ClusterId: in.ClusterID, ActiveNodeId: in.ActiveNodeID,
		RequestedMode:        api.K8sConnectorPoolHAStatusRequestedMode(in.RequestedMode),
		ActualMode:           api.K8sConnectorPoolHAStatusActualMode(in.ActualMode),
		PromotionGeneration:  in.PromotionGeneration,
		MembershipEpochKnown: in.MembershipEpoch != nil, MembershipEpoch: in.MembershipEpoch,
		TransitionRevision: in.TransitionRevision, ReasonCode: in.ReasonCode,
		RequestedAt: in.RequestedAt, AchievedAt: in.AchievedAt,
	}
}

func (s apiServer) GetK8sHASettings(ctx context.Context, req api.GetK8sHASettingsRequestObject) (api.GetK8sHASettingsResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sHAView); err != nil {
		return nil, err
	}
	settings, err := s.k8s.GetHASettings(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	return api.GetK8sHASettings200JSONResponse{Body: toAPIK8sHASettings(settings), Headers: api.GetK8sHASettings200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) SetK8sHASettings(ctx context.Context, req api.SetK8sHASettingsRequestObject) (api.SetK8sHASettingsResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sHAManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "a request body is required")
	}
	uid, _, cause := auditActor(ctx)
	settings, err := s.k8s.SetHASettings(ctx, req.OrgId, uid, cause, req.Body.Enabled, req.Body.ExpectedRevision)
	if err != nil {
		return nil, err
	}
	return api.SetK8sHASettings200JSONResponse{Body: toAPIK8sHASettings(settings), Headers: api.SetK8sHASettings200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) ListK8sConnectorPoolHAStatus(ctx context.Context, req api.ListK8sConnectorPoolHAStatusRequestObject) (api.ListK8sConnectorPoolHAStatusResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sHAView); err != nil {
		return nil, err
	}
	list, err := s.k8s.ListConnectorPoolHAStatus(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	out := make([]api.K8sConnectorPoolHAStatus, len(list))
	for i := range list {
		out[i] = toAPIK8sConnectorPoolHAStatus(list[i])
	}
	return api.ListK8sConnectorPoolHAStatus200JSONResponse{Body: out, Headers: api.ListK8sConnectorPoolHAStatus200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) GetK8sConnectorPoolHAStatus(ctx context.Context, req api.GetK8sConnectorPoolHAStatusRequestObject) (api.GetK8sConnectorPoolHAStatusResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sHAView); err != nil {
		return nil, err
	}
	status, err := s.k8s.GetConnectorPoolHAStatus(ctx, req.OrgId, req.PoolId)
	if err != nil {
		return nil, err
	}
	return api.GetK8sConnectorPoolHAStatus200JSONResponse{Body: toAPIK8sConnectorPoolHAStatus(status), Headers: api.GetK8sConnectorPoolHAStatus200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) SetK8sConnectorPoolHAMode(ctx context.Context, req api.SetK8sConnectorPoolHAModeRequestObject) (api.SetK8sConnectorPoolHAModeResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sHAManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "a request body is required")
	}
	uid, _, cause := auditActor(ctx)
	status, err := s.k8s.SetConnectorPoolHAMode(ctx, req.OrgId, req.PoolId, uid, cause, string(req.Body.RequestedMode), req.Body.ExpectedTransitionRevision)
	if err != nil {
		return nil, err
	}
	return api.SetK8sConnectorPoolHAMode200JSONResponse{Body: toAPIK8sConnectorPoolHAStatus(status), Headers: api.SetK8sConnectorPoolHAMode200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}
