package http

import (
	"context"
	"math"

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

func toAPIK8sConnectorPoolConfiguration(in k8ssvc.ConnectorPoolConfiguration) (api.K8sConnectorPoolConfiguration, error) {
	if in.Generation > math.MaxInt64 {
		return api.K8sConnectorPoolConfiguration{}, apierr.Conflict("connector_pool_generation_invalid", "the connector pool has an invalid generation")
	}
	out := api.K8sConnectorPoolConfiguration{
		PoolId: in.PoolID, ClusterId: in.ClusterID, PreferredNodeId: in.PreferredNodeID, ActiveNodeId: in.ActiveNodeID,
		Generation: int64(in.Generation), MembershipEpochKnown: in.MembershipEpochKnown,
		Members: make([]api.K8sConnectorPoolMember, len(in.Members)),
	}
	if in.MembershipEpochKnown {
		if in.MembershipEpoch > math.MaxInt64 {
			return api.K8sConnectorPoolConfiguration{}, apierr.Conflict("connector_pool_membership_epoch_invalid", "the connector pool has an invalid membership epoch")
		}
		epoch := int64(in.MembershipEpoch)
		out.MembershipEpoch = &epoch
	}
	for i, member := range in.Members {
		out.Members[i] = api.K8sConnectorPoolMember{NodeId: member.NodeID, AdminPriority: member.AdminPriority}
	}
	return out, nil
}

func configureK8sConnectorPoolRequest(in api.ConfigureK8sConnectorPoolRequest) (k8ssvc.ConfigureConnectorPoolRequest, error) {
	request := k8ssvc.ConfigureConnectorPoolRequest{Members: make([]k8ssvc.ConnectorPoolMemberConfiguration, len(in.Members))}
	for i, member := range in.Members {
		request.Members[i] = k8ssvc.ConnectorPoolMemberConfiguration{NodeID: member.NodeId, AdminPriority: member.AdminPriority}
	}
	if in.ExpectedMembershipEpoch != nil {
		if *in.ExpectedMembershipEpoch < 0 {
			return k8ssvc.ConfigureConnectorPoolRequest{}, apierr.BadRequest("connector_pool_membership_epoch_invalid", "expected_membership_epoch must be non-negative")
		}
		epoch := uint64(*in.ExpectedMembershipEpoch)
		request.ExpectedMembershipEpoch = &epoch
	}
	return request, nil
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

func (s apiServer) GetK8sConnectorPoolConfiguration(ctx context.Context, req api.GetK8sConnectorPoolConfigurationRequestObject) (api.GetK8sConnectorPoolConfigurationResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sHAView); err != nil {
		return nil, err
	}
	cluster, err := s.k8s.GetCluster(ctx, req.OrgId, req.ClusterId)
	if err != nil {
		return nil, err
	}
	configuration, err := s.k8s.GetConnectorPoolConfiguration(ctx, req.OrgId, cluster.SiteID, req.ClusterId)
	if err != nil {
		return nil, err
	}
	body, err := toAPIK8sConnectorPoolConfiguration(configuration)
	if err != nil {
		return nil, err
	}
	return api.GetK8sConnectorPoolConfiguration200JSONResponse{Body: body, Headers: api.GetK8sConnectorPoolConfiguration200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) ConfigureK8sConnectorPool(ctx context.Context, req api.ConfigureK8sConnectorPoolRequestObject) (api.ConfigureK8sConnectorPoolResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sHAManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "a request body is required")
	}
	configurationRequest, err := configureK8sConnectorPoolRequest(*req.Body)
	if err != nil {
		return nil, err
	}
	configurationRequest.ClusterID = req.ClusterId
	cluster, err := s.k8s.GetCluster(ctx, req.OrgId, req.ClusterId)
	if err != nil {
		return nil, err
	}
	uid, sys, cause := auditActor(ctx)
	configuration, err := s.k8s.ConfigureConnectorPool(ctx, req.OrgId, cluster.SiteID, configurationRequest, uid, sys, cause)
	if err != nil {
		return nil, err
	}
	body, err := toAPIK8sConnectorPoolConfiguration(configuration)
	if err != nil {
		return nil, err
	}
	return api.ConfigureK8sConnectorPool200JSONResponse{Body: body, Headers: api.ConfigureK8sConnectorPool200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}
