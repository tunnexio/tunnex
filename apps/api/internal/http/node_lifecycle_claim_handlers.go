package http

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func checkedLifecycleGeneration(value int, allowZero bool) (int32, error) {
	minimum := 1
	if allowZero {
		minimum = 0
	}
	if value < minimum || value > math.MaxInt32 {
		return 0, apierr.BadRequest("invalid_lifecycle_generation", "expected_generation is outside the supported range")
	}
	return int32(value), nil
}

func lifecycleActorFromPrincipal(principal *authctx.Principal) (nodes.LifecycleActor, error) {
	if principal == nil || principal.IsAgent() {
		return nodes.LifecycleActor{}, apierr.New(401, "unauthenticated", "authentication required")
	}
	issuer := principal.UserID
	if principal.IsMachine() {
		issuer = principal.OwnerUserID
	}
	auditUserID, auditSystem, cause := principal.AuditActor()
	if issuer == uuid.Nil || (auditUserID == uuid.Nil && auditSystem == "") {
		return nodes.LifecycleActor{}, apierr.New(401, "unattributed_lifecycle_actor", "Kubernetes lifecycle operations require an accountable human or machine owner")
	}
	return nodes.LifecycleActor{IssuerUserID: issuer, AuditUserID: auditUserID, AuditSystem: auditSystem, Cause: cause}, nil
}

func toAPINodeLifecycleClaimStatus(status nodes.LifecycleClaimStatus) api.NodeLifecycleClaimStatus {
	result := api.NodeLifecycleClaimStatus{
		Claim:          status.Claim,
		State:          api.NodeLifecycleClaimState(status.State),
		NodeName:       status.NodeName,
		Generation:     int(status.Generation),
		RequestId:      status.RequestID,
		ExpiresAt:      status.ExpiresAt,
		AcknowledgedAt: status.AcknowledgedAt,
		ConsumedAt:     status.ConsumedAt,
		AbortedAt:      status.AbortedAt,
	}
	if status.NodeID != nil {
		id := *status.NodeID
		result.NodeId = &id
	}
	return result
}

func toAPINodeLifecycleInstallOperationStatus(status nodes.LifecycleInstallOperationStatus) api.NodeLifecycleInstallOperationStatus {
	return api.NodeLifecycleInstallOperationStatus{
		Claim: status.Claim, Generation: int(status.Generation), RequestId: status.RequestID,
		OperationId: status.OperationID, Epoch: status.Epoch,
		State:            api.NodeLifecycleInstallOperationState(status.State),
		ReleaseNamespace: status.ReleaseNamespace, ReleaseName: status.ReleaseName,
		InstallIntentDigest:      status.InstallIntentDigest,
		RequestedDurationSeconds: int(status.RequestedDurationSeconds),
		NotAfter:                 status.NotAfter, ServerTime: status.ServerTime, HeartbeatAt: status.HeartbeatAt,
		AbortRequestedAt: status.AbortRequestedAt, ReleasedAt: status.ReleasedAt,
		CompletedAt: status.CompletedAt, TakenOverAt: status.TakenOverAt, AbortedAt: status.AbortedAt,
	}
}

func lifecycleInstallCAS(claim, operationID uuid.UUID, generation int, requestID uuid.UUID, epoch int64) (nodes.LifecycleInstallCAS, error) {
	if epoch <= 0 {
		return nodes.LifecycleInstallCAS{}, apierr.BadRequest("invalid_lifecycle_install_operation_cas", "expected_epoch must be positive")
	}
	checkedGeneration, err := checkedLifecycleGeneration(generation, false)
	if err != nil {
		return nodes.LifecycleInstallCAS{}, err
	}
	return nodes.LifecycleInstallCAS{
		Claim: claim, ExpectedGeneration: checkedGeneration, RequestID: requestID,
		OperationID: operationID, ExpectedEpoch: epoch,
	}, nil
}

func lifecycleRequestActor(ctx context.Context) (nodes.LifecycleActor, error) {
	principal, _ := authctx.PrincipalFrom(ctx)
	return lifecycleActorFromPrincipal(principal)
}

func (s apiServer) GetNodeLifecycleClaim(ctx context.Context, req api.GetNodeLifecycleClaimRequestObject) (api.GetNodeLifecycleClaimResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sManage); err != nil {
		return nil, err
	}
	status, err := s.nodes.GetLifecycleClaimStatus(ctx, req.OrgId, req.Claim)
	if err != nil {
		return nil, err
	}
	return api.GetNodeLifecycleClaim200JSONResponse{
		Body:    toAPINodeLifecycleClaimStatus(status),
		Headers: api.GetNodeLifecycleClaim200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

func (s apiServer) RemintNodeLifecycleClaim(ctx context.Context, req api.RemintNodeLifecycleClaimRequestObject) (api.RemintNodeLifecycleClaimResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sManage); err != nil {
		return nil, err
	}
	// Remint returns the same raw gateway join credential as ordinary node
	// enrollment. Keep the lifecycle scope gate above, and also require the
	// canonical credential-mint authority before validating claim-shaped input.
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgUpdate); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	generation, err := checkedLifecycleGeneration(req.Body.ExpectedGeneration, true)
	if err != nil {
		return nil, err
	}
	principal, _ := authctx.PrincipalFrom(ctx)
	actor, err := lifecycleActorFromPrincipal(principal)
	if err != nil {
		return nil, err
	}
	result, err := s.nodes.RemintLifecycleClaim(ctx, actor, req.OrgId, nodes.LifecycleClaimRemint{
		Claim: req.Claim, NodeName: req.Body.NodeName, ExpectedGeneration: generation, RequestID: req.Body.RequestId,
	})
	if err != nil {
		return nil, err
	}
	return api.RemintNodeLifecycleClaim200JSONResponse{
		Body: api.NodeLifecycleClaimRemintResponse{
			Claim: result.Claim, JoinToken: result.JoinToken, Generation: int(result.Generation), RequestId: result.RequestID, ExpiresAt: result.ExpiresAt,
		},
		Headers: api.RemintNodeLifecycleClaim200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

func (s apiServer) AcknowledgeNodeLifecycleClaim(ctx context.Context, req api.AcknowledgeNodeLifecycleClaimRequestObject) (api.AcknowledgeNodeLifecycleClaimResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	generation, err := checkedLifecycleGeneration(req.Body.ExpectedGeneration, false)
	if err != nil {
		return nil, err
	}
	principal, _ := authctx.PrincipalFrom(ctx)
	actor, err := lifecycleActorFromPrincipal(principal)
	if err != nil {
		return nil, err
	}
	status, err := s.nodes.AcknowledgeLifecycleClaim(ctx, actor, req.OrgId, req.Claim, req.Body.RequestId, generation)
	if err != nil {
		return nil, err
	}
	return api.AcknowledgeNodeLifecycleClaim200JSONResponse{
		Body:    toAPINodeLifecycleClaimStatus(status),
		Headers: api.AcknowledgeNodeLifecycleClaim200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

func (s apiServer) AbortNodeLifecycleClaim(ctx context.Context, req api.AbortNodeLifecycleClaimRequestObject) (api.AbortNodeLifecycleClaimResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	generation, err := checkedLifecycleGeneration(req.Body.ExpectedGeneration, true)
	if err != nil {
		return nil, err
	}
	principal, _ := authctx.PrincipalFrom(ctx)
	actor, err := lifecycleActorFromPrincipal(principal)
	if err != nil {
		return nil, err
	}
	nodeName := ""
	if req.Body.NodeName != nil {
		nodeName = *req.Body.NodeName
	}
	status, err := s.nodes.AbortLifecycleClaim(ctx, actor, req.OrgId, nodes.LifecycleClaimAbort{
		Claim: req.Claim, NodeName: nodeName, ExpectedGeneration: generation, RequestID: req.Body.RequestId,
	})
	if err != nil {
		return nil, err
	}
	return api.AbortNodeLifecycleClaim200JSONResponse{
		Body:    toAPINodeLifecycleClaimStatus(status),
		Headers: api.AbortNodeLifecycleClaim200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

func (s apiServer) GetLatestNodeLifecycleInstall(ctx context.Context, req api.GetLatestNodeLifecycleInstallRequestObject) (api.GetLatestNodeLifecycleInstallResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sManage); err != nil {
		return nil, err
	}
	status, err := s.nodes.GetLatestLifecycleInstallOperation(ctx, req.OrgId, req.Claim)
	if err != nil {
		return nil, err
	}
	return api.GetLatestNodeLifecycleInstall200JSONResponse{
		Body:    toAPINodeLifecycleInstallOperationStatus(status),
		Headers: api.GetLatestNodeLifecycleInstall200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

func (s apiServer) BeginNodeLifecycleInstall(ctx context.Context, req api.BeginNodeLifecycleInstallRequestObject) (api.BeginNodeLifecycleInstallResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	generation, err := checkedLifecycleGeneration(req.Body.ExpectedGeneration, false)
	if err != nil {
		return nil, err
	}
	if req.Body.RequestedDurationSeconds < 1 || req.Body.RequestedDurationSeconds > int(nodes.MaxLifecycleInstallDuration/time.Second) {
		return nil, apierr.BadRequest("invalid_lifecycle_install_duration", "requested_duration_seconds must be between 1 and 900")
	}
	actor, err := lifecycleRequestActor(ctx)
	if err != nil {
		return nil, err
	}
	status, err := s.nodes.BeginLifecycleInstall(ctx, actor, req.OrgId, nodes.LifecycleInstallBegin{
		Claim: req.Claim, ExpectedGeneration: generation, RequestID: req.Body.RequestId,
		OperationID: req.Body.OperationId, ReleaseNamespace: req.Body.ReleaseNamespace,
		ReleaseName: req.Body.ReleaseName, InstallIntentDigest: req.Body.InstallIntentDigest,
		RequestedDurationSeconds: int32(req.Body.RequestedDurationSeconds),
	})
	if err != nil {
		return nil, err
	}
	return api.BeginNodeLifecycleInstall200JSONResponse{
		Body:    toAPINodeLifecycleInstallOperationStatus(status),
		Headers: api.BeginNodeLifecycleInstall200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

func (s apiServer) HeartbeatNodeLifecycleInstall(ctx context.Context, req api.HeartbeatNodeLifecycleInstallRequestObject) (api.HeartbeatNodeLifecycleInstallResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	input, err := lifecycleInstallCAS(req.Claim, req.OperationId, req.Body.ExpectedGeneration, req.Body.RequestId, req.Body.ExpectedEpoch)
	if err != nil {
		return nil, err
	}
	actor, err := lifecycleRequestActor(ctx)
	if err != nil {
		return nil, err
	}
	status, err := s.nodes.HeartbeatLifecycleInstall(ctx, actor, req.OrgId, input)
	if err != nil {
		return nil, err
	}
	return api.HeartbeatNodeLifecycleInstall200JSONResponse{
		Body:    toAPINodeLifecycleInstallOperationStatus(status),
		Headers: api.HeartbeatNodeLifecycleInstall200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

func (s apiServer) CancelNodeLifecycleInstall(ctx context.Context, req api.CancelNodeLifecycleInstallRequestObject) (api.CancelNodeLifecycleInstallResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	input, err := lifecycleInstallCAS(req.Claim, req.OperationId, req.Body.ExpectedGeneration, req.Body.RequestId, req.Body.ExpectedEpoch)
	if err != nil {
		return nil, err
	}
	actor, err := lifecycleRequestActor(ctx)
	if err != nil {
		return nil, err
	}
	status, err := s.nodes.ReleaseLifecycleInstall(ctx, actor, req.OrgId, input)
	if err != nil {
		return nil, err
	}
	return api.CancelNodeLifecycleInstall200JSONResponse{
		Body:    toAPINodeLifecycleInstallOperationStatus(status),
		Headers: api.CancelNodeLifecycleInstall200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

func (s apiServer) CompleteNodeLifecycleInstall(ctx context.Context, req api.CompleteNodeLifecycleInstallRequestObject) (api.CompleteNodeLifecycleInstallResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	cas, err := lifecycleInstallCAS(req.Claim, req.OperationId, req.Body.ExpectedGeneration, req.Body.RequestId, req.Body.ExpectedEpoch)
	if err != nil {
		return nil, err
	}
	actor, err := lifecycleRequestActor(ctx)
	if err != nil {
		return nil, err
	}
	status, err := s.nodes.CompleteLifecycleInstall(ctx, actor, req.OrgId, nodes.LifecycleInstallComplete{LifecycleInstallCAS: cas, ReleaseReady: req.Body.ReleaseReady})
	if err != nil {
		return nil, err
	}
	return api.CompleteNodeLifecycleInstall200JSONResponse{
		Body:    toAPINodeLifecycleInstallOperationStatus(status),
		Headers: api.CompleteNodeLifecycleInstall200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

func (s apiServer) RequestNodeLifecycleInstallAbort(ctx context.Context, req api.RequestNodeLifecycleInstallAbortRequestObject) (api.RequestNodeLifecycleInstallAbortResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	input, err := lifecycleInstallCAS(req.Claim, req.OperationId, req.Body.ExpectedGeneration, req.Body.RequestId, req.Body.ExpectedEpoch)
	if err != nil {
		return nil, err
	}
	actor, err := lifecycleRequestActor(ctx)
	if err != nil {
		return nil, err
	}
	result, err := s.nodes.CoordinatedAbortLifecycleClaim(ctx, actor, req.OrgId, input)
	if err != nil {
		return nil, err
	}
	requestID := middleware.GetReqID(ctx)
	if result.ClaimStatus != nil && !result.Pending {
		return api.RequestNodeLifecycleInstallAbort200JSONResponse{
			Body:    toAPINodeLifecycleClaimStatus(*result.ClaimStatus),
			Headers: api.RequestNodeLifecycleInstallAbort200ResponseHeaders{XRequestId: requestID},
		}, nil
	}
	if result.OperationStatus != nil && result.Pending {
		return api.RequestNodeLifecycleInstallAbort202JSONResponse{
			Body:    toAPINodeLifecycleInstallOperationStatus(*result.OperationStatus),
			Headers: api.RequestNodeLifecycleInstallAbort202ResponseHeaders{XRequestId: requestID},
		}, nil
	}
	return nil, errors.New("lifecycle install abort returned no terminal or pending state")
}

func (s apiServer) FinalizeNodeLifecycleInstallAbort(ctx context.Context, req api.FinalizeNodeLifecycleInstallAbortRequestObject) (api.FinalizeNodeLifecycleInstallAbortResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	cas, err := lifecycleInstallCAS(req.Claim, req.OperationId, req.Body.ExpectedGeneration, req.Body.RequestId, req.Body.ExpectedEpoch)
	if err != nil {
		return nil, err
	}
	actor, err := lifecycleRequestActor(ctx)
	if err != nil {
		return nil, err
	}
	status, err := s.nodes.FinalizeLifecycleInstallAbort(ctx, actor, req.OrgId, nodes.LifecycleInstallAbortFinalize{LifecycleInstallCAS: cas, ReleaseAbsent: req.Body.ReleaseAbsent})
	if err != nil {
		return nil, err
	}
	return api.FinalizeNodeLifecycleInstallAbort200JSONResponse{
		Body:    toAPINodeLifecycleClaimStatus(status),
		Headers: api.FinalizeNodeLifecycleInstallAbort200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}
