package cli

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/cli/internal/api"
)

func lifecycleInstallStatusFromAPI(status api.NodeLifecycleInstallOperationStatus) lifecycleInstallOperationStatus {
	return lifecycleInstallOperationStatus{
		claim: status.Claim.String(), generation: status.Generation, requestID: status.RequestId.String(),
		operationID: status.OperationId.String(), epoch: status.Epoch, state: lifecycleInstallOperationState(status.State),
		releaseNamespace: status.ReleaseNamespace, releaseName: status.ReleaseName, installIntentDigest: status.InstallIntentDigest,
		requestedDurationSeconds: status.RequestedDurationSeconds, notAfter: status.NotAfter, serverTime: status.ServerTime,
		heartbeatAt: status.HeartbeatAt, abortRequestedAt: status.AbortRequestedAt, releasedAt: status.ReleasedAt,
		completedAt: status.CompletedAt, takenOverAt: status.TakenOverAt, abortedAt: status.AbortedAt,
	}
}

func parseLifecycleInstallRequestIDs(orgID string, request lifecycleInstallCASRequest) (uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, error) {
	orgUUID, claimUUID, err := parseLifecycleIDs(orgID, request.claim)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, err
	}
	requestUUID, err := uuid.Parse(request.requestID)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("invalid lifecycle request id: %w", err)
	}
	operationUUID, err := uuid.Parse(request.operationID)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("invalid lifecycle install operation id: %w", err)
	}
	return orgUUID, claimUUID, requestUUID, operationUUID, nil
}

func lifecycleInstallCASBody(request lifecycleInstallCASRequest) api.NodeLifecycleInstallCASRequest {
	requestUUID := uuid.MustParse(request.requestID)
	return api.NodeLifecycleInstallCASRequest{
		ExpectedGeneration: request.expectedGeneration,
		RequestId:          requestUUID,
		ExpectedEpoch:      request.expectedEpoch,
	}
}

func (c *apiK8sControlPlane) GetLatestLifecycleInstall(ctx context.Context, orgID, claim string) (lifecycleInstallOperationStatus, error) {
	orgUUID, claimUUID, err := parseLifecycleIDs(orgID, claim)
	if err != nil {
		return lifecycleInstallOperationStatus{}, err
	}
	resp, err := retryLifecycleRoute(ctx, c.lifecycleRetry,
		func(attemptCtx context.Context) (*api.GetLatestNodeLifecycleInstallResponse, error) {
			return c.client.GetLatestNodeLifecycleInstallWithResponse(attemptCtx, orgUUID, claimUUID)
		},
		func(response *api.GetLatestNodeLifecycleInstallResponse) (int, []byte) {
			return response.StatusCode(), response.Body
		},
	)
	if err != nil {
		return lifecycleInstallOperationStatus{}, err
	}
	if resp.JSON200 == nil {
		return lifecycleInstallOperationStatus{}, apiErr(resp.StatusCode(), resp.Body, "could not read latest lifecycle install operation")
	}
	return lifecycleInstallStatusFromAPI(*resp.JSON200), nil
}

func (c *apiK8sControlPlane) BeginLifecycleInstall(ctx context.Context, orgID string, request lifecycleInstallBeginRequest) (lifecycleInstallOperationStatus, error) {
	orgUUID, claimUUID, err := parseLifecycleIDs(orgID, request.claim)
	if err != nil {
		return lifecycleInstallOperationStatus{}, err
	}
	requestUUID, err := uuid.Parse(request.requestID)
	if err != nil {
		return lifecycleInstallOperationStatus{}, fmt.Errorf("invalid lifecycle request id: %w", err)
	}
	operationUUID, err := uuid.Parse(request.operationID)
	if err != nil {
		return lifecycleInstallOperationStatus{}, fmt.Errorf("invalid lifecycle install operation id: %w", err)
	}
	body := api.BeginNodeLifecycleInstallJSONRequestBody{
		ExpectedGeneration: request.expectedGeneration, RequestId: requestUUID, OperationId: operationUUID,
		ReleaseNamespace: request.releaseNamespace, ReleaseName: request.releaseName,
		InstallIntentDigest: request.installIntentDigest, RequestedDurationSeconds: request.requestedDurationSeconds,
	}
	resp, err := retryLifecycleRoute(ctx, c.lifecycleRetry,
		func(attemptCtx context.Context) (*api.BeginNodeLifecycleInstallResponse, error) {
			return c.client.BeginNodeLifecycleInstallWithResponse(attemptCtx, orgUUID, claimUUID, body)
		},
		func(response *api.BeginNodeLifecycleInstallResponse) (int, []byte) {
			return response.StatusCode(), response.Body
		},
	)
	if err != nil {
		return lifecycleInstallOperationStatus{}, err
	}
	if resp.JSON200 == nil {
		if resp.StatusCode() == http.StatusConflict && resp.JSON409 != nil && resp.JSON409.Error.Code == lifecycleInstallAbsentAfterExpiry {
			return lifecycleInstallOperationStatus{}, errLifecycleInstallOperationAbsentAfterExpiry
		}
		return lifecycleInstallOperationStatus{}, apiErr(resp.StatusCode(), resp.Body, "could not begin lifecycle install authority")
	}
	return lifecycleInstallStatusFromAPI(*resp.JSON200), nil
}

func (c *apiK8sControlPlane) HeartbeatLifecycleInstall(ctx context.Context, orgID string, request lifecycleInstallCASRequest) (lifecycleInstallOperationStatus, error) {
	orgUUID, claimUUID, _, operationUUID, err := parseLifecycleInstallRequestIDs(orgID, request)
	if err != nil {
		return lifecycleInstallOperationStatus{}, err
	}
	body := api.HeartbeatNodeLifecycleInstallJSONRequestBody(lifecycleInstallCASBody(request))
	resp, err := retryLifecycleRoute(ctx, c.lifecycleRetry,
		func(attemptCtx context.Context) (*api.HeartbeatNodeLifecycleInstallResponse, error) {
			return c.client.HeartbeatNodeLifecycleInstallWithResponse(attemptCtx, orgUUID, claimUUID, operationUUID, body)
		},
		func(response *api.HeartbeatNodeLifecycleInstallResponse) (int, []byte) {
			return response.StatusCode(), response.Body
		},
	)
	if err != nil {
		return lifecycleInstallOperationStatus{}, err
	}
	if resp.JSON200 == nil {
		return lifecycleInstallOperationStatus{}, apiErr(resp.StatusCode(), resp.Body, "could not heartbeat lifecycle install authority")
	}
	return lifecycleInstallStatusFromAPI(*resp.JSON200), nil
}

func (c *apiK8sControlPlane) ReleaseLifecycleInstall(ctx context.Context, orgID string, request lifecycleInstallCASRequest) (lifecycleInstallOperationStatus, error) {
	orgUUID, claimUUID, _, operationUUID, err := parseLifecycleInstallRequestIDs(orgID, request)
	if err != nil {
		return lifecycleInstallOperationStatus{}, err
	}
	body := api.CancelNodeLifecycleInstallJSONRequestBody(lifecycleInstallCASBody(request))
	resp, err := retryLifecycleRoute(ctx, c.lifecycleRetry,
		func(attemptCtx context.Context) (*api.CancelNodeLifecycleInstallResponse, error) {
			return c.client.CancelNodeLifecycleInstallWithResponse(attemptCtx, orgUUID, claimUUID, operationUUID, body)
		},
		func(response *api.CancelNodeLifecycleInstallResponse) (int, []byte) {
			return response.StatusCode(), response.Body
		},
	)
	if err != nil {
		return lifecycleInstallOperationStatus{}, err
	}
	if resp.JSON200 == nil {
		return lifecycleInstallOperationStatus{}, apiErr(resp.StatusCode(), resp.Body, "could not release lifecycle install authority")
	}
	return lifecycleInstallStatusFromAPI(*resp.JSON200), nil
}

func (c *apiK8sControlPlane) CompleteLifecycleInstall(ctx context.Context, orgID string, request lifecycleInstallCASRequest) (lifecycleInstallOperationStatus, error) {
	orgUUID, claimUUID, requestUUID, operationUUID, err := parseLifecycleInstallRequestIDs(orgID, request)
	if err != nil {
		return lifecycleInstallOperationStatus{}, err
	}
	body := api.CompleteNodeLifecycleInstallJSONRequestBody{
		ExpectedGeneration: request.expectedGeneration, RequestId: requestUUID,
		ExpectedEpoch: request.expectedEpoch, ReleaseReady: true,
	}
	resp, err := retryLifecycleRoute(ctx, c.lifecycleRetry,
		func(attemptCtx context.Context) (*api.CompleteNodeLifecycleInstallResponse, error) {
			return c.client.CompleteNodeLifecycleInstallWithResponse(attemptCtx, orgUUID, claimUUID, operationUUID, body)
		},
		func(response *api.CompleteNodeLifecycleInstallResponse) (int, []byte) {
			return response.StatusCode(), response.Body
		},
	)
	if err != nil {
		return lifecycleInstallOperationStatus{}, err
	}
	if resp.JSON200 == nil {
		return lifecycleInstallOperationStatus{}, apiErr(resp.StatusCode(), resp.Body, "could not complete lifecycle install authority")
	}
	return lifecycleInstallStatusFromAPI(*resp.JSON200), nil
}

func (c *apiK8sControlPlane) CoordinateLifecycleInstallAbort(ctx context.Context, orgID string, request lifecycleInstallCASRequest) (lifecycleInstallAbortResult, error) {
	orgUUID, claimUUID, _, operationUUID, err := parseLifecycleInstallRequestIDs(orgID, request)
	if err != nil {
		return lifecycleInstallAbortResult{}, err
	}
	body := api.RequestNodeLifecycleInstallAbortJSONRequestBody(lifecycleInstallCASBody(request))
	resp, err := retryLifecycleRoute(ctx, c.lifecycleRetry,
		func(attemptCtx context.Context) (*api.RequestNodeLifecycleInstallAbortResponse, error) {
			return c.client.RequestNodeLifecycleInstallAbortWithResponse(attemptCtx, orgUUID, claimUUID, operationUUID, body)
		},
		func(response *api.RequestNodeLifecycleInstallAbortResponse) (int, []byte) {
			return response.StatusCode(), response.Body
		},
	)
	if err != nil {
		return lifecycleInstallAbortResult{}, err
	}
	if resp.StatusCode() == http.StatusOK && resp.JSON200 != nil {
		status := lifecycleStatusFromAPI(*resp.JSON200)
		return lifecycleInstallAbortResult{claimStatus: &status}, nil
	}
	if resp.StatusCode() == http.StatusAccepted && resp.JSON202 != nil {
		status := lifecycleInstallStatusFromAPI(*resp.JSON202)
		return lifecycleInstallAbortResult{operationStatus: &status, pending: true}, nil
	}
	return lifecycleInstallAbortResult{}, apiErr(resp.StatusCode(), resp.Body, "could not coordinate lifecycle install abort")
}

func (c *apiK8sControlPlane) FinalizeLifecycleInstallAbort(ctx context.Context, orgID string, request lifecycleInstallCASRequest) (k8sLifecycleClaimStatus, error) {
	orgUUID, claimUUID, requestUUID, operationUUID, err := parseLifecycleInstallRequestIDs(orgID, request)
	if err != nil {
		return k8sLifecycleClaimStatus{}, err
	}
	body := api.FinalizeNodeLifecycleInstallAbortJSONRequestBody{
		ExpectedGeneration: request.expectedGeneration, RequestId: requestUUID,
		ExpectedEpoch: request.expectedEpoch, ReleaseAbsent: true,
	}
	resp, err := retryLifecycleRoute(ctx, c.lifecycleRetry,
		func(attemptCtx context.Context) (*api.FinalizeNodeLifecycleInstallAbortResponse, error) {
			return c.client.FinalizeNodeLifecycleInstallAbortWithResponse(attemptCtx, orgUUID, claimUUID, operationUUID, body)
		},
		func(response *api.FinalizeNodeLifecycleInstallAbortResponse) (int, []byte) {
			return response.StatusCode(), response.Body
		},
	)
	if err != nil {
		return k8sLifecycleClaimStatus{}, err
	}
	if resp.JSON200 == nil {
		return k8sLifecycleClaimStatus{}, apiErr(resp.StatusCode(), resp.Body, "could not finalize lifecycle install abort")
	}
	return lifecycleStatusFromAPI(*resp.JSON200), nil
}
