package http

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/hostupgrade"
)

func (s apiServer) GetHostUpgrade(ctx context.Context, _ api.GetHostUpgradeRequestObject) (api.GetHostUpgradeResponseObject, error) {
	if _, err := requireCPAdmin(ctx); err != nil {
		return nil, err
	}
	body := api.HostUpgradeStatus{Available: s.hostUpgrade != nil && s.hostUpgrade.Available(), State: api.HostUpgradeStatusStateIdle}
	if body.Available {
		if status, err := s.hostUpgrade.Status(); err == nil {
			body = hostUpgradeBody(status)
		} else if !errors.Is(err, hostupgrade.ErrUnavailable) {
			return nil, apierr.New(http.StatusServiceUnavailable, "host_upgrade_state_invalid", "The local upgrade runner state is unavailable or invalid.")
		}
	}
	return api.GetHostUpgrade200JSONResponse{Body: body, Headers: api.GetHostUpgrade200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}

func (s apiServer) RequestHostUpgrade(ctx context.Context, _ api.RequestHostUpgradeRequestObject) (api.RequestHostUpgradeResponseObject, error) {
	p, err := requireCPAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if s.hostUpgrade == nil || !s.hostUpgrade.Available() {
		return nil, apierr.New(http.StatusServiceUnavailable, "host_updater_unavailable", "The local host upgrade runner is not installed or configured.")
	}
	status := s.releaseStatus
	if s.releaseStatusProvider != nil {
		status = s.releaseStatusProvider()
	}
	if status == nil || !status.Verified || !status.Available || status.SourceSHA == "" || status.Version == "" || status.Sequence <= 0 {
		return nil, apierr.New(http.StatusConflict, "upgrade_not_available", "No newer verified release is currently available.")
	}
	result, _, err := s.hostUpgrade.Request(ctx, p.UserID, hostupgrade.Target{SourceSHA: status.SourceSHA, Version: status.Version, Sequence: status.Sequence})
	if err != nil {
		switch {
		case errors.Is(err, hostupgrade.ErrBusy):
			return nil, apierr.New(http.StatusConflict, "upgrade_in_progress", "Another control-plane upgrade is already active.")
		case errors.Is(err, hostupgrade.ErrUnavailable), errors.Is(err, hostupgrade.ErrInvalid):
			return nil, apierr.New(http.StatusServiceUnavailable, "host_updater_unavailable", "The local host upgrade runner is not ready.")
		default:
			return nil, err
		}
	}
	return api.RequestHostUpgrade202JSONResponse{Body: hostUpgradeBody(result), Headers: api.RequestHostUpgrade202ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}

func hostUpgradeBody(status hostupgrade.Status) api.HostUpgradeStatus {
	state := api.HostUpgradeStatusState(status.State)
	body := api.HostUpgradeStatus{Available: true, State: state}
	if status.RequestID != [16]byte{} {
		id := status.RequestID
		body.RequestId = &id
	}
	if status.TargetSource != "" {
		body.TargetSourceSha = &status.TargetSource
	}
	if status.TargetVersion != "" {
		body.TargetVersion = &status.TargetVersion
	}
	if status.BackupDump != "" {
		body.BackupDump = &status.BackupDump
	}
	if status.BackupManifest != "" {
		body.BackupManifest = &status.BackupManifest
	}
	if status.ReasonCode != "" {
		body.ReasonCode = &status.ReasonCode
	}
	if !status.UpdatedAt.IsZero() {
		body.UpdatedAt = &status.UpdatedAt
	}
	return body
}
