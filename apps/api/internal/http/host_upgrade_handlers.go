package http

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/hostupgrade"
	"github.com/tunnexio/tunnex/apps/api/internal/release"
)

func (s apiServer) GetHostUpgrade(ctx context.Context, _ api.GetHostUpgradeRequestObject) (api.GetHostUpgradeResponseObject, error) {
	if _, err := requireCPAdmin(ctx); err != nil {
		return nil, err
	}
	body := api.HostUpgradeStatus{Available: s.hostUpgrade != nil && s.hostUpgrade.Available(), State: api.HostUpgradeStatusStateIdle}
	if body.Available {
		if status, err := s.hostUpgrade.Status(); err == nil {
			body = hostUpgradeBody(status)
			rerun := hostUpgradeRerunAvailable(s.currentReleaseStatus(), status)
			body.RerunAvailable = &rerun
		} else if !errors.Is(err, hostupgrade.ErrUnavailable) {
			return nil, apierr.New(http.StatusServiceUnavailable, "host_upgrade_state_invalid", "The local upgrade runner state is unavailable or invalid.")
		}
	}
	return api.GetHostUpgrade200JSONResponse{Body: body, Headers: api.GetHostUpgrade200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}

func (s apiServer) currentReleaseStatus() *release.Status {
	if s.releaseStatusProvider != nil {
		return s.releaseStatusProvider()
	}
	return s.releaseStatus
}

// hostUpgradeRerunAvailable is the forward-fix rule (UPG-1 D2, AA-EN-1): the
// last upgrade failed, it targeted exactly the release the verified catalog
// names, and that release is the installed one (same sequence and source SHA,
// release.Status.Rerunnable). Never an older release, never a different build
// of the same sequence, and never after the App Access authority changed
// (the upgrade then says not to re-run; the restore runbook applies).
func hostUpgradeRerunAvailable(status *release.Status, host hostupgrade.Status) bool {
	return status != nil && status.Verified && status.Rerunnable && !status.Available &&
		len(status.SourceSHA) == 40 && status.Version != "" && status.Sequence > 0 &&
		host.State == "failed" && host.TargetSource == status.SourceSHA &&
		host.ReasonCode != "app_access_authority_changed"
}

func (s apiServer) RequestHostUpgrade(ctx context.Context, request api.RequestHostUpgradeRequestObject) (api.RequestHostUpgradeResponseObject, error) {
	p, err := requireCPAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if s.hostUpgrade == nil || !s.hostUpgrade.Available() {
		return nil, apierr.New(http.StatusServiceUnavailable, "host_updater_unavailable", "The local host upgrade runner is not installed or configured.")
	}
	status := s.currentReleaseStatus()
	rerun := request.Body != nil && request.Body.Rerun != nil && *request.Body.Rerun
	if rerun {
		host, hostErr := s.hostUpgrade.Status()
		if hostErr != nil || !hostUpgradeRerunAvailable(status, host) {
			return nil, apierr.New(http.StatusConflict, "rerun_not_available", "Only the installed release can be run again, and only after an upgrade to it failed.")
		}
	} else if status == nil || !status.Verified || !status.Available || status.SourceSHA == "" || status.Version == "" || status.Sequence <= 0 {
		return nil, apierr.New(http.StatusConflict, "upgrade_not_available", "No newer verified release is currently available.")
	}
	result, _, err := s.hostUpgrade.Request(ctx, p.UserID, hostupgrade.Target{SourceSHA: status.SourceSHA, Version: status.Version, Sequence: status.Sequence, Rerun: rerun})
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
