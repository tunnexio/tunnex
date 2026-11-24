package http

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
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
			if p, _ := authctx.PrincipalFrom(ctx); rerun && p != nil && s.system != nil {
				// What this administrator must prove to re-run (display only; enforced on POST).
				if r, err := s.installationReauthFor(ctx, p.UserID, s.currentParent(ctx, p)); err == nil {
					body.RerunReauthentication = &struct {
						Available bool `json:"available"`
						Mfa       bool `json:"mfa"`
						Password  bool `json:"password"`
					}{Available: r.available(), Mfa: r.mfa || r.ssoMFA, Password: r.password}
				}
			}
		} else if !errors.Is(err, hostupgrade.ErrUnavailable) {
			return nil, apierr.New(http.StatusServiceUnavailable, "host_upgrade_state_invalid", "The local upgrade runner state is unavailable or invalid.")
		}
	}
	return api.GetHostUpgrade200JSONResponse{Body: body, Headers: api.GetHostUpgrade200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}

// hostUpgradeRerunReauthScope names the re-run's password-failure budget.
const hostUpgradeRerunReauthScope = "control_plane_upgrade_rerun"

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

func (s apiServer) RequestHostUpgrade(ctx context.Context, _ api.RequestHostUpgradeRequestObject) (api.RequestHostUpgradeResponseObject, error) {
	p, err := s.requireHostUpgrade(ctx)
	if err != nil {
		return nil, err
	}
	status := s.currentReleaseStatus()
	if status == nil || !status.Verified || !status.Available || status.SourceSHA == "" || status.Version == "" || status.Sequence <= 0 {
		return nil, apierr.New(http.StatusConflict, "upgrade_not_available", "No newer verified release is currently available.")
	}
	result, err := s.requestHostUpgrade(ctx, p, hostupgrade.Target{SourceSHA: status.SourceSHA, Version: status.Version, Sequence: status.Sequence})
	if err != nil {
		return nil, err
	}
	return api.RequestHostUpgrade202JSONResponse{Body: hostUpgradeBody(result), Headers: api.RequestHostUpgrade202ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}

// RerunHostUpgrade is the dashboard forward fix (UPG-1 D2, AA-EN-1): the same
// authorization, request file and audit action as an upgrade, for the installed
// release only, and only after the upgrade to it failed.
func (s apiServer) RerunHostUpgrade(ctx context.Context, request api.RerunHostUpgradeRequestObject) (api.RerunHostUpgradeResponseObject, error) {
	p, err := requireCPAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireHumanSession(p, "Running an upgrade again from the dashboard"); err != nil {
		return nil, err
	}
	if _, err := s.requireHostUpgrade(ctx); err != nil {
		return nil, err
	}
	status := s.currentReleaseStatus()
	host, hostErr := s.hostUpgrade.Status()
	if hostErr != nil || !hostUpgradeRerunAvailable(status, host) {
		return nil, apierr.New(http.StatusConflict, "rerun_not_available", "Only the installed release can be run again, and only after an upgrade to it failed.")
	}
	var currentPassword *string
	if request.Body != nil {
		currentPassword = request.Body.CurrentPassword
	}
	// E7 / founder ruling: the same SA-UI-1 re-authentication as the Server
	// Access installation setting, with this action's own password budget.
	if err := s.requireRecentReauthentication(ctx, p, currentPassword, hostUpgradeRerunReauthScope, "run the upgrade again"); err != nil {
		return nil, err
	}
	result, err := s.requestHostUpgrade(ctx, p, hostupgrade.Target{SourceSHA: status.SourceSHA, Version: status.Version, Sequence: status.Sequence, Rerun: true})
	if err != nil {
		return nil, err
	}
	return api.RerunHostUpgrade202JSONResponse{Body: hostUpgradeBody(result), Headers: api.RerunHostUpgrade202ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}

func (s apiServer) requireHostUpgrade(ctx context.Context) (*authctx.Principal, error) {
	p, err := requireCPAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if s.hostUpgrade == nil || !s.hostUpgrade.Available() {
		return nil, apierr.New(http.StatusServiceUnavailable, "host_updater_unavailable", "The local host upgrade runner is not installed or configured.")
	}
	return p, nil
}

func (s apiServer) requestHostUpgrade(ctx context.Context, p *authctx.Principal, target hostupgrade.Target) (hostupgrade.Status, error) {
	result, _, err := s.hostUpgrade.Request(ctx, p.UserID, target)
	if err != nil {
		switch {
		case errors.Is(err, hostupgrade.ErrBusy):
			return result, apierr.New(http.StatusConflict, "upgrade_in_progress", "Another control-plane upgrade is already active.")
		case errors.Is(err, hostupgrade.ErrUnavailable), errors.Is(err, hostupgrade.ErrInvalid):
			return result, apierr.New(http.StatusServiceUnavailable, "host_updater_unavailable", "The local host upgrade runner is not ready.")
		default:
			return result, err
		}
	}
	return result, nil
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
