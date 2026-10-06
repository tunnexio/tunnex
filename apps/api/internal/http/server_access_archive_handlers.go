package http

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func (s apiServer) GetServerAccessRecordingArchive(ctx context.Context, req api.GetServerAccessRecordingArchiveRequestObject) (api.GetServerAccessRecordingArchiveResponseObject, error) {
	ctx, _, err := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessManage)
	if err != nil {
		return nil, err
	}
	out, err := s.serverAccess.GetRecordingArchive(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	return api.GetServerAccessRecordingArchive200JSONResponse(out), nil
}

func (s apiServer) UpdateServerAccessRecordingArchive(ctx context.Context, req api.UpdateServerAccessRecordingArchiveRequestObject) (api.UpdateServerAccessRecordingArchiveResponseObject, error) {
	ctx, principal, err := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessManage)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "Request body required")
	}
	out, err := s.serverAccess.ConfigureRecordingArchive(ctx, req.OrgId, principal.UserID, *req.Body)
	if err != nil {
		return nil, err
	}
	return api.UpdateServerAccessRecordingArchive200JSONResponse(out), nil
}

func (s apiServer) TestServerAccessRecordingArchive(ctx context.Context, req api.TestServerAccessRecordingArchiveRequestObject) (api.TestServerAccessRecordingArchiveResponseObject, error) {
	ctx, principal, err := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessManage)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "Request body required")
	}
	if err = s.serverAccess.TestRecordingArchive(ctx, req.OrgId, principal.UserID, *req.Body); err != nil {
		return nil, err
	}
	return api.TestServerAccessRecordingArchive200JSONResponse{Ok: true}, nil
}

func (s apiServer) ExportServerAccessRecordingS3(ctx context.Context, req api.ExportServerAccessRecordingS3RequestObject) (api.ExportServerAccessRecordingS3ResponseObject, error) {
	ctx, principal, err := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessReplay)
	if err != nil {
		return nil, err
	}
	out, err := s.serverAccess.QueueRecordingArchive(ctx, req.OrgId, req.SessionId, principal)
	if err != nil {
		return nil, err
	}
	return api.ExportServerAccessRecordingS3202JSONResponse(out), nil
}

func (s apiServer) DownloadServerAccessRecording(ctx context.Context, req api.DownloadServerAccessRecordingRequestObject) (api.DownloadServerAccessRecordingResponseObject, error) {
	ctx, principal, err := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessReplay)
	if err != nil {
		return nil, err
	}
	out, err := s.serverAccess.DownloadRecording(ctx, req.OrgId, req.SessionId, principal)
	if err != nil {
		return nil, err
	}
	return api.DownloadServerAccessRecording200JSONResponse{Body: out, Headers: api.DownloadServerAccessRecording200ResponseHeaders{
		ContentDisposition: fmt.Sprintf("attachment; filename=\"terminal-recording-%s.json\"", req.SessionId.String()),
		CacheControl:       "no-store",
	}}, nil
}

// Only the exact explicit import endpoint accepts a large package body. Other
// Terminal metadata requests retain the existing 128 KiB limit.
func terminalMetadataBodyLimit(r *http.Request) int64 {
	parts := strings.Split(r.URL.Path, "/")
	if r.Method == http.MethodPost && len(parts) == 7 && parts[1] == "api" && parts[2] == "v1" && parts[3] == "organizations" && parts[5] == "server-access" && parts[6] == "recording-import" {
		return 48 << 20
	}
	return 128 << 10
}
func serverAccessBodyLimitError(w http.ResponseWriter, r *http.Request, err error) bool {
	if !strings.Contains(r.URL.Path, "/server-access") {
		return false
	}
	var limit *http.MaxBytesError
	if errors.As(err, &limit) {
		apierr.Write(w, r, apierr.New(http.StatusRequestEntityTooLarge, "request_body_too_large", "Terminal request exceeds its bounded body limit"))
		return true
	}
	return false
}
func (s apiServer) ImportServerAccessRecordingPackage(ctx context.Context, req api.ImportServerAccessRecordingPackageRequestObject) (api.ImportServerAccessRecordingPackageResponseObject, error) {
	ctx, principal, err := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessReplay)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "Recording package required")
	}
	out, err := s.serverAccess.ImportRecordingPackage(ctx, req.OrgId, principal, req.Body.Package)
	if err != nil {
		return nil, err
	}
	return api.ImportServerAccessRecordingPackage200JSONResponse(out), nil
}
