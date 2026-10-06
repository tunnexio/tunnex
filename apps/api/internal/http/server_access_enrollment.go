package http

import (
	"context"
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/packages/apptransport/bootstrap"
	"net/http"
)

func (s apiServer) PrepareServerAccessEnrollment(ctx context.Context, req api.PrepareServerAccessEnrollmentRequestObject) (api.PrepareServerAccessEnrollmentResponseObject, error) {
	ctx, p, e := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessManage)
	if e != nil {
		return nil, e
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "Request body required")
	}
	out, e := s.serverAccess.PrepareEnrollment(ctx, req.OrgId, p, req.ServerId, *req.Body)
	if e != nil {
		return nil, e
	}
	return api.PrepareServerAccessEnrollment200JSONResponse(out), nil
}
func (s apiServer) GetServerAccessEnrollment(ctx context.Context, req api.GetServerAccessEnrollmentRequestObject) (api.GetServerAccessEnrollmentResponseObject, error) {
	ctx, p, e := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessManage)
	if e != nil {
		return nil, e
	}
	out, e := s.serverAccess.Enrollment(ctx, req.OrgId, p, req.EnrollmentId, "get")
	if e != nil {
		return nil, e
	}
	return api.GetServerAccessEnrollment200JSONResponse(out), nil
}
func (s apiServer) StartServerAccessEnrollment(ctx context.Context, req api.StartServerAccessEnrollmentRequestObject) (api.StartServerAccessEnrollmentResponseObject, error) {
	ctx, p, e := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessManage)
	if e != nil {
		return nil, e
	}
	out, e := s.serverAccess.Enrollment(ctx, req.OrgId, p, req.EnrollmentId, "start")
	if e != nil {
		return nil, e
	}
	return api.StartServerAccessEnrollment200JSONResponse(out), nil
}
func (s apiServer) CancelServerAccessEnrollment(ctx context.Context, req api.CancelServerAccessEnrollmentRequestObject) (api.CancelServerAccessEnrollmentResponseObject, error) {
	ctx, p, e := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessManage)
	if e != nil {
		return nil, e
	}
	out, e := s.serverAccess.Enrollment(ctx, req.OrgId, p, req.EnrollmentId, "cancel")
	if e != nil {
		return nil, e
	}
	return api.CancelServerAccessEnrollment200JSONResponse(out), nil
}
func (a *AgentChannel) enrollmentAgent(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	if a.serverAccess == nil || node.EnrolledKind == nil || *node.EnrolledKind != "gateway" {
		apierr.Write(w, r, apierr.Forbidden("gateway_required", "Gateway enrollment authority required"))
		return
	}
	var out any
	var e error
	if chi.URLParam(r, "enrollmentId") == "" {
		out, e = a.serverAccess.EnrollmentDesired(r.Context(), node.OrgID, node.ID, node.CertSerial)
	} else {
		id, err := uuid.Parse(chi.URLParam(r, "enrollmentId"))
		if err != nil {
			apierr.Write(w, r, apierr.BadRequest("invalid_job", "Invalid enrollment job"))
			return
		}
		var in bootstrap.Report
		if !decodeAppAccessAgent(w, r, &in) {
			return
		}
		e = a.serverAccess.EnrollmentReport(r.Context(), node.OrgID, node.ID, id, node.CertSerial, in)
		out = map[string]string{"status": "accepted"}
	}
	if e != nil {
		apierr.Write(w, r, e)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(out)
}

func (s apiServer) GetCurrentServerAccessEnrollment(ctx context.Context, req api.GetCurrentServerAccessEnrollmentRequestObject) (api.GetCurrentServerAccessEnrollmentResponseObject, error) {
	ctx, p, e := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessManage)
	if e != nil {
		return nil, e
	}
	out, e := s.serverAccess.CurrentEnrollment(ctx, req.OrgId, p, req.ServerId)
	if e != nil {
		return nil, e
	}
	return api.GetCurrentServerAccessEnrollment200JSONResponse(out), nil
}
