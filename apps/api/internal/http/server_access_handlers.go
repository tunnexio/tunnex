package http

import (
	"context"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"net/http"
)

func (s apiServer) terminalContext(ctx context.Context, org uuid.UUID, perm rbac.Permission) (context.Context, *authctx.Principal, error) {
	ctx, e := authorize(ctx, org, perm)
	if e != nil {
		return ctx, nil, e
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if p == nil || p.UserID == uuid.Nil || p.SessionID == "" || p.IsMachine() || p.IsAgent() || p.AuthMethod == authctx.AuthBearer || p.AuthMethod == authctx.AuthMachine || p.AuthMethod == authctx.AuthAgent {
		return ctx, nil, apierr.Forbidden("human_session_required", "Terminal access requires a human browser session")
	}
	if s.serverAccess == nil {
		return ctx, nil, apierr.New(503, "server_access_disabled", "Terminal capability is disabled")
	}
	return ctx, p, nil
}
func (s apiServer) GetServerAccessWorkspace(ctx context.Context, req api.GetServerAccessWorkspaceRequestObject) (api.GetServerAccessWorkspaceResponseObject, error) {
	ctx, p, e := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessUse)
	if e != nil {
		return nil, e
	}
	out, e := s.serverAccess.Workspace(ctx, req.OrgId, p)
	if e != nil {
		return nil, e
	}
	return api.GetServerAccessWorkspace200JSONResponse(out), nil
}
func (s apiServer) UpdateServerAccessSettings(ctx context.Context, req api.UpdateServerAccessSettingsRequestObject) (api.UpdateServerAccessSettingsResponseObject, error) {
	ctx, p, e := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessManage)
	if e != nil {
		return nil, e
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "Request body required")
	}
	e = s.serverAccess.Configure(ctx, req.OrgId, p.UserID, *req.Body)
	out := api.ServerAccessResult{Status: "updated"}
	if e != nil {
		return nil, e
	}
	return api.UpdateServerAccessSettings200JSONResponse(out), nil
}
func (s apiServer) CreateServerAccessServer(ctx context.Context, req api.CreateServerAccessServerRequestObject) (api.CreateServerAccessServerResponseObject, error) {
	ctx, p, e := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessManage)
	if e != nil {
		return nil, e
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "Request body required")
	}
	out, e := s.serverAccess.SaveServer(ctx, req.OrgId, p.UserID, uuid.Nil, *req.Body)
	if e != nil {
		return nil, e
	}
	return api.CreateServerAccessServer200JSONResponse(out), nil
}
func (s apiServer) UpdateServerAccessServer(ctx context.Context, req api.UpdateServerAccessServerRequestObject) (api.UpdateServerAccessServerResponseObject, error) {
	ctx, p, e := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessManage)
	if e != nil {
		return nil, e
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "Request body required")
	}
	out, e := s.serverAccess.SaveServer(ctx, req.OrgId, p.UserID, req.ServerId, *req.Body)
	if e != nil {
		return nil, e
	}
	return api.UpdateServerAccessServer200JSONResponse(out), nil
}
func (s apiServer) CheckServerAccessServer(ctx context.Context, req api.CheckServerAccessServerRequestObject) (api.CheckServerAccessServerResponseObject, error) {
	ctx, p, e := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessManage)
	if e != nil {
		return nil, e
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "Request body required")
	}
	if req.Body.ServerId != req.ServerId {
		return nil, apierr.BadRequest("server_binding_mismatch", "Server ID must match the registered server")
	}
	out, e := s.serverAccess.StartSession(ctx, req.OrgId, p, *req.Body, true)
	if e != nil {
		return nil, e
	}
	return api.CheckServerAccessServer200JSONResponse(out), nil
}
func (s apiServer) GetServerAccessTrust(ctx context.Context, req api.GetServerAccessTrustRequestObject) (api.GetServerAccessTrustResponseObject, error) {
	ctx, _, e := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessManage)
	if e != nil {
		return nil, e
	}
	out, e := s.serverAccess.Trust(ctx, req.OrgId)
	if e != nil {
		return nil, e
	}
	return api.GetServerAccessTrust200JSONResponse(out), nil
}
func (s apiServer) CreateServerAccessGrant(ctx context.Context, req api.CreateServerAccessGrantRequestObject) (api.CreateServerAccessGrantResponseObject, error) {
	ctx, p, e := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessGrant)
	if e != nil {
		return nil, e
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "Request body required")
	}
	out, e := s.serverAccess.Grant(ctx, req.OrgId, p.UserID, *req.Body)
	if e != nil {
		return nil, e
	}
	return api.CreateServerAccessGrant200JSONResponse(out), nil
}
func (s apiServer) RevokeServerAccessGrant(ctx context.Context, req api.RevokeServerAccessGrantRequestObject) (api.RevokeServerAccessGrantResponseObject, error) {
	ctx, p, e := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessGrant)
	if e != nil {
		return nil, e
	}
	e = s.serverAccess.RevokeGrant(ctx, req.OrgId, p.UserID, req.GrantId)
	out := api.ServerAccessResult{Status: "revoked"}
	if e != nil {
		return nil, e
	}
	return api.RevokeServerAccessGrant200JSONResponse(out), nil
}
func (s apiServer) CreateServerAccessSession(ctx context.Context, req api.CreateServerAccessSessionRequestObject) (api.CreateServerAccessSessionResponseObject, error) {
	ctx, p, e := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessUse)
	if e != nil {
		return nil, e
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "Request body required")
	}
	out, e := s.serverAccess.StartSession(ctx, req.OrgId, p, *req.Body, false)
	if e != nil {
		s.serverAccess.Denied(ctx, req.OrgId, p.UserID, *req.Body, e)
		return nil, e
	}
	return api.CreateServerAccessSession200JSONResponse(out), nil
}
func (s apiServer) EndServerAccessSession(ctx context.Context, req api.EndServerAccessSessionRequestObject) (api.EndServerAccessSessionResponseObject, error) {
	ctx, p, e := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessUse)
	if e != nil {
		return nil, e
	}
	e = s.serverAccess.End(ctx, req.OrgId, req.SessionId, p)
	out := api.ServerAccessResult{Status: "ended"}
	if e != nil {
		return nil, e
	}
	return api.EndServerAccessSession200JSONResponse(out), nil
}
func (s apiServer) ConnectServerAccessTerminal(ctx context.Context, req api.ConnectServerAccessTerminalRequestObject) (api.ConnectServerAccessTerminalResponseObject, error) {
	return nil, apierr.BadRequest("websocket_required", "Use the terminal websocket endpoint")
}
func (s apiServer) terminalWebsocket(w http.ResponseWriter, r *http.Request) {
	org, e := uuid.Parse(chi.URLParam(r, "orgId"))
	if e != nil {
		apierr.Write(w, r, apierr.BadRequest("invalid_org", "Invalid organization"))
		return
	}
	id, e := uuid.Parse(chi.URLParam(r, "sessionId"))
	if e != nil {
		apierr.Write(w, r, apierr.BadRequest("invalid_session", "Invalid session"))
		return
	}
	ctx, p, e := s.terminalContext(r.Context(), org, rbac.PermServerAccessUse)
	if e != nil {
		apierr.Write(w, r, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	secure, _ := requestHTTPS(ctx)
	if e = s.serverAccess.Browser(w, r.WithContext(ctx), org, id, p, secure); e != nil {
		apierr.Write(w, r, e)
	}
}

func (s apiServer) GetServerAccessRecording(ctx context.Context, req api.GetServerAccessRecordingRequestObject) (api.GetServerAccessRecordingResponseObject, error) {
	ctx, p, e := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessReplay)
	if e != nil {
		return nil, e
	}
	out, e := s.serverAccess.Recording(ctx, req.OrgId, req.SessionId, p, req.Params.MetadataOnly != nil && *req.Params.MetadataOnly)
	if e != nil {
		return nil, e
	}
	return api.GetServerAccessRecording200JSONResponse(out), nil
}

func (s apiServer) RemoveServerAccessServer(ctx context.Context, req api.RemoveServerAccessServerRequestObject) (api.RemoveServerAccessServerResponseObject, error) {
	ctx, p, e := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessManage)
	if e != nil {
		return nil, e
	}
	if e = s.serverAccess.RemoveServer(ctx, req.OrgId, p.UserID, req.ServerId); e != nil {
		return nil, e
	}
	return api.RemoveServerAccessServer200JSONResponse(api.ServerAccessResult{Status: "removed"}), nil
}
