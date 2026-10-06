package http

import (
	"context"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"net/http"
)

func (s apiServer) AuthorizeServerAccessEditor(ctx context.Context, req api.AuthorizeServerAccessEditorRequestObject) (api.AuthorizeServerAccessEditorResponseObject, error) {
	ctx, p, e := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessUse)
	if e != nil {
		return nil, e
	}
	secure, _ := requestHTTPS(ctx)
	if !secure {
		return nil, apierr.Forbidden("editor_requires_https", "Open the control plane over HTTPS")
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "Request body required")
	}
	out, e := s.serverAccess.AuthorizeEditor(ctx, req.OrgId, p, *req.Body)
	if e != nil {
		s.serverAccess.Denied(ctx, req.OrgId, p.UserID, api.ServerAccessConnectInput{ServerId: req.Body.ServerId, Account: req.Body.Account}, e)
		return nil, e
	}
	return api.AuthorizeServerAccessEditor200JSONResponse(out), nil
}
func (s apiServer) ExchangeServerAccessEditor(ctx context.Context, req api.ExchangeServerAccessEditorRequestObject) (api.ExchangeServerAccessEditorResponseObject, error) {
	secure, _ := requestHTTPS(ctx)
	if !secure {
		return nil, apierr.Forbidden("editor_requires_https", "HTTPS required")
	}
	if s.serverAccess == nil {
		return nil, apierr.Forbidden("server_access_disabled", "Server access disabled")
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "Request body required")
	}
	out, e := s.serverAccess.ExchangeEditor(ctx, *req.Body)
	if e != nil {
		return nil, e
	}
	return api.ExchangeServerAccessEditor200JSONResponse(out), nil
}
func (s apiServer) ConnectServerAccessEditor(context.Context, api.ConnectServerAccessEditorRequestObject) (api.ConnectServerAccessEditorResponseObject, error) {
	return nil, apierr.BadRequest("websocket_required", "Use the editor websocket endpoint")
}
func (s apiServer) editorWebsocket(w http.ResponseWriter, r *http.Request) {
	id, e := uuid.Parse(chi.URLParam(r, "sessionId"))
	if e != nil {
		apierr.Write(w, r, apierr.BadRequest("invalid_session", "Invalid session"))
		return
	}
	if s.serverAccess == nil {
		apierr.Write(w, r, apierr.Forbidden("server_access_disabled", "Server access disabled"))
		return
	}
	secure, _ := requestHTTPS(r.Context())
	if e = s.serverAccess.Editor(w, r, id, secure); e != nil {
		apierr.Write(w, r, e)
	}
}
