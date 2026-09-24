package http

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type ipsecConnectionRepository interface {
	ListPage(context.Context, uuid.UUID, *uuid.UUID, int) (ipsec.ConnectionPage, error)
	Read(context.Context, uuid.UUID, uuid.UUID) (ipsec.Connection, error)
	Delete(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, int64) (ipsec.Connection, error)
}

func (s apiServer) ListIPsecConnections(ctx context.Context, req api.ListIPsecConnectionsRequestObject) (api.ListIPsecConnectionsResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermOrgView)
	if err != nil {
		return nil, err
	}
	limit := 50
	if req.Params.Limit != nil {
		limit = *req.Params.Limit
	}
	if limit < 1 || limit > 100 {
		return nil, ipsecConnectionError(ipsec.ErrConnectionInvalid)
	}
	if s.ipsecConnections == nil {
		return nil, ipsecConnectionError(ipsec.ErrConnectionUnavailable)
	}
	page, err := s.ipsecConnections.ListPage(ctx, req.OrgId, req.Params.After, limit)
	if err != nil {
		return nil, ipsecConnectionError(err)
	}
	items := make([]api.IPsecConnection, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, publicIPsecConnection(item))
	}
	return api.ListIPsecConnections200JSONResponse{Body: api.IPsecConnectionPage{Items: items, NextCursor: page.NextCursor}, Headers: api.ListIPsecConnections200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}
func (s apiServer) GetIPsecConnection(ctx context.Context, req api.GetIPsecConnectionRequestObject) (api.GetIPsecConnectionResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermOrgView)
	if err != nil {
		return nil, err
	}
	if s.ipsecConnections == nil {
		return nil, ipsecConnectionError(ipsec.ErrConnectionUnavailable)
	}
	record, err := s.ipsecConnections.Read(ctx, req.OrgId, req.ConnectionId)
	if err != nil {
		return nil, ipsecConnectionError(err)
	}
	return api.GetIPsecConnection200JSONResponse{Body: publicIPsecConnection(record), Headers: api.GetIPsecConnection200ResponseHeaders{XRequestId: reqID(ctx), ETag: connectionETag(record.DesiredRevision)}}, nil
}
func (s apiServer) DeleteIPsecConnection(ctx context.Context, req api.DeleteIPsecConnectionRequestObject) (api.DeleteIPsecConnectionResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermIPsecManage)
	if err != nil {
		return nil, err
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if p.UserID == uuid.Nil || p.IsMachine() {
		return nil, apierr.Forbidden("forbidden", "a verified user is required to manage IPsec")
	}
	revision, ok := connectionRevision(req.Params.IfMatch)
	if !ok {
		return nil, ipsecConnectionError(ipsec.ErrConnectionInvalid)
	}
	if s.ipsecConnections == nil {
		return nil, ipsecConnectionError(ipsec.ErrConnectionUnavailable)
	}
	record, err := s.ipsecConnections.Delete(ctx, req.OrgId, p.UserID, req.ConnectionId, revision)
	if err != nil {
		return nil, ipsecConnectionError(err)
	}
	return api.DeleteIPsecConnection200JSONResponse{Body: publicIPsecConnection(record), Headers: api.DeleteIPsecConnection200ResponseHeaders{XRequestId: reqID(ctx), ETag: connectionETag(record.DesiredRevision)}}, nil
}
func publicIPsecConnection(c ipsec.Connection) api.IPsecConnection {
	return api.IPsecConnection{ApplicationState: api.IPsecConnectionApplicationState(c.ApplicationState), CleanupState: api.IPsecConnectionCleanupState(c.CleanupState), Id: c.ID, OrgId: c.OrgID, Name: c.Name, SiteId: c.SiteID, GatewayNodeId: c.GatewayNodeID, HistoricalSiteId: c.HistoricalSiteID, HistoricalGatewayNodeId: c.HistoricalGatewayNodeID, DesiredRevision: c.DesiredRevision, DesiredIntent: api.IPsecConnectionDesiredIntent(c.DesiredIntent), DeletedAt: c.DeletedAt, FinalizedAt: c.FinalizedAt, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}
}
func connectionETag(revision int64) string { return `"` + strconv.FormatInt(revision, 10) + `"` }
func connectionRevision(value string) (int64, bool) {
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
		return 0, false
	}
	raw := value[1 : len(value)-1]
	if raw[0] < '1' || raw[0] > '9' {
		return 0, false
	}
	for _, c := range raw {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	revision, err := strconv.ParseInt(raw, 10, 64)
	return revision, err == nil && revision > 0
}
func ipsecConnectionError(err error) error {
	switch {
	case errors.Is(err, ipsec.ErrConnectionInvalid):
		return apierr.BadRequest("invalid_ipsec_connection", "invalid IPsec connection request")
	case errors.Is(err, ipsec.ErrConnectionNotFound):
		return apierr.NotFound("ipsec_connection_not_found", "IPsec connection not found")
	case errors.Is(err, ipsec.ErrConnectionConflict):
		return apierr.Conflict("ipsec_connection_conflict", "IPsec connection changed; refresh before retrying")
	default:
		return apierr.New(http.StatusInternalServerError, "ipsec_connection_unavailable", "IPsec connection is unavailable")
	}
}
func isIPsecConnectionRequest(r *http.Request) bool {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	return (len(parts) == 6 || len(parts) == 7 || (len(parts) == 8 && parts[7] == "status" && r.Method == http.MethodGet)) && parts[0] == "api" && parts[1] == "v1" && parts[2] == "organizations" && parts[4] == "ipsec" && parts[5] == "connections" && (r.Method == http.MethodGet || (len(parts) == 7 && r.Method == http.MethodDelete))
}
func validateIPsecConnectionHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isIPsecConnectionRequest(r) {
			w.Header().Set("Cache-Control", "no-store")
			parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
			org, err := uuid.Parse(parts[3])
			if err != nil {
				apierr.Write(w, r, ipsecConnectionError(ipsec.ErrConnectionInvalid))
				return
			}
			permission := rbac.PermOrgView
			if r.Method == http.MethodDelete {
				permission = rbac.PermIPsecManage
			}
			ctx, err := authorize(r.Context(), org, permission)
			if err != nil {
				apierr.Write(w, r, err)
				return
			}
			r = r.WithContext(ctx)
			if r.Method == http.MethodDelete {
				p, _ := authctx.PrincipalFrom(ctx)
				if p.UserID == uuid.Nil || p.IsMachine() {
					apierr.Write(w, r, apierr.Forbidden("forbidden", "a verified user is required to manage IPsec"))
					return
				}
			}
		}
		if isIPsecConnectionRequest(r) && r.Method == http.MethodDelete {
			values := r.Header.Values("If-Match")
			if len(values) != 1 {
				apierr.Write(w, r, ipsecConnectionError(ipsec.ErrConnectionInvalid))
				return
			}
			if _, ok := connectionRevision(values[0]); !ok {
				apierr.Write(w, r, ipsecConnectionError(ipsec.ErrConnectionInvalid))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
