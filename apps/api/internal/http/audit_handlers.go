package http

import (
	"context"
	"encoding/json"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
)

const (
	auditDefaultLimit = 50
	auditMaxLimit     = 100
)

func auditActorScope(p *authctx.Principal, orgID uuid.UUID) *uuid.UUID {
	if p == nil {
		return nil
	}
	if role, _ := p.RoleIn(orgID); role == rbac.RoleMember {
		actor := p.UserID
		return &actor
	}
	return nil
}

// ListAuditLogs GET /api/v1/organizations/{orgId}/audit-logs — the org's audit
// feed, filterable + keyset-paginated. READ-ONLY: audit rows are append-only (DB
// triggers reject UPDATE/DELETE) and there is deliberately no mutation endpoint.
// Gated on PermOrgView — the same read the dashboard's activity slice uses; every
// read is org-scoped (query-lint), so the actor filter can't probe other orgs.
func (s apiServer) ListAuditLogs(ctx context.Context, req api.ListAuditLogsRequestObject) (api.ListAuditLogsResponseObject, error) {
	authorized, err := authorize(ctx, req.OrgId, rbac.PermOrgView)
	if err != nil {
		return nil, err
	}
	principal, _ := authctx.PrincipalFrom(authorized)
	p := req.Params
	f := tenancy.AuditFilter{Limit: auditDefaultLimit, Action: p.Action, From: p.From, To: p.To, CursorTS: p.CursorTs}
	if p.Limit != nil {
		lim := *p.Limit
		if lim < 1 {
			lim = 1
		}
		if lim > auditMaxLimit {
			lim = auditMaxLimit
		}
		f.Limit = int32(lim)
	}
	if p.Actor != nil {
		a := uuid.UUID(*p.Actor)
		f.Actor = &a
	}
	// Members retain the audit surface, but it is a self-activity view. Force the
	// actor predicate server-side so filters and cursors can never probe another
	// user's rows or infer their count.
	if scoped := auditActorScope(principal, req.OrgId); scoped != nil {
		f.Actor = scoped
	}
	// A keyset cursor is both halves or neither — a half-cursor is a client bug
	// that would otherwise SILENTLY reset to page 1 (and the row-value comparison
	// against a NULL id would drop rows at the cursor timestamp). Reject it.
	if (p.CursorTs == nil) != (p.CursorId == nil) {
		return nil, apierr.BadRequest("invalid_cursor", "cursor_ts and cursor_id must be provided together")
	}
	if p.CursorId != nil {
		c := uuid.UUID(*p.CursorId)
		f.CursorID = &c
	}
	rows, err := s.orgs.ListAuditLogs(ctx, req.OrgId, f)
	if err != nil {
		return nil, err
	}
	out := make([]api.AuditLogEntry, 0, len(rows))
	for _, r := range rows {
		out = append(out, toAuditLogEntry(r))
	}
	return api.ListAuditLogs200JSONResponse{
		Body:    out,
		Headers: api.ListAuditLogs200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

func toAuditLogEntry(a sqlc.AuditLog) api.AuditLogEntry {
	e := api.AuditLogEntry{
		Id:         a.ID,
		CreatedAt:  a.CreatedAt,
		Action:     a.Action,
		TargetType: a.TargetType,
		TargetId:   a.TargetID,
		Details:    map[string]any{},
	}
	if a.ActorUserID.Valid {
		id := openapi_types.UUID(uuid.UUID(a.ActorUserID.Bytes))
		e.ActorId = &id
	}
	// A system/service-initiated event names its actor here (e.g. "idp-sync") instead of an
	// actor_id — so a compliance reader can attribute the action (S7.5.2).
	if a.ActorSystem != nil {
		e.ActorSystem = a.ActorSystem
	}
	// details is the event metadata — secret-free by construction (the write side
	// never puts secret material in it). Rendered as-is; malformed JSON degrades
	// to an empty object rather than failing the whole page.
	if len(a.Metadata) > 0 {
		_ = json.Unmarshal(a.Metadata, &e.Details)
	}
	return e
}
