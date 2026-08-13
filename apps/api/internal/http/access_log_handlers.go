package http

import (
	"context"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/tunnexio/tunnex/apps/api/internal/accesslog"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// accessLogPort is the S7.5.1 Zero Trust access/flow-log query surface. nil in the open
// build → the endpoints return 403 edition_required (the established precedent). The query
// itself is DB-neutral; the gate is the product boundary (visibility = enterprise).
type accessLogPort interface {
	List(ctx context.Context, orgID uuid.UUID, deniesOnly bool, cursorTS time.Time, cursorID uuid.UUID, limit int32) ([]accesslog.Event, error)
	Health() accesslog.Snapshot
}

// maxUUID is the keyset first-page id sentinel (everything sorts < it at equal created_at).
var maxUUID = uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff")

// ListAccessEvents implements GET /organizations/{orgId}/access-events. authorize() first
// (keeps the 401-walk honest), then the edition gate, then a keyset page.
func (s apiServer) ListAccessEvents(ctx context.Context, req api.ListAccessEventsRequestObject) (api.ListAccessEventsResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyView); err != nil {
		return nil, err
	}
	if s.accessLog == nil {
		return nil, editionRequired()
	}
	deniesOnly := req.Params.DeniesOnly != nil && *req.Params.DeniesOnly
	cursorTS := time.Now().Add(24 * time.Hour) // first page: a far-future cursor
	if req.Params.CursorTs != nil {
		cursorTS = *req.Params.CursorTs
	}
	cursorID := maxUUID
	if req.Params.CursorId != nil {
		cursorID = *req.Params.CursorId
	}
	limit := int32(100)
	if req.Params.Limit != nil {
		limit = int32(*req.Params.Limit)
	}
	events, err := s.accessLog.List(ctx, req.OrgId, deniesOnly, cursorTS, cursorID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]api.AccessEvent, len(events))
	for i, e := range events {
		out[i] = toAPIAccessEvent(e)
	}
	return api.ListAccessEvents200JSONResponse{
		Body:    out,
		Headers: api.ListAccessEvents200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// GetAccessLogHealth implements GET /organizations/{orgId}/access-log/health.
func (s apiServer) GetAccessLogHealth(ctx context.Context, req api.GetAccessLogHealthRequestObject) (api.GetAccessLogHealthResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyView); err != nil {
		return nil, err
	}
	if s.accessLog == nil {
		return nil, editionRequired()
	}
	snap := s.accessLog.Health()
	body := api.AccessLogHealth{
		RetentionDropped: snap.RetentionDropped,
		RetentionFailed:  snap.RetentionFailed,
	}
	if !snap.RetentionLastSweep.IsZero() {
		t := snap.RetentionLastSweep
		body.RetentionLastSweep = &t
	}
	return api.GetAccessLogHealth200JSONResponse{
		Body:    body,
		Headers: api.GetAccessLogHealth200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

func toAPIAccessEvent(e accesslog.Event) api.AccessEvent {
	out := api.AccessEvent{
		Id:         e.ID,
		CreatedAt:  e.CreatedAt,
		Seq:        e.Seq,
		OccurredAt: e.OccurredAt,
		Decision:   api.AccessEventDecision(e.Decision),
		SrcIp:      e.SrcIP,
		DstIp:      e.DstIP,
		Protocol:   e.Protocol,
		RuleId:     optUUID(e.RuleID),
		NodeId:     optUUID(e.NodeID),
		// GRANT-level attribution only; device/user are deferred (never set from src_ip).
		DstResourceId: optUUID(e.DstResourceID),
		DstGroupId:    optUUID(e.DstGroupID),
	}
	if e.DstPort != 0 {
		p := e.DstPort
		out.DstPort = &p
	}
	if e.DenyCount > 1 { // meaningful only for aggregate / gap
		c := e.DenyCount
		out.DenyCount = &c
	}
	if e.WindowEnd != nil {
		out.WindowEnd = e.WindowEnd
	}
	return out
}

func optUUID(p *uuid.UUID) *openapi_types.UUID {
	if p == nil {
		return nil
	}
	u := openapi_types.UUID(*p)
	return &u
}
