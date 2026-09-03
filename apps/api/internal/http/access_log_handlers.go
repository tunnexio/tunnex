package http

import (
	"context"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/tunnexio/tunnex/apps/api/internal/accesslog"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type accessEventIdentityKind uint8

const (
	accessEventIdentityAgent accessEventIdentityKind = iota + 1
	accessEventIdentityDevice
	accessEventIdentityUser
)

// accessEventIdentityFilter is deliberately discriminated instead of carrying
// three nullable IDs. Once the handler validates the public parameters, the
// store cannot accidentally combine or choose precedence between identities.
type accessEventIdentityFilter struct {
	Kind accessEventIdentityKind
	ID   uuid.UUID
}

// accessLogPort is the S7.5.1 Zero Trust access/flow-log query surface. nil in the open
// build → the endpoints return 403 edition_required (the established precedent). The query
// itself is DB-neutral; the gate is the product boundary (visibility = enterprise).
type accessLogPort interface {
	List(ctx context.Context, orgID uuid.UUID, identity *accessEventIdentityFilter, deniesOnly bool, cursorTS time.Time, cursorID uuid.UUID, limit int32) ([]accesslog.Event, error)
	Health() accesslog.Snapshot
	Collectors(ctx context.Context, orgID uuid.UUID) ([]accessLogCollectorStatus, error)
}

type accessLogCollectorStatus struct {
	NodeID          uuid.UUID
	Name            string
	State           string
	LastReportedAt  *time.Time
	LastObservedAt  *time.Time
	LastDeliveredAt *time.Time
	LastEventAt     *time.Time
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
	var identity *accessEventIdentityFilter
	identityCount := 0
	if req.Params.SrcAgentId != nil {
		identityCount++
		identity = &accessEventIdentityFilter{Kind: accessEventIdentityAgent, ID: uuid.UUID(*req.Params.SrcAgentId)}
	}
	if req.Params.SrcDeviceId != nil {
		identityCount++
		identity = &accessEventIdentityFilter{Kind: accessEventIdentityDevice, ID: uuid.UUID(*req.Params.SrcDeviceId)}
	}
	if req.Params.SrcUserId != nil {
		identityCount++
		identity = &accessEventIdentityFilter{Kind: accessEventIdentityUser, ID: uuid.UUID(*req.Params.SrcUserId)}
	}
	if identityCount > 1 {
		return nil, apierr.BadRequest("invalid_access_event_identity_filter", "provide at most one of src_agent_id, src_device_id, or src_user_id")
	}
	events, err := s.accessLog.List(ctx, req.OrgId, identity, deniesOnly, cursorTS, cursorID, limit)
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
	// Prefer the tenant-scoped durable run over the legacy process-local
	// snapshot. This prevents one organization's sweep result from appearing in
	// another organization's health response and survives API restarts.
	if s.accessEventRetention != nil {
		latest, latestErr := s.accessEventRetention.GetLatestRun(ctx, req.OrgId)
		if latestErr != nil {
			return nil, latestErr
		}
		snap.RetentionDropped = 0
		snap.RetentionFailed = false
		snap.RetentionLastSweep = time.Time{}
		if latest != nil {
			snap.RetentionDropped = latest.DeletedRows
			snap.RetentionFailed = latest.Status == accesslog.RetentionRunFailed
			if latest.CompletedAt != nil {
				snap.RetentionLastSweep = *latest.CompletedAt
			}
		}
	}
	collectors, err := s.accessLog.Collectors(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	body := api.AccessLogHealth{
		RetentionDropped:  snap.RetentionDropped,
		RetentionFailed:   snap.RetentionFailed,
		GatewayCollectors: make([]api.AccessEventCollectorStatus, len(collectors)),
	}
	for idx, collector := range collectors {
		body.GatewayCollectors[idx] = api.AccessEventCollectorStatus{
			NodeId:          collector.NodeID,
			Name:            collector.Name,
			State:           api.AccessEventCollectorStatusState(collector.State),
			LastReportedAt:  collector.LastReportedAt,
			LastObservedAt:  collector.LastObservedAt,
			LastDeliveredAt: collector.LastDeliveredAt,
			LastEventAt:     collector.LastEventAt,
		}
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
		Id:            e.ID,
		CreatedAt:     e.CreatedAt,
		Seq:           e.Seq,
		OccurredAt:    e.OccurredAt,
		Decision:      api.AccessEventDecision(e.Decision),
		SrcIp:         e.SrcIP,
		DstIp:         e.DstIP,
		Protocol:      e.Protocol,
		RuleId:        optUUID(e.RuleID),
		NodeId:        optUUID(e.NodeID),
		SrcDeviceId:   optUUID(e.SrcDeviceID),
		SrcUserId:     optUUID(e.SrcUserID),
		DstResourceId: optUUID(e.DstResourceID),
		DstGroupId:    optUUID(e.DstGroupID),
	}
	if e.SrcKind == "human" || e.SrcKind == "agent" {
		kind := api.AccessEventSrcKind(e.SrcKind)
		out.SrcKind = &kind
	}
	if e.SrcKind == "agent" {
		out.SrcAgentId = optUUID(e.SrcDeviceID)
	}
	if e.PolicyHash != "" {
		out.PolicyHash = &e.PolicyHash
	}
	if e.PolicyVersion > 0 {
		out.PolicyVersion = &e.PolicyVersion
	}
	out.SrcConfigRevision = e.SrcConfigRevision
	if e.DecisionReason != "" {
		r := api.AccessEventDecisionReason(e.DecisionReason)
		out.DecisionReason = &r
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
