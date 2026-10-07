package http

import (
	"context"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/beam"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type beamAccessEventPort interface {
	AccessEvents(context.Context, uuid.UUID, beam.Actor, *uuid.UUID, *uuid.UUID, bool, time.Time, uuid.UUID, int) ([]beam.AccessEvent, error)
}

func (s apiServer) listBeamAccessEvents(ctx context.Context, req api.ListAccessEventsRequestObject) (api.ListAccessEventsResponseObject, error) {
	ctx, e := authorize(ctx, req.OrgId, rbac.PermBeamAuditView)
	if e != nil {
		return nil, e
	}
	p, ok := authctx.PrincipalFrom(ctx)
	if !ok || p.UserID == uuid.Nil || p.IsMachine() || p.IsAgent() || p.SessionID == "" || p.AuthMethod == authctx.AuthBearer {
		return nil, apierr.Forbidden("human_browser_session_required", "Beam access evidence requires a current human browser session")
	}
	if s.beam == nil {
		return nil, apierr.New(503, "beam_unavailable", "Beam service unavailable")
	}
	count := 0
	for _, id := range []*uuid.UUID{req.Params.SrcAgentId, req.Params.SrcDeviceId, req.Params.SrcUserId} {
		if id != nil {
			count++
		}
	}
	if count > 1 {
		return nil, apierr.BadRequest("invalid_access_event_identity_filter", "provide at most one of src_agent_id, src_device_id, or src_user_id")
	}
	limit := 100
	if req.Params.Limit != nil {
		limit = *req.Params.Limit
	}
	if limit < 1 || limit > 200 {
		return nil, apierr.BadRequest("invalid_pagination", "Invalid access-event page limit")
	}
	out := []api.AccessEvent{}
	// Beam records authenticated reviewer IDs, never a gateway/device source.
	if req.Params.SrcAgentId == nil && req.Params.SrcDeviceId == nil {
		before, beforeID := time.Now().Add(24*time.Hour), maxUUID
		if req.Params.CursorTs != nil {
			before = *req.Params.CursorTs
		}
		if req.Params.CursorId != nil {
			beforeID = *req.Params.CursorId
		}
		denies := req.Params.DeniesOnly != nil && *req.Params.DeniesOnly
		rows, err := s.beam.AccessEvents(ctx, req.OrgId, beam.Actor{ID: p.UserID, SessionID: p.SessionID}, req.Params.SrcUserId, req.Params.ShareId, denies, before, beforeID, limit)
		if err != nil {
			return nil, err
		}
		for _, v := range rows {
			decision := api.Allow
			if v.Action == "beam.access.denied" {
				decision = api.Deny
			}
			out = append(out, api.AccessEvent{Id: v.ID, CreatedAt: v.CreatedAt, OccurredAt: v.CreatedAt, Decision: decision, SrcUserId: v.UserID, Beam: &api.BeamAccessEvidence{ShareId: v.ShareID, Action: api.BeamAccessEvidenceAction(v.Action), Reason: v.Reason}})
		}
	}
	return api.ListAccessEvents200JSONResponse{Body: out, Headers: api.ListAccessEvents200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}
