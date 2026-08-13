package http

import (
	"context"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// GetOrgOverview GET /api/v1/organizations/{orgId}/overview — the dashboard home
// aggregate: counts + a recent-activity slice from the audit log.
func (s apiServer) GetOrgOverview(ctx context.Context, req api.GetOrgOverviewRequestObject) (api.GetOrgOverviewResponseObject, error) {
	authorized, err := authorize(ctx, req.OrgId, rbac.PermOrgView)
	if err != nil {
		return nil, err
	}
	var activityActor *uuid.UUID
	if p, ok := authctx.PrincipalFrom(authorized); ok {
		activityActor = auditActorScope(p, req.OrgId)
	}
	o, err := s.orgs.Overview(ctx, req.OrgId, activityActor)
	if err != nil {
		return nil, err
	}
	activity := make([]api.ActivityEntry, 0, len(o.RecentActivity))
	for _, a := range o.RecentActivity {
		activity = append(activity, toActivityEntry(a))
	}
	return api.GetOrgOverview200JSONResponse{
		Body: api.OrgOverview{
			Members:        int(o.Members),
			Devices:        int(o.Devices),
			Nodes:          int(o.Nodes),
			Online:         int(o.Online),
			RecentActivity: activity,
		},
		Headers: api.GetOrgOverview200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

func toActivityEntry(a sqlc.AuditLog) api.ActivityEntry {
	e := api.ActivityEntry{Action: a.Action, CreatedAt: a.CreatedAt, TargetType: a.TargetType, TargetId: a.TargetID}
	if a.ActorUserID.Valid {
		id := openapi_types.UUID(uuid.UUID(a.ActorUserID.Bytes))
		e.ActorId = &id
	}
	// The NAMED system actor. Without it the feed cannot tell a machine-initiated event from an
	// unattributed one — `actor_id` is absent in both cases, so both rendered the same way.
	if a.ActorSystem != nil && *a.ActorSystem != "" {
		e.ActorSystem = a.ActorSystem
	}
	return e
}
