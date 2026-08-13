package http

import (
	"context"
	"errors"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// orphanCap bounds how many orphans the 409 body renders; orphan_count carries
// the honest total so the UI's "N devices must be removed" copy is truthful even
// when the list is truncated.
const orphanCap = 20

// ResizePool PUT /api/v1/organizations/{orgId}/pool-cidr. EDITION-NEUTRAL: the
// allocator is core/open (S3.5), so there is no edition gate here. authorize runs
// first (401 before any body check — keeps the spec 401-walk honest).
func (s apiServer) ResizePool(ctx context.Context, req api.ResizePoolRequestObject) (api.ResizePoolResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgUpdate); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	p, _ := authctx.PrincipalFrom(ctx) // non-nil after authorize
	// ResizePool returns the org row it committed IN-TX, so there's no post-commit
	// re-fetch that could 404 on a concurrent soft-delete of a resize that succeeded.
	org, err := s.devices.ResizePool(ctx, p.UserID, req.OrgId, req.Body.Cidr)

	// A shrink that would strand allocations is a structured 409 (not the generic
	// error envelope): the capped orphan list + the honest total count.
	var orph *devices.ShrinkOrphansError
	if errors.As(err, &orph) {
		return api.ResizePool409JSONResponse{
			Body:    toResizeConflict(orph.Orphans),
			Headers: api.ResizePool409ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
		}, nil
	}
	if err != nil {
		return nil, err // invalid_cidr / illegal_resize / cidr_too_small (400) via the default handler
	}

	// Success (incl. idempotent no-op): return the org with its current pool_cidr.
	return api.ResizePool200JSONResponse{
		Body:    toAPIOrg(org),
		Headers: api.ResizePool200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// toResizeConflict builds the 409 body: the orphan list capped at orphanCap
// (rendered slice), with OrphanCount carrying the HONEST total so the UI's
// "N devices must be removed" copy is truthful even when the list is truncated.
// The input is already ordered by assigned_ip (ipalloc.Orphans), so the cap takes
// the numerically-lowest orphanCap regardless of reason.
func toResizeConflict(orphans []devices.OrphanDevice) api.ResizeConflict {
	shown := orphans
	if len(shown) > orphanCap {
		shown = shown[:orphanCap]
	}
	out := make([]api.Orphan, len(shown))
	for i, o := range shown {
		out[i] = api.Orphan{
			DeviceId:   o.DeviceID,
			Name:       o.Name,
			AssignedIp: o.AssignedIP,
			Reason:     api.OrphanReason(o.Reason),
		}
	}
	return api.ResizeConflict{OrphanCount: len(orphans), Orphans: out}
}
