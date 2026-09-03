package http

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/accesslog"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// accessEventRetentionPort is kept separate from the read-only access-event
// query port so policy mutation, pruning and scheduler composition have one
// deliberately narrow seam.
type accessEventRetentionPort interface {
	GetOverview(ctx context.Context, orgID uuid.UUID) (accesslog.RetentionOverview, error)
	SetSettings(ctx context.Context, orgID, actorUserID uuid.UUID, in accesslog.RetentionSettingsInput) (accesslog.RetentionSettings, error)
	GetLatestRun(ctx context.Context, orgID uuid.UUID) (*accesslog.RetentionRun, error)
	RunManual(ctx context.Context, orgID, actorUserID uuid.UUID, idempotencyKey string) (accesslog.RetentionRun, bool, error)
}

// GetAccessEventRetention implements GET /organizations/{orgId}/access-event-retention.
func (s apiServer) GetAccessEventRetention(ctx context.Context, req api.GetAccessEventRetentionRequestObject) (api.GetAccessEventRetentionResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyView); err != nil {
		return nil, err
	}
	if s.accessEventRetention == nil {
		return nil, editionRequired()
	}
	overview, err := s.accessEventRetention.GetOverview(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	return api.GetAccessEventRetention200JSONResponse{
		Body:    toAPIAccessEventRetention(overview),
		Headers: api.GetAccessEventRetention200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// UpdateAccessEventRetention implements PUT /organizations/{orgId}/access-event-retention.
// The dedicated manage permission is owner/admin-only; operators and ordinary
// members cannot shorten an audit trail or alter the pruning cadence.
func (s apiServer) UpdateAccessEventRetention(ctx context.Context, req api.UpdateAccessEventRetentionRequestObject) (api.UpdateAccessEventRetentionResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAccessEventRetentionManage); err != nil {
		return nil, err
	}
	if s.accessEventRetention == nil {
		return nil, editionRequired()
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	// Generated API integers use the platform int width. Check before narrowing
	// to the storage/service int32 types so a value such as 2^32+1 cannot wrap
	// into a valid one-day policy.
	if req.Body.RetentionDays < int(accesslog.MinRetentionDays) || req.Body.RetentionDays > int(accesslog.MaxRetentionDays) {
		return nil, apierr.BadRequest("invalid_access_event_retention_days", "retention_days must be between 1 and 3650")
	}
	if req.Body.CleanupIntervalMinutes < int(accesslog.MinCleanupIntervalMinutes) || req.Body.CleanupIntervalMinutes > int(accesslog.MaxCleanupIntervalMinutes) {
		return nil, apierr.BadRequest("invalid_access_event_cleanup_interval", "cleanup_interval_minutes must be between 5 and 1440")
	}
	p, ok := authctx.PrincipalFrom(ctx)
	if !ok || p == nil {
		return nil, apierr.New(http.StatusUnauthorized, "unauthenticated", "authentication required")
	}
	if _, err := s.accessEventRetention.SetSettings(ctx, req.OrgId, p.UserID, accesslog.RetentionSettingsInput{
		RetentionDays:          int32(req.Body.RetentionDays),
		CleanupIntervalMinutes: int32(req.Body.CleanupIntervalMinutes),
		ExpectedRevision:       req.Body.ExpectedRevision,
	}); err != nil {
		return nil, err
	}
	overview, err := s.accessEventRetention.GetOverview(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	return api.UpdateAccessEventRetention200JSONResponse{
		Body:    toAPIAccessEventRetention(overview),
		Headers: api.UpdateAccessEventRetention200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// RunAccessEventPrune implements POST
// /organizations/{orgId}/access-event-retention/actions/prune. A manual run
// always uses the persisted policy: callers cannot smuggle in a cutoff or cap.
func (s apiServer) RunAccessEventPrune(ctx context.Context, req api.RunAccessEventPruneRequestObject) (api.RunAccessEventPruneResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAccessEventRetentionManage); err != nil {
		return nil, err
	}
	if s.accessEventRetention == nil {
		return nil, editionRequired()
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	p, ok := authctx.PrincipalFrom(ctx)
	if !ok || p == nil {
		return nil, apierr.New(http.StatusUnauthorized, "unauthenticated", "authentication required")
	}
	run, claimed, err := s.accessEventRetention.RunManual(ctx, req.OrgId, p.UserID, req.Body.IdempotencyKey)
	if err != nil {
		// A claimed run that failed has already been durably finalized with a
		// bounded error code. Return that truthful outcome; a pre-claim failure
		// still follows the standard API error seam.
		if run.ID == uuid.Nil || run.Status != accesslog.RetentionRunFailed {
			return nil, err
		}
		slog.ErrorContext(ctx, "access_event_prune_failed",
			"org_id", req.OrgId.String(), "run_id", run.ID.String(), "cause", boundedQuotedError(err))
	}
	overview, overviewErr := s.accessEventRetention.GetOverview(ctx, req.OrgId)
	if overviewErr != nil {
		return nil, overviewErr
	}
	return api.RunAccessEventPrune200JSONResponse{
		Body: api.AccessEventPruneResponse{
			Retention: toAPIAccessEventRetention(overview),
			Run:       toAPIAccessEventRetentionRun(run),
			Replayed:  !claimed,
		},
		Headers: api.RunAccessEventPrune200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

func boundedQuotedError(err error) string {
	if err == nil {
		return ""
	}
	out := strconv.QuoteToASCII(err.Error())
	if len(out) > 2048 {
		out = out[:2048]
	}
	return out
}

func toAPIAccessEventRetention(overview accesslog.RetentionOverview) api.AccessEventRetention {
	out := api.AccessEventRetention{
		RetentionDays:          int(overview.Settings.RetentionDays),
		CleanupIntervalMinutes: int(overview.Settings.CleanupIntervalMinutes),
		RowCap:                 int(accesslog.DefaultPGRowCap),
		Revision:               overview.Settings.Revision,
		UpdatedAt:              overview.Settings.UpdatedAt,
		NextRunAt:              overview.NextRunAt,
	}
	if overview.LastRun != nil {
		run := toAPIAccessEventRetentionRun(*overview.LastRun)
		out.LastRun = &run
	}
	return out
}

func toAPIAccessEventRetentionRun(run accesslog.RetentionRun) api.AccessEventRetentionRun {
	return api.AccessEventRetentionRun{
		Id:          run.ID,
		Trigger:     api.AccessEventRetentionRunTrigger(run.TriggerKind),
		Status:      api.AccessEventRetentionRunStatus(run.Status),
		StartedAt:   run.StartedAt,
		CompletedAt: run.CompletedAt,
		DeletedRows: run.DeletedRows,
		Batches:     int(run.Batches),
		MorePending: run.MorePending,
		ErrorCode:   run.ErrorCode,
	}
}
