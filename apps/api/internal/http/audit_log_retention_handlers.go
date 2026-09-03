package http

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/auditretention"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type auditLogRetentionPort interface {
	GetOverview(ctx context.Context, orgID uuid.UUID) (auditretention.Overview, error)
	SetSettings(ctx context.Context, orgID, actorUserID uuid.UUID, in auditretention.SettingsInput) (auditretention.Settings, error)
	RunManual(ctx context.Context, orgID, actorUserID uuid.UUID, idempotencyKey string) (auditretention.Run, bool, error)
}

func (s apiServer) GetAuditLogRetention(ctx context.Context, req api.GetAuditLogRetentionRequestObject) (api.GetAuditLogRetentionResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAuditLogRetentionView); err != nil {
		return nil, err
	}
	if s.auditLogRetention == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "audit_log_retention_unavailable", "audit-log retention is unavailable")
	}
	overview, err := s.auditLogRetention.GetOverview(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	return api.GetAuditLogRetention200JSONResponse{
		Body:    toAPIAuditLogRetention(overview),
		Headers: api.GetAuditLogRetention200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

func (s apiServer) UpdateAuditLogRetention(ctx context.Context, req api.UpdateAuditLogRetentionRequestObject) (api.UpdateAuditLogRetentionResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAuditLogRetentionManage); err != nil {
		return nil, err
	}
	if s.auditLogRetention == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "audit_log_retention_unavailable", "audit-log retention is unavailable")
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	if req.Body.RetentionDays != nil &&
		(*req.Body.RetentionDays < int(auditretention.MinRetentionDays) ||
			*req.Body.RetentionDays > int(auditretention.MaxRetentionDays)) {
		return nil, apierr.BadRequest("invalid_audit_log_retention_days", "retention_days must be null or between 1 and 3650")
	}
	if req.Body.CleanupIntervalMinutes < int(auditretention.MinCleanupIntervalMinutes) ||
		req.Body.CleanupIntervalMinutes > int(auditretention.MaxCleanupIntervalMinutes) {
		return nil, apierr.BadRequest("invalid_audit_log_cleanup_interval", "cleanup_interval_minutes must be between 5 and 1440")
	}
	principal, ok := authctx.PrincipalFrom(ctx)
	if !ok || principal == nil {
		return nil, apierr.New(http.StatusUnauthorized, "unauthenticated", "authentication required")
	}
	var retentionDays *int32
	if req.Body.RetentionDays != nil {
		value := int32(*req.Body.RetentionDays)
		retentionDays = &value
	}
	if _, err := s.auditLogRetention.SetSettings(ctx, req.OrgId, principal.UserID, auditretention.SettingsInput{
		RetentionDays: retentionDays, CleanupIntervalMinutes: int32(req.Body.CleanupIntervalMinutes),
		ExpectedRevision: req.Body.ExpectedRevision,
	}); err != nil {
		return nil, err
	}
	overview, err := s.auditLogRetention.GetOverview(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	return api.UpdateAuditLogRetention200JSONResponse{
		Body:    toAPIAuditLogRetention(overview),
		Headers: api.UpdateAuditLogRetention200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

func (s apiServer) RunAuditLogPrune(ctx context.Context, req api.RunAuditLogPruneRequestObject) (api.RunAuditLogPruneResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAuditLogRetentionManage); err != nil {
		return nil, err
	}
	if s.auditLogRetention == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "audit_log_retention_unavailable", "audit-log retention is unavailable")
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	principal, ok := authctx.PrincipalFrom(ctx)
	if !ok || principal == nil {
		return nil, apierr.New(http.StatusUnauthorized, "unauthenticated", "authentication required")
	}
	run, claimed, err := s.auditLogRetention.RunManual(ctx, req.OrgId, principal.UserID, req.Body.IdempotencyKey)
	if err != nil {
		if run.ID == uuid.Nil || run.Status != auditretention.RetentionRunFailed {
			return nil, err
		}
		slog.ErrorContext(ctx, "audit_log_prune_failed",
			"org_id", req.OrgId.String(), "run_id", run.ID.String(), "cause", boundedQuotedError(err))
	}
	overview, overviewErr := s.auditLogRetention.GetOverview(ctx, req.OrgId)
	if overviewErr != nil {
		return nil, overviewErr
	}
	return api.RunAuditLogPrune200JSONResponse{
		Body: api.AuditLogPruneResponse{
			Retention: toAPIAuditLogRetention(overview),
			Run:       toAPIAuditLogRetentionRun(run),
			Replayed:  !claimed,
		},
		Headers: api.RunAuditLogPrune200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

func toAPIAuditLogRetention(overview auditretention.Overview) api.AuditLogRetention {
	var retentionDays *int
	if overview.Settings.RetentionDays != nil {
		value := int(*overview.Settings.RetentionDays)
		retentionDays = &value
	}
	out := api.AuditLogRetention{
		RetentionDays:          retentionDays,
		CleanupIntervalMinutes: int(overview.Settings.CleanupIntervalMinutes),
		BatchSize:              int(auditretention.RetentionBatchSize), Revision: overview.Settings.Revision,
		UpdatedAt: overview.Settings.UpdatedAt, NextRunAt: overview.NextRunAt,
	}
	if overview.LastRun != nil {
		run := toAPIAuditLogRetentionRun(*overview.LastRun)
		out.LastRun = &run
	}
	return out
}

func toAPIAuditLogRetentionRun(run auditretention.Run) api.AuditLogRetentionRun {
	return api.AuditLogRetentionRun{
		Id: run.ID, Trigger: api.AuditLogRetentionRunTrigger(run.TriggerKind),
		Status: api.AuditLogRetentionRunStatus(run.Status), StartedAt: run.StartedAt,
		CompletedAt: run.CompletedAt, DeletedRows: run.DeletedRows,
		Batches: int(run.Batches), MorePending: run.MorePending, ErrorCode: run.ErrorCode,
	}
}
