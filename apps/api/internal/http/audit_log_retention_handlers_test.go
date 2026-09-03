package http

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/auditretention"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type fakeAuditLogRetention struct {
	overview auditretention.Overview
	input    auditretention.SettingsInput
	actor    uuid.UUID
	key      string
	run      auditretention.Run
	claimed  bool
	runErr   error

	getCalls int
	setCalls int
	runCalls int
}

func (f *fakeAuditLogRetention) GetOverview(context.Context, uuid.UUID) (auditretention.Overview, error) {
	f.getCalls++
	return f.overview, nil
}

func (f *fakeAuditLogRetention) SetSettings(_ context.Context, orgID, actor uuid.UUID, input auditretention.SettingsInput) (auditretention.Settings, error) {
	f.setCalls++
	f.actor, f.input = actor, input
	f.overview.Settings = auditretention.Settings{
		OrgID: orgID, RetentionDays: input.RetentionDays,
		CleanupIntervalMinutes: input.CleanupIntervalMinutes,
		Revision:               input.ExpectedRevision + 1,
	}
	return f.overview.Settings, nil
}

func (f *fakeAuditLogRetention) RunManual(_ context.Context, _ uuid.UUID, actor uuid.UUID, key string) (auditretention.Run, bool, error) {
	f.runCalls++
	f.actor, f.key = actor, key
	return f.run, f.claimed, f.runErr
}

func TestAuditLogRetentionHandlersMapForeverPolicyAndVerifiedActor(t *testing.T) {
	orgID, actorID := uuid.New(), uuid.New()
	ctx := authctx.WithPrincipal(context.Background(), &authctx.Principal{
		UserID: actorID, EmailVerified: true,
		Roles: map[uuid.UUID]string{orgID: rbac.RoleAdmin},
	})
	port := &fakeAuditLogRetention{overview: auditretention.Overview{
		Settings: auditretention.Settings{
			OrgID: orgID, RetentionDays: nil,
			CleanupIntervalMinutes: auditretention.DefaultCleanupIntervalMinutes,
			Revision:               0,
		},
	}}
	server := apiServer{auditLogRetention: port}

	response, err := server.GetAuditLogRetention(ctx, api.GetAuditLogRetentionRequestObject{OrgId: orgID})
	if err != nil {
		t.Fatalf("get audit-log retention: %v", err)
	}
	got, ok := response.(api.GetAuditLogRetention200JSONResponse)
	if !ok {
		t.Fatalf("get response type = %T", response)
	}
	if got.Body.RetentionDays != nil || got.Body.CleanupIntervalMinutes != int(auditretention.DefaultCleanupIntervalMinutes) || got.Body.BatchSize != int(auditretention.RetentionBatchSize) || got.Body.Revision != 0 {
		t.Fatalf("Forever response = %+v", got.Body)
	}

	update, err := server.UpdateAuditLogRetention(ctx, api.UpdateAuditLogRetentionRequestObject{
		OrgId: orgID,
		Body: &api.UpdateAuditLogRetentionRequest{
			RetentionDays: nil, CleanupIntervalMinutes: 120, ExpectedRevision: 0,
		},
	})
	if err != nil {
		t.Fatalf("update audit-log retention: %v", err)
	}
	updated, ok := update.(api.UpdateAuditLogRetention200JSONResponse)
	if !ok || updated.Body.RetentionDays != nil || updated.Body.Revision != 1 {
		t.Fatalf("updated Forever response = %#v", update)
	}
	if port.setCalls != 1 || port.actor != actorID || port.input.RetentionDays != nil || port.input.CleanupIntervalMinutes != 120 || port.input.ExpectedRevision != 0 {
		t.Fatalf("settings call: calls=%d actor=%s input=%+v", port.setCalls, port.actor, port.input)
	}

	completedAt := time.Now().UTC()
	errorCode := "prune_failed"
	port.run = auditretention.Run{
		ID: uuid.New(), OrgID: orgID, TriggerKind: auditretention.RetentionTriggerManual,
		Status: auditretention.RetentionRunFailed, StartedAt: completedAt.Add(-time.Second),
		CompletedAt: &completedAt, DeletedRows: 7, Batches: 1, MorePending: true,
		ErrorCode: &errorCode,
	}
	port.claimed = true
	port.runErr = errors.New("database detail must not cross the API")
	port.overview.LastRun = &port.run
	prune, err := server.RunAuditLogPrune(ctx, api.RunAuditLogPruneRequestObject{
		OrgId: orgID, Body: &api.RunAuditLogPruneRequest{IdempotencyKey: "audit-prune-1"},
	})
	if err != nil {
		t.Fatalf("durably failed prune must return its safe result: %v", err)
	}
	pruned, ok := prune.(api.RunAuditLogPrune200JSONResponse)
	if !ok || pruned.Body.Replayed || pruned.Body.Run.Status != api.AuditLogRetentionRunStatusFailed || pruned.Body.Run.ErrorCode == nil || *pruned.Body.Run.ErrorCode != errorCode {
		t.Fatalf("prune response = %#v", prune)
	}
	if port.runCalls != 1 || port.actor != actorID || port.key != "audit-prune-1" {
		t.Fatalf("manual prune call: calls=%d actor=%s key=%q", port.runCalls, port.actor, port.key)
	}
}

func TestAuditLogRetentionHandlersRejectOverflowBeforeNarrowing(t *testing.T) {
	orgID := uuid.New()
	ctx := principalWithRole(orgID, rbac.RoleAdmin)
	port := &fakeAuditLogRetention{}
	server := apiServer{auditLogRetention: port}
	maxInt := int(^uint(0) >> 1)

	_, err := server.UpdateAuditLogRetention(ctx, api.UpdateAuditLogRetentionRequestObject{
		OrgId: orgID,
		Body: &api.UpdateAuditLogRetentionRequest{
			RetentionDays: &maxInt, CleanupIntervalMinutes: 60, ExpectedRevision: 0,
		},
	})
	if !hasCode(err, 400, "invalid_audit_log_retention_days") {
		t.Fatalf("retention_days overflow: want 400 before int32 narrowing, got %v", err)
	}

	validDays := 30
	_, err = server.UpdateAuditLogRetention(ctx, api.UpdateAuditLogRetentionRequestObject{
		OrgId: orgID,
		Body: &api.UpdateAuditLogRetentionRequest{
			RetentionDays: &validDays, CleanupIntervalMinutes: maxInt, ExpectedRevision: 0,
		},
	})
	if !hasCode(err, 400, "invalid_audit_log_cleanup_interval") {
		t.Fatalf("cleanup interval overflow: want 400 before int32 narrowing, got %v", err)
	}
	if port.setCalls != 0 {
		t.Fatalf("invalid oversized input reached service %d times", port.setCalls)
	}
}

func TestAuditLogRetentionSurfacesRequireDedicatedPermissions(t *testing.T) {
	orgID := uuid.New()
	port := &fakeAuditLogRetention{}
	server := apiServer{auditLogRetention: port}
	days := 30
	for _, role := range []string{rbac.RoleMember, rbac.RoleOperator, rbac.RoleAgent} {
		_, err := server.GetAuditLogRetention(principalWithRole(orgID, role), api.GetAuditLogRetentionRequestObject{OrgId: orgID})
		if !hasCode(err, 403, "forbidden") {
			t.Fatalf("%s get: want dedicated-permission 403, got %v", role, err)
		}
	}
	ctx := principalWithRole(orgID, rbac.RoleMember)

	_, err := server.UpdateAuditLogRetention(ctx, api.UpdateAuditLogRetentionRequestObject{
		OrgId: orgID,
		Body: &api.UpdateAuditLogRetentionRequest{
			RetentionDays: &days, CleanupIntervalMinutes: 60, ExpectedRevision: 0,
		},
	})
	if !hasCode(err, 403, "forbidden") {
		t.Fatalf("member update: want dedicated-permission 403, got %v", err)
	}
	_, err = server.RunAuditLogPrune(ctx, api.RunAuditLogPruneRequestObject{
		OrgId: orgID, Body: &api.RunAuditLogPruneRequest{IdempotencyKey: "member-prune"},
	})
	if !hasCode(err, 403, "forbidden") {
		t.Fatalf("member prune: want dedicated-permission 403, got %v", err)
	}
	if port.getCalls != 0 || port.setCalls != 0 || port.runCalls != 0 {
		t.Fatalf("unauthorized request reached retention port: get=%d set=%d run=%d", port.getCalls, port.setCalls, port.runCalls)
	}
}
