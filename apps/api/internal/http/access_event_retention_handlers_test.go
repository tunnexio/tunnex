package http

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/accesslog"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type fakeAccessEventRetention struct {
	overview accesslog.RetentionOverview
	input    accesslog.RetentionSettingsInput
	actor    uuid.UUID
	key      string
	run      accesslog.RetentionRun
	claimed  bool
	runErr   error
}

func (f *fakeAccessEventRetention) GetOverview(context.Context, uuid.UUID) (accesslog.RetentionOverview, error) {
	return f.overview, nil
}

func (f *fakeAccessEventRetention) SetSettings(_ context.Context, _ uuid.UUID, actor uuid.UUID, input accesslog.RetentionSettingsInput) (accesslog.RetentionSettings, error) {
	f.actor, f.input = actor, input
	f.overview.Settings = accesslog.RetentionSettings{
		RetentionDays: input.RetentionDays, CleanupIntervalMinutes: input.CleanupIntervalMinutes,
		Revision: input.ExpectedRevision + 1,
	}
	return f.overview.Settings, nil
}

func (f *fakeAccessEventRetention) GetLatestRun(context.Context, uuid.UUID) (*accesslog.RetentionRun, error) {
	return f.overview.LastRun, nil
}

func (f *fakeAccessEventRetention) RunManual(_ context.Context, _ uuid.UUID, actor uuid.UUID, key string) (accesslog.RetentionRun, bool, error) {
	f.actor, f.key = actor, key
	return f.run, f.claimed, f.runErr
}

func TestAccessEventRetentionHandlersMapPolicyAndActor(t *testing.T) {
	org, actor := uuid.New(), uuid.New()
	ctx := authctx.WithPrincipal(context.Background(), &authctx.Principal{
		UserID: actor, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleAdmin},
	})
	port := &fakeAccessEventRetention{overview: accesslog.RetentionOverview{Settings: accesslog.RetentionSettings{
		OrgID: org, RetentionDays: 30, CleanupIntervalMinutes: 60, Revision: 4,
	}}}
	s := apiServer{accessEventRetention: port}

	getResponse, err := s.GetAccessEventRetention(ctx, api.GetAccessEventRetentionRequestObject{OrgId: org})
	if err != nil {
		t.Fatalf("get retention: %v", err)
	}
	get, ok := getResponse.(api.GetAccessEventRetention200JSONResponse)
	if !ok || get.Body.RetentionDays != 30 || get.Body.CleanupIntervalMinutes != 60 || get.Body.RowCap != int(accesslog.DefaultPGRowCap) || get.Body.Revision != 4 {
		t.Fatalf("get response = %#v", getResponse)
	}

	updateResponse, err := s.UpdateAccessEventRetention(ctx, api.UpdateAccessEventRetentionRequestObject{
		OrgId: org,
		Body: &api.UpdateAccessEventRetentionRequest{
			RetentionDays: 45, CleanupIntervalMinutes: 120, ExpectedRevision: 4,
		},
	})
	if err != nil {
		t.Fatalf("update retention: %v", err)
	}
	updated, ok := updateResponse.(api.UpdateAccessEventRetention200JSONResponse)
	if !ok || updated.Body.RetentionDays != 45 || updated.Body.Revision != 5 || port.actor != actor {
		t.Fatalf("update response/input = %#v / %+v", updateResponse, port.input)
	}
	if port.input.RetentionDays != 45 || port.input.CleanupIntervalMinutes != 120 || port.input.ExpectedRevision != 4 {
		t.Fatalf("service input = %+v", port.input)
	}

	completed := time.Now().UTC()
	port.run = accesslog.RetentionRun{
		ID: uuid.New(), TriggerKind: accesslog.RetentionTriggerManual,
		Status: accesslog.RetentionRunSucceeded, StartedAt: completed.Add(-time.Second), CompletedAt: &completed,
		DeletedRows: 3, Batches: 1,
	}
	port.claimed = true
	port.overview.LastRun = &port.run
	pruneResponse, err := s.RunAccessEventPrune(ctx, api.RunAccessEventPruneRequestObject{
		OrgId: org, Body: &api.RunAccessEventPruneRequest{IdempotencyKey: "test-prune"},
	})
	if err != nil {
		t.Fatalf("manual prune: %v", err)
	}
	pruned, ok := pruneResponse.(api.RunAccessEventPrune200JSONResponse)
	if !ok || pruned.Body.Run.DeletedRows != 3 || pruned.Body.Replayed || pruned.Body.Retention.LastRun == nil || pruned.Body.Retention.LastRun.Id != port.run.ID || port.key != "test-prune" || port.actor != actor {
		t.Fatalf("prune response = %#v", pruneResponse)
	}
}

func TestAccessEventRetentionRejectsIntegerOverflowBeforeNarrowing(t *testing.T) {
	org, actor := uuid.New(), uuid.New()
	ctx := authctx.WithPrincipal(context.Background(), &authctx.Principal{
		UserID: actor, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleAdmin},
	})
	port := &fakeAccessEventRetention{}
	_, err := (apiServer{accessEventRetention: port}).UpdateAccessEventRetention(ctx, api.UpdateAccessEventRetentionRequestObject{
		OrgId: org,
		Body: &api.UpdateAccessEventRetentionRequest{
			RetentionDays: 1<<32 + 1, CleanupIntervalMinutes: 60,
		},
	})
	if !hasCode(err, 400, "invalid_access_event_retention_days") {
		t.Fatalf("overflowing retention_days = %v, want bounded 400", err)
	}
	if port.input.RetentionDays != 0 {
		t.Fatal("overflowing value reached the int32 service boundary")
	}
}

func TestAccessEventPruneReturnsDurableFailedOutcome(t *testing.T) {
	org, actor := uuid.New(), uuid.New()
	ctx := authctx.WithPrincipal(context.Background(), &authctx.Principal{
		UserID: actor, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner},
	})
	code := "prune_failed"
	port := &fakeAccessEventRetention{
		overview: accesslog.RetentionOverview{Settings: accesslog.RetentionSettings{OrgID: org, RetentionDays: 30, CleanupIntervalMinutes: 60}},
		run: accesslog.RetentionRun{
			ID: uuid.New(), TriggerKind: accesslog.RetentionTriggerManual, Status: accesslog.RetentionRunFailed,
			StartedAt: time.Now().UTC(), ErrorCode: &code, MorePending: true,
		},
		claimed: true,
		runErr:  errors.New("database detail must not cross the API"),
	}
	s := apiServer{accessEventRetention: port}
	response, err := s.RunAccessEventPrune(ctx, api.RunAccessEventPruneRequestObject{
		OrgId: org, Body: &api.RunAccessEventPruneRequest{IdempotencyKey: "failed-prune"},
	})
	if err != nil {
		t.Fatalf("durably finalized failure should return its safe status: %v", err)
	}
	got, ok := response.(api.RunAccessEventPrune200JSONResponse)
	if !ok || got.Body.Run.Status != api.AccessEventRetentionRunStatusFailed || got.Body.Run.ErrorCode == nil || *got.Body.Run.ErrorCode != code {
		t.Fatalf("failed response = %#v", response)
	}
}

func TestAccessEventPruneKeepsReplayedRunSeparateFromCurrentOverview(t *testing.T) {
	org, actor := uuid.New(), uuid.New()
	ctx := authctx.WithPrincipal(context.Background(), &authctx.Principal{
		UserID: actor, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleAdmin},
	})
	completed := time.Now().UTC()
	newerCompleted := completed.Add(time.Hour)
	original := accesslog.RetentionRun{
		ID: uuid.New(), TriggerKind: accesslog.RetentionTriggerManual,
		Status: accesslog.RetentionRunSucceeded, StartedAt: completed.Add(-2 * time.Hour),
		CompletedAt: &completed, DeletedRows: 3, Batches: 1,
	}
	newer := accesslog.RetentionRun{
		ID: uuid.New(), TriggerKind: accesslog.RetentionTriggerScheduled,
		Status: accesslog.RetentionRunSucceeded, StartedAt: newerCompleted.Add(-time.Second),
		CompletedAt: &newerCompleted, DeletedRows: 99, Batches: 1,
	}
	port := &fakeAccessEventRetention{
		overview: accesslog.RetentionOverview{
			Settings: accesslog.RetentionSettings{OrgID: org, RetentionDays: 30, CleanupIntervalMinutes: 60},
			LastRun:  &newer,
		},
		run: original,
		// claimed=false means RunManual found this exact key-bound run.
		claimed: false,
	}

	response, err := (apiServer{accessEventRetention: port}).RunAccessEventPrune(ctx, api.RunAccessEventPruneRequestObject{
		OrgId: org, Body: &api.RunAccessEventPruneRequest{IdempotencyKey: "original-key"},
	})
	if err != nil {
		t.Fatalf("replay prune: %v", err)
	}
	got, ok := response.(api.RunAccessEventPrune200JSONResponse)
	if !ok || !got.Body.Replayed || got.Body.Run.Id != original.ID || got.Body.Retention.LastRun == nil || got.Body.Retention.LastRun.Id != newer.ID {
		t.Fatalf("replayed response = %#v", response)
	}
}
