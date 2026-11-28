package http

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func wantAIStatus(t *testing.T, what string, err error, status int) {
	t.Helper()
	var domain *apierr.Error
	if !errors.As(err, &domain) || domain.Status != status {
		t.Errorf("%s: want %d, got %v", what, status, err)
	}
}

// AI-READY-1: who may read and change model prices, cost settings and the
// request log. Reads: ai_provider:view or ai_gateway:view. Prices:
// ai_provider:manage. Cost settings: ai_gateway:manage.
func TestAICostRoleBoundary(t *testing.T) {
	org := uuid.New()
	srv := apiServer{}
	for _, tc := range []struct {
		role              string
		read, price, sett int
	}{
		{"member", 403, 403, 403},
		{"ai-view", 503, 403, 403},
		{"auditor", 503, 403, 403},
		{"ai-admin", 503, 503, 503},
		{"owner", 503, 503, 503},
	} {
		ctx := authctx.WithPrincipal(context.Background(), &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: tc.role}})
		_, err := srv.ListAIModelPrices(ctx, api.ListAIModelPricesRequestObject{OrgId: org})
		wantAIStatus(t, tc.role+" list prices", err, tc.read)
		_, err = srv.GetAICostSettings(ctx, api.GetAICostSettingsRequestObject{OrgId: org})
		wantAIStatus(t, tc.role+" read settings", err, tc.read)
		_, err = srv.PutAIModelPrice(ctx, api.PutAIModelPriceRequestObject{OrgId: org, Body: &api.AIModelPriceInput{Model: "openrouter/x"}})
		wantAIStatus(t, tc.role+" put price", err, tc.price)
		_, err = srv.DeleteAIModelPrice(ctx, api.DeleteAIModelPriceRequestObject{OrgId: org, Params: api.DeleteAIModelPriceParams{Model: "openrouter/x", ExpectedRevision: 1}})
		wantAIStatus(t, tc.role+" delete price", err, tc.price)
		_, err = srv.PutAICostSettings(ctx, api.PutAICostSettingsRequestObject{OrgId: org, Body: &api.AICostSettingsInput{UnknownPricePolicy: "block", RequestLogRetentionDays: 30}})
		wantAIStatus(t, tc.role+" put settings", err, tc.sett)
	}
}

func TestAICostHandlers(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	org, owner := uuid.New(), uuid.New()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO organizations(id,name,slug,ai_gateway_enabled) VALUES($1,'Engineering',$2,true)`, org, "eng-"+org.String())
	exec(`INSERT INTO users(id,email,email_verified_at) VALUES($1,$2,now())`, owner, owner.String()+"@test.local")
	exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, org, owner)
	sealer, _ := crypto.NewSealer(bytes.Repeat([]byte{7}, 32))
	srv := apiServer{aiPolicies: aigateway.NewPolicies(pool, sealer, userAccessEngine{})}
	actx := authctx.WithPrincipal(ctx, &authctx.Principal{UserID: owner, EmailVerified: true, Roles: map[uuid.UUID]string{org: "owner"}})

	out := 2.5e-6
	res, err := srv.PutAIModelPrice(actx, api.PutAIModelPriceRequestObject{OrgId: org, Body: &api.AIModelPriceInput{Model: "openrouter/new-model", InputCostPerToken: 3e-7, OutputCostPerToken: &out}})
	if err != nil {
		t.Fatal(err)
	}
	// This engine cannot hold overrides, so the price stays pending, never applied.
	price, ok := res.(api.PutAIModelPrice200JSONResponse)
	if !ok || price.Revision != 1 || price.Status == "applied" || price.AppliedRevision != 0 {
		t.Fatalf("put: %#v", res)
	}
	models := []string{"openrouter/new-model"}
	list, err := srv.ListAIModelPrices(actx, api.ListAIModelPricesRequestObject{OrgId: org, Params: api.ListAIModelPricesParams{Model: &models}})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := list.(api.ListAIModelPrices200JSONResponse)
	if !ok || len(got.Prices) != 1 || len(got.Effective) != 1 || got.Effective[0].Source == "override" {
		t.Fatalf("an unapplied price is effective: %#v", list)
	}
	_, err = srv.DeleteAIModelPrice(actx, api.DeleteAIModelPriceRequestObject{OrgId: org, Params: api.DeleteAIModelPriceParams{Model: "openrouter/new-model", ExpectedRevision: 9}})
	wantAIStatus(t, "stale delete", err, 409)

	settings, err := srv.GetAICostSettings(actx, api.GetAICostSettingsRequestObject{OrgId: org})
	if s, ok := settings.(api.GetAICostSettings200JSONResponse); err != nil || !ok || s.UnknownPricePolicy != "block" || s.RequestLogRetentionDays != 30 || s.Revision != 0 {
		t.Fatalf("default settings: %#v %v", settings, err)
	}
	saved, err := srv.PutAICostSettings(actx, api.PutAICostSettingsRequestObject{OrgId: org, Body: &api.AICostSettingsInput{UnknownPricePolicy: "allow_and_alert", RequestLogRetentionDays: 7}})
	if s, ok := saved.(api.PutAICostSettings200JSONResponse); err != nil || !ok || s.Revision != 1 || s.RequestLogRetentionDays != 7 {
		t.Fatalf("save settings: %#v %v", saved, err)
	}
	_, err = srv.PutAICostSettings(actx, api.PutAICostSettingsRequestObject{OrgId: org, Body: &api.AICostSettingsInput{UnknownPricePolicy: "block", RequestLogRetentionDays: 0, ExpectedRevision: 1}})
	wantAIStatus(t, "zero retention", err, 400)
	var audits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND actor_user_id=$2 AND action IN ('ai_model_price.changed','ai_gateway.cost_settings_changed')`, org, owner).Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("audit entries: %d %v", audits, err)
	}
}
