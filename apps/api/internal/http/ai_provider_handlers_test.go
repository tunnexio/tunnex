package http

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAIProviderHandlerAuthorization(t *testing.T) {
	org := uuid.New()
	srv := apiServer{}
	for _, tc := range []struct {
		name, role string
		status     int
	}{{"anonymous", "", 401}, {"viewer", "viewer", 403}, {"member", "member", 403}, {"owner", "owner", 503}, {"admin", "admin", 503}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.role != "" {
				ctx = authctx.WithPrincipal(ctx, &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: tc.role}})
			}
			_, err := srv.CreateAIProvider(ctx, api.CreateAIProviderRequestObject{OrgId: org})
			var e *apierr.Error
			if !errors.As(err, &e) || e.Status != tc.status {
				t.Fatalf("authorization before body/availability: %v", err)
			}
		})
	}
	for _, role := range []string{"owner", "admin"} {
		if !rbac.Can(role, rbac.PermAIProviderView) || !rbac.Can(role, rbac.PermAIProviderManage) {
			t.Fatal("missing provider grant")
		}
	}
	if rbac.IsMutating(rbac.PermAIProviderView) || !rbac.IsMutating(rbac.PermAIProviderManage) {
		t.Fatal("provider permission polarity")
	}
}

// AI-UX-1: the in-use refusal lists the three kinds of user under `in_use`, as arrays even when empty.
func TestAIProviderInUseResponseShape(t *testing.T) {
	team, device := uuid.New(), uuid.New()
	res := aiProviderInUseResponse(context.Background(), &aigateway.ProviderInUse{
		Models:   []string{"openrouter/a"},
		Policies: []aigateway.ProviderInUsePolicy{{TeamID: team, Name: "Builders"}},
		Agents:   []aigateway.ProviderInUseAgent{{DeviceID: device, Name: "build-agent"}},
	})
	rec := httptest.NewRecorder()
	if err := res.VisitDeleteAIProviderResponse(rec); err != nil || rec.Code != 409 {
		t.Fatalf("status %d: %v", rec.Code, err)
	}
	var body struct {
		Error struct{ Code, Message string } `json:"error"`
		InUse struct {
			Models   []string `json:"models"`
			Policies []struct {
				TeamID uuid.UUID `json:"team_id"`
				Name   string    `json:"name"`
			} `json:"policies"`
			Agents []struct {
				DeviceID uuid.UUID `json:"device_id"`
				Name     string    `json:"name"`
			} `json:"agents"`
		} `json:"in_use"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != "ai_provider_in_use" || body.Error.Message == "" || len(body.InUse.Models) != 1 || body.InUse.Models[0] != "openrouter/a" ||
		len(body.InUse.Policies) != 1 || body.InUse.Policies[0].TeamID != team || body.InUse.Policies[0].Name != "Builders" ||
		len(body.InUse.Agents) != 1 || body.InUse.Agents[0].DeviceID != device || body.InUse.Agents[0].Name != "build-agent" {
		t.Fatalf("body: %s", rec.Body.String())
	}
	empty := httptest.NewRecorder()
	_ = aiProviderInUseResponse(context.Background(), &aigateway.ProviderInUse{}).VisitDeleteAIProviderResponse(empty)
	if !strings.Contains(empty.Body.String(), `"models":[]`) || !strings.Contains(empty.Body.String(), `"policies":[]`) || !strings.Contains(empty.Body.String(), `"agents":[]`) {
		t.Fatalf("empty lists must be arrays: %s", empty.Body.String())
	}
}
