//go:build !enterprise

package http

import (
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// The idp-sync endpoints are edition-enforced SERVER-side: an authenticated, authorized owner
// still gets 403 edition_required because the idpSync port is nil in the open build. authorize()
// runs first (a sessionless request 401s — the auth-walk stays honest); the edition gate fires
// for authenticated callers. Covers all five endpoints (config/health/trigger/map/unmap).
func TestIdpSyncEditionGatedInOpenBuild(t *testing.T) {
	s := apiServer{} // open build: idpSync port is nil
	org := uuid.New()
	ctx := principalWithRole(org, rbac.RoleOwner)

	if _, err := s.PutIdpSyncConfig(ctx, api.PutIdpSyncConfigRequestObject{OrgId: org, Provider: "microsoft", Body: &api.PutIdpSyncConfigJSONRequestBody{ClientId: "c", ClientSecret: "s"}}); !hasCode(err, 403, "edition_required") {
		t.Fatalf("open-build PutIdpSyncConfig: want 403 edition_required, got %v", err)
	}
	if _, err := s.GetIdpSyncHealth(ctx, api.GetIdpSyncHealthRequestObject{OrgId: org, Provider: "microsoft"}); !hasCode(err, 403, "edition_required") {
		t.Fatalf("open-build GetIdpSyncHealth: want 403 edition_required, got %v", err)
	}
	if _, err := s.TriggerIdpSync(ctx, api.TriggerIdpSyncRequestObject{OrgId: org, Provider: "microsoft"}); !hasCode(err, 403, "edition_required") {
		t.Fatalf("open-build TriggerIdpSync: want 403 edition_required, got %v", err)
	}
	if _, err := s.MapIdpGroup(ctx, api.MapIdpGroupRequestObject{OrgId: org, Provider: "microsoft", Body: &api.MapIdpGroupJSONRequestBody{IdpGroupId: "g"}}); !hasCode(err, 403, "edition_required") {
		t.Fatalf("open-build MapIdpGroup: want 403 edition_required, got %v", err)
	}
	if _, err := s.UnmapIdpGroup(ctx, api.UnmapIdpGroupRequestObject{OrgId: org, Provider: "microsoft", GroupId: uuid.New()}); !hasCode(err, 403, "edition_required") {
		t.Fatalf("open-build UnmapIdpGroup: want 403 edition_required, got %v", err)
	}
}
