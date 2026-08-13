//go:build !enterprise

package http

import (
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// The access-log query endpoints are edition-enforced SERVER-side (not merely hidden in the
// UI): an authenticated, authorized owner still gets 403 edition_required because the
// accessLog port is nil in the open build. authorize() runs first (a sessionless request
// 401s — the auth-walk stays honest); the edition gate fires for authenticated callers.
func TestAccessLogEditionGatedInOpenBuild(t *testing.T) {
	s := apiServer{} // open build: accessLog port is nil
	org := uuid.New()
	ctx := principalWithRole(org, rbac.RoleOwner)

	if _, err := s.ListAccessEvents(ctx, api.ListAccessEventsRequestObject{OrgId: org}); !hasCode(err, 403, "edition_required") {
		t.Fatalf("open-build ListAccessEvents: want 403 edition_required, got %v", err)
	}
	if _, err := s.GetAccessLogHealth(ctx, api.GetAccessLogHealthRequestObject{OrgId: org}); !hasCode(err, 403, "edition_required") {
		t.Fatalf("open-build GetAccessLogHealth: want 403 edition_required, got %v", err)
	}
}
