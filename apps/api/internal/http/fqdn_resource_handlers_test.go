package http

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdnresources"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func TestFQDNEnableChecksPermissionBeforeEntitlement(t *testing.T) {
	org := uuid.New()
	req := api.SetFQDNResourceEnabledRequestObject{OrgId: org, Body: &api.FQDNResourceSetting{Enabled: true}}
	s := apiServer{}
	_, err := s.SetFQDNResourceEnabled(context.Background(), req)
	if !hasCode(err, 401, "unauthenticated") {
		t.Fatalf("anonymous error = %v", err)
	}
	ctx := authctx.WithPrincipal(context.Background(), &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}})
	_, err = s.SetFQDNResourceEnabled(ctx, req)
	if !hasCode(err, 403, "entitlement_required") {
		t.Fatalf("owner unentitled error = %v", err)
	}
}

func TestFQDNResolverConfigProjectionPreservesDirectEndpoints(t *testing.T) {
	org, site, gateway := uuid.New(), uuid.New(), uuid.New()
	resource := fqdnresources.Resource{Context: &fqdnresources.Context{
		SiteID: site, GatewayID: gateway, SiteName: "east", GatewayName: "gw-east",
		Config: &fqdnresources.ResolverConfig{ID: uuid.New(), OrgID: org, SiteID: site, GatewayID: gateway, Version: 3, State: "active", CreatedAt: time.Now(), Endpoints: []fqdnresources.ResolverEndpoint{{Address: "10.20.0.53", Port: 53, Transport: "udp"}, {Address: "fd00::53", Port: 53, Transport: "tcp"}}},
	}}
	got := toAPIFQDNResource(resource)
	if got.ResolverContext == nil || got.ResolverContext.ResolverConfig == nil {
		t.Fatal("resolver context must project its explicit server-managed configuration")
	}
	if got.ResolverContext.ResolverConfig.Version != 3 || len(got.ResolverContext.ResolverConfig.Endpoints) != 2 || got.ResolverContext.ResolverConfig.Endpoints[1].Transport != "tcp" {
		t.Fatalf("unexpected resolver config projection: %#v", got.ResolverContext.ResolverConfig)
	}
}
