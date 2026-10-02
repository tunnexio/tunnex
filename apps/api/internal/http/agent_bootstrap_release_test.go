package http

import (
	"context"
	"errors"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/release"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
)

func TestIssueAgentBootstrapMetadataRequiresAuthenticationBeforeReleaseLookup(t *testing.T) {
	org := uuid.New()
	_, err := (apiServer{}).IssueAgentBootstrapToken(context.Background(), api.IssueAgentBootstrapTokenRequestObject{
		OrgId: org,
		Body:  &api.AgentBootstrapTokenRequest{GatewayId: uuid.New(), Name: "agent"},
	})
	if !hasCode(err, 401, "unauthenticated") {
		t.Fatalf("unauthenticated issue: want 401, got %v", err)
	}
}

func TestIssueAgentBootstrapVerifierFailurePrecedesTokenMint(t *testing.T) {
	org := uuid.New()
	calls := 0
	s := apiServer{releaseBootstrap: &release.BootstrapRelease{}, releaseBootstrapVerifier: func(context.Context, release.BootstrapRelease) (*release.BootstrapVerifierAssets, error) {
		calls++
		return nil, errors.New("descriptor secret detail")
	}}
	req := api.IssueAgentBootstrapTokenRequestObject{OrgId: org, Body: &api.AgentBootstrapTokenRequest{GatewayId: uuid.New(), Name: "agent"}}
	// No device service: reaching token issuance would panic, even without a DB.
	if _, err := s.IssueAgentBootstrapToken(principalWithRole(org, rbac.RoleOwner), req); !hasCode(err, 503, "bootstrap_unavailable") {
		t.Fatalf("descriptor failure = %v", err)
	}
	if calls != 1 {
		t.Fatal("descriptor was not checked")
	}
	if _, err := s.IssueAgentBootstrapToken(context.Background(), req); !hasCode(err, 401, "unauthenticated") {
		t.Fatalf("auth ordering = %v", err)
	}
	if calls != 1 {
		t.Fatal("unauthenticated request fetched metadata")
	}
	if _, err := s.IssueAgentBootstrapToken(principalWithRole(org, rbac.RoleOwner), api.IssueAgentBootstrapTokenRequestObject{OrgId: org}); !hasCode(err, 400, "invalid_request") {
		t.Fatalf("body ordering = %v", err)
	}
	if calls != 1 {
		t.Fatal("invalid request fetched metadata")
	}
}

func TestAPIBootstrapVerifierProjectionIsOptional(t *testing.T) {
	legacy := release.BootstrapRelease{}
	if got := toAPIBootstrapRelease(legacy); got.Verifier != nil {
		t.Fatal("legacy release invented executable hashes")
	}
	legacy.Verifier = &release.BootstrapVerifierAssets{LinuxAMD64: release.RuntimeAsset{Name: "releaseverify-linux-amd64", SHA256: "verified-amd64", SourceSHA: "verified-source"}, LinuxARM64: release.RuntimeAsset{Name: "releaseverify-linux-arm64", SHA256: "verified-arm64", SourceSHA: "verified-source"}}
	got := toAPIBootstrapRelease(legacy)
	if got.Verifier == nil || got.Verifier.LinuxAmd64.Sha256 != "verified-amd64" || got.Verifier.LinuxArm64.Sha256 != "verified-arm64" {
		t.Fatal("verified projection missing")
	}
}
