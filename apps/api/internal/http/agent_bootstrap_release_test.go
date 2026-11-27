package http

import (
	"context"
	"errors"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/release"
	"strings"
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

func TestGetAgentRuntimeReleaseUsesTheEnrolGateAndIssuesNothing(t *testing.T) {
	org := uuid.New()
	calls := 0
	configured := release.BootstrapRelease{Tag: "v0.4.0", SourceSHA: "source", ManifestURL: "https://release.example/v0.4.0/release.json", VerifierKeyID: "key", VerifierPublicKey: "public"}
	configured.Runtime.Version = "v0.4.0"
	// No device service: issuing or listing a token would panic.
	s := apiServer{releaseBootstrap: &configured, releaseBootstrapVerifier: func(_ context.Context, got release.BootstrapRelease) (*release.BootstrapVerifierAssets, error) {
		calls++
		if got.Tag != configured.Tag {
			t.Fatalf("verifier fetched for %q", got.Tag)
		}
		return &release.BootstrapVerifierAssets{LinuxAMD64: release.RuntimeAsset{Name: "releaseverify-linux-amd64", SHA256: "amd64"}, LinuxARM64: release.RuntimeAsset{Name: "releaseverify-linux-arm64", SHA256: "arm64"}}, nil
	}}
	req := api.GetAgentRuntimeReleaseRequestObject{OrgId: org}

	if _, err := s.GetAgentRuntimeRelease(context.Background(), req); !hasCode(err, 401, "unauthenticated") {
		t.Fatalf("unauthenticated read: %v", err)
	}
	if _, err := s.GetAgentRuntimeRelease(principalWithRole(org, rbac.RoleMember), req); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member read: want forbidden, got %v", err)
	}
	if _, err := s.GetAgentRuntimeRelease(principalWithRole(uuid.New(), rbac.RoleOwner), req); !hasCode(err, 404, "org_not_found") {
		t.Fatalf("other-organization read: want org_not_found, got %v", err)
	}
	if calls != 0 {
		t.Fatal("a refused request fetched release metadata")
	}

	for _, role := range []string{rbac.RoleOwner, rbac.RoleAdmin} {
		resp, err := s.GetAgentRuntimeRelease(principalWithRole(org, role), req)
		if err != nil {
			t.Fatalf("%s read: %v", role, err)
		}
		got, ok := resp.(api.GetAgentRuntimeRelease200JSONResponse)
		if !ok {
			t.Fatalf("%s response = %#v", role, resp)
		}
		if got.Body.Tag != "v0.4.0" || got.Body.ManifestUrl != configured.ManifestURL || got.Body.VerifierPublicKey != "public" || got.Body.Runtime.Version != "v0.4.0" {
			t.Fatalf("release = %+v", got.Body)
		}
		if got.Body.Verifier == nil || got.Body.Verifier.LinuxAmd64.Sha256 != "amd64" || got.Body.Verifier.LinuxArm64.Sha256 != "arm64" {
			t.Fatalf("verifier = %+v", got.Body.Verifier)
		}
	}
	if calls != 2 {
		t.Fatalf("verifier fetches = %d", calls)
	}
	if configured.Verifier != nil {
		t.Fatal("the configured release was mutated")
	}
}

func TestGetAgentRuntimeReleaseIsUnavailableWithoutAVerifiedRelease(t *testing.T) {
	org := uuid.New()
	req := api.GetAgentRuntimeReleaseRequestObject{OrgId: org}
	owner := principalWithRole(org, rbac.RoleOwner)
	if _, err := (apiServer{}).GetAgentRuntimeRelease(owner, req); !hasCode(err, 503, "bootstrap_unavailable") {
		t.Fatalf("no configured release: %v", err)
	}
	s := apiServer{releaseBootstrap: &release.BootstrapRelease{}, releaseBootstrapVerifier: func(context.Context, release.BootstrapRelease) (*release.BootstrapVerifierAssets, error) {
		return nil, errors.New("descriptor secret detail")
	}}
	_, err := s.GetAgentRuntimeRelease(owner, req)
	if !hasCode(err, 503, "bootstrap_unavailable") {
		t.Fatalf("descriptor failure: %v", err)
	}
	if strings.Contains(err.Error(), "descriptor secret detail") {
		t.Fatal("the descriptor failure detail was returned")
	}
}
