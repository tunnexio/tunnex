package http

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/hostupgrade"
	"github.com/tunnexio/tunnex/apps/api/internal/release"
)

func TestHostUpgradeRequiresDeploymentAdminNotOrgOwner(t *testing.T) {
	orgOwner := &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{uuid.New(): "owner"}}
	ctx := authctx.WithPrincipal(context.Background(), orgOwner)
	server := apiServer{}
	if _, err := server.RequestHostUpgrade(ctx, api.RequestHostUpgradeRequestObject{}); err == nil {
		t.Fatal("organization owner requested a deployment-wide host upgrade")
	}
}

func TestHostUpgradePinsServerVerifiedTarget(t *testing.T) {
	dir := t.TempDir()
	requestPath := filepath.Join(dir, "request")
	svc := hostupgrade.New(requestPath, filepath.Join(dir, "status"), func(context.Context, uuid.UUID, uuid.UUID, hostupgrade.Target) error { return nil })
	server := apiServer{hostUpgrade: svc, releaseStatus: &release.Status{
		Available: true, Verified: true, SourceSHA: strings.Repeat("a", 40), Version: "v9.9.9", Sequence: 99,
	}}
	admin := &authctx.Principal{UserID: uuid.New(), EmailVerified: true, CPAdmin: true}
	response, err := server.RequestHostUpgrade(authctx.WithPrincipal(context.Background(), admin), api.RequestHostUpgradeRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	accepted, ok := response.(api.RequestHostUpgrade202JSONResponse)
	if !ok || accepted.Body.State != api.HostUpgradeStatusStateRequested || accepted.Body.TargetVersion == nil || *accepted.Body.TargetVersion != "v9.9.9" {
		t.Fatalf("unexpected response: %#v", response)
	}
	body, err := os.ReadFile(requestPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"source_sha=" + strings.Repeat("a", 40), "sequence=99", "requested_by=" + admin.UserID.String()} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("server request omitted %q: %s", want, body)
		}
	}
}

func TestHostUpgradeRefusesUnverifiedCatalog(t *testing.T) {
	dir := t.TempDir()
	svc := hostupgrade.New(filepath.Join(dir, "request"), filepath.Join(dir, "status"), func(context.Context, uuid.UUID, uuid.UUID, hostupgrade.Target) error { return nil })
	server := apiServer{hostUpgrade: svc, releaseStatus: &release.Status{Available: true, Verified: false, SourceSHA: strings.Repeat("a", 40), Version: "v9.9.9", Sequence: 99}}
	admin := &authctx.Principal{UserID: uuid.New(), EmailVerified: true, CPAdmin: true}
	if _, err := server.RequestHostUpgrade(authctx.WithPrincipal(context.Background(), admin), api.RequestHostUpgradeRequestObject{}); err == nil {
		t.Fatal("unverified release reached the host runner")
	}
	if _, err := os.Stat(filepath.Join(dir, "request")); !os.IsNotExist(err) {
		t.Fatal("unverified release created a host request")
	}
}
