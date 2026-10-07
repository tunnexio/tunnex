package http

import (
	"bytes"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxes"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxproduct"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"github.com/tunnexio/tunnex/apps/api/internal/wgkey"
	"io"
	"log/slog"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSandboxBootstrapPostgresRouterClosedAtomicAndSingleUse(t *testing.T) {
	if sandboxproduct.Shelved {
		t.Skip("historical active sandbox router fixture; see docs/S-sandbox-shelved-main-reentry.md")
	}
	ctx, pool := testpostgres.New(t)
	org, user, gateway, template := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	_, public, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, query, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr,zero_trust_mode,sandboxes_enabled) VALUES($1,'sandbox route',$2,'10.99.0.0/24','enforcing',true)`, org, org.String())
	exec(`INSERT INTO users(id,email,name,email_verified_at) VALUES($1,$2,'creator',now())`, user, user.String()+"@example.test")
	exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, org, user)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,endpoint,wg_public_key) VALUES($1,$2,'gateway',$3,'192.0.2.1:51820',$4)`, gateway, org, gateway.String(), public)
	exec(`INSERT INTO sandbox_templates(id,org_id,name,image_digest,maximum_scope,memory_mib,max_ttl_seconds,enabled) VALUES($1,$2,'fixture',$3,'[]',256,3600,true)`, template, org, "sha256:"+strings.Repeat("a", 64))
	store := sandboxes.NewStore(pool)
	sandbox, _, err := store.Create(ctx, org, user, sandboxes.CreateInput{TemplateID: template, Name: "fixture", TTLSeconds: 3600, IdempotencyKey: "route", SSHPublicKeys: []string{sandboxFixtureSSHKey}})
	if err != nil {
		t.Fatal(err)
	}
	token, err := store.IssueBootstrap(ctx, org, user, sandbox.Identity.ID, gateway)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(api.SandboxBootstrapRequest{BootstrapToken: token, PublicKey: public})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	deps := Deps{Sandboxes: store, Devices: devices.NewService(pool, nil, nil)}
	call := func(handler stdhttp.Handler, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(stdhttp.MethodPost, path, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	router, err := NewRouter(logger, deps)
	if err != nil {
		t.Fatal(err)
	}
	if result := call(router, "/api/v1/sandbox/bootstrap"); result.Code != 503 {
		t.Fatalf("closed route status=%d", result.Code)
	}
	var consumed bool
	if err = pool.QueryRow(ctx, `SELECT consumed_at IS NOT NULL FROM sandbox_bootstrap_tokens WHERE sandbox_id=$1`, sandbox.Identity.ID).Scan(&consumed); err != nil || consumed {
		t.Fatal("closed route consumed bootstrap", err)
	}
	deps.SandboxProvisioningReady = func() bool { return true } // synthetic qualification only
	router, err = NewRouter(logger, deps)
	if err != nil {
		t.Fatal(err)
	}
	result := call(router, "/api/v1/sandbox/bootstrap")
	if result.Code != 200 {
		t.Fatalf("bootstrap status=%d", result.Code)
	}
	var response api.SandboxBootstrapResponse
	if json.Unmarshal(result.Body.Bytes(), &response) != nil || response.SandboxId != sandbox.Identity.ID || response.Generation != 1 || response.PeerId == uuid.Nil || !strings.HasPrefix(response.RuntimeCredential, "tnx_sandbox_runtime_") {
		t.Fatal("bootstrap binding lost")
	}
	if result = call(router, "/api/v1/sandbox/bootstrap"); result.Code != 401 {
		t.Fatalf("reuse status=%d", result.Code)
	}
	var kind string
	if err = pool.QueryRow(ctx, `SELECT kind FROM devices WHERE id=$1`, response.PeerId).Scan(&kind); err != nil || kind != "sandbox" {
		t.Fatal("wrong peer kind", err)
	}
}
