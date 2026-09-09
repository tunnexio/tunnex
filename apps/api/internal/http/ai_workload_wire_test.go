package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// This executable child uses only the SDK-compatible variables supplied by run.
// It never receives an upstream provider key or a Tunnex enrollment credential.
func TestWorkloadHTTPChild(t *testing.T) {
	if os.Getenv("TUNNEX_WORKLOAD_WIRE_CHILD") != "1" {
		t.Skip("subprocess fixture")
	}
	base, key := os.Getenv("OPENAI_BASE_URL"), os.Getenv("OPENAI_API_KEY")
	if !strings.HasPrefix(base, "http://127.0.0.1:") || key == "" || strings.HasPrefix(key, "tnx_") {
		t.Fatal("invalid local SDK configuration")
	}
	for _, c := range []struct {
		path, body string
		status     int
	}{
		{"/models", "", 200},
		{"/chat/completions", `{"model":"openrouter/workload","messages":[{"role":"user","content":"hello"}]}`, 200},
		{"/chat/completions", `{"model":"openrouter/workload","messages":[{"role":"user","content":"hello"}],"stream":true}`, 200},
		{"/chat/completions", `{"model":"openrouter/not-granted","messages":[{"role":"user","content":"hello"}]}`, 403},
	} {
		method := "POST"
		if c.body == "" {
			method = "GET"
		}
		req, _ := http.NewRequest(method, base+c.path, strings.NewReader(c.body))
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Bf-Vk", "forged")
		req.Header.Set("X-Tunnex-Tenant", uuid.NewString())
		res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			t.Fatal("local model call failed")
		}
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil || res.StatusCode != c.status {
			t.Fatalf("%s status=%d expected=%d", c.path, res.StatusCode, c.status)
		}
		if strings.Contains(string(body), "sk-bf-") || res.Header.Get("X-Bf-Vk") != "" {
			t.Fatal("private engine credential leaked")
		}
		if strings.Contains(c.body, `"stream":true`) && !strings.Contains(string(body), "[DONE]") {
			t.Fatal("incomplete stream")
		}
	}
	// Anthropic's SDK uses x-api-key; the wrapper maps to the separately typed path.
	r, _ := http.NewRequest("POST", os.Getenv("ANTHROPIC_BASE_URL")+"/v1/messages", strings.NewReader(`{"model":"openrouter/workload","max_tokens":16,"messages":[{"role":"user","content":"hello"}]}`))
	r.Header.Set("X-Api-Key", os.Getenv("ANTHROPIC_API_KEY"))
	r.Header.Set("Content-Type", "application/json")
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(r)
	if err != nil {
		t.Fatal("Anthropic call failed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("Anthropic status=%d", res.StatusCode)
	}
}

func TestWorkloadCLIHTTPWire(t *testing.T) {
	cliBinary := os.Getenv("TUNNEX_WORKLOAD_CLI")
	if cliBinary == "" {
		t.Skip("set TUNNEX_WORKLOAD_CLI to a locally built CLI for real subprocess wire proof")
	}
	ctx, pool := testpostgres.New(t)
	org, owner, connection := uuid.New(), uuid.New(), uuid.New()
	execSQL := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	execSQL(`INSERT INTO organizations(id,name,slug,ai_gateway_enabled) VALUES($1,'Workload wire fixture',$2,true)`, org, "workload-wire-"+org.String())
	execSQL(`INSERT INTO users(id,email,email_verified_at) VALUES($1,$2,now())`, owner, owner.String()+"@test.invalid")
	execSQL(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, org, owner)
	execSQL(`INSERT INTO ai_provider_connections(id,org_id,key_id,provider,name,models,enabled,revision,applied_revision,status) VALUES($1,$2,$3,'openrouter','Workload wire fixture',ARRAY['openrouter/workload'],true,1,1,'applied')`, connection, org, "tnx-managed-"+connection.String())
	sealer, _ := crypto.NewSealer(bytes.Repeat([]byte{11}, 32))
	policies := aigateway.NewPolicies(pool, sealer, userAccessEngine{})
	srv := httptest.NewUnstartedServer(nil)
	workloads, err := aigateway.NewWorkloads(policies, "http://"+srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	w, err := workloads.Put(ctx, org, owner, uuid.Nil, api.AIWorkloadInput{Name: "production/wire-bot", Enabled: true, Models: []api.AIWorkloadModel{{ConnectionId: connection, Model: "openrouter/workload", Mode: "chat"}}})
	if err != nil || w.Status != "applied" {
		t.Fatalf("workload configuration: %v", err)
	}
	key, err := workloads.CreateKey(ctx, org, owner, w.Id, api.AIWorkloadKeyInput{Name: "replicas", Reusable: true, Ephemeral: true, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	var arrivals, humanAuthCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		arrivals.Add(1)
		for _, h := range []string{"Authorization", "Cookie", "X-Tunnex-Tenant", "X-Api-Key", "X-Bf-Api-Key"} {
			if r.Header.Get(h) != "" {
				t.Errorf("%s leaked to engine", h)
			}
		}
		if r.Header.Get("X-Bf-Vk") != "sk-bf-private-group-key" {
			t.Error("workload scoped key missing")
		}
		body, _ := io.ReadAll(r.Body)
		rw.Header().Set("X-Bf-Vk", "must-not-return")
		if bytes.Contains(body, []byte(`"stream":true`)) {
			rw.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(rw, "data: {\"choices\":[{\"delta\":{\"content\":\"fixture\"}}]}\n\n")
			rw.(http.Flusher).Flush()
			io.WriteString(rw, "data: [DONE]\n\n")
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		io.WriteString(rw, `{"choices":[{"message":{"content":"fixture response"}}]}`)
	}))
	defer upstream.Close()
	adapter, err := aigateway.NewAdapter(upstream.URL, func(context.Context, string, string) (aigateway.Grant, error) {
		return aigateway.Grant{}, errors.New("legacy auth must not accept workload")
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{Orgs: tenancy.NewService(pool), AIAdapter: adapter, AIPolicies: policies, AIWorkloads: workloads, AuthFn: func(*http.Request) *authctx.Principal { humanAuthCalls.Add(1); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = h
	srv.Start()
	defer srv.Close()
	dir := t.TempDir()
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "enrollment-key")
	if err = os.WriteFile(keyPath, []byte(key.Secret), 0600); err != nil {
		t.Fatal(err)
	}
	configs := make([]string, 20)
	for i := range configs {
		configs[i] = filepath.Join(dir, fmt.Sprintf("replica-%d.json", i))
		b, _ := json.Marshal(map[string]string{"server": srv.URL, "enrollment_key_file": keyPath, "state_directory": filepath.Join(dir, fmt.Sprintf("state-%d", i))})
		if err = os.WriteFile(configs[i], b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	runCLI := func(config, command string, args ...string) ([]byte, error) {
		commandCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		argv := append([]string{"workload", command, "--config", config}, args...)
		cmd := exec.CommandContext(commandCtx, cliBinary, argv...)
		cmd.Env = append(os.Environ(), "TUNNEX_WORKLOAD_WIRE_CHILD=1")
		return cmd.CombinedOutput()
	}
	// Each real CLI process creates a distinct instance; receipts contain no secrets.
	joined := make(chan error, 20)
	for _, config := range configs {
		go func() { _, e := runCLI(config, "enroll"); joined <- e }()
	}
	for range configs {
		if err = <-joined; err != nil {
			t.Fatalf("replica enrollment failed: %v", err)
		}
	}
	var instances, keys int
	if pool.QueryRow(ctx, `SELECT count(*) FROM ai_workload_instances WHERE org_id=$1 AND workload_id=$2`, org, w.Id).Scan(&instances) != nil || instances != 20 {
		t.Fatal("replicas did not get distinct instance identity")
	}
	if pool.QueryRow(ctx, `SELECT count(DISTINCT native_key_id) FROM ai_workloads WHERE org_id=$1`, org).Scan(&keys) != nil || keys != 1 {
		t.Fatal("replicas multiplied accounting identity")
	}
	if _, err = runCLI(configs[0], "rotate"); err != nil {
		t.Fatalf("CLI key rotation failed: %v", err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if output, e := runCLI(configs[0], "run", "--", self, "-test.run=^TestWorkloadHTTPChild$", "-test.v"); e != nil {
		t.Fatalf("application fixture failed: %v\n%s", e, output)
	}
	if arrivals.Load() != 3 {
		t.Fatalf("unexpected engine calls=%d; denied call may have reached engine", arrivals.Load())
	}
	if humanAuthCalls.Load() != 0 {
		t.Fatal("machine calls consumed human authentication")
	}
	var retired int
	if pool.QueryRow(ctx, `SELECT count(*) FROM ai_workload_instances WHERE org_id=$1 AND workload_id=$2 AND state='retired'`, org, w.Id).Scan(&retired) != nil || retired != 0 {
		t.Fatal("ordinary process exit retired an instance")
	}
	if output, e := runCLI(configs[0], "run", "--", self, "-test.run=^TestWorkloadHTTPChild$", "-test.v"); e != nil {
		t.Fatalf("application restart failed: %v\n%s", e, output)
	}
	if pool.QueryRow(ctx, `SELECT count(*) FROM ai_workload_instances WHERE org_id=$1 AND workload_id=$2`, org, w.Id).Scan(&instances) != nil || instances != 20 {
		t.Fatal("ordinary restart enrolled an extra instance")
	}
	if _, e := runCLI(configs[0], "retire"); e != nil {
		t.Fatalf("explicit CLI retirement failed: %v", e)
	}
	if pool.QueryRow(ctx, `SELECT count(*) FROM ai_workload_instances WHERE org_id=$1 AND workload_id=$2 AND state='retired'`, org, w.Id).Scan(&retired) != nil || retired != 1 {
		t.Fatal("explicit retirement did not retire only its instance")
	}
	// Bootstrap revocation preserves registered instance authentication.
	if err = workloads.RevokeKey(ctx, org, owner, w.Id, key.Key.Id, false); err != nil {
		t.Fatal(err)
	}
	raw, err := runCLI(configs[1], "token")
	if err != nil {
		t.Fatal("registered instance depended on revoked setup key")
	}
	var token api.AIWorkloadToken
	if json.Unmarshal(raw, &token) != nil {
		t.Fatal("bad token response")
	}
	// Runtime tokens cannot grant organization-management authority.
	r, _ := http.NewRequest("GET", srv.URL+"/api/v1/organizations/"+org.String()+"/ai-gateway/workloads", nil)
	r.Header.Set("Authorization", "Bearer "+token.AccessToken)
	res, err := srv.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 401 && res.StatusCode != 403 {
		t.Fatalf("runtime token reached management: %d", res.StatusCode)
	}
	if _, err = workloads.Put(ctx, org, owner, w.Id, api.AIWorkloadInput{Name: w.Name, Enabled: false, ExpectedRevision: w.Revision, Models: w.Models}); err != nil {
		t.Fatal(err)
	}
	r, _ = http.NewRequest("GET", srv.URL+"/ai/v1/models", nil)
	r.Header.Set("Authorization", "Bearer "+token.AccessToken)
	res, err = srv.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatalf("disabled workload token survived: %d", res.StatusCode)
	}
	t.Log("20 real CLI enrollments; one accounting identity; rotation; SDK JSON/SSE/Anthropic calls; model deny; bootstrap revoke; retirement; management isolation; disable: verified against local HTTP fixtures")
}

func TestWorkloadManagementRoleBoundary(t *testing.T) {
	org := uuid.New()
	s := apiServer{}
	for _, c := range []struct {
		role        string
		view, write int
	}{{"member", 403, 403}, {"ai-view", 503, 403}, {"ai-admin", 503, 503}, {"owner", 503, 503}, {"admin", 503, 503}} {
		ctx := authctx.WithPrincipal(context.Background(), &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: c.role}})
		for _, write := range []bool{false, true} {
			_, _, err := s.workloadContext(ctx, org, write)
			var domain *apierr.Error
			want := c.view
			if write {
				want = c.write
			}
			if !errors.As(err, &domain) || domain.Status != want {
				t.Errorf("role=%s write=%v err=%v", c.role, write, err)
			}
		}
	}
}
