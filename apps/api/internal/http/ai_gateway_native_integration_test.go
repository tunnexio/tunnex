package http

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"io"
	"log/slog"
	"net"
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
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/nodepush"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
	"github.com/tunnexio/tunnex/apps/api/internal/testbifrost"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// Real enrolled Community identities traverse the production HTTP, policy,
// credential and native-engine seams. Provider is instrumented/zero-spend.
func TestAIGatewayNativeEnrolledWalk(t *testing.T) {
	binary := os.Getenv("AI0_BIFROST_BINARY")
	if binary == "" {
		t.Skip("explicit pinned native binary required")
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	if hex.EncodeToString(hash[:]) != testbifrost.BinarySHA256 {
		t.Fatal("native binary pin mismatch")
	}
	var arrivals atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			io.WriteString(w, `{"data":[]}`)
			return
		}
		arrivals.Add(1)
		var body struct {
			Model  string `json:"model"`
			Stream bool   `json:"stream"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("bad provider request")
			w.WriteHeader(400)
			return
		}
		if body.Model != "allowed" && body.Model != "other" {
			t.Error("unauthorized model reached provider")
		}
		if body.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, `data: {"id":"walk","object":"chat.completion.chunk","model":"`+body.Model+`","choices":[{"index":0,"delta":{"content":"OK"},"finish_reason":null}]}`+"\n\n")
			w.(http.Flusher).Flush()
			io.WriteString(w, `data: {"id":"walk","object":"chat.completion.chunk","model":"`+body.Model+`","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":1,"total_tokens":5}}`+"\n\ndata: [DONE]\n\n")
			return
		}
		io.WriteString(w, `{"id":"walk","object":"chat.completion","model":"`+body.Model+`","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":1,"total_tokens":5}}`)
	}))
	defer provider.Close()
	dir := t.TempDir()
	cfg := map[string]any{
		"client":       map[string]any{"enforce_auth_on_inference": true, "enable_logging": true, "disable_content_logging": true},
		"config_store": map[string]any{"enabled": true, "type": "sqlite", "config": map[string]any{"path": filepath.Join(dir, "config.db")}},
		"logs_store":   map[string]any{"enabled": true, "type": "sqlite", "config": map[string]any{"path": filepath.Join(dir, "logs.db")}},
		"governance":   map[string]any{"auth_config": map[string]any{"is_enabled": true, "admin_username": "ai0", "admin_password": "fixture-admin-only", "disable_auth_on_inference": false}},
		"providers":    map[string]any{"openrouter": map[string]any{"network_config": map[string]any{"base_url": provider.URL, "allow_private_network": true, "max_retries": 0}, "keys": []any{map[string]any{"id": "walk-provider", "name": "walk-provider", "value": "fixture-only", "models": []string{"allowed", "other"}, "weight": 1}}}},
	}
	raw, _ = json.Marshal(cfg)
	if os.WriteFile(filepath.Join(dir, "config.json"), raw, 0600) != nil {
		t.Fatal("write native fixture")
	}
	base, stop := startAIWalkEngine(t, binary, dir)
	defer stop()
	ctx, pool := testpostgres.New(t)
	org, owner, node, teamA, teamB := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	seed := func(q string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	seed(`INSERT INTO organizations(id,name,slug,pool_cidr,max_devices_per_user,ai_gateway_enabled,agent_policy_templates_enabled) VALUES($1,'AI native walk',$2,'10.99.0.0/24',0,true,true)`, org, "ai-walk-"+org.String())
	seed(`INSERT INTO users(id,email,name,status) VALUES($1,$2,'walk owner','active')`, owner, owner.String()+"@ai-walk.test")
	seed(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, org, owner)
	seed(`INSERT INTO nodes(id,org_id,name,cert_serial,wg_public_key,endpoint,status) VALUES($1,$2,'walk gateway',$3,$4,'gateway.example:51820','active')`, node, org, node.String(), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{11}, 32)))
	svc := devices.NewService(pool, nodepush.New(), slog.New(slog.NewTextHandler(io.Discard, nil))).WithLicence(&licence.Manager{})
	type enrolledIdentity struct {
		ID      uuid.UUID
		Runtime string
	}
	enroll := func(n byte) enrolledIdentity {
		t.Helper()
		bootstrap, e := svc.IssueAgentBootstrapToken(ctx, owner, org, node, "walk-agent")
		if e != nil {
			t.Fatal(e)
		}
		v, e := svc.Create(ctx, devices.CreateInput{BootstrapToken: bootstrap, PublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{n}, 32))})
		if e != nil {
			t.Fatal(e)
		}
		return enrolledIdentity{v.Device.ID, v.RuntimeCredential}
	}
	a, b := enroll(21), enroll(22)
	seed(`INSERT INTO agent_groups(id,org_id,name) VALUES($1,$3,'Team A'),($2,$3,'Team B')`, teamA, teamB, org)
	seed(`INSERT INTO agent_group_members(org_id,agent_group_id,device_id,created_by_user_id) VALUES($1,$2,$4,$6),($1,$3,$4,$6),($1,$3,$5,$6)`, org, teamA, teamB, a.ID, b.ID, owner)
	engine, e := aigateway.NewEngine(base, "ai0", "fixture-admin-only")
	if e != nil {
		t.Fatal(e)
	}
	sealer, _ := crypto.NewSealer(bytes.Repeat([]byte{7}, 32))
	policies := aigateway.NewPolicies(pool, sealer, engine)
	credentials := aigateway.NewCredentials(pool, agentruntime.New(pool, nil), policies)
	credentials.SetAvailable(true)
	adapter, e := aigateway.NewAdapter(base, credentials.Authorize)
	if e != nil {
		t.Fatal(e)
	}
	srv := aiSocketServer(t, Deps{System: sqlc.New(pool), Orgs: tenancy.NewService(pool), AgentRuntimePool: pool, AICredentials: credentials, AIPolicies: policies, AIAdapter: adapter, AuthFn: func(r *http.Request) *authctx.Principal {
		if r.Header.Get("X-Fixture-Role") != "owner" {
			return nil
		}
		return &authctx.Principal{UserID: owner, EmailVerified: true, Roles: map[uuid.UUID]string{org: "owner"}}
	}})
	root := "/api/v1/organizations/" + org.String() + "/ai-gateway"
	request := func(method, path string, body any, bearer, role string, want int) []byte {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		res := aiSocketRequest(t, srv, method, path, string(raw), bearer, role)
		defer res.Body.Close()
		out, readErr := io.ReadAll(res.Body)
		if readErr != nil {
			t.Fatal("response body did not complete")
		}
		if want == 200 && strings.HasPrefix(path, "/ai/") && !strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
			t.Fatal("missing SSE content type")
		}
		if res.StatusCode != want {
			t.Fatalf("%s %s status=%d expected=%d (body withheld)", method, path, res.StatusCode, want)
		}
		return out
	}
	putTeam := func(id uuid.UUID, models []string, rev int64) {
		t.Helper()
		request("PUT", root+"/teams/"+id.String(), map[string]any{"models": models, "key_ids": []string{"walk-provider"}, "expected_revision": rev}, "", "owner", 200)
	}
	assign := func(device, team uuid.UUID, rev int64) {
		t.Helper()
		raw := request("PUT", root+"/agents/"+device.String(), map[string]any{"team_id": team, "enabled": true, "models_override": []string{}, "expected_revision": rev}, "", "owner", 200)
		var v api.AIAssignment
		if json.Unmarshal(raw, &v) != nil || v.Status != api.AIAssignmentStatusApplied {
			t.Fatalf("assignment not applied: %s", v.Status)
		}
	}
	mint := func(rawRuntime string) string {
		t.Helper()
		raw := request("POST", "/api/v1/agent/runtime/ai-credential", nil, rawRuntime, "", 201)
		var v api.AICredential
		if json.Unmarshal(raw, &v) != nil || v.Audience != api.TunnexAi {
			t.Fatal("credential envelope")
		}
		return v.Token
	}
	infer := func(token, model string, want int) {
		t.Helper()
		raw := request("POST", "/ai/v1/chat/completions", map[string]any{"model": model, "messages": []any{map[string]string{"role": "user", "content": "OK"}}, "max_tokens": 8, "stream": true}, token, "", want)
		if want == 200 {
			assertAIWalkStream(t, raw)
		}
	}
	putTeam(teamA, []string{"openrouter/allowed"}, 0)
	putTeam(teamB, []string{"openrouter/other"}, 0)
	assign(a.ID, teamA, 0)
	assign(b.ID, teamB, 0)
	tokenA, tokenB := mint(a.Runtime), mint(b.Runtime)
	infer(tokenA, "openrouter/allowed", 200)
	before := arrivals.Load()
	infer(tokenA, "openrouter/other", 403)
	infer(tokenB, "openrouter/allowed", 403)
	if arrivals.Load() != before {
		t.Fatal("denial reached provider")
	}
	infer(tokenB, "openrouter/other", 200)
	from := time.Now().Add(-time.Hour)
	awaitUsage := func(team uuid.UUID, device uuid.UUID, want int64) {
		t.Helper()
		for end := time.Now().Add(15 * time.Second); time.Now().Before(end); {
			u, e := policies.Usage(ctx, org, &team, &device, from, time.Now())
			if e == nil && u.TotalRequests == want {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("native attribution did not converge")
	}
	awaitUsage(teamA, a.ID, 1)
	awaitUsage(teamB, b.ID, 1)
	var original string
	if pool.QueryRow(ctx, `SELECT native_key_id FROM ai_gateway_key_bindings WHERE org_id=$1 AND device_id=$2 AND team_id=$3`, org, a.ID, teamA).Scan(&original) != nil {
		t.Fatal("binding")
	}
	putTeam(teamA, []string{"openrouter/other"}, 1)
	infer(tokenA, "openrouter/allowed", 403)
	request("POST", root+"/agents/"+a.ID.String()+"/reconcile", nil, "", "owner", 200)
	infer(tokenA, "openrouter/other", 200)
	var revised string
	_ = pool.QueryRow(ctx, `SELECT native_key_id FROM ai_gateway_key_bindings WHERE org_id=$1 AND device_id=$2 AND team_id=$3`, org, a.ID, teamA).Scan(&revised)
	if revised != original {
		t.Fatal("policy edit reset native accounting identity")
	}
	awaitUsage(teamA, a.ID, 2)
	assign(a.ID, teamB, 1)
	infer(tokenA, "openrouter/other", 200)
	awaitUsage(teamA, a.ID, 2)
	awaitUsage(teamB, a.ID, 1)
	if err := svc.Revoke(ctx, org, owner, a.ID); err != nil {
		t.Fatal(err)
	}
	before = arrivals.Load()
	infer(tokenA, "openrouter/other", 401)
	if arrivals.Load() != before {
		t.Fatal("revoked identity dispatched")
	}
	infer(tokenB, "openrouter/other", 200)
	// Credential identity and desired policy persist independently of process memory.
	replacement := aigateway.NewPolicies(pool, sealer, engine)
	u, e := replacement.Usage(ctx, org, &teamA, &a.ID, from, time.Now())
	if e != nil || u.TotalRequests != 2 {
		t.Fatal("history relabelled or lost after resolver replacement")
	}
	t.Log("real Community enrollment -> scoped credential -> production HTTP/policy -> pinned Bifrost -> instrumented provider: streaming, denial, stable edits, historical team moves, revoke with live control PASS")
}
func startAIWalkEngine(t *testing.T, binary, dir string, environment ...string) (string, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strings.Split(l.Addr().String(), ":")[1]
	l.Close()
	cmd := exec.Command(binary, "-host", "127.0.0.1", "-port", port, "-app-dir", dir, "-log-level", "error")
	// Fixture runtime has no access to inherited provider credentials.
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, environment...)
	logFile, err := os.OpenFile(filepath.Join(dir, "runtime.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cmd.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			<-done
		}
		logFile.Close()
	}
	base := "http://127.0.0.1:" + port
	client := &http.Client{Timeout: time.Second}
	for end := time.Now().Add(30 * time.Second); time.Now().Before(end); {
		select {
		case err := <-done:
			stopped = true
			logFile.Close()
			t.Fatalf("engine exited: %v (runtime log withheld to avoid credential disclosure)", err)
		default:
		}
		res, err := client.Get(base + "/health")
		if err == nil {
			res.Body.Close()
			if res.StatusCode == 200 {
				return base, stop
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	stop()
	t.Fatal("engine readiness timed out (runtime log withheld to avoid credential disclosure)")
	return "", func() {}
}

// Require complete framed text, finish and terminal events, with no error payload.
func assertAIWalkStream(t *testing.T, body []byte) {
	t.Helper()
	frames := strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n\n")
	text, finish, terminal := false, false, false
	for i, frame := range frames {
		var data []string
		for _, line := range strings.Split(frame, "\n") {
			if strings.HasPrefix(line, "event:") && strings.TrimSpace(strings.TrimPrefix(line, "event:")) == "error" {
				t.Fatal("stream error event")
			}
			if strings.HasPrefix(line, "data:") {
				data = append(data, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			}
		}
		if len(data) == 0 {
			continue
		}
		if i == len(frames)-1 || terminal {
			t.Fatal("unterminated or post-terminal stream frame")
		}
		raw := strings.Join(data, "\n")
		if raw == "[DONE]" {
			if !text || !finish {
				t.Fatal("premature terminal stream event")
			}
			terminal = true
			continue
		}
		var event struct {
			Error   json.RawMessage `json:"error"`
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
		}
		if json.Unmarshal([]byte(raw), &event) != nil || (len(event.Error) > 0 && string(event.Error) != "null") {
			t.Fatal("invalid or errored stream event")
		}
		for _, choice := range event.Choices {
			if choice.Delta.Content != "" {
				text = true
			}
			if choice.FinishReason != nil && *choice.FinishReason != "" {
				finish = true
			}
		}
	}
	if !terminal {
		t.Fatal("stream did not terminate")
	}
}
