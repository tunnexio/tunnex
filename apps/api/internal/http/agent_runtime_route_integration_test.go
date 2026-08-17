package http

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
)

func TestAgentRuntimeRoutesPostgresContract(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	q := sqlc.New(pool)
	org, otherOrg, owner, member, node, device := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	seed := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	seed(`INSERT INTO organizations (id,name,slug,pool_cidr,managed_agent_runtime_enabled) VALUES ($1,'F04 route',$2,'10.99.0.0/24',true)`, org, "f04-route-"+org.String()[:8])
	seed(`INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'F04 other route',$2,'10.98.0.0/24')`, otherOrg, "f04-other-route-"+otherOrg.String()[:8])
	seed(`INSERT INTO users (id,email) VALUES ($1,$2)`, owner, "f04-route-"+owner.String()[:8]+"@example.com")
	seed(`INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint) VALUES ($1,$2,'gw',$3,$4,'gateway.example:51820')`, node, org, "f04-route-cert-"+node.String(), "f04-route-key-"+node.String())
	seed(`INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES ($1,$2,$3,$4,'agent',$5,$6,'active','agent')`, device, org, owner, node, "f04-route-agent-"+device.String(), fmt.Sprintf("10.99.0.%d", 2+int(device[0])%200))
	token := "tnx_runtime_route_" + device.String()
	h := sha256.Sum256([]byte(token))
	seed(`INSERT INTO agent_runtime_credentials (org_id,device_id,token_hash) VALUES ($1,$2,$3)`, org, device, h[:])
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1 OR id=$2`, org, otherOrg)
	})

	principal := &authctx.Principal{UserID: owner, Email: "owner@example.com", EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}
	router, err := NewRouter(slog.Default(), Deps{System: q, Orgs: tenancy.NewService(pool), Devices: devices.NewService(pool, nil, slog.Default()), Licence: licence.NewTestManager("growth", time.Now().Add(time.Hour)), Policy: NewPolicyPort(pool, nil), AgentRuntimeOptIn: agentruntime.OrganizationOptIn(q, func() bool { return true }), AuthFn: func(*http.Request) *authctx.Principal { return principal }})
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body, bearer string) (*httptest.ResponseRecorder, []byte) {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		b, _ := io.ReadAll(rr.Result().Body)
		return rr, b
	}

	pollPath := "/api/v1/agent/runtime/poll?applied_revision=0&client_version=v1"
	rr, body := request(http.MethodGet, pollPath, "", token)
	if rr.Code != http.StatusOK || strings.Contains(string(body), "runtime_credential") || strings.Contains(string(body), "private_key") {
		t.Fatalf("poll status/body=%d/%s", rr.Code, body)
	}
	rr, _ = request(http.MethodGet, "/api/v1/agent/runtime/poll?applied_revision=1&client_version=v1", "", token)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("unchanged poll status=%d, want 204", rr.Code)
	}
	report, _ := json.Marshal(map[string]any{"applied_revision": 0, "attempted_revision": 2, "client_version": "v1", "error_code": ""})
	rr, _ = request(http.MethodPost, "/api/v1/agent/runtime/report", string(report), token)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("ahead report status=%d, want 400", rr.Code)
	}
	report, _ = json.Marshal(map[string]any{"applied_revision": 1, "attempted_revision": 1, "client_version": "v1", "error_code": ""})
	rr, _ = request(http.MethodPost, "/api/v1/agent/runtime/report", string(report), token)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("valid report status=%d, want 204", rr.Code)
	}
	longPollStart := time.Now()
	rr, _ = request(http.MethodGet, "/api/v1/agent/runtime/poll?applied_revision=1&client_version=v1&wait_seconds=1", "", token)
	if rr.Code != http.StatusNoContent || time.Since(longPollStart) < 900*time.Millisecond {
		t.Fatalf("bounded no-change poll status/duration=%d/%s", rr.Code, time.Since(longPollStart))
	}
	bumpErr := make(chan error, 1)
	go func() {
		time.Sleep(100 * time.Millisecond)
		_, bump := q.BumpAgentDesiredRevision(context.Background(), sqlc.BumpAgentDesiredRevisionParams{DeviceID: device, OrgID: org})
		bumpErr <- bump
	}()
	changeStart := time.Now()
	rr, body = request(http.MethodGet, "/api/v1/agent/runtime/poll?applied_revision=1&client_version=v1&wait_seconds=2", "", token)
	if err := <-bumpErr; err != nil {
		t.Fatalf("bump desired revision: %v", err)
	}
	if rr.Code != http.StatusOK || !strings.Contains(string(body), `"revision":2`) || time.Since(changeStart) >= 2*time.Second {
		t.Fatalf("change-triggered poll status/duration/body=%d/%s/%s", rr.Code, time.Since(changeStart), body)
	}
	// The paid licence does not bypass the explicit organization switch. The
	// human toggle persists through the production opt-in reader immediately;
	// explicit opt-out is terminal for the machine channel but remains a typed
	// human 403 on the status projection.
	rr, body = request(http.MethodPut, "/api/v1/organizations/"+org.String()+"/agent-runtime-settings", `{"enabled":false}`, "")
	if rr.Code != http.StatusOK || !strings.Contains(string(body), `"enabled":false`) {
		t.Fatalf("disable runtime status/body=%d/%s", rr.Code, body)
	}
	rr, optOutBody := request(http.MethodGet, "/api/v1/agent/runtime/poll?applied_revision=2&client_version=v1", "", token)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("disabled runtime poll status=%d, want terminal 401", rr.Code)
	}
	rr, _ = request(http.MethodGet, "/api/v1/organizations/"+org.String()+"/agents/"+device.String()+"/runtime-status", "", "")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("disabled human runtime status=%d, want typed 403", rr.Code)
	}
	rr, body = request(http.MethodPut, "/api/v1/organizations/"+org.String()+"/agent-runtime-settings", `{"enabled":true}`, "")
	if rr.Code != http.StatusOK || !strings.Contains(string(body), `"enabled":true`) {
		t.Fatalf("enable runtime status/body=%d/%s", rr.Code, body)
	}
	rr, _ = request(http.MethodGet, "/api/v1/agent/runtime/poll?applied_revision=2&client_version=v1", "", token)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("re-enabled runtime poll status=%d, want 204", rr.Code)
	}
	report, _ = json.Marshal(map[string]any{"applied_revision": 2, "attempted_revision": 2, "client_version": "v1", "error_code": ""})
	rr, _ = request(http.MethodPost, "/api/v1/agent/runtime/report", string(report), token)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("revision 2 report status=%d, want 204", rr.Code)
	}
	// Authenticated malformed requests still reach strict OpenAPI validation.
	rr, _ = request(http.MethodGet, "/api/v1/agent/runtime/poll?client_version=v1", "", token)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("malformed authenticated poll status=%d, want 400", rr.Code)
	}
	rr, _ = request(http.MethodPost, "/api/v1/agent/runtime/report", `{}`, token)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("malformed authenticated report status=%d, want 400", rr.Code)
	}
	rr, _ = request(http.MethodPut, "/api/v1/organizations/"+org.String()+"/agent-quota", `{}`, "")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("malformed authenticated quota status=%d, want 400", rr.Code)
	}
	// A member of one organization cannot learn whether another organization or
	// device exists. Both refusals must be the same no-oracle 403 envelope.
	normalizeError := func(body []byte) string {
		var envelope map[string]any
		if err := json.Unmarshal(body, &envelope); err != nil {
			t.Fatalf("error body is not JSON: %v", err)
		}
		if e, ok := envelope["error"].(map[string]any); ok {
			delete(e, "request_id")
		}
		canonical, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return string(canonical)
	}
	rr, body = request(http.MethodPut, "/api/v1/organizations/"+otherOrg.String()+"/agent-quota", `{"max_agent_identities":1}`, "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("cross-org quota status=%d, want 404 org_not_found (no oracle)", rr.Code)
	}
	crossOrgError := normalizeError(body)
	rr, body = request(http.MethodPut, "/api/v1/organizations/"+uuid.NewString()+"/agent-quota", `{"max_agent_identities":1}`, "")
	if rr.Code != http.StatusNotFound || normalizeError(body) != crossOrgError {
		t.Fatalf("cross-org/unknown quota no-oracle mismatch: cross=404 unknown=%d", rr.Code)
	}
	rr, body = request(http.MethodGet, "/api/v1/organizations/"+org.String()+"/agents/"+device.String()+"/runtime-status", "", "")
	if rr.Code != http.StatusOK || !strings.Contains(string(body), `"health":"ready"`) || strings.Contains(string(body), "token_hash") || strings.Contains(string(body), "private_key") {
		t.Fatalf("admin status=%d/%s", rr.Code, body)
	}
	principal = &authctx.Principal{UserID: member, Email: "member@example.com", EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleMember}}
	rr, memberBody := request(http.MethodGet, "/api/v1/organizations/"+org.String()+"/agents/"+device.String()+"/runtime-status", "", "")
	if rr.Code != http.StatusForbidden || strings.Contains(string(memberBody), "desired_revision") || strings.Contains(string(memberBody), "client_version") {
		t.Fatalf("unrelated member status/body=%d/%s, want telemetry-free 403", rr.Code, memberBody)
	}
	rr, unknownBody := request(http.MethodGet, "/api/v1/organizations/"+org.String()+"/agents/"+uuid.NewString()+"/runtime-status", "", "")
	if rr.Code != http.StatusForbidden || normalizeError(unknownBody) != normalizeError(memberBody) {
		t.Fatalf("member known/unknown agent no-oracle mismatch: known=%s unknown=%d/%s", normalizeError(memberBody), rr.Code, normalizeError(unknownBody))
	}
	principal = &authctx.Principal{UserID: owner, Email: "owner@example.com", EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}
	seed(`UPDATE agent_runtime_state SET last_seen_at=now()-interval '4 minutes' WHERE device_id=$1`, device)
	rr, body = request(http.MethodGet, "/api/v1/organizations/"+org.String()+"/agents/"+device.String()+"/runtime-status", "", "")
	if rr.Code != http.StatusOK || !strings.Contains(string(body), `"health":"last_good"`) || !strings.Contains(string(body), `"stale":true`) || !strings.Contains(string(body), `"connectivity":"disconnected"`) {
		t.Fatalf("stale last-good status=%d/%s", rr.Code, body)
	}
	rr, body = request(http.MethodPut, "/api/v1/organizations/"+org.String()+"/agent-quota", `{"max_agent_identities":1}`, "")
	if rr.Code != http.StatusOK || !strings.Contains(string(body), `"max_agent_identities":1`) {
		t.Fatalf("quota set status/body=%d/%s", rr.Code, body)
	}
	rr, body = request(http.MethodPut, "/api/v1/organizations/"+org.String()+"/agent-quota", `{"max_agent_identities":null}`, "")
	if rr.Code != http.StatusOK || !strings.Contains(string(body), `"max_agent_identities":null`) {
		t.Fatalf("quota clear status/body=%d/%s", rr.Code, body)
	}

	// The released contract is enterprise-only: permission is evaluated first,
	// then the open edition refuses without exposing the agent rows.
	openRouter, err := NewRouter(slog.Default(), Deps{
		System: q, Orgs: tenancy.NewService(pool), Licence: licence.NewTestManager("community", time.Now().Add(time.Hour)),
		Policy: NewPolicyPort(pool, nil), AuthFn: func(*http.Request) *authctx.Principal { return principal },
	})
	if err != nil {
		t.Fatal(err)
	}
	openReq := httptest.NewRequest(http.MethodGet, "/api/v1/organizations/"+org.String()+"/agents", strings.NewReader(""))
	openResp := httptest.NewRecorder()
	openRouter.ServeHTTP(openResp, openReq)
	openBody, _ := io.ReadAll(openResp.Result().Body)
	if openResp.Code != http.StatusForbidden || strings.Contains(string(openBody), device.String()) || strings.Contains(string(openBody), "10.99.0.") {
		t.Fatalf("open-edition agents status/body=%d/%s", openResp.Code, openBody)
	}
	openRuntimeReq := httptest.NewRequest(http.MethodGet, "/api/v1/agent/runtime/poll?applied_revision=2&client_version=v1", strings.NewReader(""))
	openRuntimeReq.Header.Set("Authorization", "Bearer "+token)
	openRuntimeResp := httptest.NewRecorder()
	openRouter.ServeHTTP(openRuntimeResp, openRuntimeReq)
	if openRuntimeResp.Code != http.StatusForbidden || !strings.Contains(openRuntimeResp.Body.String(), "edition_required") || strings.Contains(openRuntimeResp.Body.String(), device.String()) {
		t.Fatalf("open-edition runtime status/body=%d/%s", openRuntimeResp.Code, openRuntimeResp.Body.String())
	}

	unauthRouter, err := NewRouter(slog.Default(), Deps{System: q, Orgs: tenancy.NewService(pool), Policy: NewPolicyPort(pool, nil)})
	if err != nil {
		t.Fatal(err)
	}
	unauth := func(method, path, body string) int {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp := httptest.NewRecorder()
		unauthRouter.ServeHTTP(resp, req)
		return resp.Code
	}
	if got := unauth(http.MethodGet, "/api/v1/agent/runtime/poll", ""); got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated missing-query poll status=%d, want 401", got)
	}
	if got := unauth(http.MethodPost, "/api/v1/agent/runtime/report", ""); got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated missing-body report status=%d, want 401", got)
	}
	if got := unauth(http.MethodPut, "/api/v1/organizations/"+org.String()+"/agent-quota", ""); got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated missing-body quota status=%d, want 401", got)
	}
	if got := unauth(http.MethodPut, "/api/v1/organizations/"+org.String()+"/agent-runtime-settings", ""); got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated missing-body runtime setting status=%d, want 401", got)
	}

	var firstBody string
	for _, bad := range []string{"tnx_runtime_unknown", "tnx_session_like"} {
		rr, body = request(http.MethodGet, pollPath, "", bad)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("bad token %q status=%d, want 401", bad, rr.Code)
		}
		var normalized map[string]any
		if err := json.Unmarshal(body, &normalized); err != nil {
			t.Fatalf("bad token %q body is not JSON: %v", bad, err)
		}
		if envelope, ok := normalized["error"].(map[string]any); ok {
			delete(envelope, "request_id")
		}
		canonical, err := json.Marshal(normalized)
		if err != nil {
			t.Fatal(err)
		}
		if firstBody == "" {
			firstBody = string(canonical)
		} else if string(canonical) != firstBody {
			t.Fatalf("auth refusal body changed: %q vs %q", body, firstBody)
		}
	}
	if normalizeError(optOutBody) != firstBody {
		t.Fatalf("explicit opt-out leaked a distinct machine refusal: %s vs %s", normalizeError(optOutBody), firstBody)
	}
}
