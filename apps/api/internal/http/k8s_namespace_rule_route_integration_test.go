package http

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	k8ssvc "github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/machineauth"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
)

// K8N-4 slice C and K8N-3 over real HTTP: the production router, its OpenAPI validator and its
// authentication middleware, with the operator's machine credential resolved from the database by the
// production MachineAuth. Until now the ownership rules of a namespace rule were proven at the service
// layer with a hand-built machine principal; no `tnxm_` token had been sent to these endpoints.
//
// People are injected through AuthFn, the seam the other route tests use for a signed-in session; the
// header X-Test-Human picks which person. A request with a machine token never reaches that seam.

type k8sRouteFixture struct {
	t       *testing.T
	pool    *pgxpool.Pool
	router  http.Handler
	org     uuid.UUID
	cluster uuid.UUID
	admin   uuid.UUID
	person  uuid.UUID
}

type k8sRouteCaller struct {
	token string // a machine credential
	human string // "admin" or "member"
	cause string // X-Tunnex-Cause, honoured for a machine only
}

type k8sRouteReply struct {
	status int
	code   string
	body   map[string]any
	list   []map[string]any
	raw    string
}

func newK8sRouteFixture(t *testing.T) *k8sRouteFixture {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	f := &k8sRouteFixture{t: t, pool: pool, org: uuid.New(), cluster: uuid.New(), admin: uuid.New(), person: uuid.New()}
	site, node := uuid.New(), uuid.New()
	f.exec(`INSERT INTO organizations (id,name,slug,pool_cidr,zero_trust_mode) VALUES ($1,'K8N route',$2,'10.94.0.0/24','enforcing')`, f.org, "k8n-route-"+f.org.String()[:8])
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, f.org)
	})
	for user, role := range map[uuid.UUID]string{f.admin: rbac.RoleOwner, f.person: rbac.RoleMember} {
		f.exec(`INSERT INTO users (id,email,status) VALUES ($1,$2,'active')`, user, user.String()+"@k8n-route.example")
		f.exec(`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,$3)`, f.org, user, role)
	}
	f.exec(`INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'k8n route site')`, site, f.org)
	f.exec(`INSERT INTO nodes (id,org_id,site_id,name,status,cert_serial,wg_public_key,endpoint,last_seen_at) VALUES ($1,$2,$3,'k8n-route-gw','active',$4,'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=','gw.example:51820',now())`,
		node, f.org, site, "k8n-route-"+node.String())
	f.exec(`INSERT INTO k8s_clusters (id,org_id,site_id,name,vip_range,dns_zone,dns_vip,connector_node_id) VALUES ($1,$2,$3,'prod','100.66.0.0/24','k8s.acme.com','100.66.0.2',$4)`,
		f.cluster, f.org, site, node)

	humans := map[string]*authctx.Principal{
		"admin":  {UserID: f.admin, EmailVerified: true, AuthMethod: authctx.AuthSSO, Roles: map[uuid.UUID]string{f.org: rbac.RoleOwner}},
		"member": {UserID: f.person, EmailVerified: true, AuthMethod: authctx.AuthSSO, Roles: map[uuid.UUID]string{f.org: rbac.RoleMember}},
	}
	q := sqlc.New(pool)
	f.router, err = NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{
		System: q, Orgs: tenancy.NewService(pool), K8s: k8ssvc.NewService(pool), Policy: NewPolicyPort(pool, nil),
		MachineFn: MachineAuth(q), // the production resolver of a `tnxm_` bearer token
		AuthFn: func(r *http.Request) *authctx.Principal {
			if p, ok := humans[r.Header.Get("X-Test-Human")]; ok {
				return p
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *k8sRouteFixture) exec(stmt string, args ...any) {
	f.t.Helper()
	if _, err := f.pool.Exec(context.Background(), stmt, args...); err != nil {
		f.t.Fatalf("exec %q: %v", stmt, err)
	}
}

func (f *k8sRouteFixture) count(stmt string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), stmt, args...).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// machine stores a machine credential as minting does (the SHA-256 of the token) and returns the token.
func (f *k8sRouteFixture) machine(org uuid.UUID, name, role string, owner uuid.UUID) (token string, id uuid.UUID) {
	f.t.Helper()
	id = uuid.New()
	token = machineauth.TokenPrefix + strings.ReplaceAll(id.String(), "-", "")
	hash := sha256.Sum256([]byte(token))
	f.exec(`INSERT INTO machine_credentials (id,org_id,name,role,token_hash,fingerprint,user_id) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		id, org, name, role, hash[:], "fp-"+id.String()[:8], owner)
	return token, id
}

func (f *k8sRouteFixture) do(who k8sRouteCaller, method, path, body string) k8sRouteReply {
	f.t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if who.token != "" {
		req.Header.Set("Authorization", "Bearer "+who.token)
	}
	if who.human != "" {
		req.Header.Set("X-Test-Human", who.human)
	}
	if who.cause != "" {
		req.Header.Set("X-Tunnex-Cause", who.cause)
	}
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	raw, _ := io.ReadAll(rr.Result().Body)
	reply := k8sRouteReply{status: rr.Code, raw: string(raw)}
	if len(raw) > 0 && raw[0] == '[' {
		_ = json.Unmarshal(raw, &reply.list)
	} else if len(raw) > 0 {
		_ = json.Unmarshal(raw, &reply.body)
		if envelope, ok := reply.body["error"].(map[string]any); ok {
			reply.code, _ = envelope["code"].(string)
		}
	}
	return reply
}

func (r k8sRouteReply) want(t *testing.T, what string, status int, code string) k8sRouteReply {
	t.Helper()
	if r.status != status || r.code != code {
		t.Fatalf("%s: got %d %q, want %d %q\n%s", what, r.status, r.code, status, code, r.raw)
	}
	return r
}

func (f *k8sRouteFixture) rulesPath() string {
	return "/api/v1/organizations/" + f.org.String() + "/k8s/clusters/" + f.cluster.String() + "/namespace-rules"
}

// ruleState is the stored rule as "excluded|selector|owner" where owner is the machine credential id or "".
func (f *k8sRouteFixture) ruleState(id string) string {
	f.t.Helper()
	var state string
	err := f.pool.QueryRow(context.Background(), `SELECT array_to_string(excluded_services,',')||'|'||selector::text||'|'||COALESCE(managed_by_machine::text,'')
		FROM k8s_namespace_exposure_rules WHERE id=$1`, id).Scan(&state)
	if err != nil {
		return "gone"
	}
	return state
}

func TestNamespaceRuleOwnershipOverHTTPWithAMachineCredential(t *testing.T) {
	f := newK8sRouteFixture(t)
	if !rbac.Can(rbac.RoleOperator, rbac.PermK8sManage) || rbac.Can(rbac.RoleMember, rbac.PermK8sManage) || !rbac.Can(rbac.RoleMember, rbac.PermOrgView) {
		t.Fatal("fixture: the operator role holds k8s:manage; the member role holds org:view and not k8s:manage")
	}
	operatorToken, operatorID := f.machine(f.org, "gitops", rbac.RoleOperator, f.admin)
	weakToken, _ := f.machine(f.org, "read-only", rbac.RoleMember, f.admin)
	const resource = "tunnexnamespaceexposure:gitops/pay"
	operator := k8sRouteCaller{token: operatorToken, cause: resource}
	weak := k8sRouteCaller{token: weakToken, cause: resource}
	admin := k8sRouteCaller{human: "admin"}
	rules := f.rulesPath()

	// A person makes a rule in the dashboard; the operator declares one from Git.
	byHand := admin.post(f, rules, `{"namespace":"shop"}`).want(t, "a person creates a rule", http.StatusCreated, "")
	if byHand.body["managed_by_operator"] != false {
		t.Fatalf("a person's rule must not be marked: %s", byHand.raw)
	}
	handID := byHand.body["id"].(string)
	declared := operator.post(f, rules, `{"namespace":"pay","selector":{"app":"web"}}`).want(t, "the operator creates a rule", http.StatusCreated, "")
	if declared.body["managed_by_operator"] != true || declared.body["namespace"] != "pay" {
		t.Fatalf("the operator's rule must be marked managed_by_operator: %s", declared.raw)
	}
	gitID := declared.body["id"].(string)
	if got := f.ruleState(gitID); got != `|{"app": "web"}|`+operatorID.String() {
		t.Fatalf("stored operator rule = %q", got)
	}
	// Audited as the operator with the resource as cause, never as a person.
	if n := f.count(`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='k8s.namespace_rule_created' AND target_id=$2
		AND actor_system='operator:gitops' AND actor_user_id IS NULL AND metadata->>'cause'=$3`, f.org, gitID, resource); n != 1 {
		t.Fatalf("the operator's create must be audited as operator:gitops with cause %s (found %d)", resource, n)
	}
	listed := f.do(operator, http.MethodGet, rules, "").want(t, "the operator lists rules", http.StatusOK, "")
	if len(listed.list) != 2 {
		t.Fatalf("listed rules = %s", listed.raw)
	}

	// The operator's credential may change and remove ONLY rules marked managed_by_operator.
	handBefore := f.ruleState(handID)
	operator.patch(f, rules+"/"+handID, `{"excluded_services":["admin"]}`).want(t, "the operator edits a person's rule", http.StatusConflict, "rule_not_managed_by_operator")
	operator.patch(f, rules+"/"+handID, `{"selector":{"app":"web"}}`).want(t, "the operator sets a selector on a person's rule", http.StatusConflict, "rule_not_managed_by_operator")
	for _, exposures := range []string{"keep", "withdraw"} {
		operator.delete(f, rules+"/"+handID+"?exposures="+exposures).want(t, "the operator removes a person's rule ("+exposures+")", http.StatusConflict, "rule_not_managed_by_operator")
	}
	if got := f.ruleState(handID); got != handBefore {
		t.Fatalf("a refused operator call changed a person's rule: %q -> %q", handBefore, got)
	}
	// A second namespace rule for a namespace a person already claimed is refused, not taken over.
	operator.post(f, rules, `{"namespace":"shop"}`).want(t, "the operator creates over a person's rule", http.StatusConflict, "namespace_rule_exists")
	edited := operator.patch(f, rules+"/"+gitID, `{"excluded_services":["admin"]}`).want(t, "the operator edits its own rule", http.StatusOK, "")
	if excluded, _ := edited.body["excluded_services"].([]any); len(excluded) != 1 || excluded[0] != "admin" || edited.body["managed_by_operator"] != true {
		t.Fatalf("the operator's edit = %s", edited.raw)
	}

	// A person may not edit the operator's rule, by either field.
	gitBefore := f.ruleState(gitID)
	admin.patch(f, rules+"/"+gitID, `{"excluded_services":[]}`).want(t, "a person edits the operator's rule", http.StatusConflict, "managed_by_operator")
	admin.patch(f, rules+"/"+gitID, `{"selector":{}}`).want(t, "a person clears the operator's selector", http.StatusConflict, "managed_by_operator")
	if got := f.ruleState(gitID); got != gitBefore {
		t.Fatalf("a refused edit changed the operator's rule: %q -> %q", gitBefore, got)
	}

	// A machine credential without k8s:manage is refused on every write, whatever the rule; it may read.
	weak.post(f, rules, `{"namespace":"cart"}`).want(t, "a credential without k8s:manage creates", http.StatusForbidden, "forbidden")
	weak.patch(f, rules+"/"+gitID, `{"excluded_services":[]}`).want(t, "a credential without k8s:manage edits", http.StatusForbidden, "forbidden")
	weak.delete(f, rules+"/"+gitID+"?exposures=keep").want(t, "a credential without k8s:manage removes", http.StatusForbidden, "forbidden")
	f.do(weak, http.MethodGet, rules, "").want(t, "a credential with org:view lists", http.StatusOK, "")
	// So is a person without it, a token nobody issued, a revoked one, and another organization's operator.
	k8sRouteCaller{human: "member"}.post(f, rules, `{"namespace":"cart"}`).want(t, "a member creates", http.StatusForbidden, "forbidden")
	k8sRouteCaller{token: machineauth.TokenPrefix + "nobody-issued-this"}.post(f, rules, `{"namespace":"cart"}`).want(t, "an unknown token", http.StatusUnauthorized, "unauthenticated")
	k8sRouteCaller{}.post(f, rules, `{"namespace":"cart"}`).want(t, "no credential at all", http.StatusUnauthorized, "unauthenticated")
	revokedToken, revokedID := f.machine(f.org, "revoked", rbac.RoleOperator, f.admin)
	f.exec(`UPDATE machine_credentials SET revoked_at=now() WHERE id=$1`, revokedID)
	k8sRouteCaller{token: revokedToken}.post(f, rules, `{"namespace":"cart"}`).want(t, "a revoked credential", http.StatusUnauthorized, "unauthenticated")
	otherOrg := uuid.New()
	f.exec(`INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'K8N route other',$2,'10.93.0.0/24')`, otherOrg, "k8n-route-o-"+otherOrg.String()[:8])
	t.Cleanup(func() { _, _ = f.pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, otherOrg) })
	f.exec(`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')`, otherOrg, f.admin)
	foreignToken, _ := f.machine(otherOrg, "gitops", rbac.RoleOperator, f.admin)
	foreign := k8sRouteCaller{token: foreignToken}
	foreign.post(f, rules, `{"namespace":"cart"}`).want(t, "another organization's operator creates", http.StatusNotFound, "org_not_found")
	foreign.delete(f, rules+"/"+gitID+"?exposures=keep").want(t, "another organization's operator removes", http.StatusNotFound, "org_not_found")
	if n := f.count(`SELECT count(*) FROM k8s_namespace_exposure_rules WHERE org_id=$1`, f.org); n != 2 || f.ruleState(gitID) != gitBefore {
		t.Fatalf("refused callers changed the rules: count=%d state=%q", n, f.ruleState(gitID))
	}

	// A person may REMOVE the operator's rule: the way out when the operator is gone.
	admin.delete(f, rules+"/"+gitID+"?exposures=keep").want(t, "a person removes the operator's rule", http.StatusNoContent, "")
	if f.ruleState(gitID) != "gone" {
		t.Fatal("the operator's rule is still there after a person removed it")
	}
	if n := f.count(`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='k8s.namespace_rule_deleted' AND target_id=$2 AND actor_user_id=$3
		AND actor_system IS NULL AND metadata->>'managed_by_operator'='true'`, f.org, gitID, f.admin); n != 1 {
		t.Fatalf("a person's removal of the operator's rule must be audited with the person (found %d)", n)
	}
	// And the operator removes a rule it made, with either outcome for its exposures.
	for _, exposures := range []string{"keep", "withdraw"} {
		again := operator.post(f, rules, `{"namespace":"pay"}`).want(t, "the operator declares the rule again", http.StatusCreated, "")
		id := again.body["id"].(string)
		operator.delete(f, rules+"/"+id+"?exposures="+exposures).want(t, "the operator removes its own rule ("+exposures+")", http.StatusNoContent, "")
		if f.ruleState(id) != "gone" {
			t.Fatalf("the operator's own rule is still there (%s)", exposures)
		}
	}
	operator.delete(f, rules+"/"+handID).want(t, "a delete without stating keep or withdraw", http.StatusBadRequest, "validation_failed")
	if f.ruleState(handID) != handBefore {
		t.Fatalf("the person's rule changed: %q", f.ruleState(handID))
	}
}

// K8N-3: a rule whose destination is a cluster's Kubernetes API is refused while API access is off for
// that cluster, whoever asks and for whichever reason it is off: never turned on (no endpoint row), or
// turned on and off again (the endpoint row is kept). The dashboard lists such a cluster as unavailable;
// this is the refusal behind it.
func TestK8sAPIRuleIsRefusedOverHTTPWhileAPIAccessIsOff(t *testing.T) {
	f := newK8sRouteFixture(t)
	operatorToken, _ := f.machine(f.org, "gitops", rbac.RoleOperator, f.admin)
	if !rbac.Can(rbac.RoleOperator, rbac.PermPolicyRuleManage) {
		t.Fatal("fixture: the operator role holds policy_rule:manage (rule authoring)")
	}
	operator := k8sRouteCaller{token: operatorToken, cause: "tunnexgrant:gitops/kubectl"}
	admin := k8sRouteCaller{human: "admin"}
	policies := "/api/v1/organizations/" + f.org.String() + "/policies"
	access := "/api/v1/organizations/" + f.org.String() + "/k8s/clusters/" + f.cluster.String() + "/api-access"
	ruleFor := func(user uuid.UUID) string {
		return `{"src_kind":"user","src_user_id":"` + user.String() + `","dst_kind":"k8s_api","dst_k8s_api_cluster_id":"` + f.cluster.String() + `"}`
	}
	apiRules := func() int {
		return f.count(`SELECT count(*) FROM policy_rules WHERE org_id=$1 AND dst_kind='k8s_api'`, f.org)
	}

	// Never turned on: no endpoint row exists, the read says off, and nobody can write the rule.
	if state := f.do(admin, http.MethodGet, access, "").want(t, "read API access", http.StatusOK, ""); state.body["enabled"] != false || state.body["vip"] != nil {
		t.Fatalf("API access must be off by default: %s", state.raw)
	}
	if n := f.count(`SELECT count(*) FROM k8s_api_endpoints WHERE cluster_id=$1`, f.cluster); n != 0 {
		t.Fatalf("fixture: %d endpoint rows before API access was ever turned on", n)
	}
	admin.post(f, policies, ruleFor(f.person)).want(t, "a person grants an API that was never turned on", http.StatusBadRequest, "k8s_api_not_enabled")
	operator.post(f, policies, ruleFor(f.person)).want(t, "the operator grants an API that was never turned on", http.StatusBadRequest, "k8s_api_not_enabled")
	if apiRules() != 0 {
		t.Fatalf("a refused request wrote %d rules", apiRules())
	}

	// The operator's credential cannot turn it on (that needs k8s_api:manage and a person).
	f.do(operator, http.MethodPut, access, `{"enabled":true}`).want(t, "the operator turns API access on", http.StatusForbidden, "forbidden")
	admin.post(f, policies, ruleFor(f.person)).want(t, "still off after the refused toggle", http.StatusBadRequest, "k8s_api_not_enabled")

	// On: the same request is accepted.
	if state := f.do(admin, http.MethodPut, access, `{"enabled":true}`).want(t, "a person turns API access on", http.StatusOK, ""); state.body["enabled"] != true || state.body["vip"] == nil {
		t.Fatalf("turned on = %s", state.raw)
	}
	created := admin.post(f, policies, ruleFor(f.person)).want(t, "a rule while API access is on", http.StatusCreated, "")
	if created.body["dst_kind"] != "k8s_api" || created.body["dst_k8s_api_access_off"] != false {
		t.Fatalf("created rule = %s", created.raw)
	}

	// Off again: the endpoint row is kept (so the existing rule stays readable) and a new rule is refused.
	if state := f.do(admin, http.MethodPut, access, `{"enabled":false}`).want(t, "a person turns API access off", http.StatusOK, ""); state.body["enabled"] != false || state.body["vip"] != nil {
		t.Fatalf("turned off = %s", state.raw)
	}
	if n := f.count(`SELECT count(*) FROM k8s_api_endpoints WHERE cluster_id=$1 AND NOT enabled AND vip IS NULL`, f.cluster); n != 1 {
		t.Fatalf("the endpoint row must be kept, disabled and without an address (found %d)", n)
	}
	admin.post(f, policies, ruleFor(f.admin)).want(t, "a person grants an API that was turned off", http.StatusBadRequest, "k8s_api_not_enabled")
	operator.post(f, policies, ruleFor(f.admin)).want(t, "the operator grants an API that was turned off", http.StatusBadRequest, "k8s_api_not_enabled")
	if apiRules() != 1 {
		t.Fatalf("rules for the API = %d, want only the one made while it was on", apiRules())
	}
	listed := f.do(admin, http.MethodGet, policies, "").want(t, "list rules", http.StatusOK, "")
	if len(listed.list) != 1 || listed.list[0]["dst_k8s_api_access_off"] != true {
		t.Fatalf("the kept rule must say API access is off: %s", listed.raw)
	}
}

func (who k8sRouteCaller) post(f *k8sRouteFixture, path, body string) k8sRouteReply {
	f.t.Helper()
	return f.do(who, http.MethodPost, path, body)
}

func (who k8sRouteCaller) patch(f *k8sRouteFixture, path, body string) k8sRouteReply {
	f.t.Helper()
	return f.do(who, http.MethodPatch, path, body)
}

func (who k8sRouteCaller) delete(f *k8sRouteFixture, path string) k8sRouteReply {
	f.t.Helper()
	return f.do(who, http.MethodDelete, path, "")
}
