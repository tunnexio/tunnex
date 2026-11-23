package policy_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	k8ssvc "github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

// K8N-3 stage 1, against a database: a rule whose destination is a cluster's Kubernetes API.

type k8sAPIFixture struct {
	fixture
	t         *testing.T
	pool      *pgxpool.Pool
	policy    *policy.Service
	k8s       *k8ssvc.Service
	actor     *authctx.Principal
	site      uuid.UUID
	connector uuid.UUID
	cluster   uuid.UUID
	group     uuid.UUID
}

func seedK8sAPI(t *testing.T) *k8sAPIFixture {
	t.Helper()
	pool := testPool(t)
	f := &k8sAPIFixture{fixture: seed(t, pool), t: t, pool: pool, policy: policy.NewService(pool), k8s: k8ssvc.NewService(pool),
		site: uuid.New(), connector: uuid.New(), cluster: uuid.New(), group: uuid.New()}
	f.actor = &authctx.Principal{UserID: f.user, EmailVerified: true, AuthMethod: authctx.AuthSSO}
	f.exec(`UPDATE organizations SET zero_trust_mode='enforcing' WHERE id=$1`, f.org)
	f.exec(`INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'k8s api site')`, f.site, f.org)
	f.exec(`INSERT INTO nodes (id,org_id,name,cert_serial,site_id,wg_public_key,endpoint,status) VALUES ($1,$2,'cluster-gateway',$3,$4,'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=','172.31.2.10:51820','active')`,
		f.connector, f.org, "k8s-api-"+f.connector.String(), f.site)
	f.exec(`INSERT INTO k8s_clusters (id,org_id,site_id,name,vip_range,dns_zone,dns_vip,connector_node_id) VALUES ($1,$2,$3,'prod','100.66.0.0/24','k8s.acme.com','100.66.0.2',$4)`,
		f.cluster, f.org, f.site, f.connector)
	f.exec(`INSERT INTO user_groups (id,org_id,name) VALUES ($1,$2,'platform')`, f.group, f.org)
	f.exec(`INSERT INTO group_members (org_id,group_id,user_id) VALUES ($1,$2,$3)`, f.org, f.group, f.user)
	return f
}

func (f *k8sAPIFixture) exec(query string, args ...any) {
	f.t.Helper()
	if _, err := f.pool.Exec(context.Background(), query, args...); err != nil {
		f.t.Fatalf("exec %q: %v", query, err)
	}
}

func (f *k8sAPIFixture) apiAccess(enabled bool) k8ssvc.APIAccess {
	f.t.Helper()
	state, err := f.k8s.SetAPIAccess(context.Background(), f.org, f.cluster, enabled, f.actor)
	if err != nil {
		f.t.Fatalf("set API access %v: %v", enabled, err)
	}
	return state
}

func (f *k8sAPIFixture) create(in policyspec.RuleInput) (sqlc.PolicyRule, error) {
	in.DstKind = "k8s_api"
	if in.DstK8sAPIClusterID == nil {
		in.DstK8sAPIClusterID = &f.cluster
	}
	return f.policy.CreatePolicyRule(context.Background(), f.org, in, uuid.Nil, f.user, "", "")
}

// reaches reports whether the device may open TCP 443 to vip on its own gateway AND on the cluster's.
func (f *k8sAPIFixture) reaches(vip string) (device, cluster bool) {
	f.t.Helper()
	snapshot, err := policy.BuildSnapshotWithQueries(context.Background(), sqlc.New(f.pool), f.org)
	if err != nil {
		f.t.Fatalf("build snapshot: %v", err)
	}
	compiled := policy.Compile(snapshot)
	has := func(node uuid.UUID) bool {
		for _, entry := range allowsFor(compiled, node) {
			if entry.SrcIP == "10.99.0.10" && entry.DstCIDR == vip+"/32" && entry.Protocol == policyspec.ProtoTCP && entry.PortLow == 443 && entry.PortHigh == 443 {
				return true
			}
		}
		return false
	}
	return has(f.node), has(f.connector)
}

func (f *k8sAPIFixture) auditMeta(action string, ruleID uuid.UUID) map[string]any {
	f.t.Helper()
	var raw []byte
	if err := f.pool.QueryRow(context.Background(), `SELECT metadata FROM audit_logs WHERE org_id=$1 AND action=$2 AND target_id=$3 ORDER BY created_at DESC LIMIT 1`,
		f.org, action, ruleID.String()).Scan(&raw); err != nil {
		f.t.Fatalf("audit %s for %s: %v", action, ruleID, err)
	}
	meta := map[string]any{}
	if err := json.Unmarshal(raw, &meta); err != nil {
		f.t.Fatal(err)
	}
	return meta
}

func (f *k8sAPIFixture) namesTheCluster(action string, ruleID uuid.UUID) {
	f.t.Helper()
	meta := f.auditMeta(action, ruleID)
	if meta["dst_kind"] != "k8s_api" || meta["dst_k8s_api_cluster"] != "prod" || meta["dst_k8s_api_cluster_id"] != f.cluster.String() {
		f.t.Fatalf("%s must name the destination (Kubernetes API of prod), got %v", action, meta)
	}
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), code) {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func TestK8sAPIRuleNeedsAPIAccessOnAndAPersonOrAGroup(t *testing.T) {
	f := seedK8sAPI(t)

	// Off (never enabled): refused, and nothing is created.
	_, err := f.create(policyspec.RuleInput{SrcKind: "group", SrcGroupID: f.group})
	wantCode(t, err, "k8s_api_not_enabled")
	// An unknown cluster, and another organization's cluster, are both "not found".
	unknown := uuid.New()
	_, err = f.create(policyspec.RuleInput{SrcKind: "group", SrcGroupID: f.group, DstK8sAPIClusterID: &unknown})
	wantCode(t, err, "k8s_cluster_not_found")
	other := seedK8sAPI(t)
	other.apiAccess(true)
	_, err = f.create(policyspec.RuleInput{SrcKind: "group", SrcGroupID: f.group, DstK8sAPIClusterID: &other.cluster})
	wantCode(t, err, "k8s_cluster_not_found")

	f.apiAccess(true)

	// People and groups only.
	site, cidr, agent := f.site, "10.20.0.7/32", f.device
	_, err = f.create(policyspec.RuleInput{SrcKind: "site", SrcSiteID: &site})
	wantCode(t, err, "k8s_api_source_not_allowed")
	_, err = f.create(policyspec.RuleInput{SrcKind: "cidr", SrcCIDR: &cidr})
	wantCode(t, err, "k8s_api_source_not_allowed")
	_, err = f.create(policyspec.RuleInput{SrcKind: "agent", SrcAgentDeviceID: &agent})
	wantCode(t, err, "k8s_api_source_not_allowed")
	// Shape: the cluster is required, and it is the only destination.
	_, err = f.policy.CreatePolicyRule(context.Background(), f.org, policyspec.RuleInput{SrcKind: "group", SrcGroupID: f.group, DstKind: "k8s_api"}, uuid.Nil, f.user, "", "")
	wantCode(t, err, "dst_k8s_api_cluster_id")
	_, err = f.create(policyspec.RuleInput{SrcKind: "group", SrcGroupID: f.group, DstSiteID: &site})
	wantCode(t, err, "invalid_request")
	_, err = f.policy.CreatePolicyRule(context.Background(), f.org, policyspec.RuleInput{SrcKind: "group", SrcGroupID: f.group, DstKind: "site", DstSiteID: &site, DstK8sAPIClusterID: &f.cluster}, uuid.Nil, f.user, "", "")
	wantCode(t, err, "invalid_request")
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM policy_rules WHERE org_id=$1`, f.org).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a refused request created %d rules (err=%v)", n, err)
	}

	// The database refuses the same thing whatever wrote the row.
	var endpoint uuid.UUID
	if err := f.pool.QueryRow(context.Background(), `SELECT id FROM k8s_api_endpoints WHERE cluster_id=$1`, f.cluster).Scan(&endpoint); err != nil {
		t.Fatal(err)
	}
	for name, insert := range map[string]string{
		"site":  `INSERT INTO policy_rules(org_id,src_kind,src_site_id,dst_kind,dst_k8s_api_endpoint_id) VALUES($1,'site',$2,'k8s_api',$3)`,
		"agent": `INSERT INTO policy_rules(org_id,src_kind,src_device_id,dst_kind,dst_k8s_api_endpoint_id) VALUES($1,'agent',$2,'k8s_api',$3)`,
	} {
		subject := f.site
		if name == "agent" {
			subject = f.device
		}
		if _, err := f.pool.Exec(context.Background(), insert, f.org, subject, endpoint); err == nil || !strings.Contains(err.Error(), "policy_rules_k8s_api_people_only") {
			t.Fatalf("the database must refuse a %s source for a Kubernetes API rule, got %v", name, err)
		}
	}

	// A group and a person are accepted; an identical rule is a conflict.
	groupRule, err := f.create(policyspec.RuleInput{SrcKind: "group", SrcGroupID: f.group})
	if err != nil {
		t.Fatal(err)
	}
	if groupRule.DstKind != "k8s_api" || !groupRule.DstK8sApiEndpointID.Valid || uuid.UUID(groupRule.DstK8sApiEndpointID.Bytes) != endpoint || groupRule.DstK8sServiceID.Valid || groupRule.DstK8sClusterID.Valid {
		t.Fatalf("stored rule = %+v", groupRule)
	}
	if _, err := f.create(policyspec.RuleInput{SrcKind: "user", SrcUserID: &f.user}); err != nil {
		t.Fatal(err)
	}
	_, err = f.create(policyspec.RuleInput{SrcKind: "group", SrcGroupID: f.group})
	wantCode(t, err, "conflict")
	f.namesTheCluster("policy.rule_created", groupRule.ID)

	// The list read carries the destination back.
	rules, err := f.policy.ListPolicyRules(context.Background(), f.org)
	if err != nil || len(rules) != 2 {
		t.Fatalf("rules = %+v err=%v", rules, err)
	}
	for _, rule := range rules {
		if rule.DstKind != "k8s_api" || !rule.DstK8sApiEndpointID.Valid || uuid.UUID(rule.DstK8sApiEndpointID.Bytes) != endpoint {
			t.Fatalf("listed rule lost its destination: %+v", rule)
		}
	}
}

func TestK8sAPIRuleCompilesDeniesExpiresAndFollowsAPIAccess(t *testing.T) {
	f := seedK8sAPI(t)
	ctx := context.Background()
	state := f.apiAccess(true)

	// Default deny: API access on, no rule, no path.
	if device, cluster := f.reaches(state.VIP); device || cluster {
		t.Fatal("no rule must mean no path to the API address")
	}

	// A temporary grant: it works until it expires, as for any rule.
	expires := time.Now().Add(time.Hour)
	rule, err := f.create(policyspec.RuleInput{SrcKind: "group", SrcGroupID: f.group, ExpiresAt: &expires})
	if err != nil {
		t.Fatal(err)
	}
	if device, cluster := f.reaches(state.VIP); !device || !cluster {
		t.Fatalf("the rule must open TCP 443 on the device's gateway and the cluster's: device=%v cluster=%v", device, cluster)
	}

	// Disable and re-enable.
	if _, err := f.policy.SetPolicyRuleEnabled(f.ctx, f.org, rule.ID, false); err != nil {
		t.Fatal(err)
	}
	if device, cluster := f.reaches(state.VIP); device || cluster {
		t.Fatal("a disabled rule must allow nothing")
	}
	f.namesTheCluster("policy.rule_disabled", rule.ID)
	if _, err := f.policy.SetPolicyRuleEnabled(f.ctx, f.org, rule.ID, true); err != nil {
		t.Fatal(err)
	}

	// API access off: the rule is kept and compiles to nothing. On again: it takes effect again.
	f.apiAccess(false)
	if device, cluster := f.reaches(state.VIP); device || cluster {
		t.Fatal("with API access off the kept rule must allow nothing")
	}
	var kept int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM policy_rules WHERE id=$1`, rule.ID).Scan(&kept); err != nil || kept != 1 {
		t.Fatalf("turning API access off must keep the rule (have %d, err=%v)", kept, err)
	}
	// A new rule cannot be written while it is off.
	_, err = f.create(policyspec.RuleInput{SrcKind: "user", SrcUserID: &f.user})
	wantCode(t, err, "k8s_api_not_enabled")
	state = f.apiAccess(true)
	if device, cluster := f.reaches(state.VIP); !device || !cluster {
		t.Fatal("turning API access back on must bring the kept rule back")
	}

	// Expiry: the compiler stops honouring it at once, and the sweep deletes and audits it by name.
	f.exec(`UPDATE policy_rules SET expires_at=now()-interval '1 minute' WHERE id=$1`, rule.ID)
	if device, cluster := f.reaches(state.VIP); device || cluster {
		t.Fatal("an expired grant must allow nothing")
	}
	if n, err := f.policy.SweepExpiredGrants(ctx); err != nil || n < 1 {
		t.Fatalf("sweep = %d err=%v", n, err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM policy_rules WHERE id=$1`, rule.ID).Scan(&kept); err != nil || kept != 0 {
		t.Fatalf("the expired grant must be deleted (have %d, err=%v)", kept, err)
	}
	f.namesTheCluster("policy.grant_expired", rule.ID)

	// Delete names the cluster too.
	permanent, err := f.create(policyspec.RuleInput{SrcKind: "user", SrcUserID: &f.user})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.policy.DeletePolicyRule(ctx, f.org, permanent.ID, f.user, "", ""); err != nil {
		t.Fatal(err)
	}
	f.namesTheCluster("policy.rule_deleted", permanent.ID)
	// An ordinary rule's delete entry is unchanged: nothing is added to it.
	resource := uuid.New()
	f.exec(`INSERT INTO resources (id,org_id,name,cidr) VALUES ($1,$2,'db','10.0.5.0/24')`, resource, f.org)
	ordinary, err := f.policy.CreatePolicyRule(ctx, f.org, policyspec.RuleInput{SrcKind: "group", SrcGroupID: f.group, DstKind: "resource", DstResourceID: &resource}, uuid.Nil, f.user, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.policy.DeletePolicyRule(ctx, f.org, ordinary.ID, f.user, "", ""); err != nil {
		t.Fatal(err)
	}
	if meta := f.auditMeta("policy.rule_deleted", ordinary.ID); len(meta) != 0 {
		t.Fatalf("an ordinary rule's delete entry must be as before, got %v", meta)
	}
}

// Deregistering the cluster removes its API endpoint and the rules that named it, and says how many.
func TestDeregisteringAClusterRemovesItsAPIRulesAndCountsThem(t *testing.T) {
	f := seedK8sAPI(t)
	ctx := context.Background()
	f.apiAccess(true)
	if _, err := f.create(policyspec.RuleInput{SrcKind: "group", SrcGroupID: f.group}); err != nil {
		t.Fatal(err)
	}
	if err := f.k8s.DeregisterCluster(ctx, f.user, "", "", f.org, f.cluster); err != nil {
		t.Fatal(err)
	}
	var endpoints, rules int
	if err := f.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM k8s_api_endpoints WHERE cluster_id=$1), (SELECT count(*) FROM policy_rules WHERE org_id=$2 AND dst_kind='k8s_api')`, f.cluster, f.org).Scan(&endpoints, &rules); err != nil {
		t.Fatal(err)
	}
	if endpoints != 0 || rules != 0 {
		t.Fatalf("after deregistration: endpoints=%d rules=%d, want 0 and 0", endpoints, rules)
	}
	var raw []byte
	if err := f.pool.QueryRow(ctx, `SELECT metadata FROM audit_logs WHERE org_id=$1 AND action='k8s.cluster_deregistered' AND target_id=$2`, f.org, f.cluster.String()).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	meta := map[string]any{}
	_ = json.Unmarshal(raw, &meta)
	if meta["api_access_was_on"] != true || meta["api_rules_deleted"] != float64(1) {
		t.Fatalf("the deregistration entry must count what the cascade removed, got %v", meta)
	}
}
