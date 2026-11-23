package k8s

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
)

// K8N-4 database proof. The gateway's reports are seeded as rows; nothing here needs a cluster.

type nsRuleFixture struct {
	t       *testing.T
	pool    *pgxpool.Pool
	svc     *Service
	org     uuid.UUID
	site    uuid.UUID
	node    uuid.UUID
	cluster uuid.UUID
	replay  uuid.UUID
	ledger  uuid.UUID
	seq     int64
	actor   *authctx.Principal
}

type nsSvc struct {
	namespace, name string
	ports           []int32
}

const nsRuleDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func newNSRuleFixture(t *testing.T, vipRange string) *nsRuleFixture {
	t.Helper()
	pool := testPool(t)
	org, site, actorID := seedOrgSiteActor(t, pool)
	f := &nsRuleFixture{t: t, pool: pool, svc: NewService(pool), org: org, site: site, node: uuid.New(), cluster: uuid.New(), replay: uuid.New(), ledger: uuid.New(),
		actor: &authctx.Principal{UserID: actorID, EmailVerified: true, AuthMethod: authctx.AuthSSO}}
	f.exec(`INSERT INTO nodes(id,org_id,site_id,name,cert_serial,status,wg_public_key,endpoint)
		VALUES($1,$2,$3,'ns-connector',$4,'active','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=','172.31.20.10:51820')`, f.node, org, site, "ns-"+f.node.String())
	f.exec(`INSERT INTO k8s_clusters(id,org_id,site_id,name,vip_range,connector_node_id) VALUES($1,$2,$3,'prod',$4,$5)`, f.cluster, org, site, vipRange, f.node)
	f.exec(`INSERT INTO k8s_service_uid_observation_replay_states(id,org_id,site_id,cluster_id,connector_node_id,scope_identity) VALUES($1,$2,$3,$4,$5,'scope')`,
		f.replay, org, site, f.cluster, f.node)
	f.exec(`INSERT INTO k8s_service_uid_observation_ledgers(id,org_id,site_id,cluster_id,scope_identity) VALUES($1,$2,$3,$4,'scope')`, f.ledger, org, site, f.cluster)
	return f
}

func (f *nsRuleFixture) exec(query string, args ...any) {
	f.t.Helper()
	if _, err := f.pool.Exec(context.Background(), query, args...); err != nil {
		f.t.Fatalf("exec %q: %v", query, err)
	}
}

// report stores the next gateway report. age>0 makes it a report received that long ago (so stale).
func (f *nsRuleFixture) report(age time.Duration, services ...nsSvc) {
	f.t.Helper()
	ctx := context.Background()
	f.seq++
	reportID := uuid.New()
	received := time.Now().UTC().Add(-age)
	f.exec(`UPDATE k8s_service_uid_observation_replay_states SET sequence=$2,digest=$3 WHERE id=$1`, f.replay, f.seq, nsRuleDigest)
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO k8s_service_inventory_reports
		(id,org_id,site_id,cluster_id,connector_node_id,replay_state_id,replay_sequence,promotion_generation,digest,service_count,observed_at,received_at,fresh_until)
		VALUES($1,$2,$3,$4,$5,$6,$7,0,$8,$9,$10,$10,$11)`, reportID, f.org, f.site, f.cluster, f.node, f.replay, f.seq, nsRuleDigest, len(services), received, received.Add(90*time.Second)); err != nil {
		f.t.Fatalf("inventory report: %v", err)
	}
	for _, service := range services {
		// The UID ledger must name this Service as live at this report's sequence, as the real writer does.
		if _, err := tx.Exec(ctx, `INSERT INTO k8s_service_uid_observation_current(ledger_id,org_id,namespace,service,uid,state,replay_sequence)
			VALUES($1,$2,$3,$4,$5,'live',$6)
			ON CONFLICT (ledger_id,namespace,service) DO UPDATE SET uid=EXCLUDED.uid,state='live',replay_sequence=EXCLUDED.replay_sequence`,
			f.ledger, f.org, service.namespace, service.name, "uid-"+service.namespace+"-"+service.name, f.seq); err != nil {
			f.t.Fatalf("uid ledger: %v", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO k8s_service_uid_observation_current_attributions(ledger_id,org_id,namespace,service,replay_state_id,replay_sequence)
			VALUES($1,$2,$3,$4,$5,$6)
			ON CONFLICT (ledger_id,namespace,service) DO UPDATE SET replay_state_id=EXCLUDED.replay_state_id,replay_sequence=EXCLUDED.replay_sequence`,
			f.ledger, f.org, service.namespace, service.name, f.replay, f.seq); err != nil {
			f.t.Fatalf("uid attribution: %v", err)
		}
		var ref uuid.UUID
		if err := tx.QueryRow(ctx, `INSERT INTO k8s_service_inventory_items(report_id,org_id,cluster_id,namespace,service,service_uid,port_count)
			VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING inventory_ref`, reportID, f.org, f.cluster, service.namespace, service.name, "uid-"+service.namespace+"-"+service.name, len(service.ports)).Scan(&ref); err != nil {
			f.t.Fatalf("inventory item: %v", err)
		}
		for _, port := range service.ports {
			if _, err := tx.Exec(ctx, `INSERT INTO k8s_service_inventory_ports(report_id,inventory_ref,protocol,service_port) VALUES($1,$2,'tcp',$3)`, reportID, ref, port); err != nil {
				f.t.Fatalf("inventory port: %v", err)
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		f.t.Fatalf("inventory commit: %v", err)
	}
}

func (f *nsRuleFixture) reconcileAt(at time.Time) {
	f.t.Helper()
	if err := f.svc.reconcileNamespaceRulesAt(context.Background(), f.org, f.cluster, at); err != nil {
		f.t.Fatalf("reconcile: %v", err)
	}
}

// live returns "namespace/name:port" → "owner@vip" for every live exposure of the cluster; owner is
// "rule", "operator" or "manual".
func (f *nsRuleFixture) live() map[string]string {
	f.t.Helper()
	rows, err := f.pool.Query(context.Background(), `SELECT namespace||'/'||name||':'||port_low,
		CASE WHEN e.rule_id IS NOT NULL THEN 'rule' WHEN managed_by_machine IS NOT NULL THEN 'operator' ELSE 'manual' END||'@'||host(vip)
		FROM k8s_services s LEFT JOIN k8s_namespace_rule_exposures e ON e.service_id=s.id WHERE s.cluster_id=$1 AND s.deleted_at IS NULL`, f.cluster)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			f.t.Fatal(err)
		}
		out[key] = value
	}
	return out
}

func (f *nsRuleFixture) liveKeys() string {
	live := f.live()
	keys := make([]string, 0, len(live))
	for key, value := range live {
		keys = append(keys, key+"="+value[:strings.Index(value, "@")])
	}
	sort.Strings(keys)
	return strings.Join(keys, " ")
}

func (f *nsRuleFixture) rule(namespace string) NamespaceRule {
	f.t.Helper()
	rules, err := f.svc.ListNamespaceRules(context.Background(), f.org, f.cluster)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, rule := range rules {
		if rule.Namespace == namespace {
			return rule
		}
	}
	f.t.Fatalf("no rule for %s in %+v", namespace, rules)
	return NamespaceRule{}
}

func (f *nsRuleFixture) count(query string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func TestNamespaceRuleExposesOnlyItsNamespaceAndGrantsNothing(t *testing.T) {
	f := newNSRuleFixture(t, "100.66.0.0/24")
	ctx := context.Background()
	f.report(0,
		nsSvc{"shop", "web", []int32{80, 443}}, nsSvc{"shop", "api", []int32{8080}},
		nsSvc{"billing", "ledger", []int32{5432}}, nsSvc{"kube-system", "kube-dns", []int32{53}})

	rule, err := f.svc.CreateNamespaceRule(ctx, f.org, f.cluster, NamespaceRuleInput{Namespace: "shop"}, f.actor)
	if err != nil {
		t.Fatal(err)
	}
	if rule.Status != NamespaceRuleOK || rule.ExposedServices != 2 || rule.ExposedPorts != 3 || rule.WaitingServices != 0 || rule.LastReconciledAt == nil {
		t.Fatalf("rule after first pass = %+v", rule)
	}
	if got := f.liveKeys(); got != "shop/api:8080=rule shop/web:443=rule shop/web:80=rule" {
		t.Fatalf("live exposures = %q; billing and kube-system must not be exposed", got)
	}
	live := f.live()
	if live["shop/web:80"] != live["shop/web:443"] || live["shop/web:80"] == live["shop/api:8080"] {
		t.Fatalf("one address per Service expected: %v", live)
	}
	// Exposure never grants access: no access rule and no scope membership was created.
	if n := f.count(`SELECT count(*) FROM policy_rules WHERE org_id=$1`, f.org); n != 0 {
		t.Fatalf("a namespace rule created %d access rules", n)
	}
	if n := f.count(`SELECT count(*) FROM k8s_cluster_scope_memberships WHERE org_id=$1 AND status<>'pending'`, f.org); n != 0 {
		t.Fatalf("a namespace rule approved %d scope memberships", n)
	}
	// Every automatic exposure is audited as the system actor with the rule as its cause.
	if n := f.count(`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='k8s.service_exposed' AND actor_system='k8s-namespace-rule'
		AND actor_user_id IS NULL AND metadata->>'cause'=$2 AND metadata->>'namespace_rule_id'=$3`, f.org, "namespace_rule:"+rule.ID.String(), rule.ID.String()); n != 3 {
		t.Fatalf("system-actor exposure audits = %d, want 3", n)
	}
	if n := f.count(`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='k8s.namespace_rule_created' AND actor_user_id=$2`, f.org, f.actor.UserID); n != 1 {
		t.Fatalf("human rule-created audits = %d", n)
	}

	// A Service added later is exposed by the next report's pass; a second pass changes nothing.
	f.report(0, nsSvc{"shop", "web", []int32{80, 443}}, nsSvc{"shop", "api", []int32{8080}}, nsSvc{"shop", "cart", []int32{9090}}, nsSvc{"billing", "ledger", []int32{5432}})
	if err := f.svc.ReconcileNamespaceRulesForOrg(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.ReconcileNamespaceRulesForOrg(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if got := f.liveKeys(); got != "shop/api:8080=rule shop/cart:9090=rule shop/web:443=rule shop/web:80=rule" {
		t.Fatalf("after a Service was added: %q", got)
	}

	// Removing one of the rule's exposures by hand is refused: the rule would put it back.
	var cartID uuid.UUID
	if err := f.pool.QueryRow(ctx, `SELECT id FROM k8s_services WHERE cluster_id=$1 AND name='cart' AND deleted_at IS NULL`, f.cluster).Scan(&cartID); err != nil {
		t.Fatal(err)
	}
	assertScopeAPIError(t, f.svc.UnexposeService(ctx, f.actor.UserID, "", "", f.org, cartID), http.StatusConflict, "managed_by_namespace_rule")
}

func TestNamespaceRuleRefusals(t *testing.T) {
	f := newNSRuleFixture(t, "100.66.0.0/24")
	ctx := context.Background()
	for _, namespace := range []string{"kube-system", "kube-public", "kube-node-lease", "tunnex-system", "tunnex", "tunnex-gitops"} {
		_, err := f.svc.CreateNamespaceRule(ctx, f.org, f.cluster, NamespaceRuleInput{Namespace: namespace}, f.actor)
		assertScopeAPIError(t, err, http.StatusBadRequest, "namespace_not_eligible")
	}
	for _, namespace := range []string{"", "*", "shop,billing"} {
		_, err := f.svc.CreateNamespaceRule(ctx, f.org, f.cluster, NamespaceRuleInput{Namespace: namespace}, f.actor)
		assertScopeAPIError(t, err, http.StatusBadRequest, "invalid_namespace")
	}
	// The database refuses a system namespace even past the API.
	for _, namespace := range []string{"kube-system", "tunnex-system", "tunnex-anything"} {
		if _, err := f.pool.Exec(ctx, `INSERT INTO k8s_namespace_exposure_rules(org_id,cluster_id,namespace) VALUES($1,$2,$3)`, f.org, f.cluster, namespace); err == nil {
			t.Fatalf("database accepted a rule for %s", namespace)
		}
	}
	// A machine credential with no current owner, an agent and a gateway never create a rule. (What an
	// owned operator credential may do is slice C's test.)
	ownerless := &authctx.Principal{MachineID: uuid.New(), MachineName: "gitops", AuthMethod: authctx.AuthMachine}
	_, err := f.svc.CreateNamespaceRule(ctx, f.org, f.cluster, NamespaceRuleInput{Namespace: "shop"}, ownerless)
	assertScopeAPIError(t, err, http.StatusForbidden, "actor_required")
	for _, notAnAdmin := range []*authctx.Principal{nil, {UserID: f.actor.UserID, EmailVerified: true, AuthMethod: authctx.AuthAgent}, {UserID: f.actor.UserID, EmailVerified: true, NodeID: uuid.New()}, {}} {
		_, err = f.svc.CreateNamespaceRule(ctx, f.org, f.cluster, NamespaceRuleInput{Namespace: "shop"}, notAnAdmin)
		assertScopeAPIError(t, err, http.StatusForbidden, "human_actor_required")
	}
	_, err = f.svc.CreateNamespaceRule(ctx, f.org, f.cluster, NamespaceRuleInput{Namespace: "shop"}, &authctx.Principal{UserID: f.actor.UserID})
	assertScopeAPIError(t, err, http.StatusForbidden, "email_not_verified")
	_, err = f.svc.CreateNamespaceRule(ctx, f.org, uuid.New(), NamespaceRuleInput{Namespace: "shop"}, f.actor)
	assertScopeAPIError(t, err, http.StatusNotFound, "cluster_not_found")

	// No report yet: the rule exists, says why nothing happened, and exposed nothing.
	rule, err := f.svc.CreateNamespaceRule(ctx, f.org, f.cluster, NamespaceRuleInput{Namespace: "shop"}, f.actor)
	if err != nil {
		t.Fatal(err)
	}
	if rule.Status != NamespaceRuleInventoryUnavailable || rule.StatusMessage == "" || len(f.live()) != 0 {
		t.Fatalf("rule without a report = %+v live=%v", rule, f.live())
	}
	_, err = f.svc.CreateNamespaceRule(ctx, f.org, f.cluster, NamespaceRuleInput{Namespace: "shop"}, f.actor)
	assertScopeAPIError(t, err, http.StatusConflict, "namespace_rule_exists")
}

func TestNamespaceRuleWithdrawsOnlyItsOwnAfterTheWaitAndKeepsAccessRules(t *testing.T) {
	f := newNSRuleFixture(t, "100.66.0.0/24")
	ctx := context.Background()
	// shop/web:80 is exposed by hand and shop/metrics:9100 by the operator before the rule exists.
	manual, err := f.svc.ExposeService(ctx, f.org, f.cluster, "web", "shop", "tcp", p32(80), p32(80), uuid.Nil, f.actor.UserID, "", "")
	if err != nil {
		t.Fatal(err)
	}
	machine := uuid.New()
	f.exec(`INSERT INTO machine_credentials(id,org_id,name,token_hash,fingerprint) VALUES($1,$2,'gitops',$3,$4)`, machine, f.org, machine[:], "fp-"+machine.String())
	operatorRow, err := f.svc.ExposeService(ctx, f.org, f.cluster, "metrics", "shop", "tcp", p32(9100), p32(9100), machine, uuid.Nil, "operator:gitops", "cr")
	if err != nil {
		t.Fatal(err)
	}
	all := []nsSvc{{"shop", "web", []int32{80, 443}}, {"shop", "metrics", []int32{9100}}, {"shop", "api", []int32{8080}}}
	f.report(0, all...)
	rule, err := f.svc.CreateNamespaceRule(ctx, f.org, f.cluster, NamespaceRuleInput{Namespace: "shop"}, f.actor)
	if err != nil {
		t.Fatal(err)
	}
	// Not adopted: the hand-made and operator rows keep their owner; the rule only fills the gaps and
	// puts web:443 on web's existing address.
	if got := f.liveKeys(); got != "shop/api:8080=rule shop/metrics:9100=operator shop/web:443=rule shop/web:80=manual" {
		t.Fatalf("after the first pass: %q", got)
	}
	if live := f.live(); live["shop/web:443"] != "rule@"+manual.Vip.String() {
		t.Fatalf("web:443 must share web's address %s: %v", manual.Vip, live)
	}
	if rule.ExposedPorts != 2 {
		t.Fatalf("the rule owns 2 ports, got %+v", rule)
	}

	// An access rule points at the rule-made exposure of shop/api.
	var apiID uuid.UUID
	if err := f.pool.QueryRow(ctx, `SELECT id FROM k8s_services WHERE cluster_id=$1 AND name='api' AND deleted_at IS NULL`, f.cluster).Scan(&apiID); err != nil {
		t.Fatal(err)
	}
	grant := uuid.New()
	f.exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, f.org, f.actor.UserID)
	f.exec(`INSERT INTO policy_rules(id,org_id,src_kind,src_user_id,dst_kind,dst_k8s_service_id) VALUES($1,$2,'user',$3,'k8s_service',$4)`, grant, f.org, f.actor.UserID, apiID)

	// Every Service of the namespace disappears from the reports.
	t0 := time.Now().UTC()
	f.report(0, nsSvc{"billing", "ledger", []int32{5432}})
	f.reconcileAt(t0)
	if got := f.liveKeys(); got != "shop/api:8080=rule shop/metrics:9100=operator shop/web:443=rule shop/web:80=manual" {
		t.Fatalf("a first missing report must withdraw nothing: %q", got)
	}
	if n := f.count(`SELECT count(*) FROM k8s_namespace_rule_exposures e JOIN k8s_services s ON s.id=e.service_id WHERE s.cluster_id=$1 AND e.missing_since IS NOT NULL`, f.cluster); n != 2 {
		t.Fatalf("rows marked missing = %d, want the rule's 2 (never the manual or operator row)", n)
	}
	f.reconcileAt(t0.Add(NamespaceRuleWithdrawWait - time.Minute))
	if n := len(f.live()); n != 4 {
		t.Fatalf("inside the wait nothing is withdrawn, live=%d", n)
	}

	// api comes back before the wait is over: its mark is cleared, same exposure id, the grant still points at it.
	f.report(0, nsSvc{"shop", "api", []int32{8080}})
	f.reconcileAt(t0.Add(NamespaceRuleWithdrawWait - time.Minute))
	if n := f.count(`SELECT count(*) FROM k8s_services s JOIN k8s_namespace_rule_exposures e ON e.service_id=s.id WHERE s.id=$1 AND s.deleted_at IS NULL AND e.missing_since IS NULL`, apiID); n != 1 {
		t.Fatal("a Service that came back must keep its exposure and lose the missing mark")
	}

	// Past the wait: web:443 (the rule's) is withdrawn; web:80 (manual) and metrics (operator) are not.
	f.reconcileAt(t0.Add(NamespaceRuleWithdrawWait + time.Second))
	if got := f.liveKeys(); got != "shop/api:8080=rule shop/metrics:9100=operator shop/web:80=manual" {
		t.Fatalf("after the wait: %q", got)
	}

	// api disappears for good. Its exposure is withdrawn after the wait; the access rule is KEPT and
	// still points at the withdrawn exposure, which the compiler no longer resolves.
	f.report(0, nsSvc{"billing", "ledger", []int32{5432}})
	t1 := t0.Add(time.Hour)
	f.reconcileAt(t1)
	f.reconcileAt(t1.Add(NamespaceRuleWithdrawWait))
	if got := f.liveKeys(); got != "shop/metrics:9100=operator shop/web:80=manual" {
		t.Fatalf("after api was withdrawn: %q", got)
	}
	if n := f.count(`SELECT count(*) FROM policy_rules WHERE id=$1 AND dst_k8s_service_id=$2`, grant, apiID); n != 1 {
		t.Fatal("the access rule that pointed at the withdrawn exposure must be kept")
	}
	liveIDs, err := f.svc.LiveServiceIDs(ctx, f.org)
	if err != nil {
		t.Fatal(err)
	}
	if liveIDs[apiID] || !liveIDs[manual.ID] || !liveIDs[operatorRow.ID] {
		t.Fatalf("live ids after withdrawal = %v", liveIDs)
	}
	if n := f.count(`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='k8s.service_unexposed' AND actor_system='k8s-namespace-rule'
		AND metadata->>'reason'='service_not_reported'`, f.org); n != 2 {
		t.Fatalf("system-actor withdrawal audits = %d, want 2", n)
	}

	// The Service returns: a NEW exposure with a new id. The old access rule does not come back to life.
	f.report(0, nsSvc{"shop", "api", []int32{8080}})
	f.reconcileAt(t1.Add(2 * NamespaceRuleWithdrawWait))
	var newAPIID uuid.UUID
	if err := f.pool.QueryRow(ctx, `SELECT id FROM k8s_services WHERE cluster_id=$1 AND name='api' AND deleted_at IS NULL`, f.cluster).Scan(&newAPIID); err != nil {
		t.Fatal(err)
	}
	if newAPIID == apiID {
		t.Fatal("a returning Service must get a new exposure id")
	}
	if n := f.count(`SELECT count(*) FROM policy_rules WHERE org_id=$1 AND dst_k8s_service_id=$2`, f.org, newAPIID); n != 0 {
		t.Fatal("the old access rule must not follow the new exposure")
	}
}

func TestNamespaceRuleFullRangeExposesNothingAndSaysWhy(t *testing.T) {
	// A /29 has five usable addresses (.2 to .6).
	f := newNSRuleFixture(t, "100.66.9.0/29")
	ctx := context.Background()
	six := []nsSvc{{"shop", "a", []int32{80}}, {"shop", "b", []int32{80}}, {"shop", "c", []int32{80}}, {"shop", "d", []int32{80}}, {"shop", "e", []int32{80}}, {"shop", "f", []int32{80}}}
	f.report(0, six...)
	rule, err := f.svc.CreateNamespaceRule(ctx, f.org, f.cluster, NamespaceRuleInput{Namespace: "shop"}, f.actor)
	if err != nil {
		t.Fatal(err)
	}
	if rule.Status != NamespaceRuleVIPRangeExhausted || rule.WaitingServices != 6 || rule.ExposedPorts != 0 || !strings.Contains(rule.StatusMessage, "100.66.9.0/29") {
		t.Fatalf("rule on a full range = %+v", rule)
	}
	if n := len(f.live()); n != 0 {
		t.Fatalf("a pass that cannot expose everything must expose nothing, live=%d", n)
	}
	if n := f.count(`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='k8s.service_exposed'`, f.org); n != 0 {
		t.Fatalf("rolled-back exposures left %d audit rows", n)
	}
	// Once it fits, the next report's pass exposes all of it and the reason clears.
	f.report(0, six[:5]...)
	f.reconcileAt(time.Now().UTC())
	rule = f.rule("shop")
	if rule.Status != NamespaceRuleOK || rule.WaitingServices != 0 || rule.ExposedServices != 5 || rule.StatusMessage != "" {
		t.Fatalf("rule once it fits = %+v", rule)
	}
}

func TestNamespaceRuleDoesNothingWithoutAFreshReport(t *testing.T) {
	f := newNSRuleFixture(t, "100.66.0.0/24")
	ctx := context.Background()
	f.report(0, nsSvc{"shop", "web", []int32{80}})
	if _, err := f.svc.CreateNamespaceRule(ctx, f.org, f.cluster, NamespaceRuleInput{Namespace: "shop"}, f.actor); err != nil {
		t.Fatal(err)
	}
	// The newest report is ten minutes old and lists nothing. It is not current, so it proves nothing:
	// no exposure is marked missing or withdrawn however much time passes.
	f.report(10 * time.Minute)
	f.reconcileAt(time.Now().UTC().Add(24 * time.Hour))
	if got := f.liveKeys(); got != "shop/web:80=rule" {
		t.Fatalf("a stale report changed exposures: %q", got)
	}
	if n := f.count(`SELECT count(*) FROM k8s_namespace_rule_exposures e JOIN k8s_services s ON s.id=e.service_id WHERE s.cluster_id=$1 AND e.missing_since IS NOT NULL`, f.cluster); n != 0 {
		t.Fatal("a stale report marked an exposure missing")
	}
	if rule := f.rule("shop"); rule.Status != NamespaceRuleInventoryStale || rule.StatusMessage == "" {
		t.Fatalf("rule with a stale report = %+v", rule)
	}
	var stored string
	if err := f.pool.QueryRow(ctx, `SELECT status FROM k8s_namespace_exposure_rules WHERE cluster_id=$1`, f.cluster).Scan(&stored); err != nil || stored != NamespaceRuleInventoryStale {
		t.Fatalf("stored status = %q err=%v", stored, err)
	}
}

func TestDeleteNamespaceRuleKeepOrWithdraw(t *testing.T) {
	f := newNSRuleFixture(t, "100.66.0.0/24")
	ctx := context.Background()
	f.report(0, nsSvc{"shop", "web", []int32{80}}, nsSvc{"shop", "api", []int32{8080}}, nsSvc{"billing", "ledger", []int32{5432}})
	shop, err := f.svc.CreateNamespaceRule(ctx, f.org, f.cluster, NamespaceRuleInput{Namespace: "shop"}, f.actor)
	if err != nil {
		t.Fatal(err)
	}
	billing, err := f.svc.CreateNamespaceRule(ctx, f.org, f.cluster, NamespaceRuleInput{Namespace: "billing"}, f.actor)
	if err != nil {
		t.Fatal(err)
	}
	machine := &authctx.Principal{MachineID: uuid.New(), MachineName: "gitops", AuthMethod: authctx.AuthMachine}
	assertScopeAPIError(t, f.svc.DeleteNamespaceRule(ctx, f.org, f.cluster, shop.ID, true, machine), http.StatusForbidden, "actor_required")
	assertScopeAPIError(t, f.svc.DeleteNamespaceRule(ctx, f.org, f.cluster, uuid.New(), true, f.actor), http.StatusNotFound, "namespace_rule_not_found")

	// keep: the rule is gone, its exposures stay as ordinary exposures and can be removed by hand.
	if err := f.svc.DeleteNamespaceRule(ctx, f.org, f.cluster, billing.ID, false, f.actor); err != nil {
		t.Fatal(err)
	}
	if got := f.liveKeys(); got != "billing/ledger:5432=manual shop/api:8080=rule shop/web:80=rule" {
		t.Fatalf("after keep: %q", got)
	}
	var ledgerID uuid.UUID
	if err := f.pool.QueryRow(ctx, `SELECT id FROM k8s_services WHERE cluster_id=$1 AND name='ledger' AND deleted_at IS NULL`, f.cluster).Scan(&ledgerID); err != nil {
		t.Fatal(err)
	}
	// With the rule gone nothing withdraws or re-exposes it, even when it leaves the reports.
	f.report(0, nsSvc{"shop", "web", []int32{80}}, nsSvc{"shop", "api", []int32{8080}})
	f.reconcileAt(time.Now().UTC().Add(time.Hour))
	f.reconcileAt(time.Now().UTC().Add(2 * time.Hour))
	if _, ok := f.live()["billing/ledger:5432"]; !ok {
		t.Fatal("a kept exposure was withdrawn after its rule was removed")
	}
	if err := f.svc.UnexposeService(ctx, f.actor.UserID, "", "", f.org, ledgerID); err != nil {
		t.Fatalf("a kept exposure must be removable by hand: %v", err)
	}

	// withdraw: every exposure of the rule goes with it, audited with the human.
	if err := f.svc.DeleteNamespaceRule(ctx, f.org, f.cluster, shop.ID, true, f.actor); err != nil {
		t.Fatal(err)
	}
	if n := len(f.live()); n != 0 {
		t.Fatalf("after withdraw live=%v", f.live())
	}
	if n := f.count(`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='k8s.service_unexposed' AND actor_user_id=$2 AND metadata->>'namespace_rule_removed'='true'`, f.org, f.actor.UserID); n != 2 {
		t.Fatalf("human withdrawal audits = %d", n)
	}
	if n := f.count(`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='k8s.namespace_rule_deleted' AND metadata->>'exposures' IN ('kept','withdrawn')`, f.org); n != 2 {
		t.Fatalf("rule-deleted audits = %d", n)
	}
	rules, err := f.svc.ListNamespaceRules(ctx, f.org, f.cluster)
	if err != nil || len(rules) != 0 {
		t.Fatalf("rules after delete = %+v err=%v", rules, err)
	}
	// With no rule left a report exposes nothing.
	f.report(0, nsSvc{"shop", "web", []int32{80}})
	if err := f.svc.ReconcileNamespaceRulesForOrg(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if n := len(f.live()); n != 0 {
		t.Fatalf("exposed without a rule: %v", f.live())
	}
}

// Where cluster scopes are in use, an automatically exposed port arrives as a PENDING review in each
// active scope, exactly like a hand-made exposure. Nothing is approved by the rule.
func TestNamespaceRuleExposureIsPendingInActiveClusterScopes(t *testing.T) {
	f := newNSRuleFixture(t, "100.66.0.0/24")
	ctx := context.Background()
	f.exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, f.org, f.actor.UserID)
	f.report(0, nsSvc{"billing", "ledger", []int32{5432}})
	if _, err := f.svc.SetClusterScopeSetting(ctx, f.org, f.actor, true, true, 0, "test"); err != nil {
		t.Fatal(err)
	}
	scope, err := f.svc.CreateClusterScope(ctx, CreateClusterScopeInput{OrgID: f.org, ClusterID: f.cluster,
		Source: ClusterScopeSource{Kind: "user", ID: f.actor.UserID}, Actor: f.actor, EntitlementUnlocked: true, Cause: "test"})
	if err != nil {
		t.Fatal(err)
	}
	f.report(0, nsSvc{"shop", "web", []int32{80, 443}}, nsSvc{"billing", "ledger", []int32{5432}})
	rule, err := f.svc.CreateNamespaceRule(ctx, f.org, f.cluster, NamespaceRuleInput{Namespace: "shop"}, f.actor)
	if err != nil {
		t.Fatal(err)
	}
	if rule.Status != NamespaceRuleOK || rule.ExposedPorts != 2 {
		t.Fatalf("rule = %+v", rule)
	}
	if n := f.count(`SELECT count(*) FROM k8s_cluster_scope_memberships WHERE org_id=$1 AND rule_id=$2 AND status='pending'`, f.org, scope.RuleID); n != 2 {
		t.Fatalf("pending scope reviews = %d, want one per exposed port", n)
	}
	if n := f.count(`SELECT count(*) FROM k8s_cluster_scope_memberships WHERE org_id=$1 AND status<>'pending'`, f.org); n != 0 {
		t.Fatalf("the rule decided %d scope reviews", n)
	}
}
