package k8s

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
)

// K8N-4 slice A: excluding one Service from a namespace rule. Reports are seeded rows; no cluster.

func (f *nsRuleFixture) serviceID(name string, port int32) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.pool.QueryRow(context.Background(), `SELECT id FROM k8s_services WHERE cluster_id=$1 AND name=$2 AND port_low=$3 AND deleted_at IS NULL`, f.cluster, name, port).Scan(&id); err != nil {
		f.t.Fatalf("exposure %s:%d: %v", name, port, err)
	}
	return id
}

func TestNamespaceRuleExclusionWithdrawsOnlyTheRulesOwnAtOnce(t *testing.T) {
	f := newNSRuleFixture(t, "100.66.0.0/24")
	ctx := context.Background()
	// shop/web:80 is exposed by hand before the rule exists; the rule adds web:443, api and cart.
	if _, err := f.svc.ExposeService(ctx, f.org, f.cluster, "web", "shop", "tcp", p32(80), p32(80), uuid.Nil, f.actor.UserID, "", ""); err != nil {
		t.Fatal(err)
	}
	all := []nsSvc{{"shop", "web", []int32{80, 443}}, {"shop", "api", []int32{8080}}, {"shop", "cart", []int32{9090}}}
	f.report(0, all...)
	rule, err := f.svc.CreateNamespaceRule(ctx, f.org, f.cluster, NamespaceRuleInput{Namespace: "shop", ExcludedServices: []string{"cart"}}, f.actor)
	if err != nil {
		t.Fatal(err)
	}
	// An exclusion given at creation is honoured by the first pass.
	if got := f.liveKeys(); got != "shop/api:8080=rule shop/web:443=rule shop/web:80=manual" {
		t.Fatalf("after create with cart excluded: %q", got)
	}
	if len(rule.ExcludedServices) != 1 || rule.ExcludedServices[0] != "cart" || rule.Status != NamespaceRuleOK {
		t.Fatalf("rule = %+v", rule)
	}

	// An access rule points at the rule-made exposure of shop/api.
	apiID := f.serviceID("api", 8080)
	grant := uuid.New()
	f.exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, f.org, f.actor.UserID)
	f.exec(`INSERT INTO policy_rules(id,org_id,src_kind,src_user_id,dst_kind,dst_k8s_service_id) VALUES($1,$2,'user',$3,'k8s_service',$4)`, grant, f.org, f.actor.UserID, apiID)

	// Excluding api and web: the rule's exposures of them go on this call, with no wait, although both
	// Services are still reported. web:80, made by hand, is not the rule's and stays.
	excluded := []string{"web", "cart", "api"}
	rule, err = f.svc.UpdateNamespaceRule(ctx, f.org, f.cluster, rule.ID, NamespaceRuleUpdate{ExcludedServices: &excluded}, f.actor)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.liveKeys(); got != "shop/web:80=manual" {
		t.Fatalf("after excluding api and web: %q", got)
	}
	if strings.Join(rule.ExcludedServices, ",") != "api,cart,web" || rule.Status != NamespaceRuleOK || rule.ExposedPorts != 0 {
		t.Fatalf("rule after exclusion = %+v", rule)
	}
	// The access rule is kept and points at the withdrawn exposure, which no longer resolves.
	if n := f.count(`SELECT count(*) FROM policy_rules WHERE id=$1 AND dst_k8s_service_id=$2`, grant, apiID); n != 1 {
		t.Fatal("the access rule that pointed at the excluded exposure must be kept")
	}
	if liveIDs, err := f.svc.LiveServiceIDs(ctx, f.org); err != nil || liveIDs[apiID] {
		t.Fatalf("the excluded exposure is still live: %v err=%v", liveIDs, err)
	}
	if n := f.count(`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='k8s.service_unexposed' AND actor_system='k8s-namespace-rule'
		AND actor_user_id IS NULL AND metadata->>'reason'='service_excluded' AND metadata->>'cause'=$2`, f.org, "namespace_rule:"+rule.ID.String()); n != 2 {
		t.Fatalf("system-actor exclusion withdrawals = %d, want 2 (api:8080, web:443)", n)
	}
	if n := f.count(`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='k8s.namespace_rule_updated' AND actor_user_id=$2
		AND metadata->'excluded_services_added'=$3::jsonb AND metadata->'excluded_services_removed'='[]'::jsonb`, f.org, f.actor.UserID, `["api","web"]`); n != 1 {
		t.Fatalf("human rule-updated audits = %d", n)
	}

	// Later reports never bring an excluded Service back, and an identical update writes no audit entry.
	f.report(0, all...)
	if err := f.svc.ReconcileNamespaceRulesForOrg(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if got := f.liveKeys(); got != "shop/web:80=manual" {
		t.Fatalf("an excluded Service was exposed again: %q", got)
	}
	if _, err := f.svc.UpdateNamespaceRule(ctx, f.org, f.cluster, rule.ID, NamespaceRuleUpdate{ExcludedServices: &excluded}, f.actor); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='k8s.namespace_rule_updated'`, f.org); n != 1 {
		t.Fatalf("an unchanged list wrote an audit entry: %d", n)
	}

	// An excluded Service can still be exposed by hand, and the rule leaves that exposure alone.
	manualAPI, err := f.svc.ExposeService(ctx, f.org, f.cluster, "api", "shop", "tcp", p32(8080), p32(8080), uuid.Nil, f.actor.UserID, "", "")
	if err != nil {
		t.Fatalf("exposing an excluded Service by hand: %v", err)
	}
	if err := f.svc.ReconcileNamespaceRulesForOrg(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if got := f.liveKeys(); got != "shop/api:8080=manual shop/web:80=manual" {
		t.Fatalf("a hand-made exposure of an excluded Service was touched: %q", got)
	}

	// Taking cart and web off the list: cart is exposed, web's missing port is filled; a NEW id each,
	// and the hand-made api exposure is still not adopted when api comes off the list too.
	none := []string{}
	if rule, err = f.svc.UpdateNamespaceRule(ctx, f.org, f.cluster, rule.ID, NamespaceRuleUpdate{ExcludedServices: &none}, f.actor); err != nil {
		t.Fatal(err)
	}
	if got := f.liveKeys(); got != "shop/api:8080=manual shop/cart:9090=rule shop/web:443=rule shop/web:80=manual" {
		t.Fatalf("after clearing the list: %q", got)
	}
	if len(rule.ExcludedServices) != 0 || f.serviceID("api", 8080) != manualAPI.ID {
		t.Fatalf("rule = %+v", rule)
	}
	if n := f.count(`SELECT count(*) FROM policy_rules WHERE org_id=$1 AND dst_k8s_service_id=$2`, f.org, manualAPI.ID); n != 0 {
		t.Fatal("the old access rule must not follow a new exposure")
	}
}

func TestNamespaceRuleExclusionRefusalsAndNoReport(t *testing.T) {
	f := newNSRuleFixture(t, "100.66.0.0/24")
	ctx := context.Background()
	_, err := f.svc.CreateNamespaceRule(ctx, f.org, f.cluster, NamespaceRuleInput{Namespace: "shop", ExcludedServices: []string{"web-*"}}, f.actor)
	assertScopeAPIError(t, err, http.StatusBadRequest, "invalid_excluded_service")

	f.report(0, nsSvc{"shop", "web", []int32{80}}, nsSvc{"shop", "api", []int32{8080}})
	rule, err := f.svc.CreateNamespaceRule(ctx, f.org, f.cluster, NamespaceRuleInput{Namespace: "shop"}, f.actor)
	if err != nil {
		t.Fatal(err)
	}
	web := []string{"web"}
	machine := &authctx.Principal{MachineID: uuid.New(), MachineName: "gitops", OwnerUserID: f.actor.UserID, AuthMethod: authctx.AuthMachine}
	_, err = f.svc.UpdateNamespaceRule(ctx, f.org, f.cluster, rule.ID, NamespaceRuleUpdate{ExcludedServices: &web}, machine)
	assertScopeAPIError(t, err, http.StatusForbidden, "human_actor_required")
	_, err = f.svc.UpdateNamespaceRule(ctx, f.org, f.cluster, uuid.New(), NamespaceRuleUpdate{ExcludedServices: &web}, f.actor)
	assertScopeAPIError(t, err, http.StatusNotFound, "namespace_rule_not_found")
	_, err = f.svc.UpdateNamespaceRule(ctx, f.org, uuid.New(), rule.ID, NamespaceRuleUpdate{ExcludedServices: &web}, f.actor)
	assertScopeAPIError(t, err, http.StatusNotFound, "namespace_rule_not_found")
	twice := []string{"web", "web"}
	_, err = f.svc.UpdateNamespaceRule(ctx, f.org, f.cluster, rule.ID, NamespaceRuleUpdate{ExcludedServices: &twice}, f.actor)
	assertScopeAPIError(t, err, http.StatusBadRequest, "invalid_excluded_service")
	// The database refuses a pattern or an over-long list even past the API.
	for _, bad := range []string{`ARRAY['web-*']`, `ARRAY['Web']`, `ARRAY['a,b']`, `ARRAY(SELECT 's'||g FROM generate_series(1,101) g)`, `ARRAY[NULL]::text[]`} {
		if _, err := f.pool.Exec(ctx, `UPDATE k8s_namespace_exposure_rules SET excluded_services=`+bad+` WHERE id=$1`, rule.ID); err == nil {
			t.Fatalf("database accepted excluded_services=%s", bad)
		}
	}
	if got := f.liveKeys(); got != "shop/api:8080=rule shop/web:80=rule" {
		t.Fatalf("a refused change touched exposures: %q", got)
	}

	// No fresh report: the exclusion is stored, nothing is withdrawn, and the rule says why. The next
	// report applies it.
	f.report(5*time.Minute, nsSvc{"shop", "web", []int32{80}}, nsSvc{"shop", "api", []int32{8080}})
	updated, err := f.svc.UpdateNamespaceRule(ctx, f.org, f.cluster, rule.ID, NamespaceRuleUpdate{ExcludedServices: &web}, f.actor)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != NamespaceRuleInventoryStale && updated.Status != NamespaceRuleInventoryUnavailable {
		t.Fatalf("status without a fresh report = %q", updated.Status)
	}
	if len(updated.ExcludedServices) != 1 || f.liveKeys() != "shop/api:8080=rule shop/web:80=rule" {
		t.Fatalf("without a report nothing may be withdrawn: rule=%+v live=%q", updated, f.liveKeys())
	}
	f.report(0, nsSvc{"shop", "web", []int32{80}}, nsSvc{"shop", "api", []int32{8080}})
	if err := f.svc.ReconcileNamespaceRulesForOrg(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if got := f.liveKeys(); got != "shop/api:8080=rule" {
		t.Fatalf("the next report must apply the stored exclusion: %q", got)
	}
}

// A withdrawal an exclusion asks for is refused like any other while an agent access request points at
// or a template version points at the exposure: the rule says which Service, keeps the exposure, and
// tries again on every pass.
func TestNamespaceRuleExclusionBlockedWithdrawalIsVisibleAndRetried(t *testing.T) {
	f := newNSRuleFixture(t, "100.66.0.0/24")
	ctx := context.Background()
	f.report(0, nsSvc{"shop", "web", []int32{80}}, nsSvc{"shop", "api", []int32{8080}})
	rule, err := f.svc.CreateNamespaceRule(ctx, f.org, f.cluster, NamespaceRuleInput{Namespace: "shop"}, f.actor)
	if err != nil {
		t.Fatal(err)
	}
	f.blockWithdrawal(f.serviceID("web", 80))
	both := []string{"web", "api"}
	rule, err = f.svc.UpdateNamespaceRule(ctx, f.org, f.cluster, rule.ID, NamespaceRuleUpdate{ExcludedServices: &both}, f.actor)
	if err != nil {
		t.Fatal(err)
	}
	if rule.Status != NamespaceRuleWithdrawalBlocked || !strings.Contains(rule.StatusMessage, "shop/web is excluded from this rule but its exposure cannot be withdrawn") {
		t.Fatalf("blocked exclusion = %q %q", rule.Status, rule.StatusMessage)
	}
	// api, which nothing blocks, is withdrawn; web is kept.
	if got := f.liveKeys(); got != "shop/web:80=rule" {
		t.Fatalf("after a blocked exclusion: %q", got)
	}
	// The next report's pass tries again and says the same thing; the exposure is still there, and a
	// refused withdrawal never leaves the exposure without its rule.
	f.report(0, nsSvc{"shop", "web", []int32{80}}, nsSvc{"shop", "api", []int32{8080}})
	if err := f.svc.ReconcileNamespaceRulesForOrg(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if got := f.liveKeys(); got != "shop/web:80=rule" || f.rule("shop").Status != NamespaceRuleWithdrawalBlocked {
		t.Fatalf("after a second blocked pass: live=%q status=%q", got, f.rule("shop").Status)
	}
	if n := f.count(`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='k8s.service_unexposed' AND metadata->>'name'='web'`, f.org); n != 0 {
		t.Fatalf("a refused withdrawal was audited as done: %d", n)
	}
}

// blockWithdrawal makes an agent policy template version point at the exposure, which refuses its
// withdrawal. A template version is immutable, so the block cannot be lifted again in a test.
func (f *nsRuleFixture) blockWithdrawal(serviceID uuid.UUID) {
	f.t.Helper()
	templateID, versionID := uuid.New(), uuid.New()
	f.exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner') ON CONFLICT DO NOTHING`, f.org, f.actor.UserID)
	f.exec(`INSERT INTO agent_policy_templates (id,org_id,name) VALUES ($1,$2,$3)`, templateID, f.org, "blocker-"+templateID.String())
	f.exec(`INSERT INTO agent_policy_template_versions (id,org_id,template_id,version,created_by_user_id) VALUES ($1,$2,$3,1,$4)`, versionID, f.org, templateID, f.actor.UserID)
	f.exec(`INSERT INTO agent_policy_template_version_items (org_id,template_version_id,ordinal,dst_kind,dst_k8s_service_id) VALUES ($1,$2,1,'k8s_service',$3)`, f.org, versionID, serviceID)
}
