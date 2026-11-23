package k8s

import (
	"net/http"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/k8s/scopeapproval"
)

func tcp(port int32) inventoryExposurePort {
	return inventoryExposurePort{Protocol: scopeapproval.Protocol("tcp"), Port: port}
}

func TestNamespaceEligible(t *testing.T) {
	for _, namespace := range []string{"shop", "default", "payments-eu", "tunnexish"} {
		if err := NamespaceEligible(namespace); err != nil {
			t.Errorf("%q refused: %v", namespace, err)
		}
	}
	for namespace, code := range map[string]string{
		"kube-system": "namespace_not_eligible", "kube-public": "namespace_not_eligible", "kube-node-lease": "namespace_not_eligible",
		"tunnex": "namespace_not_eligible", "tunnex-system": "namespace_not_eligible", "tunnex-gitops": "namespace_not_eligible",
		"": "invalid_namespace", "*": "invalid_namespace", "Shop": "invalid_namespace", "a b": "invalid_namespace",
	} {
		assertScopeAPIError(t, NamespaceEligible(namespace), http.StatusBadRequest, code)
	}
}

func TestPlanNamespaceRule(t *testing.T) {
	rule, otherRule := uuid.New(), uuid.New()
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	recently, longAgo := now.Add(-2*time.Minute), now.Add(-NamespaceRuleWithdrawWait)
	ids := map[string]uuid.UUID{}
	id := func(name string) uuid.UUID {
		if _, ok := ids[name]; !ok {
			ids[name] = uuid.New()
		}
		return ids[name]
	}

	reported := []reportedService{
		{Service: "web", UID: "uid-web", Ports: []inventoryExposurePort{tcp(80), tcp(443)}},
		{Service: "api", UID: "uid-api", Ports: []inventoryExposurePort{tcp(8080)}},
		{Service: "back", UID: "uid-back", Ports: []inventoryExposurePort{tcp(9000)}},
		{Service: "legacy", UID: "uid-legacy", Ports: []inventoryExposurePort{tcp(1), tcp(2)}},
		{Service: "new", UID: "uid-new", Ports: []inventoryExposurePort{tcp(7000)}},
	}
	exposed := []exposedPort{
		// web:80 was exposed by hand; the rule adds only 443 and reuses the Service's address.
		{ID: id("web-80-manual"), Service: "web", Protocol: "tcp", Port: 80, VIP: "100.66.0.3"},
		// api is the rule's own and still reported: nothing to do.
		{ID: id("api-8080-rule"), Service: "api", Protocol: "tcp", Port: 8080, VIP: "100.66.0.4", RuleID: rule},
		// back came back before the wait ran out: the mark is cleared.
		{ID: id("back-9000-rule"), Service: "back", Protocol: "tcp", Port: 9000, VIP: "100.66.0.5", RuleID: rule, MissingSince: &recently},
		// a legacy all-ports exposure covers every port of its Service.
		{ID: id("legacy-all"), Service: "legacy", Protocol: "any", Port: 0, VIP: "100.66.0.6"},
		// gone1 is the rule's and missing for the first time; gone2 is missing but inside the wait;
		// gone3 has been missing for the whole wait.
		{ID: id("gone1"), Service: "gone1", Protocol: "tcp", Port: 80, VIP: "100.66.0.7", RuleID: rule},
		{ID: id("gone2"), Service: "gone2", Protocol: "tcp", Port: 80, VIP: "100.66.0.8", RuleID: rule, MissingSince: &recently},
		{ID: id("gone3"), Service: "gone3", Protocol: "tcp", Port: 80, VIP: "100.66.0.9", RuleID: rule, MissingSince: &longAgo},
		// Not reported, but not this rule's: by hand, by the operator (no rule id either), by another rule.
		{ID: id("manual-gone"), Service: "manual-gone", Protocol: "tcp", Port: 80, VIP: "100.66.0.10", MissingSince: &longAgo},
		{ID: id("other-rule-gone"), Service: "other-gone", Protocol: "tcp", Port: 80, VIP: "100.66.0.11", RuleID: otherRule, MissingSince: &longAgo},
	}

	plan := planNamespaceRule(namespaceRuleSpec{ID: rule}, reported, exposed, now, NamespaceRuleWithdrawWait)

	wantExpose := []plannedExposure{
		{Service: "new", UID: "uid-new", Ports: []inventoryExposurePort{tcp(7000)}},
		{Service: "web", UID: "uid-web", Ports: []inventoryExposurePort{tcp(443)}, VIP: "100.66.0.3"},
	}
	if !reflect.DeepEqual(plan.Expose, wantExpose) {
		t.Errorf("expose = %+v\nwant     %+v", plan.Expose, wantExpose)
	}
	if !reflect.DeepEqual(plan.ClearMissing, []uuid.UUID{id("back-9000-rule")}) {
		t.Errorf("clear = %v", plan.ClearMissing)
	}
	if !reflect.DeepEqual(plan.MarkMissing, []uuid.UUID{id("gone1")}) {
		t.Errorf("mark = %v", plan.MarkMissing)
	}
	if !reflect.DeepEqual(plan.Withdraw, []uuid.UUID{id("gone3")}) {
		t.Errorf("withdraw = %v, want only the rule's own row past the wait", plan.Withdraw)
	}
}

func TestPlanNamespaceRuleSettledNamespaceIsEmpty(t *testing.T) {
	rule := uuid.New()
	reported := []reportedService{{Service: "web", UID: "u", Ports: []inventoryExposurePort{tcp(80)}}}
	exposed := []exposedPort{{ID: uuid.New(), Service: "web", Protocol: "tcp", Port: 80, VIP: "100.66.0.3", RuleID: rule}}
	if plan := planNamespaceRule(namespaceRuleSpec{ID: rule}, reported, exposed, time.Now(), NamespaceRuleWithdrawWait); !plan.empty() {
		t.Fatalf("a settled namespace must plan nothing: %+v", plan)
	}
	// An empty namespace exposes nothing and, with no rows of its own, withdraws nothing.
	if plan := planNamespaceRule(namespaceRuleSpec{ID: rule}, nil, nil, time.Now(), NamespaceRuleWithdrawWait); !plan.empty() {
		t.Fatalf("empty namespace planned %+v", plan)
	}
}

// K8N-3: a namespace rule never exposes default/kubernetes, the cluster's API server. An exposure of it
// that a rule made before this refusal existed is still "reported", so it is neither marked missing nor
// withdrawn: existing rows are left in place.
func TestPlanNamespaceRuleNeverExposesTheAPIServer(t *testing.T) {
	rule := uuid.New()
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	longAgo := now.Add(-2 * NamespaceRuleWithdrawWait)
	reported := []reportedService{
		{Service: "kubernetes", UID: "uid-kubernetes", Ports: []inventoryExposurePort{tcp(443)}, APIServer: true},
		{Service: "web", UID: "uid-web", Ports: []inventoryExposurePort{tcp(80)}},
	}

	// Nothing exposed yet: only the ordinary Service is planned.
	plan := planNamespaceRule(namespaceRuleSpec{ID: rule}, reported, nil, now, NamespaceRuleWithdrawWait)
	if len(plan.Expose) != 1 || plan.Expose[0].Service != "web" {
		t.Fatalf("only web may be exposed, got %+v", plan.Expose)
	}

	// The rule exposed the API server before the refusal existed. It is still reported, so it stays.
	legacy := uuid.New()
	exposed := []exposedPort{{ID: legacy, Service: "kubernetes", Protocol: "tcp", Port: 443, VIP: "100.66.0.9", RuleID: rule}}
	plan = planNamespaceRule(namespaceRuleSpec{ID: rule}, reported, exposed, now, NamespaceRuleWithdrawWait)
	if len(plan.MarkMissing) != 0 || len(plan.Withdraw) != 0 {
		t.Fatalf("an existing API server exposure must be left in place, got mark=%v withdraw=%v", plan.MarkMissing, plan.Withdraw)
	}
	// Even one already marked missing long ago is cleared, not withdrawn, while the Service is reported.
	exposed[0].MissingSince = &longAgo
	plan = planNamespaceRule(namespaceRuleSpec{ID: rule}, reported, exposed, now, NamespaceRuleWithdrawWait)
	if len(plan.Withdraw) != 0 || !reflect.DeepEqual(plan.ClearMissing, []uuid.UUID{legacy}) {
		t.Fatalf("a reported API server exposure is cleared, never withdrawn: %+v", plan)
	}
	if !IsAPIServerService("default", "kubernetes") || IsAPIServerService("prod", "kubernetes") || IsAPIServerService("default", "kubernetes-dashboard") {
		t.Fatal("only default/kubernetes is the API server")
	}
}

func TestPlanNamespaceRuleExclusions(t *testing.T) {
	rule, other := uuid.New(), uuid.New()
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	webRule, webManual, apiRule, goneRule, otherRule := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	reported := []reportedService{
		{Service: "web", UID: "uid-web", Ports: []inventoryExposurePort{tcp(80), tcp(443), tcp(8443)}},
		{Service: "api", UID: "uid-api", Ports: []inventoryExposurePort{tcp(8080)}},
		{Service: "new", UID: "uid-new", Ports: []inventoryExposurePort{tcp(7000)}},
		{Service: "skip", UID: "uid-skip", Ports: []inventoryExposurePort{tcp(1)}},
	}
	exposed := []exposedPort{
		{ID: webRule, Service: "web", Protocol: "tcp", Port: 80, VIP: "100.66.0.3", RuleID: rule},
		{ID: webManual, Service: "web", Protocol: "tcp", Port: 443, VIP: "100.66.0.3"},
		{ID: apiRule, Service: "api", Protocol: "tcp", Port: 8080, VIP: "100.66.0.4", RuleID: rule},
		// excluded and already gone from the report: still withdrawn at once, not after the wait.
		{ID: goneRule, Service: "gone", Protocol: "tcp", Port: 9, VIP: "100.66.0.5", RuleID: rule},
		// another rule's exposure of an excluded name is never this rule's to withdraw.
		{ID: otherRule, Service: "skip", Protocol: "tcp", Port: 2, VIP: "100.66.0.6", RuleID: other},
	}
	spec := namespaceRuleSpec{ID: rule, Excluded: map[string]bool{"web": true, "gone": true, "skip": true, "not-deployed-yet": true}}
	plan := planNamespaceRule(spec, reported, exposed, now, NamespaceRuleWithdrawWait)

	if len(plan.Expose) != 1 || plan.Expose[0].Service != "new" {
		t.Fatalf("only the Service that is not excluded is exposed (web:8443 and skip:1 are not): %+v", plan.Expose)
	}
	got := map[uuid.UUID]bool{}
	for _, id := range plan.WithdrawExcluded {
		got[id] = true
	}
	if len(got) != 2 || !got[webRule] || !got[goneRule] {
		t.Fatalf("exactly the rule's own exposures of excluded Services are withdrawn: %v", plan.WithdrawExcluded)
	}
	if len(plan.Withdraw) != 0 || len(plan.MarkMissing) != 0 || len(plan.ClearMissing) != 0 {
		t.Fatalf("an exclusion uses neither the missing mark nor the wait: %+v", plan)
	}

	// Without the exclusion the same inputs withdraw nothing at once and fill web's gap.
	plain := planNamespaceRule(namespaceRuleSpec{ID: rule}, reported, exposed, now, NamespaceRuleWithdrawWait)
	if len(plain.WithdrawExcluded) != 0 || len(plain.Expose) != 3 {
		t.Fatalf("plan without exclusions = %+v", plain)
	}
}

func TestNormalizeExcludedServices(t *testing.T) {
	got, err := normalizeExcludedServices([]string{"web", "api", "a-1"})
	if err != nil || len(got) != 3 || got[0] != "a-1" || got[1] != "api" || got[2] != "web" {
		t.Fatalf("got %v err=%v", got, err)
	}
	if got, err := normalizeExcludedServices(nil); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("an empty list is valid and not nil: %v %v", got, err)
	}
	for _, bad := range [][]string{{"web", "web"}, {"*"}, {"web-*"}, {""}, {"Web"}, {"a/b"}, {"a,b"}} {
		_, err := normalizeExcludedServices(bad)
		assertScopeAPIError(t, err, http.StatusBadRequest, "invalid_excluded_service")
	}
	many := make([]string, MaxNamespaceRuleExclusions+1)
	for i := range many {
		many[i] = "svc-" + strconv.Itoa(i)
	}
	_, err = normalizeExcludedServices(many)
	assertScopeAPIError(t, err, http.StatusBadRequest, "excluded_services_limit")
	if _, err := normalizeExcludedServices(many[:MaxNamespaceRuleExclusions]); err != nil {
		t.Fatalf("exactly the limit must be accepted: %v", err)
	}
}
