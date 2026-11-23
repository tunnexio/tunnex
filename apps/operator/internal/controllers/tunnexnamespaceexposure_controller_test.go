package controllers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	tunnexv1 "github.com/tunnexio/tunnex/apps/operator/api/v1alpha1"
	cpapi "github.com/tunnexio/tunnex/apps/operator/internal/cp"
)

// K8N-4 slice C: a TunnexNamespaceExposure keeps ONE control-plane namespace rule equal to its spec,
// under K8L-8's rules. The control plane here is a fake that records every write.

// ruleCP is a fake control plane holding one cluster's namespace rules.
type ruleCP struct {
	t     *testing.T
	rules []map[string]any
	// writes is every mutating call: "METHOD path?query cause=<X-Tunnex-Cause> body=<json>".
	writes []string
	// refuse answers a mutating call whose "METHOD " prefix matches with this status and code.
	refuse map[string][2]any
	// clusterGone makes the rule list answer 404.
	clusterGone bool
}

func (f *ruleCP) client() *cpapi.Client {
	return testCP(f.t, func(w http.ResponseWriter, r *http.Request) {
		const base = "/k8s/clusters/clu-1/namespace-rules"
		i := strings.Index(r.URL.Path, base)
		if i < 0 {
			f.t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", http.StatusInternalServerError)
			return
		}
		id := strings.TrimPrefix(r.URL.Path[i+len(base):], "/")
		if r.Method == http.MethodGet {
			if f.clusterGone {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "cluster_not_found", "message": "no such cluster"}})
				return
			}
			json.NewEncoder(w).Encode(f.rules)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		encoded, _ := json.Marshal(body)
		target := r.URL.Path[i:]
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		f.writes = append(f.writes, r.Method+" "+target+" cause="+r.Header.Get("X-Tunnex-Cause")+" body="+string(encoded))
		if refusal, ok := f.refuse[r.Method]; ok {
			w.WriteHeader(refusal[0].(int))
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": refusal[1].(string), "message": "refused: " + refusal[1].(string)}})
			return
		}
		switch r.Method {
		case http.MethodPost:
			rule := nsRuleRow("rule-new", body["namespace"].(string), true, "applied")
			rule["selector"], rule["excluded_services"] = body["selector"], body["excluded_services"]
			f.rules = append(f.rules, rule)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(rule)
		case http.MethodPatch:
			for _, rule := range f.rules {
				if rule["id"] == id {
					rule["selector"], rule["excluded_services"] = body["selector"], body["excluded_services"]
					json.NewEncoder(w).Encode(rule)
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
		case http.MethodDelete:
			kept := f.rules[:0]
			for _, rule := range f.rules {
				if rule["id"] != id {
					kept = append(kept, rule)
				}
			}
			f.rules = kept
			w.WriteHeader(http.StatusNoContent)
		}
	})
}

func nsRuleRow(id, namespace string, managed bool, status string) map[string]any {
	return map[string]any{"id": id, "cluster_id": "clu-1", "namespace": namespace, "selector": map[string]any{}, "excluded_services": []any{},
		"status": status, "status_message": "", "waiting_services": 0, "exposed_services": 3, "exposed_ports": 5, "managed_by_operator": managed}
}

func nsExposure(name, namespace, ruleID string) *tunnexv1.TunnexNamespaceExposure {
	meta := managedMeta("ns", name)
	meta.UID = types.UID("uid-" + name)
	return &tunnexv1.TunnexNamespaceExposure{
		ObjectMeta: meta,
		Spec:       tunnexv1.TunnexNamespaceExposureSpec{Cluster: "prod-cluster", Namespace: namespace},
		Status:     tunnexv1.TunnexNamespaceExposureStatus{RuleID: ruleID},
	}
}

func nsK8s(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objs...).
		WithStatusSubresource(&tunnexv1.TunnexCluster{}, &tunnexv1.TunnexNamespaceExposure{}).Build()
}

func nsReconcile(t *testing.T, f *ruleCP, rec record.EventRecorder, objs ...client.Object) (*TunnexNamespaceExposureReconciler, func(name string) (tunnexv1.TunnexNamespaceExposure, bool)) {
	t.Helper()
	f.t = t
	r := &TunnexNamespaceExposureReconciler{Client: nsK8s(t, objs...), CP: f.client(), Recorder: rec}
	return r, func(name string) (tunnexv1.TunnexNamespaceExposure, bool) {
		var got tunnexv1.TunnexNamespaceExposure
		err := r.Get(context.Background(), types.NamespacedName{Namespace: "ns", Name: name}, &got)
		if apierrors.IsNotFound(err) {
			return got, false
		}
		if err != nil {
			t.Fatal(err)
		}
		return got, true
	}
}

func mustReady(t *testing.T, cr tunnexv1.TunnexNamespaceExposure, status metav1.ConditionStatus, reason string) *metav1.Condition {
	t.Helper()
	c := readyCond(t, cr.Status.Conditions)
	if c == nil || c.Status != status || c.Reason != reason {
		t.Fatalf("want Ready=%s reason=%s, got %+v", status, reason, c)
	}
	return c
}

func events(rec *record.FakeRecorder) []string {
	var out []string
	for {
		select {
		case e := <-rec.Events:
			out = append(out, e)
		default:
			return out
		}
	}
}

// No rule for the namespace yet: the operator creates one with exactly what the resource declares, names
// the resource as the cause, and reports the control plane's counts.
func TestNamespaceExposureCreatesTheRuleItDeclares(t *testing.T) {
	f := &ruleCP{rules: []map[string]any{nsRuleRow("rule-other", "billing", false, "applied")}}
	cr := nsExposure("shop", "shop", "")
	cr.Spec.Selector = map[string]tunnexv1.SelectorValue{"app": "web"}
	cr.Spec.ExcludedServices = []tunnexv1.ServiceName{"zeta", "admin"}
	r, get := nsReconcile(t, f, nil, readyCluster(), cr)
	res, err := r.Reconcile(context.Background(), req("ns", "shop"))
	if err != nil || res.RequeueAfter != resyncReady {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	want := `POST /k8s/clusters/clu-1/namespace-rules cause=tunnexnamespaceexposure:ns/shop body={"excluded_services":["admin","zeta"],"namespace":"shop","selector":{"app":"web"}}`
	if len(f.writes) != 1 || f.writes[0] != want {
		t.Fatalf("writes = %q\n want   [%q]", f.writes, want)
	}
	got, _ := get("shop")
	mustReady(t, got, metav1.ConditionTrue, "Applied")
	if got.Status.RuleID != "rule-new" || got.Status.RuleStatus != "applied" || got.Status.ExposedServices != 3 || got.Status.ExposedPorts != 5 {
		t.Fatalf("status = %+v", got.Status)
	}
	// A second pass finds the rule equal to the spec and writes nothing.
	if _, err := r.Reconcile(context.Background(), req("ns", "shop")); err != nil || len(f.writes) != 1 {
		t.Fatalf("a settled resource wrote again: %q err=%v", f.writes, err)
	}
}

// With no selector and no exclusions the request still says so explicitly: never null, never absent.
func TestNamespaceExposureWholeNamespaceSendsAnEmptySelector(t *testing.T) {
	f := &ruleCP{}
	r, _ := nsReconcile(t, f, nil, readyCluster(), nsExposure("shop", "shop", ""))
	if _, err := r.Reconcile(context.Background(), req("ns", "shop")); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 1 || !strings.HasSuffix(f.writes[0], `body={"excluded_services":[],"namespace":"shop","selector":{}}`) {
		t.Fatalf("writes = %q", f.writes)
	}
}

// Ready is the rule's own status. A rule the control plane has not applied is NOT Ready, with the control
// plane's status as reason and its sentence as message; nothing is written and it is re-read sooner.
func TestNamespaceExposureReadyOnlyWhileTheRuleIsApplied(t *testing.T) {
	for status, message := range map[string]string{
		"vip_range_exhausted":   "the cluster's address range 100.66.0.0/24 is full: 4 Services in shop are waiting and none was exposed.",
		"gateway_too_old":       "the cluster's gateway reports Services without labels: it is older than label selectors. Upgrade the gateway.",
		"inventory_stale":       "the cluster's gateway has not reported its Services recently",
		"withdrawal_blocked":    "shop/web is excluded from this rule but its exposure cannot be withdrawn",
		"labels_incomplete":     "2 Service(s) in shop have more labels than the gateway reports",
		"scope_review_limit":    "shop/web could not be exposed",
		"inventory_unavailable": "there is no current Service report",
		"pending":               "",
	} {
		rule := nsRuleRow("rule-1", "shop", true, status)
		rule["status_message"], rule["waiting_services"] = message, 4
		f := &ruleCP{rules: []map[string]any{rule}}
		r, get := nsReconcile(t, f, nil, readyCluster(), nsExposure("shop", "shop", "rule-1"))
		res, err := r.Reconcile(context.Background(), req("ns", "shop"))
		if err != nil || res.RequeueAfter != requeueRuleNotApplied {
			t.Fatalf("%s: res=%+v err=%v", status, res, err)
		}
		got, _ := get("shop")
		c := mustReady(t, got, metav1.ConditionFalse, status)
		if message != "" && c.Message != message {
			t.Fatalf("%s: message = %q, want the control plane's sentence", status, c.Message)
		}
		if message == "" && !strings.Contains(c.Message, "has not applied the namespace rule yet") {
			t.Fatalf("%s: message = %q", status, c.Message)
		}
		if got.Status.RuleStatus != status || got.Status.WaitingServices != 4 || len(f.writes) != 0 {
			t.Fatalf("%s: status=%+v writes=%q", status, got.Status, f.writes)
		}
	}
}

// A rule for the namespace made in the dashboard is not adopted, not changed, and deleting the resource
// removes nothing.
func TestNamespaceExposureNeverAdoptsOrRemovesADashboardRule(t *testing.T) {
	f := &ruleCP{rules: []map[string]any{nsRuleRow("rule-dash", "shop", false, "applied")}}
	cr := nsExposure("shop", "shop", "")
	cr.Spec.ExcludedServices = []tunnexv1.ServiceName{"admin"}
	r, get := nsReconcile(t, f, nil, readyCluster(), cr)
	if _, err := r.Reconcile(context.Background(), req("ns", "shop")); err != nil {
		t.Fatal(err)
	}
	got, _ := get("shop")
	c := mustReady(t, got, metav1.ConditionFalse, reasonUnmanaged)
	if !strings.Contains(c.Message, "made outside the operator") || got.Status.RuleID != "" || len(f.writes) != 0 {
		t.Fatalf("message=%q status=%+v writes=%q", c.Message, got.Status, f.writes)
	}
	if err := r.Delete(context.Background(), &got); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), req("ns", "shop")); err != nil {
		t.Fatal(err)
	}
	if _, still := get("shop"); still || len(f.writes) != 0 || len(f.rules) != 1 {
		t.Fatalf("deleting a resource that never owned the rule must call nothing: still=%v writes=%q", still, f.writes)
	}
}

// A rule the operator's credential made earlier (a status write that failed, a restored cluster) is
// adopted, unless another resource already holds it.
func TestNamespaceExposureAdoptsOnlyAnUnclaimedOperatorRule(t *testing.T) {
	f := &ruleCP{rules: []map[string]any{nsRuleRow("rule-1", "shop", true, "applied")}}
	r, get := nsReconcile(t, f, nil, readyCluster(), nsExposure("first", "shop", ""))
	if _, err := r.Reconcile(context.Background(), req("ns", "first")); err != nil {
		t.Fatal(err)
	}
	if got, _ := get("first"); got.Status.RuleID != "rule-1" || len(f.writes) != 0 {
		t.Fatalf("an operator-made rule equal to the spec is adopted without a write: %+v %q", got.Status, f.writes)
	} else {
		mustReady(t, got, metav1.ConditionTrue, "Applied")
	}

	f2 := &ruleCP{rules: []map[string]any{nsRuleRow("rule-1", "shop", true, "applied")}}
	second := nsExposure("second", "shop", "")
	second.Spec.ExcludedServices = []tunnexv1.ServiceName{"admin"}
	r2, get2 := nsReconcile(t, f2, nil, readyCluster(), nsExposure("first", "shop", "rule-1"), second)
	if _, err := r2.Reconcile(context.Background(), req("ns", "second")); err != nil {
		t.Fatal(err)
	}
	got, _ := get2("second")
	c := mustReady(t, got, metav1.ConditionFalse, reasonDuplicate)
	if !strings.Contains(c.Message, "ns/first") || len(f2.writes) != 0 || got.Status.RuleID != "" {
		t.Fatalf("message=%q writes=%q", c.Message, f2.writes)
	}
}

// selector and excludedServices are applied in place with one call naming the resource. An emptied
// selector is sent as empty, so the rule really becomes a whole-namespace rule only when Git says so.
func TestNamespaceExposureAppliesSelectorAndExclusionEdits(t *testing.T) {
	rule := nsRuleRow("rule-1", "shop", true, "applied")
	rule["selector"], rule["excluded_services"] = map[string]any{"app": "web"}, []any{"admin"}
	f := &ruleCP{rules: []map[string]any{rule}}
	cr := nsExposure("shop", "shop", "rule-1")
	cr.Spec.Selector = map[string]tunnexv1.SelectorValue{"app": "web", "tier": "frontend"}
	cr.Spec.ExcludedServices = []tunnexv1.ServiceName{"admin"}
	r, get := nsReconcile(t, f, nil, readyCluster(), cr)
	if _, err := r.Reconcile(context.Background(), req("ns", "shop")); err != nil {
		t.Fatal(err)
	}
	want := `PATCH /k8s/clusters/clu-1/namespace-rules/rule-1 cause=tunnexnamespaceexposure:ns/shop body={"excluded_services":["admin"],"selector":{"app":"web","tier":"frontend"}}`
	if len(f.writes) != 1 || f.writes[0] != want {
		t.Fatalf("writes = %q\n want   [%q]", f.writes, want)
	}
	got, _ := get("shop")
	mustReady(t, got, metav1.ConditionTrue, "Applied")

	got.Spec.Selector, got.Spec.ExcludedServices = nil, nil
	if err := r.Update(context.Background(), &got); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), req("ns", "shop")); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 2 || !strings.HasSuffix(f.writes[1], `body={"excluded_services":[],"selector":{}}`) {
		t.Fatalf("writes = %q", f.writes)
	}
	// The control plane refuses an edit (a selector it does not accept): not Ready, its code and sentence.
	f.refuse = map[string][2]any{http.MethodPatch: {http.StatusBadRequest, "invalid_selector"}}
	got, _ = get("shop")
	got.Spec.Selector = map[string]tunnexv1.SelectorValue{"bad key": "x"}
	if err := r.Update(context.Background(), &got); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), req("ns", "shop")); err != nil {
		t.Fatal(err)
	}
	got, _ = get("shop")
	if c := mustReady(t, got, metav1.ConditionFalse, "invalid_selector"); c.Message != "refused: invalid_selector" {
		t.Fatalf("message = %q", c.Message)
	}
}

// The namespace is the rule's identity. An edited namespace is not Ready, names what is live, and writes
// nothing: no rule is created for the new namespace and the old one is not removed.
func TestNamespaceExposureRefusesANamespaceEdit(t *testing.T) {
	f := &ruleCP{rules: []map[string]any{nsRuleRow("rule-1", "shop", true, "applied")}}
	r, get := nsReconcile(t, f, nil, readyCluster(), nsExposure("shop", "billing", "rule-1"))
	if _, err := r.Reconcile(context.Background(), req("ns", "shop")); err != nil {
		t.Fatal(err)
	}
	got, _ := get("shop")
	c := mustReady(t, got, metav1.ConditionFalse, reasonSpecChange)
	if !strings.Contains(c.Message, "namespace rule for shop") || len(f.writes) != 0 {
		t.Fatalf("message=%q writes=%q", c.Message, f.writes)
	}
}

// A rule removed behind the operator's back is created again from the resource, with an Event. If the
// namespace meanwhile got a dashboard rule, that rule is left alone.
func TestNamespaceExposureRecreatesARemovedRuleButNotOverADashboardOne(t *testing.T) {
	rec := record.NewFakeRecorder(8)
	f := &ruleCP{}
	r, get := nsReconcile(t, f, rec, readyCluster(), nsExposure("shop", "shop", "rule-gone"))
	if _, err := r.Reconcile(context.Background(), req("ns", "shop")); err != nil {
		t.Fatal(err)
	}
	got, _ := get("shop")
	mustReady(t, got, metav1.ConditionTrue, "Applied")
	drift := apimeta.FindStatusCondition(got.Status.Conditions, condDrift)
	if len(f.writes) != 1 || !strings.HasPrefix(f.writes[0], "POST ") || got.Status.RuleID != "rule-new" || drift == nil || drift.Status != metav1.ConditionTrue {
		t.Fatalf("writes=%q status=%+v", f.writes, got.Status)
	}
	if ev := events(rec); len(ev) != 1 || !strings.Contains(ev[0], "DriftHealed") || !strings.Contains(ev[0], "are not adopted") {
		t.Fatalf("events = %q", ev)
	}

	f2 := &ruleCP{rules: []map[string]any{nsRuleRow("rule-dash", "shop", false, "applied")}}
	r2, get2 := nsReconcile(t, f2, nil, readyCluster(), nsExposure("shop", "shop", "rule-gone"))
	if _, err := r2.Reconcile(context.Background(), req("ns", "shop")); err != nil {
		t.Fatal(err)
	}
	got, _ = get2("shop")
	mustReady(t, got, metav1.ConditionFalse, reasonUnmanaged)
	if len(f2.writes) != 0 {
		t.Fatalf("a dashboard rule was written to: %q", f2.writes)
	}
}

// A rule this resource holds whose operator mark is gone (the credential was replaced) is not written to.
func TestNamespaceExposureLeavesARuleItNoLongerManages(t *testing.T) {
	f := &ruleCP{rules: []map[string]any{nsRuleRow("rule-1", "shop", false, "applied")}}
	cr := nsExposure("shop", "shop", "rule-1")
	cr.Spec.ExcludedServices = []tunnexv1.ServiceName{"admin"}
	r, get := nsReconcile(t, f, nil, readyCluster(), cr)
	if _, err := r.Reconcile(context.Background(), req("ns", "shop")); err != nil {
		t.Fatal(err)
	}
	got, _ := get("shop")
	mustReady(t, got, metav1.ConditionFalse, reasonUnmanaged)
	if len(f.writes) != 0 {
		t.Fatalf("writes = %q", f.writes)
	}
}

// Deleting the resource does exactly what deletionPolicy says, and says which in an Event. Unset means
// Keep: the safe one.
func TestNamespaceExposureDeletionPolicy(t *testing.T) {
	for _, tc := range []struct {
		policy, query, event string
	}{
		{"", "exposures=keep", "kept as ordinary exposures (deletionPolicy Keep)"},
		{tunnexv1.DeletionPolicyKeep, "exposures=keep", "kept as ordinary exposures (deletionPolicy Keep)"},
		{tunnexv1.DeletionPolicyWithdraw, "exposures=withdraw", "every exposure it made withdrawn (deletionPolicy Withdraw)"},
	} {
		rec := record.NewFakeRecorder(8)
		f := &ruleCP{rules: []map[string]any{nsRuleRow("rule-1", "shop", true, "applied"), nsRuleRow("rule-2", "billing", true, "applied")}}
		cr := nsExposure("shop", "shop", "rule-1")
		cr.Spec.DeletionPolicy = tc.policy
		r, get := nsReconcile(t, f, rec, readyCluster(), cr)
		if err := r.Delete(context.Background(), cr); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Reconcile(context.Background(), req("ns", "shop")); err != nil {
			t.Fatalf("policy %q: %v", tc.policy, err)
		}
		want := "DELETE /k8s/clusters/clu-1/namespace-rules/rule-1?" + tc.query + " cause=tunnexnamespaceexposure:ns/shop body=null"
		if len(f.writes) != 1 || f.writes[0] != want {
			t.Fatalf("policy %q: writes = %q\n want   [%q]", tc.policy, f.writes, want)
		}
		if _, still := get("shop"); still || len(f.rules) != 1 || f.rules[0]["id"] != "rule-2" {
			t.Fatalf("policy %q: resource still=%v rules=%v", tc.policy, still, f.rules)
		}
		if ev := events(rec); len(ev) != 1 || !strings.Contains(ev[0], tc.event) {
			t.Fatalf("policy %q: events = %q", tc.policy, ev)
		}
	}
}

// A withdrawal the control plane refuses keeps the resource (finalizer held) and says why; nothing was
// changed, so the rule is still there.
func TestNamespaceExposureBlockedWithdrawKeepsTheResourceAndSaysWhy(t *testing.T) {
	rec := record.NewFakeRecorder(8)
	f := &ruleCP{rules: []map[string]any{nsRuleRow("rule-1", "shop", true, "applied")},
		refuse: map[string][2]any{http.MethodDelete: {http.StatusConflict, "agent_access_destination_in_use"}}}
	cr := nsExposure("shop", "shop", "rule-1")
	cr.Spec.DeletionPolicy = tunnexv1.DeletionPolicyWithdraw
	r, get := nsReconcile(t, f, rec, readyCluster(), cr)
	if err := r.Delete(context.Background(), cr); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), req("ns", "shop")); err == nil {
		t.Fatal("a refused teardown must be returned so it is retried")
	}
	got, still := get("shop")
	blocked := apimeta.FindStatusCondition(got.Status.Conditions, condTeardownBlocked)
	if !still || blocked == nil || blocked.Reason != "agent_access_destination_in_use" || len(f.rules) != 1 {
		t.Fatalf("still=%v blocked=%+v rules=%v", still, blocked, f.rules)
	}
	if ev := events(rec); len(ev) != 1 || !strings.Contains(ev[0], "TeardownBlocked") {
		t.Fatalf("events = %q", ev)
	}
}

// When the control plane says the rule is not the operator's, or it is already gone, or its cluster
// resource is gone, the resource is released and nothing else is asked for.
func TestNamespaceExposureDeleteReleasesWhenThereIsNothingOfItsOwnToRemove(t *testing.T) {
	rec := record.NewFakeRecorder(8)
	f := &ruleCP{rules: []map[string]any{nsRuleRow("rule-1", "shop", false, "applied")},
		refuse: map[string][2]any{http.MethodDelete: {http.StatusConflict, codeRuleNotManaged}}}
	cr := nsExposure("shop", "shop", "rule-1")
	r, get := nsReconcile(t, f, rec, readyCluster(), cr)
	_ = r.Delete(context.Background(), cr)
	if _, err := r.Reconcile(context.Background(), req("ns", "shop")); err != nil {
		t.Fatal(err)
	}
	if _, still := get("shop"); still || len(f.rules) != 1 {
		t.Fatalf("still=%v rules=%v", still, f.rules)
	}
	if ev := events(rec); len(ev) != 1 || !strings.Contains(ev[0], "no longer managed by the operator and was left in place") {
		t.Fatalf("events = %q", ev)
	}

	gone := &ruleCP{refuse: map[string][2]any{http.MethodDelete: {http.StatusNotFound, "namespace_rule_not_found"}}}
	cr = nsExposure("shop", "shop", "rule-1")
	r, get = nsReconcile(t, gone, nil, readyCluster(), cr)
	_ = r.Delete(context.Background(), cr)
	if _, err := r.Reconcile(context.Background(), req("ns", "shop")); err != nil {
		t.Fatal(err)
	}
	if _, still := get("shop"); still {
		t.Fatal("a rule that is already gone must not wedge the delete")
	}

	// No TunnexCluster resource any more: the control plane is not called at all.
	cr = nsExposure("shop", "shop", "rule-1")
	orphan := &TunnexNamespaceExposureReconciler{Client: nsK8s(t, cr), CP: cpDown(t)}
	_ = orphan.Delete(context.Background(), cr)
	if _, err := orphan.Reconcile(context.Background(), req("ns", "shop")); err != nil {
		t.Fatal(err)
	}
}

// Ordering, and keep-last: no cluster yet is a wait; a control-plane outage leaves the last status alone.
func TestNamespaceExposureWaitsForItsClusterAndKeepsLastOnOutage(t *testing.T) {
	r := &TunnexNamespaceExposureReconciler{Client: nsK8s(t, nsExposure("shop", "shop", "")), CP: cpDown(t)}
	res, err := r.Reconcile(context.Background(), req("ns", "shop"))
	if err != nil || res.RequeueAfter != requeueDependency {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	var got tunnexv1.TunnexNamespaceExposure
	_ = r.Get(context.Background(), types.NamespacedName{Namespace: "ns", Name: "shop"}, &got)
	mustReady(t, got, metav1.ConditionFalse, "WaitingForCluster")

	healthy := nsExposure("shop", "shop", "rule-1")
	setReady(&healthy.Status.Conditions, metav1.ConditionTrue, "Applied", "applied", 0)
	down := &TunnexNamespaceExposureReconciler{Client: nsK8s(t, readyCluster(), healthy), CP: testCP(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	})}
	if _, err := down.Reconcile(context.Background(), req("ns", "shop")); err == nil {
		t.Fatal("an outage must be returned for backoff")
	}
	_ = down.Get(context.Background(), types.NamespacedName{Namespace: "ns", Name: "shop"}, &got)
	mustReady(t, got, metav1.ConditionTrue, "Applied")
}

// The first pass only stamps the label and the finalizer; the control plane is not called before a delete
// can be honoured.
func TestNamespaceExposureFinalizerBeforeAnyWrite(t *testing.T) {
	cr := &tunnexv1.TunnexNamespaceExposure{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "shop"},
		Spec: tunnexv1.TunnexNamespaceExposureSpec{Cluster: "prod-cluster", Namespace: "shop"}}
	r := &TunnexNamespaceExposureReconciler{Client: nsK8s(t, readyCluster(), cr), CP: cpDown(t)}
	res, err := r.Reconcile(context.Background(), req("ns", "shop"))
	if err != nil || !res.Requeue {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	var got tunnexv1.TunnexNamespaceExposure
	_ = r.Get(context.Background(), types.NamespacedName{Namespace: "ns", Name: "shop"}, &got)
	if got.Labels[managedByLabel] != managedByValue || len(got.Finalizers) != 1 {
		t.Fatalf("meta = %+v", got.ObjectMeta)
	}
}
