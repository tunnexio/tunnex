package controllers

import (
	"context"
	"fmt"
	"sort"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	tunnexv1 "github.com/tunnexio/tunnex/apps/operator/api/v1alpha1"
	"github.com/tunnexio/tunnex/apps/operator/internal/cp"
)

const (
	// The control plane's status of a rule that is fully in effect. Every other status is a rule that is
	// not, and becomes the reason of Ready=False verbatim.
	namespaceRuleApplied = "applied"
	// The control plane's refusal when the operator's credential is asked to change or remove a rule it
	// did not create.
	codeRuleNotManaged = "rule_not_managed_by_operator"
	// requeueRuleNotApplied re-reads a rule that is not applied yet. Its status changes when the gateway
	// reports or a limit is lifted, and nothing tells the operator.
	requeueRuleNotApplied = clientErrRequeue
)

// TunnexNamespaceExposureReconciler keeps one control-plane namespace rule (K8N-4) equal to a
// TunnexNamespaceExposure. It lists no Services and exposes nothing itself: the control plane applies the
// rule each time the cluster's gateway reports. K8L-8's rules hold: it adopts only a rule the operator's
// credential created, never changes or removes one made in the dashboard, refuses edits the control plane
// cannot apply, and reports Ready=True only while the control plane says the rule is applied.
type TunnexNamespaceExposureReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	CP       *cp.Client
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=tunnex.io,resources=tunnexnamespaceexposures,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=tunnex.io,resources=tunnexnamespaceexposures/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=tunnex.io,resources=tunnexclusters,verbs=get;list;watch

func (r *TunnexNamespaceExposureReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cr tunnexv1.TunnexNamespaceExposure
	if err := r.Get(ctx, req.NamespacedName, &cr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !cr.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, &cr)
	}
	if ensureMeta(&cr) {
		if err := r.Update(ctx, &cr); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}
	gen := cr.Generation

	// ORDERING: the cluster resource must exist and be registered first.
	var cluster tunnexv1.TunnexCluster
	if err := r.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: cr.Spec.Cluster}, &cluster); err != nil {
		if apierrors.IsNotFound(err) {
			return r.waiting(ctx, &cr, "no TunnexCluster resource named "+cr.Spec.Cluster+" yet", gen)
		}
		return ctrl.Result{}, err
	}
	if cluster.Status.ClusterID == "" {
		return r.waiting(ctx, &cr, "cluster "+cr.Spec.Cluster+" is not registered yet", gen)
	}
	clusterID := cluster.Status.ClusterID

	rules, found, err := r.CP.ListNamespaceRules(ctx, clusterID)
	if err != nil {
		return ctrl.Result{}, err // keep-last
	}
	if !found {
		return r.waiting(ctx, &cr, "cluster "+cr.Spec.Cluster+" is not registered in the control plane", gen)
	}
	want := desiredNamespaceRule(&cr)
	cause := crRef("tunnexnamespaceexposure", cr.Namespace, cr.Name)

	var rule *cp.NamespaceRule
	drift := false
	if cr.Status.RuleID != "" {
		// We hold a rule: confirm THAT rule by id. Gone means it was removed behind the operator's back.
		for i := range rules {
			if rules[i].ID == cr.Status.RuleID {
				rule = &rules[i]
			}
		}
		switch {
		case rule == nil:
			if other := ruleForNamespace(rules, cr.Spec.Namespace); other != nil && !other.ManagedByOperator {
				// Removed and made again in the dashboard. It is not this resource's any more.
				return r.notReady(ctx, &cr, reasonUnmanaged,
					"the namespace rule this resource declared was removed, and "+cr.Spec.Namespace+" now has a rule made outside the operator; this resource will not change or remove it. Remove that rule, or remove this resource", gen)
			}
			drift = true
		case rule.Namespace != cr.Spec.Namespace:
			// The CRD refuses this edit at admission; this is the same refusal for a cluster without it.
			return r.notReady(ctx, &cr, reasonSpecChange, fmt.Sprintf(
				"this resource declares the namespace rule for %s and its namespace cannot be changed in place; restore the spec, or delete this resource and create a new one",
				rule.Namespace), gen)
		case !rule.ManagedByOperator:
			return r.notReady(ctx, &cr, reasonUnmanaged,
				"the namespace rule for "+rule.Namespace+" is no longer managed by the operator (its credential was replaced); this resource will not change or remove it", gen)
		}
	}
	if rule == nil {
		// One rule per namespace per cluster: an existing rule for this namespace is the only candidate.
		if existing := ruleForNamespace(rules, cr.Spec.Namespace); existing != nil {
			if !existing.ManagedByOperator {
				return r.notReady(ctx, &cr, reasonUnmanaged,
					"the namespace "+cr.Spec.Namespace+" already has a namespace rule made outside the operator; this resource will not adopt, change or remove it. Remove that rule first, or remove this resource", gen)
			}
			if other, err := r.claimedByAnother(ctx, &cr, existing.ID); err != nil {
				return ctrl.Result{}, err
			} else if other != "" {
				return r.notReady(ctx, &cr, reasonDuplicate, "resource "+other+" already declares the namespace rule for "+cr.Spec.Namespace, gen)
			}
			rule, drift = existing, false
		}
	}

	switch {
	case rule == nil:
		created, err := r.CP.CreateNamespaceRule(ctx, clusterID, want, cause)
		if res, e, handled, persist := onCPError(&cr.Status.Conditions, err, gen); handled {
			if persist {
				if u := r.Status().Update(ctx, &cr); u != nil {
					return ctrl.Result{}, u
				}
			}
			return res, e
		}
		rule = &created
	case !sameNamespaceRuleSpec(rule, want):
		// selector and excludedServices are the two things the control plane changes in place.
		updated, err := r.CP.UpdateNamespaceRule(ctx, clusterID, rule.ID, want, cause)
		if res, e, handled, persist := onCPError(&cr.Status.Conditions, err, gen); handled {
			if persist {
				if u := r.Status().Update(ctx, &cr); u != nil {
					return ctrl.Result{}, u
				}
			}
			return res, e
		}
		rule = &updated
	}

	cr.Status.RuleID = rule.ID
	cr.Status.RuleStatus = rule.Status
	cr.Status.ExposedServices, cr.Status.ExposedPorts, cr.Status.WaitingServices = rule.ExposedServices, rule.ExposedPorts, rule.WaitingServices
	if drift {
		const driftMsg = "the control-plane namespace rule was absent; recreated from the resource. Exposures the earlier rule made were kept or withdrawn by whoever removed it and are not adopted"
		setDrift(&cr.Status.Conditions, true, driftMsg, gen)
		recordDriftHealed(r.Recorder, &cr, driftMsg)
	} else {
		setDrift(&cr.Status.Conditions, false, "in sync with the control plane", gen)
	}
	if rule.Status != namespaceRuleApplied {
		// The rule exists and equals the spec, but it is not in effect. Ready says so, with the control
		// plane's own status and sentence.
		message := rule.StatusMessage
		if message == "" {
			message = "the control plane has not applied the namespace rule yet (status " + rule.Status + ")"
		}
		setReady(&cr.Status.Conditions, metav1.ConditionFalse, reasonFor(rule.Status), message, gen)
		return ctrl.Result{RequeueAfter: requeueRuleNotApplied}, r.Status().Update(ctx, &cr)
	}
	setReady(&cr.Status.Conditions, metav1.ConditionTrue, "Applied", fmt.Sprintf(
		"the control plane applies the namespace rule: %d Service(s), %d port(s) exposed by it. Exposure grants no access",
		rule.ExposedServices, rule.ExposedPorts), gen)
	return ctrl.Result{RequeueAfter: resyncReady}, r.Status().Update(ctx, &cr)
}

// desiredNamespaceRule is the rule the resource declares. Selector and exclusions are never nil: an
// omitted field means "none", and is sent as none.
func desiredNamespaceRule(cr *tunnexv1.TunnexNamespaceExposure) cp.NamespaceRuleRequest {
	want := cp.NamespaceRuleRequest{Namespace: cr.Spec.Namespace, Selector: map[string]string{}, ExcludedServices: []string{}}
	for key, value := range cr.Spec.Selector {
		want.Selector[key] = string(value)
	}
	for _, name := range cr.Spec.ExcludedServices {
		want.ExcludedServices = append(want.ExcludedServices, string(name))
	}
	sort.Strings(want.ExcludedServices)
	return want
}

func sameNamespaceRuleSpec(rule *cp.NamespaceRule, want cp.NamespaceRuleRequest) bool {
	if len(rule.Selector) != len(want.Selector) || len(rule.ExcludedServices) != len(want.ExcludedServices) {
		return false
	}
	for key, value := range want.Selector {
		if got, ok := rule.Selector[key]; !ok || got != value {
			return false
		}
	}
	have := append([]string(nil), rule.ExcludedServices...)
	sort.Strings(have)
	for i := range have {
		if have[i] != want.ExcludedServices[i] {
			return false
		}
	}
	return true
}

func ruleForNamespace(rules []cp.NamespaceRule, namespace string) *cp.NamespaceRule {
	for i := range rules {
		if rules[i].Namespace == namespace {
			return &rules[i]
		}
	}
	return nil
}

func (r *TunnexNamespaceExposureReconciler) waiting(ctx context.Context, cr *tunnexv1.TunnexNamespaceExposure, msg string, gen int64) (ctrl.Result, error) {
	setReady(&cr.Status.Conditions, metav1.ConditionFalse, "WaitingForCluster", msg, gen)
	if err := r.Status().Update(ctx, cr); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: requeueDependency}, nil
}

// notReady records an honest Ready=False for this generation and retries slowly.
func (r *TunnexNamespaceExposureReconciler) notReady(ctx context.Context, cr *tunnexv1.TunnexNamespaceExposure, reason, msg string, gen int64) (ctrl.Result, error) {
	setReady(&cr.Status.Conditions, metav1.ConditionFalse, reason, msg, gen)
	if err := r.Status().Update(ctx, cr); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: clientErrRequeue}, nil
}

// claimedByAnother returns the namespace/name of a different TunnexNamespaceExposure that already holds
// the rule id, or "". Two resources for one rule would overwrite each other's selector and exclusions,
// and deleting either would remove the rule for both.
func (r *TunnexNamespaceExposureReconciler) claimedByAnother(ctx context.Context, cr *tunnexv1.TunnexNamespaceExposure, ruleID string) (string, error) {
	var all tunnexv1.TunnexNamespaceExposureList
	if err := r.List(ctx, &all); err != nil {
		return "", err
	}
	for i := range all.Items {
		other := &all.Items[i]
		if other.UID != cr.UID && other.Status.RuleID == ruleID && other.DeletionTimestamp.IsZero() {
			return other.Namespace + "/" + other.Name, nil
		}
	}
	return "", nil
}

// finalize removes the rule this resource declared, doing with its exposures exactly what
// spec.deletionPolicy says: Keep (the default) leaves them as ordinary exposures, Withdraw removes them
// with the rule. Nothing is implied. A rule the operator no longer manages is left alone.
func (r *TunnexNamespaceExposureReconciler) finalize(ctx context.Context, cr *tunnexv1.TunnexNamespaceExposure) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(cr, finalizerName) {
		return ctrl.Result{}, nil
	}
	if cr.Status.RuleID != "" {
		var cluster tunnexv1.TunnexCluster
		err := r.Get(ctx, client.ObjectKey{Namespace: cr.Namespace, Name: cr.Spec.Cluster}, &cluster)
		switch {
		case apierrors.IsNotFound(err) || (err == nil && cluster.Status.ClusterID == ""):
			// The cluster resource is gone, and deregistering a cluster removes its rules with it.
			r.event(cr, "Normal", "RuleNotRemoved", "the TunnexCluster resource "+cr.Spec.Cluster+" is gone; a deregistered cluster's namespace rules went with it, so nothing was removed here")
		case err != nil:
			return ctrl.Result{}, err
		default:
			withdraw := cr.Spec.DeletionPolicy == tunnexv1.DeletionPolicyWithdraw
			cause := crRef("tunnexnamespaceexposure", cr.Namespace, cr.Name)
			err := ignoreCPNotFound(r.CP.DeleteNamespaceRule(ctx, cluster.Status.ClusterID, cr.Status.RuleID, withdraw, cause))
			switch e := cp.AsAPIError(err); {
			case err == nil && withdraw:
				r.event(cr, "Normal", "RuleRemoved", "namespace rule for "+cr.Spec.Namespace+" removed and every exposure it made withdrawn (deletionPolicy Withdraw)")
			case err == nil:
				r.event(cr, "Normal", "RuleRemoved", "namespace rule for "+cr.Spec.Namespace+" removed; the exposures it made are kept as ordinary exposures (deletionPolicy Keep)")
			case e != nil && e.Code == codeRuleNotManaged:
				// Not the operator's any more: release the resource, leave the rule.
				r.event(cr, "Warning", "RuleNotRemoved", "the namespace rule for "+cr.Spec.Namespace+" is no longer managed by the operator and was left in place")
			default:
				return ctrl.Result{}, surfaceTeardown(ctx, r.Status(), r.Recorder, cr, &cr.Status.Conditions, err, cr.Generation)
			}
		}
	}
	controllerutil.RemoveFinalizer(cr, finalizerName)
	return ctrl.Result{}, r.Update(ctx, cr)
}

func (r *TunnexNamespaceExposureReconciler) event(obj runtime.Object, kind, reason, msg string) {
	if r.Recorder != nil {
		r.Recorder.Event(obj, kind, reason, msg)
	}
}

func (r *TunnexNamespaceExposureReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&tunnexv1.TunnexNamespaceExposure{}).Complete(r)
}
