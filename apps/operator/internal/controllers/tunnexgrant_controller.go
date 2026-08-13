package controllers

import (
	"context"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	tunnexv1 "github.com/tunnexio/tunnex/apps/operator/api/v1alpha1"
	"github.com/tunnexio/tunnex/apps/operator/internal/cp"
)

// TunnexGrantReconciler creates a grant reaching an exposed Service via the CP policy verb (ENTERPRISE — a
// 403 edition_required in the open build surfaces VERBATIM in status, never a silent no-op). ORDERING: it
// waits until the referenced TunnexExposedService CR carries a status.ServiceID before creating the rule —
// create-service-before-grant, expressed as a requeue.
type TunnexGrantReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	CP       *cp.Client
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=tunnex.io,resources=tunnexgrants,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=tunnex.io,resources=tunnexgrants/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=tunnex.io,resources=tunnexexposedservices,verbs=get;list;watch

func (r *TunnexGrantReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cr tunnexv1.TunnexGrant
	if err := r.Get(ctx, req.NamespacedName, &cr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !cr.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, &cr) // delete the grant CP-side (revocation on the wire, audited, CR as cause)
	}
	if ensureMeta(&cr) {
		if err := r.Update(ctx, &cr); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}
	gen := cr.Generation

	// ORDERING: the destination service must be exposed (status.ServiceID set) first.
	var svc tunnexv1.TunnexExposedService
	if err := r.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: cr.Spec.Service}, &svc); err != nil {
		if apierrors.IsNotFound(err) {
			setReady(&cr.Status.Conditions, metav1.ConditionFalse, "WaitingForService",
				"no TunnexExposedService resource named "+cr.Spec.Service+" yet", gen)
			if e := r.Status().Update(ctx, &cr); e != nil {
				return ctrl.Result{}, e
			}
			return ctrl.Result{RequeueAfter: requeueDependency}, nil
		}
		return ctrl.Result{}, err
	}
	if svc.Status.ServiceID == "" {
		setReady(&cr.Status.Conditions, metav1.ConditionFalse, "WaitingForService",
			"service "+cr.Spec.Service+" is not exposed yet", gen)
		if e := r.Status().Update(ctx, &cr); e != nil {
			return ctrl.Result{}, e
		}
		return ctrl.Result{RequeueAfter: requeueDependency}, nil
	}
	serviceID := svc.Status.ServiceID

	// Idempotent: policy rules aren't named, so once we hold a RuleID we consider the grant placed (drift
	// reconcile is Slice 4). A create-then-status-write failure could double-place; identical grants are
	// same-effect (default-deny + idempotent allow) — the residual is registered in the paper.
	if cr.Status.RuleID != "" {
		if !meta.IsStatusConditionTrue(cr.Status.Conditions, condReady) {
			setReady(&cr.Status.Conditions, metav1.ConditionTrue, "Accepted", "grant placed", gen)
			return ctrl.Result{}, r.Status().Update(ctx, &cr)
		}
		return ctrl.Result{}, nil
	}

	// Resolve the friendly subject -> the CP's src fields. A subject that doesn't resolve is HONEST non-Ready.
	greq := cp.CreateGrantRequest{SrcKind: cr.Spec.SubjectKind, DstKind: "k8s_service", DstK8sServiceID: &serviceID}
	switch cr.Spec.SubjectKind {
	case "cidr":
		v := cr.Spec.Subject
		greq.SrcCidr = &v
	case "site":
		id, found, err := resolveSite(ctx, r.CP, cr.Spec.Subject)
		if err != nil {
			return ctrl.Result{}, err // keep-last
		}
		if !found {
			return r.rejectSubject(ctx, &cr, "no site named "+cr.Spec.Subject, gen)
		}
		greq.SrcSiteID = &id
	case "user":
		id, found, err := resolveMember(ctx, r.CP, cr.Spec.Subject)
		if err != nil {
			return ctrl.Result{}, err
		}
		if !found {
			return r.rejectSubject(ctx, &cr, "no member with email "+cr.Spec.Subject, gen)
		}
		greq.SrcUserID = &id
	case "group":
		id, found, err := resolveGroup(ctx, r.CP, cr.Spec.Subject)
		if err != nil {
			return ctrl.Result{}, err
		}
		if !found {
			return r.rejectSubject(ctx, &cr, "no group named "+cr.Spec.Subject, gen)
		}
		greq.SrcGroupID = &id
	default:
		return r.rejectSubject(ctx, &cr, "unsupported subjectKind "+cr.Spec.SubjectKind, gen)
	}
	if cr.Spec.ExpiresAt != nil {
		s := cr.Spec.ExpiresAt.UTC().Format(time.RFC3339)
		greq.ExpiresAt = &s
	}

	// M2 idempotence-by-identity: policy rules are unnamed, so a status-write failure after a prior create
	// would otherwise re-place a DUPLICATE grant (doubled access). Find an existing MANAGED rule matching this
	// grant's (dst service, src subject) first; adopt it if present. Same instinct as everywhere else here.
	rules, err := r.CP.ListPolicies(ctx)
	if res, e, handled, persist := onCPError(&cr.Status.Conditions, err, gen); handled {
		// A 4xx here (notably edition_required in the open build — policy list is enterprise too) is surfaced
		// HONESTLY, same as the create path; a 5xx/transport failure keeps-last.
		if persist {
			if u := r.Status().Update(ctx, &cr); u != nil {
				return ctrl.Result{}, u
			}
		}
		return res, e
	}
	if id := matchGrant(rules, greq); id != "" {
		cr.Status.RuleID = id
		setReady(&cr.Status.Conditions, metav1.ConditionTrue, "Accepted", "grant placed (adopted existing)", gen)
		return ctrl.Result{}, r.Status().Update(ctx, &cr)
	}

	rule, err := r.CP.CreateGrant(ctx, greq)
	if res, e, handled, persist := onCPError(&cr.Status.Conditions, err, gen); handled {
		if persist {
			if u := r.Status().Update(ctx, &cr); u != nil {
				return ctrl.Result{}, u
			}
		}
		return res, e
	}

	cr.Status.RuleID = rule.ID
	setReady(&cr.Status.Conditions, metav1.ConditionTrue, "Accepted", "control plane created the grant", gen)
	return ctrl.Result{}, r.Status().Update(ctx, &cr)
}

// finalize deletes the grant CP-side through the AUDITED policy verb — revocation on the wire (the flow that
// was allowed dies), CR as cause — then releases the finalizer.
func (r *TunnexGrantReconciler) finalize(ctx context.Context, cr *tunnexv1.TunnexGrant) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(cr, finalizerName) {
		return ctrl.Result{}, nil
	}
	if cr.Status.RuleID != "" {
		cause := crRef("tunnexgrant", cr.Namespace, cr.Name)
		if err := ignoreCPNotFound(r.CP.DeleteGrant(ctx, cr.Status.RuleID, cause)); err != nil {
			return ctrl.Result{}, surfaceTeardown(ctx, r.Status(), r.Recorder, cr, &cr.Status.Conditions, err, cr.Generation)
		}
	}
	controllerutil.RemoveFinalizer(cr, finalizerName)
	return ctrl.Result{}, r.Update(ctx, cr)
}

// rejectSubject writes an HONEST subject_not_found status and requeues slowly (the subject may appear later).
func (r *TunnexGrantReconciler) rejectSubject(ctx context.Context, cr *tunnexv1.TunnexGrant, msg string, gen int64) (ctrl.Result, error) {
	setReady(&cr.Status.Conditions, metav1.ConditionFalse, "subject_not_found", msg, gen)
	if e := r.Status().Update(ctx, cr); e != nil {
		return ctrl.Result{}, e
	}
	return ctrl.Result{RequeueAfter: clientErrRequeue}, nil
}

func (r *TunnexGrantReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&tunnexv1.TunnexGrant{}).Complete(r)
}
