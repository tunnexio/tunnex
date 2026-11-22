package controllers

import (
	"context"
	"fmt"
	"strconv"
	"strings"

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

// TunnexExposedServiceReconciler exposes an in-cluster Service via the CP ExposeService verb. ORDERING: it
// waits until the owning TunnexCluster CR carries a status.ClusterID (the cluster is registered) before
// calling the CP — create-before-expose, expressed as a requeue, not an error.
type TunnexExposedServiceReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	CP       *cp.Client
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=tunnex.io,resources=tunnexexposedservices,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=tunnex.io,resources=tunnexexposedservices/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=tunnex.io,resources=tunnexclusters,verbs=get;list;watch

func (r *TunnexExposedServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cr tunnexv1.TunnexExposedService
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

	// ORDERING: the owning cluster CR must exist and be registered (status.ClusterID set) first.
	var cluster tunnexv1.TunnexCluster
	if err := r.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: cr.Spec.Cluster}, &cluster); err != nil {
		if apierrors.IsNotFound(err) {
			setReady(&cr.Status.Conditions, metav1.ConditionFalse, "WaitingForCluster",
				"no TunnexCluster resource named "+cr.Spec.Cluster+" yet", gen)
			if e := r.Status().Update(ctx, &cr); e != nil {
				return ctrl.Result{}, e
			}
			return ctrl.Result{RequeueAfter: requeueDependency}, nil
		}
		return ctrl.Result{}, err
	}
	if cluster.Status.ClusterID == "" {
		setReady(&cr.Status.Conditions, metav1.ConditionFalse, "WaitingForCluster",
			"cluster "+cr.Spec.Cluster+" is not registered yet", gen)
		if e := r.Status().Update(ctx, &cr); e != nil {
			return ctrl.Result{}, e
		}
		return ctrl.Result{RequeueAfter: requeueDependency}, nil
	}
	clusterID := cluster.Status.ClusterID

	// IDENTITY. One exposure is one Service PORT: the control plane keeps a row per (cluster, namespace,
	// name, protocol, port). Matching on less made a second CR for another port of the same Service adopt
	// the first CR's row and report Ready for a port that was never exposed (K8L-8).
	matches := func(s *cp.Service) bool {
		return s.ClusterID == clusterID && s.Namespace == cr.Spec.Namespace && s.Name == cr.Spec.Service &&
			strings.EqualFold(s.Protocol, cr.Spec.Protocol) && s.PortLow != nil && *s.PortLow == cr.Spec.Port
	}
	var exp *cp.Service
	drift := false
	if cr.Status.ServiceID != "" {
		// We already own a row: confirm THAT row by id (a single-row GET cannot be fooled by a stale or
		// empty list). Authoritative 404 → it was removed out of band → drift, recreate from the CR.
		existing, found, err := r.CP.GetService(ctx, cr.Status.ServiceID)
		if err != nil {
			return ctrl.Result{}, err // keep-last
		}
		switch {
		case !found:
			drift = true
		case !matches(&existing):
			// The spec was edited after the exposure was made. An exposure's cluster, namespace, name,
			// protocol and port are its identity; the control plane has no "change port" verb. Saying Ready
			// would claim the new port is open while the old one still is.
			port := "none"
			if existing.PortLow != nil {
				port = strconv.Itoa(int(*existing.PortLow))
			}
			return r.notReady(ctx, &cr, reasonSpecChange, fmt.Sprintf(
				"this resource exposes %s/%s %s %s and cannot be changed in place; restore the spec, or delete this resource and create a new one",
				existing.Namespace, existing.Name, strings.ToUpper(existing.Protocol), port), gen)
		default:
			exp = &existing
		}
	}
	if exp == nil {
		services, err := r.CP.ListServices(ctx)
		if err != nil {
			return ctrl.Result{}, err // keep-last
		}
		for i := range services {
			if matches(&services[i]) {
				exp = &services[i]
				break
			}
		}
		if exp != nil && !exp.ManagedByOperator {
			// Exposed from the dashboard or the API. Adopting it would let deleting this CR unexpose
			// something the operator never created.
			return r.notReady(ctx, &cr, reasonUnmanaged,
				"this Service port is already exposed outside the operator; unexpose it there first, or remove this resource", gen)
		}
		if exp != nil {
			if other, err := r.claimedByAnother(ctx, &cr, exp.ID); err != nil {
				return ctrl.Result{}, err
			} else if other != "" {
				return r.notReady(ctx, &cr, reasonDuplicate, "resource "+other+" already declares this Service port", gen)
			}
		}
	}
	if exp == nil {
		s, err := r.CP.ExposeService(ctx, clusterID, cp.ExposeServiceRequest{
			Name: cr.Spec.Service, Namespace: cr.Spec.Namespace, Protocol: cr.Spec.Protocol,
			PortLow: cr.Spec.Port, PortHigh: cr.Spec.Port, // single specific port (CP refuses all-ports)
		})
		if res, e, handled, persist := onCPError(&cr.Status.Conditions, err, gen); handled {
			if persist {
				if u := r.Status().Update(ctx, &cr); u != nil {
					return ctrl.Result{}, u
				}
			}
			return res, e
		}
		exp = &s
	}

	cr.Status.ServiceID = exp.ID
	cr.Status.VIP = exp.Vip
	cr.Status.FQDN = exp.Fqdn // DERIVED, copied from the CP — never assembled (S10.3 copy-don't-construct)
	if drift {
		const driftMsg = "control-plane service was absent; recreated from the CR"
		setDrift(&cr.Status.Conditions, true, driftMsg, gen)
		// WF-OP-3: the condition self-clears next pass; the Event is the durable record.
		recordDriftHealed(r.Recorder, &cr, driftMsg)
	} else {
		setDrift(&cr.Status.Conditions, false, "in sync with the control plane", gen)
	}
	setReady(&cr.Status.Conditions, metav1.ConditionTrue, "Accepted", "control plane exposed the service", gen)
	return ctrl.Result{RequeueAfter: resyncReady}, r.Status().Update(ctx, &cr)
}

// notReady records an honest Ready=False for this generation and retries slowly.
func (r *TunnexExposedServiceReconciler) notReady(ctx context.Context, cr *tunnexv1.TunnexExposedService, reason, msg string, gen int64) (ctrl.Result, error) {
	setReady(&cr.Status.Conditions, metav1.ConditionFalse, reason, msg, gen)
	if err := r.Status().Update(ctx, cr); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: clientErrRequeue}, nil
}

// claimedByAnother returns the namespace/name of a different TunnexExposedService that already holds the
// control-plane exposure id, or "". Two CRs for one exposure would each believe they own it, and deleting
// either would unexpose it for both.
func (r *TunnexExposedServiceReconciler) claimedByAnother(ctx context.Context, cr *tunnexv1.TunnexExposedService, serviceID string) (string, error) {
	var all tunnexv1.TunnexExposedServiceList
	if err := r.List(ctx, &all); err != nil {
		return "", err
	}
	for i := range all.Items {
		other := &all.Items[i]
		if other.UID != cr.UID && other.Status.ServiceID == serviceID && other.DeletionTimestamp.IsZero() {
			return other.Namespace + "/" + other.Name, nil
		}
	}
	return "", nil
}

// finalize unexposes the service CP-side through the AUDITED verb (CR as cause), then releases the finalizer.
func (r *TunnexExposedServiceReconciler) finalize(ctx context.Context, cr *tunnexv1.TunnexExposedService) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(cr, finalizerName) {
		return ctrl.Result{}, nil
	}
	if cr.Status.ServiceID != "" {
		cause := crRef("tunnexexposedservice", cr.Namespace, cr.Name)
		if err := ignoreCPNotFound(r.CP.UnexposeService(ctx, cr.Status.ServiceID, cause)); err != nil {
			return ctrl.Result{}, surfaceTeardown(ctx, r.Status(), r.Recorder, cr, &cr.Status.Conditions, err, cr.Generation)
		}
	}
	controllerutil.RemoveFinalizer(cr, finalizerName)
	return ctrl.Result{}, r.Update(ctx, cr)
}

func (r *TunnexExposedServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&tunnexv1.TunnexExposedService{}).Complete(r)
}
