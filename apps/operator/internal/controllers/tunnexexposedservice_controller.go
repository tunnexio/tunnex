package controllers

import (
	"context"

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

	// Idempotent: find-by (cluster, namespace, name) before exposing.
	services, err := r.CP.ListServices(ctx)
	if err != nil {
		return ctrl.Result{}, err // keep-last
	}
	var exp *cp.Service
	for i := range services {
		s := &services[i]
		if s.ClusterID == clusterID && s.Namespace == cr.Spec.Namespace && s.Name == cr.Spec.Service {
			exp = s
			break
		}
	}
	// DRIFT: find-by (cluster,ns,name) missed but we hold a ServiceID — C2 confirm-by-ID before recreating
	// (a single-row GET can't be fooled by a spuriously-empty list). Still there → adopt (stale list, no
	// drift, no duplicate VIP); authoritatively 404 → drift; transport failure → keep-last.
	drift := false
	if exp == nil && cr.Status.ServiceID != "" {
		existing, found, err := r.CP.GetService(ctx, cr.Status.ServiceID)
		if err != nil {
			return ctrl.Result{}, err // keep-last
		}
		if found {
			exp = &existing
		} else {
			drift = true
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
	return ctrl.Result{}, r.Status().Update(ctx, &cr)
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
