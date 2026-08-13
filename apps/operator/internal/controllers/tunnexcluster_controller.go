package controllers

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	tunnexv1 "github.com/tunnexio/tunnex/apps/operator/api/v1alpha1"
	"github.com/tunnexio/tunnex/apps/operator/internal/cp"
)

// TunnexClusterReconciler registers a TunnexCluster on the fabric through the CP RegisterCluster verb. It is
// the ROOT of the ordering chain: a TunnexExposedService waits on its cluster's status.ClusterID, and a
// TunnexGrant waits on the service — so cluster-before-service-before-grant falls out of each reconciler
// requeueing until its dependency's status is populated (no topological sort).
type TunnexClusterReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	CP       *cp.Client
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=tunnex.io,resources=tunnexclusters,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=tunnex.io,resources=tunnexclusters/status,verbs=get;update;patch

func (r *TunnexClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cr tunnexv1.TunnexCluster
	if err := r.Get(ctx, req.NamespacedName, &cr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !cr.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, &cr) // deregister CP-side (audited, CR as cause) then release the finalizer
	}
	if ensureMeta(&cr) {
		if err := r.Update(ctx, &cr); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil // next pass runs against the labeled+finalized object
	}
	gen := cr.Generation

	// Resolve the fronting site NAME -> id (the CP verb wants a UUID).
	siteID, found, err := resolveSite(ctx, r.CP, cr.Spec.Site)
	if err != nil {
		return ctrl.Result{}, err // transport/5xx -> keep-last
	}
	if !found {
		setReady(&cr.Status.Conditions, metav1.ConditionFalse, "site_not_found",
			"no site named "+cr.Spec.Site+" in this org", gen)
		if e := r.Status().Update(ctx, &cr); e != nil {
			return ctrl.Result{}, e
		}
		return ctrl.Result{RequeueAfter: clientErrRequeue}, nil
	}

	// Idempotent: find-by-name before create (reconcile runs repeatedly; never double-register).
	clusters, err := r.CP.ListClusters(ctx)
	if err != nil {
		return ctrl.Result{}, err // keep-last
	}
	var reg *cp.Cluster
	for i := range clusters {
		if clusters[i].Name == cr.Spec.Name {
			reg = &clusters[i]
			break
		}
	}
	// DRIFT: find-by-name missed but we hold a ClusterID. C2 confirm-by-ID before recreating — a single-row
	// GET can't be fooled by a spuriously-empty LIST the way find-by-name can. If it's still there, the list
	// was stale: adopt it, no drift, no duplicate. If authoritatively 404, it was deleted out-of-band → drift
	// (recreate from the CR, the one truth about intent). A transport failure keeps-last (never a false gone).
	drift := false
	if reg == nil && cr.Status.ClusterID != "" {
		existing, found, err := r.CP.GetCluster(ctx, cr.Status.ClusterID)
		if err != nil {
			return ctrl.Result{}, err // keep-last
		}
		if found {
			reg = &existing
		} else {
			drift = true
		}
	}
	if reg == nil {
		c, err := r.CP.RegisterCluster(ctx, cp.RegisterClusterRequest{
			SiteID: siteID, Name: cr.Spec.Name, VipRange: cr.Spec.VIPRange,
			ServiceCidr: cr.Spec.ServiceCIDR, DnsZone: cr.Spec.DNSZone,
		})
		if res, e, handled, persist := onCPError(&cr.Status.Conditions, err, gen); handled {
			if persist {
				if u := r.Status().Update(ctx, &cr); u != nil {
					return ctrl.Result{}, u
				}
			}
			return res, e
		}
		reg = &c
	}

	// Accepted — mirror the CP's DERIVED truth into status.
	cr.Status.ClusterID = reg.ID
	cr.Status.DNSVIP = reg.DnsVip
	if drift {
		const driftMsg = "control-plane cluster was absent; recreated from the CR"
		setDrift(&cr.Status.Conditions, true, driftMsg, gen)
		// WF-OP-3: the condition self-clears next pass; the Event is the durable record.
		recordDriftHealed(r.Recorder, &cr, driftMsg)
	} else {
		setDrift(&cr.Status.Conditions, false, "in sync with the control plane", gen)
	}
	setReady(&cr.Status.Conditions, metav1.ConditionTrue, "Accepted", "control plane registered the cluster", gen)
	return ctrl.Result{}, r.Status().Update(ctx, &cr)
}

// finalize deregisters the cluster CP-side through the AUDITED verb (cascade counts + the CR as cause), then
// releases the finalizer so k8s can remove the CR. A CP 404 is success (already gone). A transient failure
// keeps the finalizer — the object is held until teardown actually lands (never a dangling CP object).
func (r *TunnexClusterReconciler) finalize(ctx context.Context, cr *tunnexv1.TunnexCluster) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(cr, finalizerName) {
		return ctrl.Result{}, nil
	}
	if cr.Status.ClusterID != "" {
		cause := crRef("tunnexcluster", cr.Namespace, cr.Name)
		if err := ignoreCPNotFound(r.CP.DeregisterCluster(ctx, cr.Status.ClusterID, cause)); err != nil {
			return ctrl.Result{}, surfaceTeardown(ctx, r.Status(), r.Recorder, cr, &cr.Status.Conditions, err, cr.Generation)
		}
	}
	controllerutil.RemoveFinalizer(cr, finalizerName)
	return ctrl.Result{}, r.Update(ctx, cr)
}

func (r *TunnexClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&tunnexv1.TunnexCluster{}).Complete(r)
}
