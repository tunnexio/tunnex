package controllers

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

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
	connectorID, found, inSite, err := resolveConnector(ctx, r.CP, cr.Spec.Connector, siteID)
	if err != nil {
		return ctrl.Result{}, err // transport/5xx -> keep-last
	}
	if !found {
		setReady(&cr.Status.Conditions, metav1.ConditionFalse, "connector_not_found",
			"no active gateway named "+cr.Spec.Connector+" in this org", gen)
		if e := r.Status().Update(ctx, &cr); e != nil {
			return ctrl.Result{}, e
		}
		return ctrl.Result{RequeueAfter: clientErrRequeue}, nil
	}
	if !inSite {
		setReady(&cr.Status.Conditions, metav1.ConditionFalse, "connector_not_in_cluster_site",
			"gateway "+cr.Spec.Connector+" is not bound to site "+cr.Spec.Site, gen)
		if e := r.Status().Update(ctx, &cr); e != nil {
			return ctrl.Result{}, e
		}
		return ctrl.Result{RequeueAfter: clientErrRequeue}, nil
	}

	// OWNERSHIP. Once this CR holds a ClusterID, that row is confirmed by id. Before that, a cluster with
	// the same name is adopted only if the operator's credential created it and no other CR owns it:
	// adopting a dashboard-created cluster would let deleting this CR deregister it, with its Services and
	// grants (K8L-8).
	var reg *cp.Cluster
	drift := false
	if cr.Status.ClusterID != "" {
		// A single-row GET cannot be fooled by a spuriously-empty LIST. Still there → ours. Authoritative
		// 404 → deleted out of band → drift (recreate from the CR). Transport failure → keep-last.
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
		clusters, err := r.CP.ListClusters(ctx)
		if err != nil {
			return ctrl.Result{}, err // keep-last
		}
		for i := range clusters {
			if clusters[i].Name == cr.Spec.Name {
				reg = &clusters[i]
				break
			}
		}
		if reg != nil && !reg.ManagedByOperator {
			return r.notReady(ctx, &cr, reasonUnmanaged,
				"a cluster named "+cr.Spec.Name+" is already registered outside the operator; this resource will not adopt or remove it", gen)
		}
		if reg != nil {
			if other, err := r.claimedByAnother(ctx, &cr, reg.ID); err != nil {
				return ctrl.Result{}, err
			} else if other != "" {
				return r.notReady(ctx, &cr, reasonDuplicate, "resource "+other+" already declares cluster "+cr.Spec.Name, gen)
			}
		}
	}
	created := false
	if reg == nil {
		c, err := r.CP.RegisterCluster(ctx, cp.RegisterClusterRequest{
			SiteID: siteID, ConnectorNodeID: connectorID, Name: cr.Spec.Name, VipRange: cr.Spec.VIPRange,
			ServiceCidr: cr.Spec.ServiceCIDR, DnsZone: cr.Spec.DNSZone,
			Provider: cr.Spec.Provider, Platform: cr.Spec.Platform,
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
		created = true
	}

	// Explicit provider/platform is declarative presentation metadata. Reconcile
	// it through the CP's audited correction verb; omission means "leave the CP
	// value unchanged", never "infer" or "reset to unknown". A rejected update
	// must not be reported as Ready for the new CR generation.
	if !created && cr.Spec.Provider != "" &&
		(reg.Provider != cr.Spec.Provider || reg.Platform != cr.Spec.Platform) {
		cause := crRef("tunnexcluster", cr.Namespace, cr.Name)
		updated, err := r.CP.SetClusterProviderMetadata(
			ctx, reg.ID, cr.Spec.Provider, cr.Spec.Platform, cause,
		)
		if res, e, handled, persist := onCPError(&cr.Status.Conditions, err, gen); handled {
			if persist {
				if u := r.Status().Update(ctx, &cr); u != nil {
					return ctrl.Result{}, u
				}
			}
			return res, e
		}
		reg = &updated
	}

	// SPEC EDITS. The control plane can replace a cluster's connector; it cannot rename a cluster or move
	// its address range, Service network, DNS zone or site. Reporting Ready for such an edit would claim
	// the new values are live while the old ones still serve traffic.
	if !created {
		if field, live := clusterSpecMismatch(&cr, reg, siteID); field != "" {
			return r.notReady(ctx, &cr, reasonSpecChange, fmt.Sprintf(
				"spec.%s cannot be changed after registration (the registered cluster uses %s); restore it, or delete this resource and create a new one",
				field, live), gen)
		}
		if reg.ConnectorNodeID == nil || *reg.ConnectorNodeID != connectorID {
			cause := crRef("tunnexcluster", cr.Namespace, cr.Name)
			err := r.CP.SetClusterConnector(ctx, reg.ID, connectorID, cause)
			if res, e, handled, persist := onCPError(&cr.Status.Conditions, err, gen); handled {
				if persist {
					if u := r.Status().Update(ctx, &cr); u != nil {
						return ctrl.Result{}, u
					}
				}
				return res, e
			}
		}
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
	return ctrl.Result{RequeueAfter: resyncReady}, r.Status().Update(ctx, &cr)
}

// clusterSpecMismatch names the first spec field that differs from the registered cluster and cannot be
// changed in place, with the live value; "" when the immutable part of the spec matches. Address ranges are
// compared as networks, so 100.64.0.0/16 and 100.64.0.1/16 are the same range.
func clusterSpecMismatch(cr *tunnexv1.TunnexCluster, reg *cp.Cluster, siteID string) (field, live string) {
	sameRange := func(a, b string) bool {
		pa, ea := netip.ParsePrefix(strings.TrimSpace(a))
		pb, eb := netip.ParsePrefix(strings.TrimSpace(b))
		if ea != nil || eb != nil {
			return strings.TrimSpace(a) == strings.TrimSpace(b)
		}
		return pa.Masked() == pb.Masked()
	}
	switch {
	case reg.Name != "" && reg.Name != cr.Spec.Name:
		return "name", reg.Name
	case reg.SiteID != "" && reg.SiteID != siteID:
		return "site", "another site"
	case reg.VipRange != "" && !sameRange(reg.VipRange, cr.Spec.VIPRange):
		return "vipRange", reg.VipRange
	case reg.ServiceCidr != "" && !sameRange(reg.ServiceCidr, cr.Spec.ServiceCIDR):
		return "serviceCIDR", reg.ServiceCidr
	case reg.DnsZone != "" && !strings.EqualFold(reg.DnsZone, cr.Spec.DNSZone):
		return "dnsZone", reg.DnsZone
	}
	return "", ""
}

// notReady records an honest Ready=False for this generation and retries slowly.
func (r *TunnexClusterReconciler) notReady(ctx context.Context, cr *tunnexv1.TunnexCluster, reason, msg string, gen int64) (ctrl.Result, error) {
	setReady(&cr.Status.Conditions, metav1.ConditionFalse, reason, msg, gen)
	if err := r.Status().Update(ctx, cr); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: clientErrRequeue}, nil
}

// claimedByAnother returns the namespace/name of a different TunnexCluster that already holds the
// control-plane cluster id, or "".
func (r *TunnexClusterReconciler) claimedByAnother(ctx context.Context, cr *tunnexv1.TunnexCluster, clusterID string) (string, error) {
	var all tunnexv1.TunnexClusterList
	if err := r.List(ctx, &all); err != nil {
		return "", err
	}
	for i := range all.Items {
		other := &all.Items[i]
		if other.UID != cr.UID && other.Status.ClusterID == clusterID && other.DeletionTimestamp.IsZero() {
			return other.Namespace + "/" + other.Name, nil
		}
	}
	return "", nil
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
