package controllers

import (
	"context"
	"net/http"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/tunnexio/tunnex/apps/operator/internal/cp"
)

// finalizerName holds a CR back from k8s garbage-collection until the operator has deleted its control-plane
// object through the AUDITED API verb (D2 cond 2) — never a dangling CP object, never a DB delete.
const finalizerName = "tunnex.io/finalizer"

// crRef is the audit cause the operator names on a delete: the CR that drove it (e.g.
// "tunnexcluster:default/prod") — so a cascade delete is traceable to the git declaration, not just the
// credential (D2 cond 2, the S10.3 H2 lesson: governance must not vanish untraceably).
func crRef(kind, namespace, name string) string {
	return kind + ":" + namespace + "/" + name
}

// ignoreCPNotFound treats a CP 404 on delete as success — the object is already gone (idempotent teardown,
// so a retried finalizer or a cascade that already removed it converges instead of wedging).
func ignoreCPNotFound(err error) error {
	if e := cp.AsAPIError(err); e != nil && e.Status == http.StatusNotFound {
		return nil
	}
	return err
}

// surfaceTeardown (S10.2 H1) makes a blocked teardown VISIBLE instead of a silently-wedged CR: it records the
// TeardownBlocked condition (naming the CP code/message) + a Warning Event, then RETURNS err so the finalizer
// stays held and controller-runtime retries. Fail-closed is correct (never a dangling CP object); the defect
// this fixes is only the silence — an admin staring at a CR that won't delete with no reason anywhere.
func surfaceTeardown(ctx context.Context, sw client.StatusWriter, rec record.EventRecorder, obj client.Object, conds *[]metav1.Condition, err error, gen int64) error {
	setTeardownBlocked(conds, err, gen)
	if rec != nil {
		rec.Event(obj, "Warning", "TeardownBlocked", err.Error())
	}
	_ = sw.Update(ctx, obj) // best-effort surface; the ORIGINAL err is returned so the finalizer retries
	return err
}

// matchGrant (S10.2 M2) finds an existing MANAGED rule with the SAME identity as greq — same destination
// service and same source subject — returning its id, else "". Idempotence-by-identity: a re-reconcile after
// a status-write failure adopts the rule it already created instead of placing a duplicate. (Two CRs
// declaring the identical grant would adopt the same rule — a genuine duplicate declaration; noted, not
// prevented. Expiry is not part of the identity: a re-create carries the same greq, so src+dst suffices.)
func matchGrant(rules []cp.Rule, greq cp.CreateGrantRequest) string {
	for i := range rules {
		r := &rules[i]
		if !r.ManagedByOperator || r.DstKind != greq.DstKind || !ptrEq(r.DstK8sServiceID, greq.DstK8sServiceID) {
			continue
		}
		if r.SrcKind != greq.SrcKind {
			continue
		}
		if ptrEq(r.SrcUserID, greq.SrcUserID) && ptrEq(r.SrcGroupID, greq.SrcGroupID) &&
			ptrEq(r.SrcSiteID, greq.SrcSiteID) && ptrEq(r.SrcCidr, greq.SrcCidr) {
			return r.ID
		}
	}
	return ""
}

func ptrEq(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// ensureMeta stamps the ownership label AND the finalizer, reporting whether either changed. Called only on a
// live (non-deleting) object — the finalizer must be present BEFORE the first CP create so a delete can never
// race ahead of teardown.
func ensureMeta(obj client.Object) bool {
	changed := false
	labels := obj.GetLabels()
	if labels[managedByLabel] != managedByValue {
		if labels == nil {
			labels = map[string]string{}
		}
		labels[managedByLabel] = managedByValue
		obj.SetLabels(labels)
		changed = true
	}
	if !controllerutil.ContainsFinalizer(obj, finalizerName) {
		controllerutil.AddFinalizer(obj, finalizerName)
		changed = true
	}
	return changed
}

// ── friendly-name → UUID resolution (read-only CP lookups; a not-found is an HONEST non-Ready, not an error) ──
//
// found=false means the CP has no such site/user/group — a spec problem the reconciler renders as Ready=False.
// A non-nil err is a transport/CP failure — keep-last (the reconciler holds status and requeues).

func resolveSite(ctx context.Context, c *cp.Client, name string) (id string, found bool, err error) {
	sites, err := c.ListSites(ctx)
	if err != nil {
		return "", false, err
	}
	for _, s := range sites {
		if s.Name == name {
			return s.ID, true, nil
		}
	}
	return "", false, nil
}

func resolveMember(ctx context.Context, c *cp.Client, email string) (id string, found bool, err error) {
	members, err := c.ListMembers(ctx)
	if err != nil {
		return "", false, err
	}
	for _, m := range members {
		if m.Email == email {
			return m.UserID, true, nil
		}
	}
	return "", false, nil
}

func resolveGroup(ctx context.Context, c *cp.Client, name string) (id string, found bool, err error) {
	groups, err := c.ListGroups(ctx)
	if err != nil {
		return "", false, err
	}
	for _, g := range groups {
		if g.Name == name {
			return g.ID, true, nil
		}
	}
	return "", false, nil
}
