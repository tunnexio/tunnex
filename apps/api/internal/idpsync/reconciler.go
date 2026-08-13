package idpsync

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Reconciler drives group_members(origin='idp_sync') to match a DirectoryProvider's authoritative
// view (S7.5.2 slice 3). It is provider-agnostic (talks only to DirectoryProvider) and
// storage-agnostic (talks only to Store + Deprovisioner) — the slice-4 adapter wires the concrete
// sqlc + policy push + DeactivateMember sweep behind these seams; the unit tests wire fakes.
//
// THE LOAD-BEARING GUARANTEE (D2 fail-static): a removal is only ever computed from a
// SUCCESSFULLY-FETCHED member set. This is structural, not a runtime check — reconcileGroup returns
// on a transient fetch error BEFORE converge (the only code that computes removals) is called, so a
// failed fetch has no code path that reaches a delete. A Graph outage can therefore never revoke a
// live grant; it can only trip the health alarm and leave last-known membership standing.
type Reconciler struct {
	provider DirectoryProvider
	store    Store
	deprov   Deprovisioner
	now      func() time.Time
	// provisioningAllowed reports whether the licence still entitles this deployment to PROVISION.
	// nil = allowed (no licence system wired yet, and the pre-S12.1 behaviour).
	//
	// ⭐ D1, RULED: A LICENCE MAY STOP GRANTING ACCESS. IT MUST NEVER STOP REMOVING IT.
	provisioningAllowed func() bool
}

// SyncGroup is one IdP→Tunnex group mapping to reconcile.
type SyncGroup struct {
	ID         uuid.UUID // the Tunnex user_groups row
	IdpGroupID string    // the external directory group id
}

// SyncedMember is one current idp_sync group_members row: the Tunnex user and the directory external
// id recorded when it was synced. ExternalID may be "" for a legacy row predating external-id storage
// — such a row can't be resolved on removal, so it only ever gets a group-removal (never a sweep).
type SyncedMember struct {
	UserID     uuid.UUID
	ExternalID string
}

// Store is the persistence surface the reconciler needs. The slice-4 adapter implements it over
// sqlc (Add/Remove write origin='idp_sync' rows + audit; PushOrg fires the org-wide <5s recompile).
type Store interface {
	ListIdpSyncGroups(ctx context.Context, orgID uuid.UUID, provider string) ([]SyncGroup, error)
	ListIdpGroupMembers(ctx context.Context, orgID, groupID uuid.UUID) ([]SyncedMember, error)
	// ResolveOrgUser maps a directory email to a Tunnex user that belongs to the org. found=false
	// (no matching org user) → the member is skipped: sync grants EXISTING users, it does not
	// JIT-provision (that's S2.5).
	ResolveOrgUser(ctx context.Context, orgID uuid.UUID, email string) (userID uuid.UUID, found bool, err error)
	// AddIdpGroupMember records the directory externalID with the membership so a later removal can
	// resolve the user's directory status (D3 delete-sweep). didChange=false on an idempotent no-op
	// (row already present, e.g. a concurrent converge won the insert) so the reconciler doesn't fire
	// a redundant org-wide push for a row it didn't actually change.
	AddIdpGroupMember(ctx context.Context, orgID, groupID, userID uuid.UUID, externalID string) (didChange bool, err error)
	RemoveIdpGroupMember(ctx context.Context, orgID, groupID, userID uuid.UUID) (didChange bool, err error)
	RecordResult(ctx context.Context, orgID uuid.UUID, provider string, ok, advanceClock bool, errMsg string, now time.Time) error
	PushOrg(ctx context.Context, orgID uuid.UUID)
}

// Deprovisioner cuts a user's access org-wide — the full DeactivateMember sweep (sessions + CLI
// creds + peers out of desired-state + org-wide push). Behind an interface so the reconciler only
// decides WHO to deprovision; the slice-4 adapter wires the real tenancy sweep + audit attribution.
// It returns didAct=false when the user was ALREADY deactivated (idempotent no-op) so the reconciler
// doesn't fire a redundant org-wide push on every poll for a still-listed disabled member (#7).
type Deprovisioner interface {
	DeactivateForSync(ctx context.Context, orgID, userID uuid.UUID, provider string) (didAct bool, err error)
	RevokeOrgAccess(ctx context.Context, orgID, userID uuid.UUID, cause string) (didAct bool, err error)
}

// NewReconciler builds a reconciler. now defaults to time.Now.
func NewReconciler(p DirectoryProvider, s Store, d Deprovisioner, now func() time.Time) *Reconciler {
	if now == nil {
		now = time.Now
	}
	return &Reconciler{provider: p, store: s, deprov: d, now: now}
}

// WithProvisioningGate injects the licence predicate. A separate setter rather than a NewReconciler
// parameter so the DEFAULT is "allowed" — the pre-licence behaviour — and so no existing caller silently
// acquires a gate it did not ask for.
//
// ⛔ THE GATE IS ON THE ADDITIVE HALF ONLY, BY CONSTRUCTION. There is deliberately no equivalent hook for
// removals: the way to be sure a licence can never stop a revocation is that no seam exists through which
// it could.
func (r *Reconciler) WithProvisioningGate(fn func() bool) *Reconciler {
	r.provisioningAllowed = fn
	return r
}

// mayProvision reports whether the ADDITIVE half of converge may run.
func (r *Reconciler) mayProvision() bool {
	return r.provisioningAllowed == nil || r.provisioningAllowed()
}

// ReconcileConfig reconciles every mapped group for one org+provider, then records the poll's
// two-tier health outcome. Per-group fail-static: one group's transient failure never blocks
// another group's authoritative reconcile — it only degrades the config's health.
func (r *Reconciler) ReconcileConfig(ctx context.Context, orgID uuid.UUID, provider string) error {
	groups, err := r.store.ListIdpSyncGroups(ctx, orgID, provider)
	if err != nil {
		// A DB read failure is not a directory outage; surface it without stamping health
		// (we didn't actually attempt a sync).
		return err
	}

	var transientErr error  // first transient fetch/apply failure → immediate + escalating tier
	var goneGroups []string // authoritatively-deleted mappings → immediate tier, non-escalating
	for _, g := range groups {
		gone, gErr := r.reconcileGroup(ctx, orgID, provider, g)
		if gone {
			goneGroups = append(goneGroups, g.IdpGroupID)
		}
		if gErr != nil && transientErr == nil {
			transientErr = gErr
		}
	}

	now := r.now()
	switch {
	case transientErr != nil:
		// FAIL-STATIC health: ok=false, clock FROZEN (advanceClock=false) so staleness accrues
		// toward the escalation tier. Membership was left untouched for the failed group(s).
		_ = r.store.RecordResult(ctx, orgID, provider, false, false, transientErr.Error(), now)
		return transientErr
	case len(goneGroups) > 0:
		// Authoritative but degraded: the fetch(es) succeeded (data is fresh → advanceClock=true,
		// immediate tier only), but a mapped group no longer exists upstream. Membership WAS
		// emptied for it; the operator must re-point or delete the dangling mapping.
		msg := "mapped idp group(s) no longer exist upstream: " + strings.Join(goneGroups, ", ")
		return r.store.RecordResult(ctx, orgID, provider, false, true, msg, now)
	default:
		return r.store.RecordResult(ctx, orgID, provider, true, true, "", now)
	}
}

// reconcileGroup fetches one group's authoritative membership and converges it. The transient-vs-
// authoritative fork lives HERE, and it is the whole fail-static guarantee:
//   - ErrGroupGone  → authoritative empty membership → converge on an empty set (returns gone=true)
//   - other error   → transient → return immediately; converge is NEVER reached, so no removal
//     can be computed from a failed fetch
//   - success       → converge on the fetched set
func (r *Reconciler) reconcileGroup(ctx context.Context, orgID uuid.UUID, provider string, g SyncGroup) (gone bool, err error) {
	members, ferr := r.provider.ListGroupMembers(ctx, g.IdpGroupID)
	if errors.Is(ferr, ErrGroupGone) {
		// Authoritative: the group is deleted upstream → desired membership is empty.
		return true, r.converge(ctx, orgID, provider, g, []DirectoryMember{})
	}
	if ferr != nil {
		// TRANSIENT. Return without ever constructing a desired/removal set. converge is unreachable.
		return false, fmt.Errorf("list members of idp group %s: %w", g.IdpGroupID, ferr)
	}
	return false, r.converge(ctx, orgID, provider, g, members)
}

// converge is the ONLY code that computes removals — and it is only ever called with an
// authoritative member set (a clean fetch, or the empty set of a deleted group). It:
//   - adds active members that resolve to an org user and aren't already in the group
//   - removes current members that are not in the desired-active set
//   - routes StatusDisabled members to the full DeactivateMember sweep (org-wide access cut)
//
// A single org-wide push fires (via defer, #2) iff anything changed — even when a later per-user
// error aborts the rest, so an already-committed removal always reaches the gateway. Per-user errors
// are COLLECTED, never fatal (#3): one un-deprovisionable user (e.g. a sole-owner last_owner 409)
// must not strand every other removal/sweep in the group. A non-nil return degrades config health.
func (r *Reconciler) converge(ctx context.Context, orgID uuid.UUID, provider string, g SyncGroup, members []DirectoryMember) (err error) {
	desired := map[uuid.UUID]string{}   // uid -> directory external id (recorded on the add)
	deprovision := map[uuid.UUID]bool{} // uid listed as DISABLED in this group → full sweep
	for _, m := range members {
		uid, found, e := r.store.ResolveOrgUser(ctx, orgID, m.Email)
		if e != nil {
			return e // a resolve failure before any mutation → fail-static (nothing changed yet)
		}
		if !found {
			continue // sync grants existing org users only; unmatched directory members are skipped
		}
		switch m.Status {
		case StatusActive:
			desired[uid] = m.ExternalID
		case StatusDisabled:
			deprovision[uid] = true // excluded from desired → also removed from the group below
		case StatusGone:
			// A gone user is normally simply absent from a listing; if returned, treat as not-desired.
		}
	}

	currentMembers, e := r.store.ListIdpGroupMembers(ctx, orgID, g.ID)
	if e != nil {
		return e
	}

	changed := false
	defer func() {
		if changed {
			r.store.PushOrg(ctx, orgID) // #2: committed changes propagate even if err != nil
		}
	}()
	var errs []error

	// Adds (grant). Fail-closed: collect + continue (a failed add just means fewer grants).
	//
	// ⭐ D1 (RULED): A LICENCE MAY STOP GRANTING ACCESS. IT MUST NEVER STOP REMOVING IT.
	//
	// On a lapsed licence THIS BLOCK IS SKIPPED and the two below still run. Joiners stop being
	// provisioned — the capability the customer was paying for — while leavers keep losing access,
	// because that is not a feature being sold, it is the product not leaking access.
	//
	// ⛔ THE OBVIOUS IMPLEMENTATION IS THE WRONG ONE, AND IT LOOKS LIKE THE CONVENTION. The precedent is
	// ReleaseAllHealthBlocks (devices/health.go:260), which RELEASES posture enforcement on downgrade.
	// Copying it here means "stop reconciling", which freezes membership at the last sync and leaves a
	// directory-removed person with working access indefinitely. Posture is a RESTRICTION, so releasing it
	// is safe; sync is a REVOCATION MECHANISM, so releasing it is the fail-open. See docs/laws.md.
	//
	// ⚠ The desired-set computation above is SHARED and ungated, so removals are still derived only from a
	// SUCCESSFULLY-FETCHED member set — the fail-static property is untouched by this gate.
	currentSet := map[uuid.UUID]bool{}
	for _, m := range currentMembers {
		currentSet[m.UserID] = true
	}
	// Evaluated ONCE, before the loop: a predicate re-read per member could grant half a group and skip the
	// rest, which is a state no operator could explain and no test would reliably reproduce.
	if r.mayProvision() {
		for _, uid := range sortedUUIDKeys(desired) {
			if !currentSet[uid] {
				did, e := r.store.AddIdpGroupMember(ctx, orgID, g.ID, uid, desired[uid])
				if e != nil {
					errs = append(errs, fmt.Errorf("add %s: %w", uid, e))
					continue
				}
				if did { // false on an idempotent no-op → no redundant push
					changed = true
				}
			}
		}
	}

	// Removes + D3 delete-sweep (1(a)). A member no longer desired leaves the group. If they were
	// DELETED or DISABLED in the directory (ResolveUserStatus) — not merely moved out of this group —
	// they also get the full sweep; an ACTIVE user (moved teams) keeps their account (Red 1). A
	// member listed as disabled here is swept in the deprovision loop instead (skip the extra lookup).
	for _, m := range currentMembers {
		if _, keep := desired[m.UserID]; keep {
			continue
		}
		did, e := r.store.RemoveIdpGroupMember(ctx, orgID, g.ID, m.UserID)
		if e != nil {
			errs = append(errs, fmt.Errorf("remove %s: %w", m.UserID, e))
			continue
		}
		if !did {
			continue // already removed by a concurrent converge — it owns the sweep decision
		}
		changed = true
		if deprovision[m.UserID] || m.ExternalID == "" {
			continue // disabled (swept below), or a legacy row we can't resolve → group-removal only
		}
		st, rerr := r.provider.ResolveUserStatus(ctx, m.ExternalID)
		if rerr != nil {
			errs = append(errs, fmt.Errorf("resolve %s: %w", m.UserID, rerr)) // ambiguous → NO sweep (fail-static)
			continue
		}
		if st == StatusGone || st == StatusDisabled {
			if did, de := r.deprov.DeactivateForSync(ctx, orgID, m.UserID, provider); de != nil {
				errs = append(errs, fmt.Errorf("sweep %s: %w", m.UserID, de))
			} else if did {
				changed = true
			}
		}
	}

	// Deprovision members listed as DISABLED in this group (full sweep). Collect + continue (#3).
	for _, uid := range sortedUUIDKeys(deprovision) {
		if did, de := r.deprov.DeactivateForSync(ctx, orgID, uid, provider); de != nil {
			errs = append(errs, fmt.Errorf("deprovision %s: %w", uid, de))
			continue
		} else if did {
			changed = true
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func sortedUUIDKeys[V any](m map[uuid.UUID]V) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
