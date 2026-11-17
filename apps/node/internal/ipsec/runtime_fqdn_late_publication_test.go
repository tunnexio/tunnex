package ipsec

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

// lateFQDNPublicationClient publishes only after an actual short native commit.
// Immediate precommit advice therefore sees the genuine unchanged material. Old
// CP replies retain their original absolute deadline rather than restarting TTL.
type lateFQDNPublicationClient struct {
	base                     *fqdnTurnoverClient
	rig                      *renewalCycleRig
	original                 RuntimeMaterial
	originalDeadline         time.Duration
	installedAt, publishAt   time.Duration
	oldFetches, freshFetches int
	requests                 []RuntimeLeaseRequest
}

func (c *lateFQDNPublicationClient) published() bool {
	return c.publishAt != 0 && *c.rig.now >= c.publishAt
}

func (c *lateFQDNPublicationClient) IPsecMaterial(_ context.Context, id uuid.UUID, revision int64) (RuntimeMaterial, error) {
	if id != c.base.target || revision != c.original.DesiredRevision {
		return RuntimeMaterial{}, ErrRuntimeController
	}
	m := c.original
	if c.published() {
		c.freshFetches++
		m = c.base.material
	} else {
		c.oldFetches++
	}
	// Secrets are a fixed array copied with the material; production may wipe its returned copy.
	return m, nil
}

func (c *lateFQDNPublicationClient) RenewIPsecLease(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
	c.requests = append(c.requests, q)
	if id != c.base.target {
		return c.base.base.RenewIPsecLease(ctx, id, q)
	}
	if q.PolicyHash != c.base.oldHash {
		if !c.published() {
			return RuntimeLease{}, ErrRuntimeController
		}
		return c.base.RenewIPsecLease(ctx, id, q)
	}
	if c.published() {
		return RuntimeLease{}, fqdnTurnoverConflict{}
	}
	if !reflect.DeepEqual(q.FQDNGrants, c.original.Policy.FQDNGrants) {
		return RuntimeLease{}, ErrRuntimeController
	}
	reply, err := c.base.base.RenewIPsecLease(ctx, id, q)
	if err != nil {
		return reply, err
	}
	remaining := c.originalDeadline - *c.rig.now
	if remaining <= 0 {
		return RuntimeLease{}, ErrPermitLease
	}
	for _, grant := range q.FQDNGrants {
		reply.FQDNPermits = append(reply.FQDNPermits, RuntimeFQDNPermit{GrantDigest: runtimeFQDNGrantDigest(grant), TTLMS: remaining.Milliseconds()})
	}
	return reply, nil
}

func lateFQDNPublicationFixture(t *testing.T, static ...bool) (*renewalCycleRig, *lateFQDNPublicationClient, string) {
	t.Helper()
	r, base := fqdnExpiryTurnoverRig(t, static...)
	original := r.c.active[r.target]
	for id := range r.c.active {
		if id != r.target {
			delete(r.c.active, id)
		}
	}
	material := base.material
	material.Policy.FQDNGrants = append([]RuntimeFQDNGrant(nil), original.FQDNLeaseDescriptors...)
	material.Policy.Hash = original.Identity.PolicyHash
	name := ""
	for _, grant := range original.Grants {
		if grant.FQDNManaged {
			name = guardFQDNSetName(grant)
		}
	}
	if name == "" {
		t.Fatal("missing exact FQDN fixture")
	}
	// Existing unchanged proof/CP costs turn this eight-second old native window
	// into a retained six-to-nine-second new membership, not an omitted grant.
	*r.now = r.installed[name] - 8*time.Second
	client := &lateFQDNPublicationClient{base: base, rig: r, original: material,
		originalDeadline: original.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(original.FQDNLeaseDescriptors[0])]}
	r.c.client = client
	replace := r.c.replace
	r.c.replace = func(ctx context.Context, intent GuardIntent) (GuardManifest, error) {
		manifest, err := replace(ctx, intent)
		if err == nil && client.installedAt == 0 {
			if end, ok := r.installed[name]; ok && end > *r.now {
				client.installedAt = *r.now
				client.publishAt = client.installedAt + 2*time.Second
			}
		}
		return manifest, err
	}
	return r, client, name
}

func TestLateFQDNPublicationFixtureBoundary(t *testing.T) {
	r, client, name := lateFQDNPublicationFixture(t)
	old := r.c.active[r.target]
	savedDeadline := old.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(old.FQDNLeaseDescriptors[0])]
	if err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil); err != nil {
		t.Fatal(err)
	}
	left := r.installed[name] - *r.now
	t.Logf("first actual commit=%v return=%v native remaining=%v publish=%v old material reads=%d fresh material reads=%d", client.installedAt, *r.now, left, client.publishAt, client.oldFetches, client.freshFetches)
	if client.installedAt == 0 || client.publishAt != client.installedAt+2*time.Second || client.freshFetches != 0 || left <= 0 || left > 9*time.Second {
		t.Fatal("fixture did not reach retained short-member boundary")
	}
	if old.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(old.FQDNLeaseDescriptors[0])] != savedDeadline {
		t.Fatal("original authority was extended")
	}
}

func TestLateFQDNPublicationFollowupPreservesNativeContinuity(t *testing.T) {
	for _, fastReturn := range []bool{false, true} {
		name := "ordinary_return"
		if fastReturn {
			name = "fast_post_commit_return"
		}
		t.Run(name, func(t *testing.T) { lateFQDNPublicationContinuity(t, fastReturn) })
	}
}

func lateFQDNPublicationContinuity(t *testing.T, fastReturn bool) {
	r, client, oldName := lateFQDNPublicationFixture(t)
	original := r.c.active[r.target]
	originalDeadline := original.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(original.FQDNLeaseDescriptors[0])]
	process := r.c.bgpProcesses[original.Entry.DeliveryID]
	gap := false
	check := func() {
		live := false
		for name, end := range r.installed {
			if len(name) > 5 && name[:5] == "fqdn_" && end > *r.now {
				live = true
			}
		}
		if !live {
			gap = true
			t.Logf("native FQDN member absent at %s", *r.now)
		}
		for _, name := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
			if r.installed[name] <= *r.now {
				t.Errorf("ordinary permit %s expired", name)
			}
		}
	}
	proof := r.c.prove
	r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
		err := proof(ctx, e, env)
		check()
		return err
	}
	observe := r.c.recoveryObserve
	firstRenewal := true
	r.c.recoveryObserve = func(ctx context.Context, e RuntimeJournalEntry) [2]string {
		if fastReturn && firstRenewal && client.installedAt != 0 {
			// A faster initial post-commit status returns one second after the
			// native install. CP publication still occurs two seconds after that
			// actual install; immediate follow-up must see unchanged material.
			r.charge("fast_post_commit_status", 400*time.Millisecond)
			check()
			return [2]string{"up", "up"}
		}
		out := observe(ctx, e)
		check()
		return out
	}
	replace := r.c.replace
	commits := 0
	r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
		check()
		if commits > 0 && !client.published() {
			t.Error("unchanged immediate material removed/replaced native authority before publication")
		}
		out, err := replace(ctx, in)
		if err == nil {
			commits++
		}
		check()
		return out, err
	}
	if err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil); err != nil {
		t.Fatal(err)
	}
	firstRenewal = false
	check()
	if fastReturn && *r.now-client.installedAt > time.Second {
		t.Fatalf("fast-return case did not reach the early followup: commit=%s now=%s", client.installedAt, *r.now)
	}
	nativeDeadline := r.installed[oldName]
	emitted := nativeDeadline - client.installedAt
	if emitted < 6*time.Second || emitted > 9*time.Second || client.published() || client.freshFetches != 0 {
		t.Fatalf("not the late-publication boundary: emitted=%s current=%s publish=%s fresh=%d", emitted, *r.now, client.publishAt, client.freshFetches)
	}
	waits := 0
	waited := time.Duration(0)
	wait := func(ctx context.Context, d time.Duration) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d <= 0 || d > 2*time.Second {
			t.Fatalf("unbounded followup wait %s", d)
		}
		waits++
		waited += d
		r.charge("late_publication_scheduler_wait", d)
		check()
		return nil
	}
	// This is the production followup used by the caller, with only waiting bound
	// to the fixture clock. The test never manually advances to publication or
	// calls renewal at a favorable time.
	reports := 0
	publish := func(_ context.Context, d RuntimeDelivery, report RuntimeStatusReport) error {
		check()
		if d.ID != original.Delivery.ID || report.DeliveryID != d.ID || report.DesiredRevision != d.DesiredRevision {
			t.Fatal("followup published another delivery")
		}
		reports++
		return nil
	}
	err := r.c.followupFQDNMaintenance(context.Background(), maintenanceAuthority(r), func() bool { return true }, publish, nil, wait)
	check()
	r.charge("mandatory_discovery_material_work", 10*time.Second)
	check()
	after := r.c.active[r.target]
	t.Logf("emitted=%s deadline=%s publish=%s final=%s oldFetches=%d freshFetches=%d waits=%d waited=%s commits=%d gap=%t err=%v", emitted, nativeDeadline, client.publishAt, *r.now, client.oldFetches, client.freshFetches, waits, waited, commits, gap, err)
	if err != nil || gap || client.oldFetches == 0 || client.freshFetches != 1 || commits != 2 || reports != 1 || waits == 0 || waited > 2*time.Second {
		t.Fatal("late same-answer generation did not preserve finite native continuity")
	}
	if after.Identity.PolicyHash != client.base.material.Policy.Hash || !reflect.DeepEqual(after.Entry, original.Entry) || r.c.bgpProcesses[original.Entry.DeliveryID] != process || !process.Alive() {
		t.Fatal("followup changed transport or failed to acquire the fresh exact material")
	}
	if original.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(original.FQDNLeaseDescriptors[0])] != originalDeadline {
		t.Fatal("followup extended original finite authority")
	}
	nonces := map[string]bool{}
	for _, q := range client.requests {
		if q.Nonce == "" || nonces[q.Nonce] {
			t.Fatal("followup reused lease nonce")
		}
		nonces[q.Nonce] = true
	}
	for _, grant := range after.Grants {
		if grant.FQDNManaged {
			if r.installed[guardFQDNSetName(grant)] <= *r.now {
				t.Fatal("fresh exact native member missing")
			}
			if _, err := after.Authority.RemainingFQDNForApply(after.Identity, guardFQDNGrantDigest(grant), time.Millisecond); err != nil {
				t.Fatal("fresh member has no exact current CP lease", err)
			}
		}
	}
}
