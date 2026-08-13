package idpsync

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// --- fakes (no live Graph, no DB) ---

type fakeProvider struct {
	members []DirectoryMember
	listErr error
	// resolve: per-externalID status for the D3 delete-sweep (default StatusActive); resolveErr
	// makes ResolveUserStatus fail (ambiguous → no sweep).
	resolve    map[string]UserStatus
	resolveErr error
}

func (f *fakeProvider) ListGroupMembers(ctx context.Context, groupID string) ([]DirectoryMember, error) {
	return f.members, f.listErr
}
func (f *fakeProvider) ResolveUserStatus(ctx context.Context, externalID string) (UserStatus, error) {
	if f.resolveErr != nil {
		return StatusActive, f.resolveErr
	}
	if st, ok := f.resolve[externalID]; ok {
		return st, nil
	}
	return StatusActive, nil
}

type recordCall struct {
	ok      bool
	advance bool
	errMsg  string
}

type fakeStore struct {
	groups     []SyncGroup
	current    map[uuid.UUID][]uuid.UUID // groupID → member user ids
	ext        map[uuid.UUID]string      // userID → recorded directory external id (for current members)
	byEmail    map[string]uuid.UUID      // resolvable org users
	resolveErr error
	removeErr  map[uuid.UUID]bool // RemoveIdpGroupMember returns an error for these users
	addNoop    map[uuid.UUID]bool // AddIdpGroupMember returns didChange=false (concurrent conflict)

	added   []memberOp
	removed []memberOp
	pushes  int
	records []recordCall
}

type memberOp struct {
	group, user uuid.UUID
	ext         string
}

func (s *fakeStore) ListIdpSyncGroups(ctx context.Context, orgID uuid.UUID, provider string) ([]SyncGroup, error) {
	return s.groups, nil
}
func (s *fakeStore) ListIdpGroupMembers(ctx context.Context, orgID, groupID uuid.UUID) ([]SyncedMember, error) {
	out := make([]SyncedMember, 0, len(s.current[groupID]))
	for _, uid := range s.current[groupID] {
		out = append(out, SyncedMember{UserID: uid, ExternalID: s.ext[uid]})
	}
	return out, nil
}
func (s *fakeStore) ResolveOrgUser(ctx context.Context, orgID uuid.UUID, email string) (uuid.UUID, bool, error) {
	if s.resolveErr != nil {
		return uuid.Nil, false, s.resolveErr
	}
	uid, ok := s.byEmail[email]
	return uid, ok, nil
}
func (s *fakeStore) AddIdpGroupMember(ctx context.Context, orgID, groupID, userID uuid.UUID, externalID string) (bool, error) {
	if s.addNoop[userID] {
		return false, nil // ON CONFLICT DO NOTHING — a concurrent converge already inserted
	}
	s.added = append(s.added, memberOp{group: groupID, user: userID, ext: externalID})
	return true, nil
}
func (s *fakeStore) RemoveIdpGroupMember(ctx context.Context, orgID, groupID, userID uuid.UUID) (bool, error) {
	if s.removeErr[userID] {
		return false, errors.New("remove failed for " + userID.String())
	}
	s.removed = append(s.removed, memberOp{group: groupID, user: userID})
	return true, nil
}
func (s *fakeStore) RecordResult(ctx context.Context, orgID uuid.UUID, provider string, ok, advance bool, errMsg string, now time.Time) error {
	s.records = append(s.records, recordCall{ok, advance, errMsg})
	return nil
}
func (s *fakeStore) PushOrg(ctx context.Context, orgID uuid.UUID) { s.pushes++ }

type fakeDeprov struct {
	attempted   []uuid.UUID        // every user DeactivateForSync was called for
	deactivated []uuid.UUID        // users actually deactivated (didAct=true)
	failFor     map[uuid.UUID]bool // return an error (e.g. sole-owner last_owner)
	already     map[uuid.UUID]bool // already deactivated → didAct=false, no error (#7)
}

func (d *fakeDeprov) DeactivateForSync(ctx context.Context, orgID, userID uuid.UUID, provider string) (bool, error) {
	d.attempted = append(d.attempted, userID)
	if d.failFor[userID] {
		return false, errors.New("last_owner: " + userID.String())
	}
	if d.already[userID] {
		return false, nil // idempotent no-op
	}
	d.deactivated = append(d.deactivated, userID)
	return true, nil
}

func (d *fakeDeprov) RevokeOrgAccess(context.Context, uuid.UUID, uuid.UUID, string) (bool, error) {
	return true, nil
}

// --- helpers ---

var (
	org  = uuid.New()
	grp  = uuid.New()
	uAli = uuid.New()
	uBob = uuid.New()
	uCar = uuid.New()
)

func baseStore() *fakeStore {
	return &fakeStore{
		groups:  []SyncGroup{{ID: grp, IdpGroupID: "g-ext-1"}},
		current: map[uuid.UUID][]uuid.UUID{},
		byEmail: map[string]uuid.UUID{"alice@acme.com": uAli, "bob@acme.com": uBob, "carol@acme.com": uCar},
	}
}

func run(t *testing.T, p DirectoryProvider, s *fakeStore, d *fakeDeprov) {
	t.Helper()
	r := NewReconciler(p, s, d, func() time.Time { return time.Unix(1700000000, 0) })
	if err := r.ReconcileConfig(context.Background(), org, "microsoft"); err != nil {
		// transient path returns the error by design; callers assert on it separately.
		t.Logf("ReconcileConfig returned: %v", err)
	}
}

// --- tests ---

func TestReconcile_AddsActiveMembers(t *testing.T) {
	s := baseStore()
	p := &fakeProvider{members: []DirectoryMember{
		{ExternalID: "x1", Email: "alice@acme.com", Status: StatusActive},
		{ExternalID: "x2", Email: "bob@acme.com", Status: StatusActive},
	}}
	d := &fakeDeprov{}
	run(t, p, s, d)

	if len(s.added) != 2 {
		t.Fatalf("want 2 adds, got %d: %+v", len(s.added), s.added)
	}
	if len(s.removed) != 0 {
		t.Errorf("want 0 removes, got %+v", s.removed)
	}
	if s.pushes != 1 {
		t.Errorf("want exactly 1 org-wide push, got %d", s.pushes)
	}
	if len(s.records) != 1 || !s.records[0].ok || !s.records[0].advance {
		t.Errorf("want one ok=true advance=true record, got %+v", s.records)
	}
}

func TestReconcile_RemovesMembersNoLongerActive(t *testing.T) {
	s := baseStore()
	s.current[grp] = []uuid.UUID{uAli, uBob} // both currently in the group
	p := &fakeProvider{members: []DirectoryMember{
		{ExternalID: "x1", Email: "alice@acme.com", Status: StatusActive}, // bob dropped out of the group
	}}
	run(t, p, s, &fakeDeprov{})

	if len(s.added) != 0 {
		t.Errorf("alice already present — want 0 adds, got %+v", s.added)
	}
	if len(s.removed) != 1 || s.removed[0].user != uBob {
		t.Fatalf("want bob removed, got %+v", s.removed)
	}
}

func TestReconcile_DisabledMemberSweptAndRemoved(t *testing.T) {
	s := baseStore()
	s.current[grp] = []uuid.UUID{uAli}
	p := &fakeProvider{members: []DirectoryMember{
		{ExternalID: "x1", Email: "alice@acme.com", Status: StatusDisabled}, // disabled upstream
	}}
	d := &fakeDeprov{}
	run(t, p, s, d)

	if len(d.deactivated) != 1 || d.deactivated[0] != uAli {
		t.Fatalf("want alice deprovisioned (full sweep), got %+v", d.deactivated)
	}
	if len(s.removed) != 1 || s.removed[0].user != uAli {
		t.Errorf("disabled member must also leave the idp group, got removed=%+v", s.removed)
	}
}

// THE LOAD-BEARING TEST. A transient fetch error must NEVER cause a removal — proven by there being
// no code path from a failed fetch to converge(). We seed a full current membership and a 503; the
// membership must be left entirely alone and health must trip fail-static (ok=false, clock frozen).
func TestReconcile_TransientFetchIsFailStatic(t *testing.T) {
	s := baseStore()
	s.current[grp] = []uuid.UUID{uAli, uBob, uCar} // a live membership sitting there
	p := &fakeProvider{listErr: errors.New("graph 503 service unavailable")}
	d := &fakeDeprov{}
	run(t, p, s, d)

	if len(s.removed) != 0 {
		t.Fatalf("FAIL-STATIC VIOLATED: a transient fetch removed %+v — a Graph outage revoked live access", s.removed)
	}
	if len(s.added) != 0 || len(d.deactivated) != 0 {
		t.Errorf("transient fetch must touch nothing; added=%+v deactivated=%+v", s.added, d.deactivated)
	}
	if s.pushes != 0 {
		t.Errorf("nothing changed → no push; got %d", s.pushes)
	}
	if len(s.records) != 1 || s.records[0].ok || s.records[0].advance {
		t.Fatalf("want fail-static health record ok=false advance=false (clock frozen), got %+v", s.records)
	}
}

// A transient failure on ONE group must not block another group's authoritative reconcile.
func TestReconcile_TransientOnOneGroupDoesNotBlockOther(t *testing.T) {
	grp2 := uuid.New()
	s := baseStore()
	s.groups = []SyncGroup{{ID: grp, IdpGroupID: "g-ext-1"}, {ID: grp2, IdpGroupID: "g-ext-2"}}
	// A per-group provider: group 1 fails transiently, group 2 lists alice.
	p := &perGroupProvider{byGroup: map[string]providerResult{
		"g-ext-1": {err: errors.New("graph 503")},
		"g-ext-2": {members: []DirectoryMember{{ExternalID: "x1", Email: "alice@acme.com", Status: StatusActive}}},
	}}
	run(t, p, s, &fakeDeprov{})

	// group 2 got its add; group 1 touched nothing; config health = fail-static.
	if len(s.added) != 1 || s.added[0].group != grp2 {
		t.Fatalf("group 2 must still reconcile despite group 1 failing, got %+v", s.added)
	}
	if len(s.records) != 1 || s.records[0].ok {
		t.Errorf("one failed group must degrade the config, got %+v", s.records)
	}
}

func TestReconcile_GroupGoneEmptiesMembershipAndDegrades(t *testing.T) {
	s := baseStore()
	s.current[grp] = []uuid.UUID{uAli, uBob}
	p := &fakeProvider{listErr: ErrGroupGone}
	run(t, p, s, &fakeDeprov{})

	if len(s.removed) != 2 {
		t.Fatalf("a deleted upstream group → membership emptied (0 grants), got removed=%+v", s.removed)
	}
	// Degraded but authoritative: ok=false, clock ADVANCES (fetch succeeded → data fresh, non-escalating).
	if len(s.records) != 1 || s.records[0].ok || !s.records[0].advance {
		t.Fatalf("gone-group health = ok=false advance=true, got %+v", s.records)
	}
}

func TestReconcile_UnmatchedEmailSkipped(t *testing.T) {
	s := baseStore()
	p := &fakeProvider{members: []DirectoryMember{
		{ExternalID: "x9", Email: "stranger@other.com", Status: StatusActive}, // not an org user
	}}
	run(t, p, s, &fakeDeprov{})
	if len(s.added) != 0 {
		t.Errorf("directory member with no matching org user must be skipped (no JIT), got %+v", s.added)
	}
}

func TestClassifySyncHealth(t *testing.T) {
	now := time.Unix(1700000000, 0)
	created := now.Add(-2 * time.Hour)
	fresh := now.Add(-5 * time.Minute)
	stale := now.Add(-40 * time.Minute)
	cases := []struct {
		name   string
		ok     bool
		lastAt *time.Time
		want   SyncTier
	}{
		{"ok", true, &fresh, TierOK},
		{"degraded-fresh-good-sync", false, &fresh, TierDegraded},
		{"escalated-stale-good-sync", false, &stale, TierEscalated},
		{"escalated-never-synced-old-config", false, nil, TierEscalated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifySyncHealth(tc.ok, tc.lastAt, created, now, EscalationCeiling)
			if got != tc.want {
				t.Errorf("ClassifySyncHealth = %v, want %v", got, tc.want)
			}
		})
	}
}

func containsUUID(s []uuid.UUID, u uuid.UUID) bool {
	for _, x := range s {
		if x == u {
			return true
		}
	}
	return false
}

// #2: a committed removal must reach the gateway even when a LATER op in the same converge errors —
// the push is deferred so an already-applied removal is never left un-propagated.
func TestReconcile_MidApplyErrorStillPushesRemoval(t *testing.T) {
	s := baseStore()
	s.current[grp] = []uuid.UUID{uAli}
	s.ext = map[uuid.UUID]string{uAli: "ext-ali"}
	p := &fakeProvider{members: []DirectoryMember{{ExternalID: "ext-ali", Email: "alice@acme.com", Status: StatusDisabled}}}
	d := &fakeDeprov{failFor: map[uuid.UUID]bool{uAli: true}} // the sweep fails AFTER the group-removal commits
	run(t, p, s, d)

	if len(s.removed) != 1 {
		t.Fatalf("the group removal must have committed, got %+v", s.removed)
	}
	if s.pushes != 1 {
		t.Fatalf("#2 VIOLATED: a committed removal was not pushed because a later op errored (pushes=%d)", s.pushes)
	}
	if len(s.records) != 1 || s.records[0].ok {
		t.Errorf("the sweep error must degrade config health, got %+v", s.records)
	}
}

// #3: one un-deprovisionable user (a sole-owner last_owner 409) must not strand deprovisioning of
// the other disabled members in the same group.
func TestReconcile_OneFailingDeprovDoesNotStrandSiblings(t *testing.T) {
	s := baseStore()
	p := &fakeProvider{members: []DirectoryMember{
		{ExternalID: "ea", Email: "alice@acme.com", Status: StatusDisabled}, // sole owner → fails
		{ExternalID: "eb", Email: "bob@acme.com", Status: StatusDisabled},   // ordinary → must still be swept
	}}
	d := &fakeDeprov{failFor: map[uuid.UUID]bool{uAli: true}}
	run(t, p, s, d)

	if !containsUUID(d.attempted, uBob) {
		t.Fatalf("#3 VIOLATED: bob was stranded after alice's deprovision failed; attempted=%v", d.attempted)
	}
	if !containsUUID(d.deactivated, uBob) {
		t.Fatalf("bob (an ordinary disabled member) must be deactivated; deactivated=%v", d.deactivated)
	}
	if len(s.records) != 1 || s.records[0].ok {
		t.Errorf("alice's failure must degrade config health, got %+v", s.records)
	}
}

// 1(a): a member removed from the group who is GONE (deleted) in the directory gets the full sweep;
// one who is still ACTIVE (merely moved out of this group) keeps their account (Red 1 stays green).
func TestReconcile_DeletedDirectoryUserSwept_MovedUserKept(t *testing.T) {
	s := baseStore()
	s.current[grp] = []uuid.UUID{uAli, uBob}
	s.ext = map[uuid.UUID]string{uAli: "ext-ali", uBob: "ext-bob"}
	// both absent from the group now; alice deleted upstream, bob just moved to another group.
	p := &fakeProvider{members: []DirectoryMember{}, resolve: map[string]UserStatus{"ext-ali": StatusGone, "ext-bob": StatusActive}}
	d := &fakeDeprov{}
	run(t, p, s, d)

	if len(s.removed) != 2 {
		t.Fatalf("both must leave the group, got %+v", s.removed)
	}
	if len(d.deactivated) != 1 || d.deactivated[0] != uAli {
		t.Fatalf("only the directory-GONE user is swept; the moved-but-active user is kept. got deactivated=%v", d.deactivated)
	}
}

// A ResolveUserStatus error on a removed member is ambiguous → NO sweep (fail-static), degrade.
func TestReconcile_ResolveErrorDoesNotSweep(t *testing.T) {
	s := baseStore()
	s.current[grp] = []uuid.UUID{uAli}
	s.ext = map[uuid.UUID]string{uAli: "ext-ali"}
	p := &fakeProvider{members: []DirectoryMember{}, resolveErr: errors.New("graph 503")}
	d := &fakeDeprov{}
	run(t, p, s, d)

	if len(s.removed) != 1 {
		t.Fatalf("the group removal is authoritative and proceeds, got %+v", s.removed)
	}
	if len(d.deactivated) != 0 {
		t.Fatalf("an ambiguous resolve must NOT sweep, got %v", d.deactivated)
	}
	if len(s.records) != 1 || s.records[0].ok {
		t.Errorf("the resolve error must degrade health, got %+v", s.records)
	}
}

// #7: an already-deactivated user (idempotent no-op) must not fire a redundant org-wide push.
func TestReconcile_AlreadyDeactivatedIsNoPush(t *testing.T) {
	s := baseStore()
	// uAli disabled upstream but NOT currently in the group (already removed a prior poll) → the only
	// candidate action is the sweep, which is a no-op because uAli is already deactivated.
	p := &fakeProvider{members: []DirectoryMember{{ExternalID: "ea", Email: "alice@acme.com", Status: StatusDisabled}}}
	d := &fakeDeprov{already: map[uuid.UUID]bool{uAli: true}}
	run(t, p, s, d)

	if len(d.attempted) != 1 {
		t.Fatalf("the sweep is still attempted, got %v", d.attempted)
	}
	if len(d.deactivated) != 0 {
		t.Errorf("already-deactivated → no-op, got %v", d.deactivated)
	}
	if s.pushes != 0 {
		t.Fatalf("#7 VIOLATED: an already-deactivated no-op fired a redundant push (pushes=%d)", s.pushes)
	}
	if len(s.records) != 1 || !s.records[0].ok {
		t.Errorf("a clean poll with no real change is healthy, got %+v", s.records)
	}
}

// Re-review survivor (low): an idempotent no-op add (ON CONFLICT DO NOTHING under a concurrent
// Trigger+PollAll race) must NOT fire a redundant org-wide push — didChange=false → changed stays false.
func TestReconcile_NoopAddDoesNotPush(t *testing.T) {
	s := baseStore()
	s.addNoop = map[uuid.UUID]bool{uAli: true} // the insert loses the race → 0 rows
	p := &fakeProvider{members: []DirectoryMember{{ExternalID: "x1", Email: "alice@acme.com", Status: StatusActive}}}
	run(t, p, s, &fakeDeprov{})

	if len(s.added) != 0 {
		t.Fatalf("no-op add recorded a change, got %+v", s.added)
	}
	if s.pushes != 0 {
		t.Fatalf("a no-op add must not fire a redundant push, got pushes=%d", s.pushes)
	}
}

// Directory sync supports the two managed providers; unknown providers are rejected.
func TestSupportedProvider(t *testing.T) {
	if err := supportedProvider("microsoft"); err != nil {
		t.Fatalf("microsoft must be supported, got %v", err)
	}
	if err := supportedProvider("google"); err != nil {
		t.Fatalf("google must be supported, got %v", err)
	}
	for _, p := range []string{"okta", ""} {
		if err := supportedProvider(p); err == nil {
			t.Errorf("#6: provider %q must be rejected at config time", p)
		}
	}
}

// perGroupProvider serves distinct results per group id (for the mixed-failure test).
type providerResult struct {
	members []DirectoryMember
	err     error
}
type perGroupProvider struct{ byGroup map[string]providerResult }

func (p *perGroupProvider) ListGroupMembers(ctx context.Context, groupID string) ([]DirectoryMember, error) {
	r := p.byGroup[groupID]
	return r.members, r.err
}
func (p *perGroupProvider) ResolveUserStatus(ctx context.Context, externalID string) (UserStatus, error) {
	return StatusActive, nil
}
