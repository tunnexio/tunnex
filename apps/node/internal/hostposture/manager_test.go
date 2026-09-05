package hostposture

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

type fakeOwnerSource struct {
	owners []Owner
	err    error
}

func (f *fakeOwnerSource) List(context.Context, string, int) ([]Owner, error) {
	return append([]Owner(nil), f.owners...), f.err
}

type fakePostureStore struct {
	journal     Journal
	haveJournal bool
	saveErr     error
	saveHook    func(Journal) error
	heartbeat   Heartbeat
	saveStates  []string
	saveOwners  [][]Owner
}

func (f *fakePostureStore) LoadJournal() (Journal, error) {
	if !f.haveJournal {
		return Journal{}, ErrNoJournal
	}
	return f.journal, nil
}
func (f *fakePostureStore) SaveJournal(journal Journal) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	if f.saveHook != nil {
		if err := f.saveHook(journal); err != nil {
			return err
		}
	}
	f.journal, f.haveJournal = journal, true
	f.saveStates = append(f.saveStates, journal.State)
	f.saveOwners = append(f.saveOwners, append([]Owner(nil), journal.Owners...))
	return nil
}
func (f *fakePostureStore) SaveHeartbeat(heartbeat Heartbeat) error {
	f.heartbeat = heartbeat
	return nil
}

type fakeKernel struct {
	store              *fakePostureStore
	capture            int
	captureStagingName string
	prepare            int
	enforce            int
	restore            int
	prepareErr         error
	enforceErr         error
	restoreErr         error
}

func (f *fakeKernel) CaptureBaseline(_ context.Context, stagingName string) ([]SysctlReceipt, error) {
	f.capture++
	f.captureStagingName = stagingName
	if !validWireGuardStagingName(stagingName) {
		return nil, fmt.Errorf("invalid staging identity")
	}
	out := desiredSysctls()
	for i := range out {
		out[i].Original = fmt.Sprintf("original-%d", i)
	}
	return out, nil
}
func (f *fakeKernel) Prepare(_ context.Context, journal *Journal, _ func(*Journal) error) error {
	f.prepare++
	if !f.store.haveJournal || f.store.journal.State != StatePreparing || len(f.store.journal.Sysctls) != 3 {
		return fmt.Errorf("kernel mutation occurred before durable preparing journal")
	}
	if f.prepareErr != nil {
		return f.prepareErr
	}
	journal.Artifacts.WireGuard.StagingIfIndex = 41
	journal.Artifacts.WireGuard.IfIndex = 41
	journal.Artifacts.WireGuard.Phase = WireGuardPhaseCommitted
	return nil
}
func (f *fakeKernel) Enforce(context.Context, Journal) error {
	f.enforce++
	return f.enforceErr
}
func (f *fakeKernel) RestoreAndCleanup(_ context.Context, journal *Journal) error {
	f.restore++
	if len(f.store.journal.Owners) != 0 || f.store.journal.State != StateRestoring {
		return fmt.Errorf("cleanup occurred before durable empty-owner restoring state")
	}
	if f.restoreErr != nil {
		return f.restoreErr
	}
	for i := range journal.Sysctls {
		journal.Sysctls[i].Restored = true
	}
	return nil
}

func testOwner() Owner {
	return Owner{UID: "11111111-2222-3333-4444-555555555555", Namespace: "tunnex-system", Name: "gw-a"}
}

func newTestManager(t *testing.T, source *fakeOwnerSource, store *fakePostureStore, kernel *fakeKernel) *Manager {
	t.Helper()
	kernel.store = store
	manager, err := NewManager(Config{
		NodeName: "worker-a", ManagerUID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", ManagerBootID: "11111111111111111111111111111111", MaxOwners: 4, ReconcileInterval: time.Second,
	}, source, kernel, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return time.Unix(1234, 0) }
	return manager
}

func TestManagerJournalsBeforeMutationAndRestoresOnlyAfterDurableLastOwner(t *testing.T) {
	source := &fakeOwnerSource{owners: []Owner{testOwner()}}
	store := &fakePostureStore{}
	kernel := &fakeKernel{}
	manager := newTestManager(t, source, store, kernel)

	if err := manager.ReconcileOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if kernel.capture != 1 || kernel.prepare != 1 || kernel.enforce != 1 || kernel.restore != 0 {
		t.Fatalf("active calls capture=%d prepare=%d enforce=%d restore=%d", kernel.capture, kernel.prepare, kernel.enforce, kernel.restore)
	}
	if store.journal.State != StateActive || store.journal.Artifacts.WireGuard.IfIndex != 41 || store.heartbeat.State != HeartbeatActive || !heartbeatHasOwner(store.heartbeat, testOwner().UID) {
		t.Fatalf("active journal=%+v heartbeat=%+v", store.journal, store.heartbeat)
	}
	if kernel.captureStagingName == "" || store.journal.Artifacts.WireGuard.StagingName != kernel.captureStagingName {
		t.Fatalf("baseline staging identity=%q journal=%q", kernel.captureStagingName, store.journal.Artifacts.WireGuard.StagingName)
	}
	if len(store.saveStates) < 2 || store.saveStates[0] != StatePreparing || store.saveStates[1] != StateActive {
		t.Fatalf("journal ordering=%v, want preparing before active", store.saveStates)
	}

	source.owners = nil
	if err := manager.ReconcileOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if kernel.restore != 1 || store.journal.State != StateRestored || len(store.journal.Owners) != 0 || store.heartbeat.State != HeartbeatIdle {
		t.Fatalf("restored journal=%+v heartbeat=%+v restore=%d", store.journal, store.heartbeat, kernel.restore)
	}
	if got := store.saveOwners[len(store.saveOwners)-2]; len(got) != 0 {
		t.Fatalf("empty owner set was not durable before restore: %+v", store.saveOwners)
	}
	if got := store.saveStates[len(store.saveStates)-2:]; got[0] != StateRestoring || got[1] != StateRestored {
		t.Fatalf("cleanup journal ordering=%v, want restoring then restored", got)
	}
}

func TestManagerAPIFaultRetainsAndEnforcesLastDurableOwnersWithoutCleanup(t *testing.T) {
	source := &fakeOwnerSource{owners: []Owner{testOwner()}}
	store := &fakePostureStore{}
	kernel := &fakeKernel{}
	manager := newTestManager(t, source, store, kernel)
	if err := manager.ReconcileOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	source.owners, source.err = nil, errors.New("API partition")
	err := manager.ReconcileOnce(t.Context())
	if err == nil || kernel.restore != 0 || kernel.enforce != 2 || store.journal.State != StateActive || len(store.journal.Owners) != 1 || store.heartbeat.State != HeartbeatBlocked {
		t.Fatalf("fault err=%v kernel=%+v journal=%+v heartbeat=%+v", err, kernel, store.journal, store.heartbeat)
	}
}

func TestManagerRefusesMutationWhenPreMutationJournalCannotPersist(t *testing.T) {
	source := &fakeOwnerSource{owners: []Owner{testOwner()}}
	store := &fakePostureStore{saveErr: errors.New("disk full")}
	kernel := &fakeKernel{}
	manager := newTestManager(t, source, store, kernel)
	if err := manager.ReconcileOnce(t.Context()); err == nil {
		t.Fatal("expected journal persistence failure")
	}
	if kernel.prepare != 0 || kernel.enforce != 0 || kernel.restore != 0 {
		t.Fatalf("kernel mutated without durable journal: %+v", kernel)
	}
}

func TestManagerCleanupFailureRemainsRetryableAndNeverClaimsRestored(t *testing.T) {
	source := &fakeOwnerSource{owners: []Owner{testOwner()}}
	store := &fakePostureStore{}
	kernel := &fakeKernel{}
	manager := newTestManager(t, source, store, kernel)
	if err := manager.ReconcileOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	kernel.restoreErr = errors.New("ambiguous nft marker")
	source.owners = nil
	if err := manager.ReconcileOnce(t.Context()); err == nil {
		t.Fatal("expected cleanup refusal")
	}
	if store.journal.State == StateRestored || store.heartbeat.State != HeartbeatBlocked {
		t.Fatalf("cleanup failure claimed success: journal=%+v heartbeat=%+v", store.journal, store.heartbeat)
	}
	if store.journal.State != StateRestoring {
		t.Fatalf("cleanup failure lost durable teardown intent: state=%q", store.journal.State)
	}
}

func TestManagerRefusesCleanupWhenRestoringIntentCannotPersist(t *testing.T) {
	source := &fakeOwnerSource{owners: []Owner{testOwner()}}
	store := &fakePostureStore{}
	kernel := &fakeKernel{}
	manager := newTestManager(t, source, store, kernel)
	if err := manager.ReconcileOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	store.saveHook = func(journal Journal) error {
		if journal.State == StateRestoring {
			return errors.New("disk full before restoring intent")
		}
		return nil
	}
	source.owners = nil
	if err := manager.ReconcileOnce(t.Context()); err == nil {
		t.Fatal("expected restoring-intent persistence failure")
	}
	if kernel.restore != 0 {
		t.Fatalf("cleanup calls=%d, want zero before durable restoring state", kernel.restore)
	}
	if store.journal.State != StateActive || len(store.journal.Owners) != 0 {
		t.Fatalf("durable journal=%+v, want active with proven empty owners", store.journal)
	}
}

func TestManagerFinishesDurableRestoreBeforeAdmittingReappearedOwner(t *testing.T) {
	source := &fakeOwnerSource{owners: []Owner{testOwner()}}
	store := &fakePostureStore{}
	kernel := &fakeKernel{}
	manager := newTestManager(t, source, store, kernel)
	if err := manager.ReconcileOnce(t.Context()); err != nil {
		t.Fatal(err)
	}

	kernel.restoreErr = errors.New("transient cleanup failure")
	source.owners = nil
	if err := manager.ReconcileOnce(t.Context()); err == nil || store.journal.State != StateRestoring {
		t.Fatalf("failed cleanup err=%v journal=%+v", err, store.journal)
	}

	kernel.restoreErr = nil
	source.owners = []Owner{testOwner()}
	if err := manager.ReconcileOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if store.journal.State != StateRestored || store.heartbeat.State != HeartbeatIdle || kernel.prepare != 1 || kernel.enforce != 1 {
		t.Fatalf("reappeared owner bypassed old cleanup: journal=%+v heartbeat=%+v kernel=%+v", store.journal, store.heartbeat, kernel)
	}

	if err := manager.ReconcileOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if store.journal.State != StateActive || store.journal.Epoch != 2 || kernel.capture != 2 {
		t.Fatalf("fresh owner epoch was not created after cleanup: journal=%+v kernel=%+v", store.journal, kernel)
	}
}

func TestManagerDoesNotMutateRestoringEpochDuringAPIAmbiguity(t *testing.T) {
	source := &fakeOwnerSource{err: errors.New("API partition")}
	journal := mustTestJournal(t, StateRestoring, nil)
	store := &fakePostureStore{journal: journal, haveJournal: true}
	kernel := &fakeKernel{}
	manager := newTestManager(t, source, store, kernel)
	if err := manager.ReconcileOnce(t.Context()); err == nil {
		t.Fatal("expected authoritative owner readback failure")
	}
	if kernel.restore != 0 || kernel.prepare != 0 || kernel.enforce != 0 || store.journal.State != StateRestoring {
		t.Fatalf("API ambiguity mutated restoring epoch: kernel=%+v journal=%+v", kernel, store.journal)
	}
}

func mustTestJournal(t *testing.T, state string, owners []Owner) Journal {
	t.Helper()
	receipts := desiredSysctls()
	for i := range receipts {
		receipts[i].Original = "0"
	}
	journal, err := newJournal("worker-a", 1, receipts, owners, "tnx0123456789ab", time.Unix(1234, 0))
	if err != nil {
		t.Fatal(err)
	}
	journal.State = state
	journal.Artifacts.WireGuard.Phase = WireGuardPhaseCommitted
	journal.Artifacts.WireGuard.StagingIfIndex = 41
	journal.Artifacts.WireGuard.IfIndex = 41
	return journal
}

func TestRestoringJournalRequiresDurableEmptyOwnerSet(t *testing.T) {
	journal := mustTestJournal(t, StateRestoring, []Owner{testOwner()})
	if err := journal.validate("worker-a"); err == nil || err.Error() != "restoring journal retains owners" {
		t.Fatalf("restoring journal with an owner validation=%v", err)
	}
}
