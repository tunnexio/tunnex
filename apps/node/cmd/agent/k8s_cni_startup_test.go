package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/hostposture"
	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
)

func cniStartupLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func cniStartupGrant(scope k8snetprep.AuthorityScope) k8snetprep.AuthorityGrant {
	return k8snetprep.AuthorityGrant{Scope: scope, NotAfter: time.Now().Add(time.Minute)}
}

func awaitCNIStartup(t *testing.T, admitted <-chan struct{}) {
	t.Helper()
	select {
	case <-admitted:
	case <-time.After(2 * time.Second):
		t.Fatal("runtime CNI observer did not admit a valid current grant")
	}
}

func assertCNIStartupBlocked(t *testing.T, admitted <-chan struct{}) {
	t.Helper()
	select {
	case <-admitted:
		t.Fatal("runtime CNI startup admitted before a valid current grant")
	default:
	}
}

func awaitCNIStartupCalls(t *testing.T, calls *atomic.Int64, minimum int64) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for calls.Load() < minimum {
		select {
		case <-deadline.C:
			t.Fatalf("CNI observer calls=%d, want at least %d", calls.Load(), minimum)
		case <-ticker.C:
		}
	}
}

func TestKubernetesCNIStartupObserverWaitsAndKeepsSampling(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var calls, releases atomic.Int64
	var allow atomic.Bool
	guard := func(context.Context) (k8snetprep.AuthorityGrant, func(), error) {
		calls.Add(1)
		if !allow.Load() {
			return k8snetprep.AuthorityGrant{}, nil, errors.New("awaits two advancing exact-owner heartbeats")
		}
		return cniStartupGrant(k8snetprep.ScopeIPMasqAndAWS), func() { releases.Add(1) }, nil
	}
	admitted := startKubernetesCNIAuthorityObserver(ctx, guard, 2*time.Millisecond, cniStartupLogger())
	awaitCNIStartupCalls(t, &calls, 3)
	assertCNIStartupBlocked(t, admitted)
	allow.Store(true)
	awaitCNIStartup(t, admitted)
	if releases.Load() == 0 {
		t.Fatal("startup admitted while its probe lock was still held")
	}
	// The caller can now block in CP work; the observer must keep using the
	// same guard instead of becoming a one-shot admission/cache.
	afterAdmission := calls.Load()
	awaitCNIStartupCalls(t, &calls, afterAdmission+3)
	cancel()
	time.Sleep(20 * time.Millisecond)
	stopped := calls.Load()
	time.Sleep(20 * time.Millisecond)
	if calls.Load() != stopped {
		t.Fatal("CNI observer kept sampling after cancellation")
	}
}

func TestKubernetesCNIStartupObserverRefusesInvalidGrants(t *testing.T) {
	for _, name := range []string{"error", "missing expiry", "expired", "expires during release", "unknown scope", "nil release"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var calls, releases atomic.Int64
			guard := func(context.Context) (k8snetprep.AuthorityGrant, func(), error) {
				calls.Add(1)
				grant := cniStartupGrant(k8snetprep.ScopeIPMasqAndAWS)
				var release func() = func() { releases.Add(1) }
				var err error
				switch name {
				case "error":
					err = errors.New("public authority is unavailable")
				case "missing expiry":
					grant.NotAfter = time.Time{}
				case "expired":
					grant.NotAfter = time.Now().Add(-time.Second)
				case "expires during release":
					grant.NotAfter = time.Now().Add(time.Millisecond)
					release = func() {
						time.Sleep(3 * time.Millisecond)
						releases.Add(1)
					}
				case "unknown scope":
					grant.Scope = "future-unbounded-scope"
				case "nil release":
					release = nil
				}
				return grant, release, err
			}
			admitted := startKubernetesCNIAuthorityObserver(ctx, guard, 2*time.Millisecond, cniStartupLogger())
			awaitCNIStartupCalls(t, &calls, 3)
			assertCNIStartupBlocked(t, admitted)
			if name != "nil release" && releases.Load() < 2 {
				t.Fatal("refused grant leaked a probe lock between attempts")
			}
		})
	}
	t.Run("nil guard", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		admitted := startKubernetesCNIAuthorityObserver(ctx, nil, time.Millisecond, cniStartupLogger())
		time.Sleep(10 * time.Millisecond)
		assertCNIStartupBlocked(t, admitted)
	})
}

func TestKubernetesCNIStartupObserverAcceptsBothClosedScopes(t *testing.T) {
	for _, scope := range []k8snetprep.AuthorityScope{k8snetprep.ScopeIPMasqOnly, k8snetprep.ScopeIPMasqAndAWS} {
		t.Run(string(scope), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			guard := func(context.Context) (k8snetprep.AuthorityGrant, func(), error) {
				return cniStartupGrant(scope), func() {}, nil
			}
			awaitCNIStartup(t, startKubernetesCNIAuthorityObserver(ctx, guard, time.Millisecond, cniStartupLogger()))
		})
	}
}

func TestKubernetesCNIStartupObserverReleasesBeforeAdmissionAndNextProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	releasing := make(chan struct{})
	finishRelease := make(chan struct{})
	var held atomic.Bool
	var calls atomic.Int64
	guard := func(context.Context) (k8snetprep.AuthorityGrant, func(), error) {
		call := calls.Add(1)
		if held.Swap(true) {
			t.Error("next observation acquired while the previous probe lock remained held")
		}
		return cniStartupGrant(k8snetprep.ScopeIPMasqAndAWS), func() {
			if call == 1 {
				close(releasing)
				<-finishRelease
			}
			held.Store(false)
		}, nil
	}
	admitted := startKubernetesCNIAuthorityObserver(ctx, guard, 2*time.Millisecond, cniStartupLogger())
	select {
	case <-releasing:
	case <-time.After(2 * time.Second):
		t.Fatal("observer did not release its admission probe")
	}
	assertCNIStartupBlocked(t, admitted)
	close(finishRelease)
	awaitCNIStartup(t, admitted)
	awaitCNIStartupCalls(t, &calls, 3)
}

func TestKubernetesCNIStartupObserverCancellationNeverAdmits(t *testing.T) {
	t.Run("already canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		guard := func(context.Context) (k8snetprep.AuthorityGrant, func(), error) {
			return cniStartupGrant(k8snetprep.ScopeIPMasqAndAWS), func() {}, nil
		}
		admitted := startKubernetesCNIAuthorityObserver(ctx, guard, time.Millisecond, cniStartupLogger())
		time.Sleep(10 * time.Millisecond)
		assertCNIStartupBlocked(t, admitted)
	})
	t.Run("during probe", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		entered, released := make(chan struct{}), make(chan struct{})
		guard := func(probeCtx context.Context) (k8snetprep.AuthorityGrant, func(), error) {
			close(entered)
			<-probeCtx.Done()
			// A faulty runner can return success after cancellation. The observer
			// must release the lock without turning that result into admission.
			return cniStartupGrant(k8snetprep.ScopeIPMasqAndAWS), func() { close(released) }, nil
		}
		admitted := startKubernetesCNIAuthorityObserver(ctx, guard, time.Millisecond, cniStartupLogger())
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("observer never entered the probe")
		}
		cancel()
		select {
		case <-released:
		case <-time.After(time.Second):
			t.Fatal("canceled in-flight probe did not release promptly")
		}
		time.Sleep(10 * time.Millisecond)
		assertCNIStartupBlocked(t, admitted)
	})
}

const cniStartupOwnerUID = "11111111-2222-3333-4444-555555555555"

// Publish only public test records, under the same operation lock as the real
// manager. This is not a fake runtime grant or an init proof transferred to it.
func publishCNIStartupPair(t *testing.T, manager *hostposture.Store, sequence, epoch uint64, schema int, observed time.Time) {
	t.Helper()
	release, err := manager.AcquireCNIOperationLock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	heartbeat := hostposture.Heartbeat{
		SchemaVersion: hostposture.HeartbeatSchemaVersion, Contract: hostposture.Contract,
		NodeName: "worker-a", ManagerUID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		ManagerBootID: "11111111111111111111111111111111", Sequence: sequence,
		State: hostposture.HeartbeatActive, ObservedAt: observed,
		Owners: []hostposture.Owner{{UID: cniStartupOwnerUID, Namespace: "tunnex-system", Name: "gateway-a"}},
	}
	scope := k8snetprep.ScopeIPMasqAndAWS
	if schema < hostposture.JournalSchemaVersion {
		scope = k8snetprep.ScopeIPMasqOnly
	}
	authority := hostposture.CNIAuthority{
		SchemaVersion: hostposture.CNIAuthoritySchemaVersion, Contract: hostposture.CNIAuthorityContract,
		State: hostposture.CNIAuthorityGranted, NodeName: heartbeat.NodeName,
		ManagerUID: heartbeat.ManagerUID, ManagerBootID: heartbeat.ManagerBootID,
		Sequence: sequence, Epoch: epoch, JournalSchema: schema, Scope: scope, ObservedAt: observed,
	}
	if err := manager.SaveHeartbeat(heartbeat); err != nil {
		t.Fatal(err)
	}
	if err := manager.SaveCNIAuthority(authority); err != nil {
		t.Fatal(err)
	}
}

func realCNIStartupGuard(t *testing.T) (*hostposture.Store, k8snetprep.AuthorityGuard) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("real CNI operation flock is only available on Linux and Darwin")
	}
	dir := t.TempDir()
	manager, err := hostposture.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := newKubernetesCNIAuthorityGuard(dir, "worker-a", cniStartupOwnerUID)
	if err != nil {
		t.Fatal(err)
	}
	return manager, guard
}

func TestKubernetesCNIStartupObserverRealStoreRequiresAdvancementAndFreshOperationAuthority(t *testing.T) {
	manager, guard := realCNIStartupGuard(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var calls atomic.Int64
	countedGuard := func(ctx context.Context) (k8snetprep.AuthorityGrant, func(), error) {
		grant, release, err := guard(ctx)
		calls.Add(1)
		return grant, release, err
	}
	admitted := startKubernetesCNIAuthorityObserver(ctx, countedGuard, 2*time.Millisecond, cniStartupLogger())
	awaitCNIStartupCalls(t, &calls, 3)
	assertCNIStartupBlocked(t, admitted) // Missing public records never admit.
	publishCNIStartupPair(t, manager, 1, 7, 3, time.Now().Add(-hostposture.HeartbeatFreshness-time.Second))
	awaitCNIStartupCalls(t, &calls, calls.Load()+3)
	assertCNIStartupBlocked(t, admitted) // Stale correlated records never admit.
	publishCNIStartupPair(t, manager, 1, 7, 3, time.Now())
	unlock, err := manager.AcquireCNIOperationLock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := manager.LoadCNIAuthority()
	if err == nil {
		foreign.ManagerUID = "foreign-manager"
		err = manager.SaveCNIAuthority(foreign)
	}
	unlock()
	if err != nil {
		t.Fatal(err)
	}
	awaitCNIStartupCalls(t, &calls, calls.Load()+3)
	assertCNIStartupBlocked(t, admitted) // Foreign manager correlation never admits.
	publishCNIStartupPair(t, manager, 1, 7, 3, time.Now())
	awaitCNIStartupCalls(t, &calls, calls.Load()+3)
	assertCNIStartupBlocked(t, admitted) // Repeated sequence one is one proof.
	observed := time.Now()
	publishCNIStartupPair(t, manager, 2, 7, 3, observed)
	awaitCNIStartup(t, admitted)
	grant, release, err := guard(t.Context())
	if err != nil {
		t.Fatalf("same runtime guard lost its two-proof history: %v", err)
	}
	release()
	if grant.Scope != k8snetprep.ScopeIPMasqAndAWS || !grant.NotAfter.Equal(observed.Add(hostposture.HeartbeatFreshness)) {
		t.Fatalf("operation authority changed scope or refreshed expiry: %+v", grant)
	}
	// A closed admission channel is not authority to use the previous epoch's
	// scope. Repeated observations of the replacement's first frame still fail.
	publishCNIStartupPair(t, manager, 3, 8, 2, time.Now())
	awaitCNIStartupCalls(t, &calls, calls.Load()+3)
	if _, release, err := guard(t.Context()); err == nil || release != nil {
		if release != nil {
			release()
		}
		t.Fatal("startup admission cached authority across an epoch/scope change")
	}
	publishCNIStartupPair(t, manager, 4, 8, 2, time.Now())
	awaitCNIStartupCalls(t, &calls, calls.Load()+3)
	grant, release, err = guard(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	release()
	if grant.Scope != k8snetprep.ScopeIPMasqOnly {
		t.Fatal("later operation reused the initial AWS scope")
	}
	publishCNIStartupPair(t, manager, 5, 8, 2, time.Now().Add(-hostposture.HeartbeatFreshness-time.Second))
	if _, release, err := guard(t.Context()); err == nil || release != nil {
		if release != nil {
			release()
		}
		t.Fatal("startup admission allowed a later stale operation grant")
	}
}

func TestKubernetesCNIStartupObserverKeepsRealProofFreshAcrossSlowStartup(t *testing.T) {
	manager, guard := realCNIStartupGuard(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var calls atomic.Int64
	countedGuard := func(ctx context.Context) (k8snetprep.AuthorityGrant, func(), error) {
		grant, release, err := guard(ctx)
		calls.Add(1)
		return grant, release, err
	}
	publishCNIStartupPair(t, manager, 1, 7, 3, time.Now())
	admitted := startKubernetesCNIAuthorityObserver(ctx, countedGuard, 20*time.Millisecond, cniStartupLogger())
	awaitCNIStartupCalls(t, &calls, 2)
	assertCNIStartupBlocked(t, admitted)
	publishCNIStartupPair(t, manager, 2, 7, 3, time.Now())
	awaitCNIStartup(t, admitted)
	// Model a successful CP request that takes longer than the real ten-second
	// history window. Only manager publication and the read-only observer run;
	// no startup/steady-state data-plane operation maintains proof for them.
	started := time.Now()
	sequence := uint64(2)
	for time.Since(started) <= hostposture.HeartbeatFreshness+250*time.Millisecond {
		time.Sleep(100 * time.Millisecond)
		sequence++
		publishCNIStartupPair(t, manager, sequence, 7, 3, time.Now())
	}
	grant, release, err := guard(t.Context())
	if err != nil {
		t.Fatalf("slow successful startup lost runtime proof despite continued manager heartbeats: %v", err)
	}
	release()
	if grant.Scope != k8snetprep.ScopeIPMasqAndAWS || !time.Now().Before(grant.NotAfter) {
		t.Fatalf("slow startup received invalid fresh operation authority: %+v", grant)
	}
}
