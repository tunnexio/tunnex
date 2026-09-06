package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testStateFencePurgeID = "88888888-8888-8888-8888-888888888888"
	testStateFenceReuseID = "99999999-9999-9999-9999-999999999999"
)

type stateFenceTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *stateFenceTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *stateFenceTestClock) Advance(delta time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(delta)
	return c.now
}

type stateFenceTestTicker struct {
	ch       chan time.Time
	stopOnce sync.Once
}

func newStateFenceTestTicker() *stateFenceTestTicker {
	return &stateFenceTestTicker{ch: make(chan time.Time, 1)}
}

func (t *stateFenceTestTicker) C() <-chan time.Time { return t.ch }
func (t *stateFenceTestTicker) Stop()               { t.stopOnce.Do(func() {}) }
func (t *stateFenceTestTicker) Tick(now time.Time)  { t.ch <- now }

type stateFenceTestRunner struct {
	mu sync.Mutex

	lease           *stateFenceLease
	commands        []k8sCommand
	events          []string
	createCount     int
	replaceCount    int
	deleteCount     int
	deleteUID       string
	deleteVersion   string
	replaceObserved chan struct{}
}

func (r *stateFenceTestRunner) LookPath(name string) (string, error) {
	if name == "kubectl" {
		return "/fake/kubectl", nil
	}
	return "", errors.New("not found")
}

func (r *stateFenceTestRunner) Run(ctx context.Context, command k8sCommand) (k8sCommandResult, error) {
	select {
	case <-ctx.Done():
		return k8sCommandResult{}, context.Cause(ctx)
	default:
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	copyCommand := k8sCommand{name: command.name, args: append([]string(nil), command.args...), stdin: append([]byte(nil), command.stdin...)}
	r.commands = append(r.commands, copyCommand)
	joined := strings.Join(command.args, " ")
	switch {
	case strings.Contains(joined, "get lease "):
		r.events = append(r.events, "get")
		if r.lease == nil {
			return stdout(""), nil
		}
		raw, _ := json.Marshal(r.lease)
		return stdout(string(raw)), nil
	case strings.Contains(joined, "create -f -"):
		r.events = append(r.events, "create")
		if r.lease != nil {
			return k8sCommandResult{stderr: []byte("AlreadyExists")}, errors.New("AlreadyExists")
		}
		var lease stateFenceLease
		if err := json.Unmarshal(command.stdin, &lease); err != nil {
			return k8sCommandResult{}, err
		}
		if _, err := time.Parse(kubernetesMicroTimeLayout, lease.Spec.AcquireTime); err != nil {
			return k8sCommandResult{stderr: []byte("BadRequest")}, err
		}
		if _, err := time.Parse(kubernetesMicroTimeLayout, lease.Spec.RenewTime); err != nil {
			return k8sCommandResult{stderr: []byte("BadRequest")}, err
		}
		lease.Metadata.UID = "lease-uid-1"
		lease.Metadata.ResourceVersion = "1"
		r.lease = &lease
		r.createCount++
		raw, _ := json.Marshal(lease)
		return stdout(string(raw)), nil
	case strings.Contains(joined, "replace --raw=") && strings.Contains(joined, "/leases/"):
		r.events = append(r.events, "replace")
		var lease stateFenceLease
		if err := json.Unmarshal(command.stdin, &lease); err != nil {
			return k8sCommandResult{}, err
		}
		if _, err := time.Parse(kubernetesMicroTimeLayout, lease.Spec.AcquireTime); err != nil {
			return k8sCommandResult{stderr: []byte("BadRequest")}, err
		}
		if _, err := time.Parse(kubernetesMicroTimeLayout, lease.Spec.RenewTime); err != nil {
			return k8sCommandResult{stderr: []byte("BadRequest")}, err
		}
		if r.lease == nil || lease.Metadata.UID != r.lease.Metadata.UID || lease.Metadata.ResourceVersion != r.lease.Metadata.ResourceVersion {
			return k8sCommandResult{stderr: []byte("Conflict")}, errors.New("Conflict")
		}
		rv, _ := strconv.Atoi(r.lease.Metadata.ResourceVersion)
		lease.Metadata.ResourceVersion = strconv.Itoa(rv + 1)
		r.lease = &lease
		r.replaceCount++
		if r.replaceObserved != nil {
			select {
			case r.replaceObserved <- struct{}{}:
			default:
			}
		}
		raw, _ := json.Marshal(lease)
		return stdout(string(raw)), nil
	case strings.Contains(joined, "delete --raw=") && strings.Contains(joined, "/leases/"):
		r.events = append(r.events, "delete")
		var options struct {
			Preconditions struct {
				UID             string `json:"uid"`
				ResourceVersion string `json:"resourceVersion"`
			} `json:"preconditions"`
		}
		if err := json.Unmarshal(command.stdin, &options); err != nil {
			return k8sCommandResult{}, err
		}
		if r.lease == nil || options.Preconditions.UID != r.lease.Metadata.UID || options.Preconditions.ResourceVersion != r.lease.Metadata.ResourceVersion {
			return k8sCommandResult{stderr: []byte("Conflict")}, errors.New("Conflict")
		}
		r.deleteUID = options.Preconditions.UID
		r.deleteVersion = options.Preconditions.ResourceVersion
		r.lease = nil
		r.deleteCount++
		return stdout(`{"kind":"Status","status":"Success"}`), nil
	default:
		return k8sCommandResult{}, errors.New("unexpected test command: " + command.name + " " + joined)
	}
}

func (r *stateFenceTestRunner) record(event string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
}

func (r *stateFenceTestRunner) clearEvents() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = nil
}

func (r *stateFenceTestRunner) snapshot() (stateFenceLease, bool, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lease == nil {
		return stateFenceLease{}, false, append([]string(nil), r.events...)
	}
	raw, _ := json.Marshal(r.lease)
	var lease stateFenceLease
	_ = json.Unmarshal(raw, &lease)
	return lease, true, append([]string(nil), r.events...)
}

func (r *stateFenceTestRunner) mutateLease(mutate func(*stateFenceLease)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	mutate(r.lease)
}

func stateFenceTestBinding() retainedStateFenceBinding {
	return retainedStateFenceBinding{
		kubeContext: "walk-context", namespace: "tunnex", release: "gateway-a",
		claim: "retained-state-a", pvcUID: "pvc-uid-a",
	}
}

func stateFenceTestDeps(runner k8sRunner, clock *stateFenceTestClock, operationID string, ticker k8sTicker) k8sDeps {
	deps := k8sDeps{
		runner: runner, now: clock.Now,
		newOperationID: func() string { return operationID },
	}
	if ticker != nil {
		deps.newTicker = func(time.Duration) k8sTicker { return ticker }
	}
	return deps.normalized()
}

func requireFenceTestResult(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for deterministic fence test barrier")
		return nil
	}
}

func TestRetainedStateFenceBlocksReuseAcrossPurgeFinalCheckWindow(t *testing.T) {
	clock := &stateFenceTestClock{now: time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)}
	runner := &stateFenceTestRunner{}
	binding := stateFenceTestBinding()
	finalCheckReached := make(chan struct{})
	allowPurgeToFinish := make(chan struct{})
	purgeDone := make(chan error, 1)
	go func() {
		fence, err := acquireRetainedStateFence(context.Background(), stateFenceTestDeps(runner, clock, testStateFencePurgeID, nil), binding, retainedStateFenceOperationPurge, func(context.Context) error { return nil })
		if err != nil {
			purgeDone <- err
			return
		}
		// This is the old final-check -> delete gap. The purge holder now owns
		// the Lease throughout that entire interval.
		close(finalCheckReached)
		<-allowPurgeToFinish
		purgeDone <- fence.release(context.Background())
	}()

	select {
	case <-finalCheckReached:
	case <-time.After(time.Second):
		t.Fatal("purge did not reach the final-check barrier")
	}
	reproofCalls := 0
	_, err := acquireRetainedStateFence(context.Background(), stateFenceTestDeps(runner, clock, testStateFenceReuseID, nil), binding, retainedStateFenceOperationReuse, func(context.Context) error {
		reproofCalls++
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "fenced by live purge operation") {
		t.Fatalf("reuse during purge final-check window error = %v", err)
	}
	if reproofCalls != 0 {
		t.Fatalf("live foreign holder triggered %d reproofs", reproofCalls)
	}
	close(allowPurgeToFinish)
	if err := requireFenceTestResult(t, purgeDone); err != nil {
		t.Fatalf("release purge fence: %v", err)
	}
	if _, err := acquireRetainedStateFence(context.Background(), stateFenceTestDeps(runner, clock, testStateFenceReuseID, nil), binding, retainedStateFenceOperationReuse, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("reuse did not acquire after purge released: %v", err)
	}
}

func TestRetainedStateFenceCrashAndExpiryTakeoverRequireFreshReproof(t *testing.T) {
	clock := &stateFenceTestClock{now: time.Date(2026, 8, 30, 11, 0, 0, 0, time.UTC)}
	runner := &stateFenceTestRunner{}
	binding := stateFenceTestBinding()
	if _, err := acquireRetainedStateFence(context.Background(), stateFenceTestDeps(runner, clock, testStateFencePurgeID, nil), binding, retainedStateFenceOperationPurge, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash by deliberately leaving the Lease behind.
	clock.Advance(retainedStateFenceLeaseDuration - time.Second)
	reproofCalls := 0
	if _, err := acquireRetainedStateFence(context.Background(), stateFenceTestDeps(runner, clock, testStateFenceReuseID, nil), binding, retainedStateFenceOperationReuse, func(context.Context) error {
		reproofCalls++
		return nil
	}); err == nil || !strings.Contains(err.Error(), "fenced by live purge operation") {
		t.Fatalf("pre-expiry crash takeover error = %v", err)
	}
	if reproofCalls != 0 {
		t.Fatalf("pre-expiry takeover ran %d reproofs", reproofCalls)
	}

	clock.Advance(2 * time.Second)
	runner.clearEvents()
	if _, err := acquireRetainedStateFence(context.Background(), stateFenceTestDeps(runner, clock, testStateFenceReuseID, nil), binding, retainedStateFenceOperationReuse, func(context.Context) error {
		reproofCalls++
		runner.record("reproof")
		return errors.New("PVC or release changed")
	}); err == nil || !strings.Contains(err.Error(), "PVC or release changed") {
		t.Fatalf("failed expiry reproof error = %v", err)
	}
	lease, exists, events := runner.snapshot()
	if !exists || lease.Spec.HolderIdentity != testStateFencePurgeID || runner.replaceCount != 0 || strings.Join(events, ",") != "get,reproof" {
		t.Fatalf("failed reproof mutated takeover: exists=%v holder=%q replaces=%d events=%v", exists, lease.Spec.HolderIdentity, runner.replaceCount, events)
	}

	runner.clearEvents()
	fence, err := acquireRetainedStateFence(context.Background(), stateFenceTestDeps(runner, clock, testStateFenceReuseID, nil), binding, retainedStateFenceOperationReuse, func(context.Context) error {
		reproofCalls++
		runner.record("reproof")
		return nil
	})
	if err != nil {
		t.Fatalf("expired takeover: %v", err)
	}
	lease, exists, events = runner.snapshot()
	if !exists || lease.Spec.HolderIdentity != testStateFenceReuseID || lease.Spec.LeaseTransitions != 1 {
		t.Fatalf("takeover lease = exists:%v holder:%q transitions:%d", exists, lease.Spec.HolderIdentity, lease.Spec.LeaseTransitions)
	}
	if reproofCalls != 2 || strings.Join(events, ",") != "get,reproof,replace,get" {
		t.Fatalf("takeover ordering calls=%d events=%v", reproofCalls, events)
	}
	if err := fence.release(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestD13iCallSitesFenceTheApprovedMutationWindow(t *testing.T) {
	t.Run("purge confirmation then locked final reproof", func(t *testing.T) {
		legacyPVC := readyLegacyPVCJSON("retained-state-a", "gateway-a")
		wrong := purgeRunner(legacyPVC)
		wrongArgs := append(lifecyclePurgeArgs("wrong"), "--legacy-without-lifecycle-proof")
		err := runK8s(context.Background(), wrongArgs, baseK8sDeps(wrong, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{}))
		if err == nil || !strings.Contains(err.Error(), "confirmation did not match") {
			t.Fatalf("wrong purge confirmation error = %v", err)
		}
		for _, command := range wrong.commands {
			if strings.Contains(strings.Join(command.args, " "), "/leases/") || bytes.Contains(command.stdin, []byte(`"kind":"Lease"`)) {
				t.Fatalf("purge acquired Lease before exact confirmation: %+v", command)
			}
		}

		runner := purgeRunner(legacyPVC)
		args := append(lifecyclePurgeArgs("DELETE LEGACY retained-state-a"), "--legacy-without-lifecycle-proof")
		if err := runK8s(context.Background(), args, baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})); err != nil {
			t.Fatalf("locked purge: %v", err)
		}
		leaseCreate := -1
		pvcDelete := -1
		pvcReads := make([]int, 0, 2)
		for index, command := range runner.commands {
			joined := strings.Join(command.args, " ")
			if command.name == "kubectl" && strings.Contains(joined, "create -f -") && bytes.Contains(command.stdin, []byte(`"kind":"Lease"`)) {
				leaseCreate = index
			}
			if command.name == "kubectl" && strings.Contains(joined, "get pvc retained-state-a") {
				pvcReads = append(pvcReads, index)
			}
			if command.name == "kubectl" && strings.Contains(joined, "/persistentvolumeclaims/retained-state-a") {
				pvcDelete = index
			}
		}
		if leaseCreate < 0 || len(pvcReads) < 2 || pvcReads[len(pvcReads)-1] <= leaseCreate || pvcDelete <= pvcReads[len(pvcReads)-1] {
			t.Fatalf("purge command order lease=%d pvcReads=%v pvcDelete=%d", leaseCreate, pvcReads, pvcDelete)
		}
	})

	t.Run("reuse lock before final read and Helm", func(t *testing.T) {
		runner := &fakeK8sRunner{}
		runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
			if command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "get deployment") {
				return stdout(readyDeploymentJSON("tunnex-gateway", "retained-state-a")), nil
			}
			return baseRunnerHandler(command)
		}
		deps := baseK8sDeps(runner, retainedReuseControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})
		if err := runK8s(context.Background(), []string{"install", "--node-name", "gateway-a", "--mode", "reuse", "--existing-claim", "retained-state-a", "--yes"}, deps); err != nil {
			t.Fatalf("fenced reuse: %v", err)
		}
		leaseCreate := -1
		helmInstall := -1
		leaseDelete := -1
		pvcReads := make([]int, 0, 3)
		for index, command := range runner.commands {
			joined := strings.Join(command.args, " ")
			if command.name == "kubectl" && strings.Contains(joined, "create -f -") && bytes.Contains(command.stdin, []byte(`"kind":"Lease"`)) {
				leaseCreate = index
			}
			if command.name == "kubectl" && strings.Contains(joined, "get pvc retained-state-a") {
				pvcReads = append(pvcReads, index)
			}
			if command.name == "helm" && strings.HasPrefix(joined, "install ") {
				helmInstall = index
			}
			if command.name == "kubectl" && strings.Contains(joined, "delete --raw=") && strings.Contains(joined, "/leases/") {
				leaseDelete = index
			}
		}
		finalReadBeforeHelm := false
		for _, index := range pvcReads {
			if index > leaseCreate && index < helmInstall {
				finalReadBeforeHelm = true
			}
		}
		if leaseCreate < 0 || helmInstall <= leaseCreate || !finalReadBeforeHelm || leaseDelete <= helmInstall {
			t.Fatalf("reuse command order lease=%d pvcReads=%v helm=%d leaseDelete=%d", leaseCreate, pvcReads, helmInstall, leaseDelete)
		}
	})
}

func TestD13iFailedReuseRetainsFenceWhenMutationMayRemain(t *testing.T) {
	tests := map[string]func(k8sCommand) (k8sCommandResult, bool){
		"Helm release exists": func(command k8sCommand) (k8sCommandResult, bool) {
			joined := strings.Join(command.args, " ")
			if command.name == "helm" && strings.HasPrefix(joined, "list --all ") {
				return stdout(`[{"name":"tunnex-gateway","namespace":"tunnex","revision":"1","status":"failed","chart":"tunnex-gateway-0.2.0","app_version":"v0.2.0"}]`), true
			}
			return k8sCommandResult{}, false
		},
		"claim is mounted": func(command k8sCommand) (k8sCommandResult, bool) {
			joined := strings.Join(command.args, " ")
			if command.name == "kubectl" && strings.Contains(joined, "get pods") {
				return stdout(`{"items":[` + claimPodJSON("gateway-pod", "Running", "", "ReplicaSet", "gateway-rs", "retained-state-a") + `]}`), true
			}
			return k8sCommandResult{}, false
		},
		"orphan workload exists": func(command k8sCommand) (k8sCommandResult, bool) {
			joined := strings.Join(command.args, " ")
			if command.name == "kubectl" && strings.Contains(joined, "get deployments,statefulsets,daemonsets,jobs,pods,services") {
				return stdout("deployment.apps/tunnex-gateway-tunnex-gateway\n"), true
			}
			return k8sCommandResult{}, false
		},
	}

	for name, afterFailure := range tests {
		t.Run(name, func(t *testing.T) {
			postFailure := false
			runner := &fakeK8sRunner{}
			runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
				joined := strings.Join(command.args, " ")
				if command.name == "helm" && strings.HasPrefix(joined, "install tunnex-gateway ") {
					postFailure = true
					return k8sCommandResult{stderr: []byte("synthetic failed reuse")}, errors.New("exit 1")
				}
				if postFailure {
					if result, ok := afterFailure(command); ok {
						return result, nil
					}
				}
				return baseRunnerHandler(command)
			}
			deps := baseK8sDeps(runner, retainedReuseControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})
			err := runK8s(context.Background(), []string{"install", "--node-name", "gateway-a", "--mode", "reuse", "--existing-claim", "retained-state-a", "--yes"}, deps)
			if err == nil || !strings.Contains(err.Error(), "Lease remains until its bounded expiry") {
				t.Fatalf("failed reuse error = %v, want retained-fence recovery error", err)
			}
			leaseDeletes := 0
			for _, command := range runner.commands {
				joined := strings.Join(command.args, " ")
				if command.name == "kubectl" && strings.Contains(joined, "delete --raw=") && strings.Contains(joined, "/leases/") {
					leaseDeletes++
				}
			}
			if leaseDeletes != 0 || len(runner.leases) != 1 {
				t.Fatalf("ambiguous failed reuse deleted fence: deletes=%d leases=%d", leaseDeletes, len(runner.leases))
			}
		})
	}
}

func TestRetainedStateFenceRefusesForeignBindingAndNeverDeletesForeignHolder(t *testing.T) {
	clock := &stateFenceTestClock{now: time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)}
	runner := &stateFenceTestRunner{}
	binding := stateFenceTestBinding()
	fence, err := acquireRetainedStateFence(context.Background(), stateFenceTestDeps(runner, clock, testStateFencePurgeID, nil), binding, retainedStateFenceOperationPurge, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}

	foreignBinding := binding
	foreignBinding.claim = "other-state"
	foreignBinding.pvcUID = "other-pvc-uid"
	clock.Advance(retainedStateFenceLeaseDuration + time.Second)
	reproofCalls := 0
	if _, err := acquireRetainedStateFence(context.Background(), stateFenceTestDeps(runner, clock, testStateFenceReuseID, nil), foreignBinding, retainedStateFenceOperationReuse, func(context.Context) error {
		reproofCalls++
		return nil
	}); err == nil || !strings.Contains(err.Error(), "foreign or bound to different state") {
		t.Fatalf("foreign binding error = %v", err)
	}
	if reproofCalls != 0 || runner.replaceCount != 0 {
		t.Fatalf("foreign binding mutated lease: reproofs=%d replaces=%d", reproofCalls, runner.replaceCount)
	}

	// A successor/foreign writer wins the live object. The stale holder must
	// refuse cleanup instead of deleting that operation's Lease.
	runner.mutateLease(func(lease *stateFenceLease) {
		lease.Spec.HolderIdentity = testStateFenceReuseID
		lease.Metadata.Annotations[stateFenceOperationAnnotation] = retainedStateFenceOperationReuse
		lease.Metadata.ResourceVersion = "2"
		lease.Spec.RenewTime = clock.Now().Format(time.RFC3339Nano)
	})
	if err := fence.release(context.Background()); err == nil || !strings.Contains(err.Error(), "held by another operation") {
		t.Fatalf("stale release error = %v", err)
	}
	if runner.deleteCount != 0 {
		t.Fatalf("stale holder deleted %d foreign leases", runner.deleteCount)
	}
}

func TestRetainedStateFenceRenewsWithFakeTickerAndCancelsOnLoss(t *testing.T) {
	t.Run("renew", func(t *testing.T) {
		clock := &stateFenceTestClock{now: time.Date(2026, 8, 30, 13, 0, 0, 0, time.UTC)}
		runner := &stateFenceTestRunner{replaceObserved: make(chan struct{}, 1)}
		ticker := newStateFenceTestTicker()
		deps := stateFenceTestDeps(runner, clock, testStateFenceReuseID, ticker)
		fence, err := acquireRetainedStateFence(context.Background(), deps, stateFenceTestBinding(), retainedStateFenceOperationReuse, func(context.Context) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		renewal := startRetainedStateFenceRenewal(context.Background(), deps, fence)
		now := clock.Advance(retainedStateFenceRenewInterval)
		ticker.Tick(now)
		select {
		case <-runner.replaceObserved:
		case <-time.After(time.Second):
			t.Fatal("fake tick did not renew Lease")
		}
		if err := renewal.stop(); err != nil {
			t.Fatalf("stop renewed fence: %v", err)
		}
		lease, exists, _ := runner.snapshot()
		if !exists || lease.Metadata.ResourceVersion != "2" || lease.Spec.RenewTime != formatKubernetesMicroTime(now) {
			t.Fatalf("renewed lease = exists:%v rv:%q renew:%q", exists, lease.Metadata.ResourceVersion, lease.Spec.RenewTime)
		}
	})

	t.Run("loss cancels operation", func(t *testing.T) {
		clock := &stateFenceTestClock{now: time.Date(2026, 8, 30, 14, 0, 0, 0, time.UTC)}
		runner := &stateFenceTestRunner{}
		ticker := newStateFenceTestTicker()
		deps := stateFenceTestDeps(runner, clock, testStateFenceReuseID, ticker)
		fence, err := acquireRetainedStateFence(context.Background(), deps, stateFenceTestBinding(), retainedStateFenceOperationReuse, func(context.Context) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		renewal := startRetainedStateFenceRenewal(context.Background(), deps, fence)
		runner.mutateLease(func(lease *stateFenceLease) {
			lease.Spec.HolderIdentity = testStateFencePurgeID
			lease.Metadata.Annotations[stateFenceOperationAnnotation] = retainedStateFenceOperationPurge
			lease.Metadata.ResourceVersion = "2"
		})
		ticker.Tick(clock.Advance(retainedStateFenceRenewInterval))
		select {
		case <-renewal.ctx.Done():
		case <-time.After(time.Second):
			t.Fatal("foreign-holder renewal loss did not cancel operation context")
		}
		if err := renewal.stop(); err == nil || !strings.Contains(err.Error(), "no longer held by this operation") {
			t.Fatalf("renewal loss error = %v", err)
		}
		if runner.deleteCount != 0 {
			t.Fatalf("renewal loss deleted %d leases", runner.deleteCount)
		}
	})
}

func TestStateFenceLeaseUsesKubernetesMicroTime(t *testing.T) {
	now := time.Date(2026, 8, 31, 9, 47, 35, 980818952, time.UTC)
	lease := newStateFenceLease(stateFenceTestBinding(), retainedStateFenceOperationReuse, testStateFenceReuseID, now)
	const want = "2026-08-31T09:47:35.980818Z"
	if lease.Spec.AcquireTime != want || lease.Spec.RenewTime != want {
		t.Fatalf("Lease MicroTime = acquire:%q renew:%q, want %q", lease.Spec.AcquireTime, lease.Spec.RenewTime, want)
	}
	if _, err := time.Parse(kubernetesMicroTimeLayout, lease.Spec.AcquireTime); err != nil {
		t.Fatalf("Lease acquireTime is not Kubernetes MicroTime: %v", err)
	}
}

func TestRetainedStateFenceManifestAndReleaseUseExactUIDResourceVersion(t *testing.T) {
	clock := &stateFenceTestClock{now: time.Date(2026, 8, 30, 15, 0, 0, 0, time.UTC)}
	runner := &stateFenceTestRunner{}
	binding := stateFenceTestBinding()
	fence, err := acquireRetainedStateFence(context.Background(), stateFenceTestDeps(runner, clock, testStateFenceReuseID, nil), binding, retainedStateFenceOperationReuse, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	lease, exists, _ := runner.snapshot()
	if !exists || lease.Metadata.Annotations[stateFencePVCUIDAnnotation] != binding.pvcUID ||
		lease.Metadata.Annotations[stateFenceClaimAnnotation] != binding.claim ||
		lease.Metadata.Annotations[stateFenceReleaseAnnotation] != binding.release ||
		lease.Metadata.Annotations[stateFenceNamespaceAnnotation] != binding.namespace ||
		len(lease.Metadata.OwnerReferences) != 1 || lease.Metadata.OwnerReferences[0].UID != binding.pvcUID {
		t.Fatalf("Lease lost exact PVC binding: %+v", lease)
	}
	if err := fence.release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.deleteCount != 1 || runner.deleteUID != "lease-uid-1" || runner.deleteVersion != "1" {
		t.Fatalf("release preconditions deletes=%d uid=%q rv=%q", runner.deleteCount, runner.deleteUID, runner.deleteVersion)
	}
}

func TestRetainedStateFenceRefusesForeignOwnerAndCoordinatedElectionFields(t *testing.T) {
	clock := &stateFenceTestClock{now: time.Date(2026, 8, 30, 16, 0, 0, 0, time.UTC)}
	binding := stateFenceTestBinding()
	truth := true
	tests := map[string]func(*stateFenceLease){
		"controller owner": func(lease *stateFenceLease) {
			lease.Metadata.OwnerReferences[0].Controller = &truth
		},
		"blocking owner": func(lease *stateFenceLease) {
			lease.Metadata.OwnerReferences[0].BlockOwnerDeletion = &truth
		},
		"coordinated strategy": func(lease *stateFenceLease) {
			lease.Spec.Strategy = "OldestEmulationVersion"
		},
		"preferred holder": func(lease *stateFenceLease) {
			lease.Spec.PreferredHolder = "foreign-candidate"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			lease := newStateFenceLease(binding, retainedStateFenceOperationReuse, testStateFenceReuseID, clock.Now())
			lease.Metadata.UID = "lease-uid-1"
			lease.Metadata.ResourceVersion = "1"
			mutate(&lease)
			if _, err := validateStateFenceLease(lease, binding, clock.Now()); err == nil {
				t.Fatalf("foreign Lease field %q was accepted", name)
			}
		})
	}

	// Kubernetes defaults both owner flags to false. Explicit false remains the
	// exact non-controller PVC owner contract and must stay compatible.
	falsity := false
	lease := newStateFenceLease(binding, retainedStateFenceOperationReuse, testStateFenceReuseID, clock.Now())
	lease.Metadata.UID = "lease-uid-1"
	lease.Metadata.ResourceVersion = "1"
	lease.Metadata.OwnerReferences[0].Controller = &falsity
	lease.Metadata.OwnerReferences[0].BlockOwnerDeletion = &falsity
	if _, err := validateStateFenceLease(lease, binding, clock.Now()); err != nil {
		t.Fatalf("explicit false owner defaults were refused: %v", err)
	}
}
