package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type d13dK8sControlPlane struct {
	*fakeK8sControlPlane
	beforeMintCalls    int
	tombstoneCreates   int
	failAfterPersist   int
	beforeMintCallHook func() error
}

func (f *d13dK8sControlPlane) AbortLifecycleClaimBeforeMint(_ context.Context, _, claim, nodeName, requestID string) (k8sLifecycleClaimStatus, error) {
	f.beforeMintCalls++
	if f.beforeMintCallHook != nil {
		if err := f.beforeMintCallHook(); err != nil {
			return k8sLifecycleClaimStatus{}, err
		}
	}
	status, exists := f.claims[claim]
	if !exists {
		f.tombstoneCreates++
		status = k8sLifecycleClaimStatus{
			claim: claim, nodeName: nodeName, generation: 0, requestID: requestID,
			expiresAt: time.Unix(0, 0).UTC(),
		}
	}
	if status.claim != claim || status.nodeName != nodeName || status.requestID != requestID || (status.generation != 0 && status.generation != 1) {
		return k8sLifecycleClaimStatus{}, errors.New("test control-plane pre-mint identity mismatch")
	}
	status.state = "aborted"
	abortedAt := time.Now().UTC()
	if status.abortedAt == nil {
		status.abortedAt = &abortedAt
	}
	if status.generation == 0 {
		status.expiresAt = time.Unix(0, 0).UTC()
		status.nodeID = ""
	}
	f.claims[claim] = status
	if f.failAfterPersist > 0 {
		f.failAfterPersist--
		return k8sLifecycleClaimStatus{}, errors.New("simulated lost generation-zero abort response")
	}
	return status, nil
}

func d13dPendingAnchor(release string) lifecycleAnchorMetadata {
	anchor := testLifecycleAnchor(release, "aks-gateway-a", "pending")
	anchor.expectedGeneration = 0
	anchor.generation = 0
	anchor.expiresAt = time.Time{}
	return anchor
}

func TestK8sGenerationZeroAbortFencesBeforeCPAndStaleMintCannotPersist(t *testing.T) {
	anchor := d13dPendingAnchor("tunnex-gateway")
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}, handler: baseRunnerHandler}
	cp := &d13dK8sControlPlane{fakeK8sControlPlane: baseK8sControlPlane()}
	var stalePersistErr error
	cp.beforeMintCallHook = func() error {
		fenced := runner.anchors[anchor.name]
		if fenced.state != "aborting" || fenced.uid != anchor.uid || fenced.resourceVersion == anchor.resourceVersion {
			return errors.New("control-plane abort ran before durable aborting anchor fence")
		}
		stale := anchor
		stale.state = "issued"
		stale.generation = 1
		stale.expiresAt = testLifecycleExpiry
		_, stalePersistErr = updateLifecycleAnchor(context.Background(), k8sDeps{runner: runner}, installOptions{
			release: anchor.instance, namespace: defaultK8sNamespace, kubeContext: "walk-context",
		}, stale)
		return nil
	}
	var out bytes.Buffer
	deps := baseK8sDeps(runner, cp, &out, &bytes.Buffer{})
	args := []string{"abort-install", "--release", anchor.instance, "--claim", anchor.lifecycleClaim, "--confirm", "ABORT " + anchor.lifecycleClaim}
	if err := runK8s(context.Background(), args, deps); err != nil {
		t.Fatalf("generation-zero abort: %v", err)
	}
	if stalePersistErr == nil {
		t.Fatalf("stale installer persisted mint response after abort fence: %v", stalePersistErr)
	}
	if cp.beforeMintCalls != 1 || cp.tombstoneCreates != 1 {
		t.Fatalf("generation-zero abort calls/creates = %d/%d", cp.beforeMintCalls, cp.tombstoneCreates)
	}
	if _, exists := runner.anchors[anchor.name]; exists {
		t.Fatal("successful generation-zero abort retained lifecycle anchor")
	}
	status := cp.claims[anchor.lifecycleClaim]
	if status.state != "aborted" || status.generation != 0 || status.abortedAt == nil || !status.expiresAt.Equal(time.Unix(0, 0).UTC()) {
		t.Fatalf("generation-zero tombstone = %+v", status)
	}
	replacedBeforeDelete := false
	for _, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		if strings.Contains(joined, "replace --raw=") && bytes.Contains(command.stdin, []byte(`"tunnex.io/lifecycle-state":"aborting"`)) {
			replacedBeforeDelete = true
		}
		if strings.Contains(joined, "/secrets/") && strings.Contains(joined, "delete --raw=") {
			t.Fatalf("generation-zero abort deleted a bootstrap Secret: %+v", command)
		}
	}
	if !replacedBeforeDelete {
		t.Fatal("generation-zero abort did not persist the aborting anchor fence")
	}
}

func TestK8sGenerationZeroAbortResumesFromPersistedFenceBeforeCP(t *testing.T) {
	anchor := d13dPendingAnchor("tunnex-gateway")
	anchor.state = "aborting"
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}, handler: baseRunnerHandler}
	cp := &d13dK8sControlPlane{fakeK8sControlPlane: baseK8sControlPlane()}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	args := []string{"abort-install", "--release", anchor.instance, "--claim", anchor.lifecycleClaim, "--confirm", "ABORT " + anchor.lifecycleClaim}

	if err := runK8s(context.Background(), args, deps); err != nil {
		t.Fatalf("resume from pre-control-plane abort fence: %v", err)
	}
	if cp.beforeMintCalls != 1 || cp.tombstoneCreates != 1 {
		t.Fatalf("fenced resume calls/creates = %d/%d", cp.beforeMintCalls, cp.tombstoneCreates)
	}
	if _, exists := runner.anchors[anchor.name]; exists {
		t.Fatal("fenced resume retained lifecycle anchor")
	}
	status := cp.claims[anchor.lifecycleClaim]
	if status.state != "aborted" || status.generation != 0 || status.abortedAt == nil || !status.expiresAt.Equal(time.Unix(0, 0).UTC()) {
		t.Fatalf("fenced resume tombstone = %+v", status)
	}
	for _, command := range runner.commands {
		if strings.Contains(strings.Join(command.args, " "), "/secrets/") && strings.Contains(strings.Join(command.args, " "), "delete --raw=") {
			t.Fatalf("fenced resume deleted a bootstrap Secret: %+v", command)
		}
	}
}

func TestK8sGenerationZeroAbortResumesAfterFenceAndLostTombstoneResponse(t *testing.T) {
	anchor := d13dPendingAnchor("tunnex-gateway")
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}, handler: baseRunnerHandler}
	cp := &d13dK8sControlPlane{fakeK8sControlPlane: baseK8sControlPlane(), failAfterPersist: 1}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	args := []string{"abort-install", "--release", anchor.instance, "--claim", anchor.lifecycleClaim, "--confirm", "ABORT " + anchor.lifecycleClaim}

	if err := runK8s(context.Background(), args, deps); err == nil || !strings.Contains(err.Error(), "lost generation-zero abort response") {
		t.Fatalf("lost-response abort error = %v", err)
	}
	fenced, exists := runner.anchors[anchor.name]
	if !exists || fenced.state != "aborting" || fenced.resourceVersion == anchor.resourceVersion {
		t.Fatalf("lost-response abort did not retain durable fence: %+v exists=%t", fenced, exists)
	}
	status := cp.claims[anchor.lifecycleClaim]
	if status.state != "aborted" || status.generation != 0 || status.abortedAt == nil || cp.tombstoneCreates != 1 {
		t.Fatalf("lost-response control-plane tombstone = %+v creates=%d", status, cp.tombstoneCreates)
	}

	if err := runK8s(context.Background(), args, deps); err != nil {
		t.Fatalf("resume after fence/tombstone: %v", err)
	}
	if _, exists := runner.anchors[anchor.name]; exists {
		t.Fatal("resumed abort retained lifecycle anchor")
	}
	if cp.beforeMintCalls != 2 || cp.tombstoneCreates != 1 {
		t.Fatalf("resumed abort calls/creates = %d/%d", cp.beforeMintCalls, cp.tombstoneCreates)
	}

	runner.commands = nil
	if err := runK8s(context.Background(), args, deps); err != nil {
		t.Fatalf("anchor-absent generation-zero completion: %v", err)
	}
	if cp.beforeMintCalls != 2 {
		t.Fatalf("anchor-absent completion repeated CP abort: %d", cp.beforeMintCalls)
	}
	for _, command := range runner.commands {
		if strings.Contains(strings.Join(command.args, " "), "delete --raw=") {
			t.Fatalf("anchor-absent completion repeated Kubernetes deletion: %+v", command)
		}
	}
}

func TestK8sInstallRefusesAbortingAnchorBeforeMintOrChartFetch(t *testing.T) {
	anchor := d13dPendingAnchor("tunnex-gateway")
	anchor.state = "aborting"
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}, handler: baseRunnerHandler}
	cp := &d13dK8sControlPlane{fakeK8sControlPlane: baseK8sControlPlane()}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"plan", "--node-name", anchor.nodeName}, deps)
	if err == nil || !strings.Contains(err.Error(), "resume 'tunnex k8s abort-install") {
		t.Fatalf("aborting anchor plan error = %v", err)
	}
	if cp.issueCount != 0 || cp.metaCount != 0 || cp.beforeMintCalls != 0 {
		t.Fatalf("aborting anchor contacted lifecycle CP: issue/meta/abort=%d/%d/%d", cp.issueCount, cp.metaCount, cp.beforeMintCalls)
	}
	for _, command := range runner.commands {
		if command.name == "helm" && len(command.args) > 0 && (command.args[0] == "pull" || command.args[0] == "package") {
			t.Fatalf("aborting anchor fetched chart artifact: %+v", command)
		}
		if command.name == "kubectl" && (bytes.Contains(command.stdin, []byte(`"kind":"Secret"`)) || strings.Contains(strings.Join(command.args, " "), "create -f -")) {
			t.Fatalf("aborting anchor mutated Kubernetes: %+v", command)
		}
	}
}
