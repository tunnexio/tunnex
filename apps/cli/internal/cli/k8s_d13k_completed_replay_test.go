package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func d13kCompletedControlPlane() (*fakeK8sControlPlane, string) {
	cp := baseK8sControlPlane()
	now := time.Now().UTC()
	completedAt := now.Add(-time.Minute)
	consumedAt := completedAt.Add(-time.Second)
	acknowledgedAt := consumedAt.Add(-time.Second)
	digest := "sha256:" + strings.Repeat("d", 64)
	cp.installOperations[testStateFenceOpID] = lifecycleInstallOperationStatus{
		claim: testLifecycleClaim, generation: 1, requestID: testLifecycleRequest,
		operationID: testStateFenceOpID, epoch: 1, state: lifecycleInstallCompleted,
		releaseNamespace: defaultK8sNamespace, releaseName: defaultK8sRelease, installIntentDigest: digest,
		requestedDurationSeconds: 660, notAfter: now.Add(time.Minute), serverTime: now, heartbeatAt: completedAt.Add(-time.Second),
		completedAt: &completedAt,
	}
	cp.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{
		claim: testLifecycleClaim, state: "consumed", nodeName: "aks-gateway-a", nodeID: testLifecycleNodeID,
		generation: 1, requestID: testLifecycleRequest, expiresAt: testLifecycleExpiry,
		acknowledgedAt: &acknowledgedAt, consumedAt: &consumedAt,
	}
	return cp, digest
}

func d13kDeploymentJSON(release, claim, installIntentDigest string) string {
	return strings.Replace(
		readyDeploymentJSON(release, claim),
		`"template":{"spec"`,
		fmt.Sprintf(`"template":{"metadata":{"annotations":{"tunnex.io/rollout-revision":%q}},"spec"`, rolloutRevision(installIntentDigest)),
		1,
	)
}

func d13kCompletedReplayRunner(installIntentDigest string) *fakeK8sRunner {
	claim := gatewayFullname(defaultK8sRelease) + "-state"
	runner := &fakeK8sRunner{}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		switch {
		case command.name == "kubectl" && strings.Contains(joined, "get deployment "):
			return stdout(d13kDeploymentJSON(defaultK8sRelease, claim, installIntentDigest)), nil
		case command.name == "kubectl" && strings.Contains(joined, "get pvc "+claim):
			return stdout(readyPVCJSON(claim, defaultK8sRelease)), nil
		default:
			return installedRunnerHandler(command)
		}
	}
	return runner
}

func assertD13kNoMutation(t *testing.T, runner *fakeK8sRunner, cp *fakeK8sControlPlane) {
	t.Helper()
	for _, command := range runner.commands {
		if command.name == "helm" && len(command.args) > 0 {
			switch command.args[0] {
			case "install", "upgrade", "uninstall", "rollback":
				t.Fatalf("completed replay issued Helm mutation: %+v", command)
			}
		}
		if command.name == "kubectl" && len(command.args) > 0 {
			joined := " " + strings.Join(command.args, " ") + " "
			for _, verb := range []string{" create ", " replace ", " delete ", " patch ", " apply ", " scale "} {
				if strings.Contains(joined, verb) {
					t.Fatalf("completed replay issued Kubernetes mutation: %+v", command)
				}
			}
		}
	}
	if cp.issueCount != 0 || cp.abortCount != 0 || cp.installBeginCount != 0 || cp.installHeartbeatCount != 0 ||
		cp.installReleaseCount != 0 || cp.installCompleteCount != 0 || cp.installAbortCount != 0 || cp.installFinalizeAbortCount != 0 {
		t.Fatalf("completed replay mutated control plane: issue=%d abort=%d begin=%d heartbeat=%d release=%d complete=%d coordinate=%d finalize=%d",
			cp.issueCount, cp.abortCount, cp.installBeginCount, cp.installHeartbeatCount, cp.installReleaseCount, cp.installCompleteCount, cp.installAbortCount, cp.installFinalizeAbortCount)
	}
	for claim, count := range cp.ackCount {
		if count != 0 {
			t.Fatalf("completed replay acknowledged claim %s %d times", claim, count)
		}
	}
}

func TestD13kAnchorlessCompletedReplayIsReadOnlyAndIdempotent(t *testing.T) {
	cp, digest := d13kCompletedControlPlane()
	runner := d13kCompletedReplayRunner(digest)
	out := &bytes.Buffer{}
	deps := baseK8sDeps(runner, cp, out, &bytes.Buffer{})

	for attempt := 0; attempt < 2; attempt++ {
		if err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps); err != nil {
			t.Fatalf("completed replay attempt %d: %v", attempt+1, err)
		}
	}
	if !strings.Contains(out.String(), `"action": "replay-completed-install"`) ||
		!strings.Contains(out.String(), "No token, Helm release, Kubernetes object, or control-plane state was mutated") {
		t.Fatalf("completed replay output lacks read-only plan/success proof:\n%s", out.String())
	}
	for _, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		if command.name == "helm" && (strings.HasPrefix(joined, "pull ") || strings.HasPrefix(joined, "package ") || strings.HasPrefix(joined, "show chart ")) {
			t.Fatalf("completed replay fetched or materialized a chart: %+v", command)
		}
	}
	assertD13kNoMutation(t, runner, cp)
}

func TestD13kCompletedReplayRefusesAmbiguousControlPlaneProofWithoutMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fakeK8sControlPlane)
	}{
		{name: "active operation", mutate: func(cp *fakeK8sControlPlane) {
			status := cp.installOperations[testStateFenceOpID]
			status.state, status.completedAt = lifecycleInstallActive, nil
			cp.installOperations[testStateFenceOpID] = status
		}},
		{name: "released marker", mutate: func(cp *fakeK8sControlPlane) {
			status := cp.installOperations[testStateFenceOpID]
			now := time.Now().UTC()
			status.releasedAt = &now
			cp.installOperations[testStateFenceOpID] = status
		}},
		{name: "wrong release scope", mutate: func(cp *fakeK8sControlPlane) {
			status := cp.installOperations[testStateFenceOpID]
			status.releaseNamespace = "other"
			cp.installOperations[testStateFenceOpID] = status
		}},
		{name: "wrong consumed node", mutate: func(cp *fakeK8sControlPlane) {
			status := cp.claims[testLifecycleClaim]
			status.nodeName = "other-gateway"
			cp.claims[testLifecycleClaim] = status
		}},
		{name: "wrong consumed request", mutate: func(cp *fakeK8sControlPlane) {
			status := cp.claims[testLifecycleClaim]
			status.requestID = testLifecycleOldReq
			cp.claims[testLifecycleClaim] = status
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cp, digest := d13kCompletedControlPlane()
			test.mutate(cp)
			runner := d13kCompletedReplayRunner(digest)
			err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}))
			if err == nil {
				t.Fatal("ambiguous completed replay unexpectedly succeeded")
			}
			assertD13kNoMutation(t, runner, cp)
		})
	}
}

func TestD13kCompletedReplayRefusesRolloutIntentMismatchWithoutMutation(t *testing.T) {
	cp, _ := d13kCompletedControlPlane()
	runner := d13kCompletedReplayRunner("sha256:" + strings.Repeat("e", 64))
	err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}))
	if err == nil || !strings.Contains(err.Error(), "rollout revision") {
		t.Fatalf("rollout intent mismatch error = %v", err)
	}
	assertD13kNoMutation(t, runner, cp)
}

type d13kLatestDriftControlPlane struct {
	*fakeK8sControlPlane
	latestCalls int
	driftAt     int
	drift       func(*lifecycleInstallOperationStatus)
}

func (c *d13kLatestDriftControlPlane) GetLatestLifecycleInstall(ctx context.Context, orgID, claim string) (lifecycleInstallOperationStatus, error) {
	status, err := c.fakeK8sControlPlane.GetLatestLifecycleInstall(ctx, orgID, claim)
	if err != nil {
		return status, err
	}
	c.latestCalls++
	if c.latestCalls == c.driftAt && c.drift != nil {
		c.drift(&status)
	}
	return status, nil
}

func d13kPrepareCompletedReplay(t *testing.T, runner *fakeK8sRunner, cp k8sControlPlane) (preparedInstall, k8sDeps) {
	t.Helper()
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}).normalized()
	o, err := parseInstallOptions([]string{"--node-name", "aks-gateway-a", "--yes"}, deps)
	if err != nil {
		t.Fatalf("parse completed replay options: %v", err)
	}
	prepared, err := prepareInstall(context.Background(), o, deps)
	if err != nil {
		t.Fatalf("prepare completed replay: %v", err)
	}
	return prepared, deps
}

func TestD13kCompletedReplayFinalWindowDriftRefusesWithoutMutation(t *testing.T) {
	t.Run("control-plane proof", func(t *testing.T) {
		base, digest := d13kCompletedControlPlane()
		cp := &d13kLatestDriftControlPlane{
			fakeK8sControlPlane: base, driftAt: 3,
			drift: func(status *lifecycleInstallOperationStatus) {
				status.heartbeatAt = status.heartbeatAt.Add(time.Nanosecond)
			},
		}
		runner := d13kCompletedReplayRunner(digest)
		prepared, deps := d13kPrepareCompletedReplay(t, runner, cp)
		err := runCompletedInstallReplay(context.Background(), deps, prepared)
		if err == nil || !strings.Contains(err.Error(), "proof changed") {
			t.Fatalf("final control-plane drift error = %v", err)
		}
		assertD13kNoMutation(t, runner, base)
	})

	t.Run("PVC identity", func(t *testing.T) {
		cp, digest := d13kCompletedControlPlane()
		claim := gatewayFullname(defaultK8sRelease) + "-state"
		pvcReads := 0
		runner := d13kCompletedReplayRunner(digest)
		baseHandler := runner.handler
		runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
			joined := strings.Join(command.args, " ")
			if command.name == "kubectl" && strings.Contains(joined, "get pvc "+claim) {
				pvcReads++
				body := readyPVCJSON(claim, defaultK8sRelease)
				if pvcReads >= 3 {
					body = strings.Replace(body, `"resourceVersion":"42"`, `"resourceVersion":"43"`, 1)
				}
				return stdout(body), nil
			}
			return baseHandler(command)
		}
		prepared, deps := d13kPrepareCompletedReplay(t, runner, cp)
		err := runCompletedInstallReplay(context.Background(), deps, prepared)
		if err == nil || !strings.Contains(err.Error(), "PVC") {
			t.Fatalf("final PVC drift error = %v", err)
		}
		assertD13kNoMutation(t, runner, cp)
	})

	t.Run("release identity", func(t *testing.T) {
		cp, digest := d13kCompletedControlPlane()
		releaseReads := 0
		runner := d13kCompletedReplayRunner(digest)
		baseHandler := runner.handler
		runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
			joined := strings.Join(command.args, " ")
			if command.name == "helm" && strings.HasPrefix(joined, "list --all --namespace tunnex ") {
				releaseReads++
				if releaseReads >= 3 {
					return stdout(`[ {"name":"tunnex-gateway","namespace":"tunnex","revision":"4","status":"deployed","chart":"tunnex-gateway-0.2.0","app_version":"0.2.0"} ]`), nil
				}
			}
			return baseHandler(command)
		}
		prepared, deps := d13kPrepareCompletedReplay(t, runner, cp)
		err := runCompletedInstallReplay(context.Background(), deps, prepared)
		if err == nil || !strings.Contains(err.Error(), "Helm release changed") {
			t.Fatalf("final release drift error = %v", err)
		}
		assertD13kNoMutation(t, runner, cp)
	})

	t.Run("late Secret", func(t *testing.T) {
		cp, digest := d13kCompletedControlPlane()
		secretReads := 0
		runner := d13kCompletedReplayRunner(digest)
		baseHandler := runner.handler
		runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
			joined := strings.Join(command.args, " ")
			if command.name == "kubectl" && strings.Contains(joined, "get secret tunnex-gateway-bootstrap") {
				secretReads++
				if secretReads >= 2 {
					return stdout(bootstrapSecretMetadataLine(defaultK8sRelease)), nil
				}
			}
			return baseHandler(command)
		}
		prepared, deps := d13kPrepareCompletedReplay(t, runner, cp)
		err := runCompletedInstallReplay(context.Background(), deps, prepared)
		if err == nil || !strings.Contains(err.Error(), "found a bootstrap Secret") {
			t.Fatalf("late Secret error = %v", err)
		}
		assertD13kNoMutation(t, runner, cp)
	})

	t.Run("late anchor", func(t *testing.T) {
		cp, digest := d13kCompletedControlPlane()
		runner := d13kCompletedReplayRunner(digest)
		prepared, deps := d13kPrepareCompletedReplay(t, runner, cp)
		anchor := testLifecycleAnchor(defaultK8sRelease, "aks-gateway-a", "installing")
		runner.anchors[anchor.name] = anchor
		err := runCompletedInstallReplay(context.Background(), deps, prepared)
		if err == nil || !strings.Contains(err.Error(), "found a lifecycle anchor") {
			t.Fatalf("late anchor error = %v", err)
		}
		assertD13kNoMutation(t, runner, cp)
	})
}

func d13kAPIControlPlane(t *testing.T, transport http.RoundTripper) *apiK8sControlPlane {
	t.Helper()
	client, err := newAuthedClientWithTransport(
		Credential{Server: "http://127.0.0.1", Token: "cli-secret"},
		lifecycleFreshConnectionTransport{base: transport},
	)
	if err != nil {
		t.Fatalf("new API client: %v", err)
	}
	return &apiK8sControlPlane{client: client, lifecycleRetry: d13cNoWaitRetryPolicy()}
}

func d13kAPIResponse(request *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status, Status: http.StatusText(status), Header: http.Header{"Content-Type": []string{"application/json"}},
		Body: io.NopCloser(strings.NewReader(body)), Request: request,
	}
}

func TestD13hBeginClassifiesOnlyExactTypedAbsentAfterExpiry(t *testing.T) {
	tests := []struct {
		name         string
		status       int
		code         string
		wantSentinel bool
	}{
		{name: "exact", status: http.StatusConflict, code: lifecycleInstallAbsentAfterExpiry, wantSentinel: true},
		{name: "wrong code", status: http.StatusConflict, code: "lifecycle_install_operation_not_found"},
		{name: "wrong status", status: http.StatusBadRequest, code: lifecycleInstallAbsentAfterExpiry},
		{name: "method not allowed", status: http.StatusMethodNotAllowed, code: "validation_failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			cp := d13kAPIControlPlane(t, d13cRoundTripper(func(request *http.Request) (*http.Response, error) {
				calls++
				return d13kAPIResponse(request, test.status, d13cErrorBody(test.code, test.name)), nil
			}))
			_, err := cp.BeginLifecycleInstall(context.Background(), d13cTestOrgID, lifecycleInstallBeginRequest{
				claim: testLifecycleClaim, expectedGeneration: 1, requestID: testLifecycleRequest, operationID: testStateFenceOpID,
				releaseNamespace: defaultK8sNamespace, releaseName: defaultK8sRelease,
				installIntentDigest: "sha256:" + strings.Repeat("d", 64), requestedDurationSeconds: 660,
			})
			if err == nil || errors.Is(err, errLifecycleInstallOperationAbsentAfterExpiry) != test.wantSentinel {
				t.Fatalf("Begin error=%v sentinel=%t, want %t", err, errors.Is(err, errLifecycleInstallOperationAbsentAfterExpiry), test.wantSentinel)
			}
			if calls != 1 {
				t.Fatalf("Begin calls=%d, want one fail-closed response", calls)
			}
		})
	}
}

func TestD13kLatestOperationGETFailsClosedOn405AndDomain404(t *testing.T) {
	tests := []struct {
		name   string
		status int
		code   string
	}{
		{name: "intermediate method not allowed", status: http.StatusMethodNotAllowed, code: "validation_failed"},
		{name: "domain operation not found", status: http.StatusNotFound, code: "lifecycle_install_operation_not_found"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			cp := d13kAPIControlPlane(t, d13cRoundTripper(func(request *http.Request) (*http.Response, error) {
				calls++
				return d13kAPIResponse(request, test.status, d13cErrorBody(test.code, test.name)), nil
			}))
			_, err := cp.GetLatestLifecycleInstall(context.Background(), d13cTestOrgID, testLifecycleClaim)
			if err == nil || errors.Is(err, errK8sControlPlaneRolloutIncomplete) {
				t.Fatalf("latest operation error=%v, want immediate fail-closed domain/405 response", err)
			}
			if calls != 1 {
				t.Fatalf("latest operation calls=%d, want no retry", calls)
			}
		})
	}
}
