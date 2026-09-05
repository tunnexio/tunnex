package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func (f *fakeK8sControlPlane) GetLatestLifecycleInstall(_ context.Context, _ string, claim string) (lifecycleInstallOperationStatus, error) {
	f.installMu.Lock()
	defer f.installMu.Unlock()
	var latest lifecycleInstallOperationStatus
	found := false
	for _, status := range f.installOperations {
		if status.claim != claim {
			continue
		}
		if !found || status.epoch > latest.epoch || (status.epoch == latest.epoch && status.operationID > latest.operationID) {
			latest = status
			found = true
		}
	}
	if !found {
		return lifecycleInstallOperationStatus{}, errors.New("lifecycle_install_operation_not_found")
	}
	latest.serverTime = time.Now().UTC()
	return latest, nil
}

func (f *fakeK8sControlPlane) BeginLifecycleInstall(_ context.Context, _ string, request lifecycleInstallBeginRequest) (lifecycleInstallOperationStatus, error) {
	f.installMu.Lock()
	defer f.installMu.Unlock()
	f.installBeginCount++
	if f.installOperations == nil {
		f.installOperations = map[string]lifecycleInstallOperationStatus{}
	}
	now := time.Now().UTC()
	if status, ok := f.installOperations[request.operationID]; ok {
		status.serverTime = now
		if status.state == lifecycleInstallActive && !status.notAfter.After(now) {
			status.state = lifecycleInstallExpired
		}
		f.installOperations[request.operationID] = status
		return status, nil
	}
	epoch := int64(1)
	for _, prior := range f.installOperations {
		if prior.epoch >= epoch {
			epoch = prior.epoch + 1
		}
		if prior.state != lifecycleInstallReleased && prior.state != lifecycleInstallAborted {
			return lifecycleInstallOperationStatus{}, errors.New("fake lifecycle install operation held")
		}
	}
	status := lifecycleInstallOperationStatus{
		claim: request.claim, generation: request.expectedGeneration, requestID: request.requestID,
		operationID: request.operationID, epoch: epoch, state: lifecycleInstallActive,
		releaseNamespace: request.releaseNamespace, releaseName: request.releaseName, installIntentDigest: request.installIntentDigest,
		requestedDurationSeconds: request.requestedDurationSeconds, notAfter: now.Add(time.Duration(request.requestedDurationSeconds) * time.Second),
		serverTime: now, heartbeatAt: now,
	}
	f.installOperations[request.operationID] = status
	return status, nil
}

func (f *fakeK8sControlPlane) HeartbeatLifecycleInstall(_ context.Context, _ string, request lifecycleInstallCASRequest) (lifecycleInstallOperationStatus, error) {
	f.installMu.Lock()
	defer f.installMu.Unlock()
	f.installHeartbeatCount++
	status, ok := f.installOperations[request.operationID]
	if !ok || status.epoch != request.expectedEpoch {
		return lifecycleInstallOperationStatus{}, errors.New("fake lifecycle install heartbeat fenced")
	}
	now := time.Now().UTC()
	status.serverTime = now
	if status.state == lifecycleInstallActive && !status.notAfter.After(now) {
		status.state = lifecycleInstallExpired
	}
	if status.abortRequestedAt != nil && status.state == lifecycleInstallActive {
		status.state = lifecycleInstallAbortRequested
	}
	status.heartbeatAt = now
	f.installOperations[request.operationID] = status
	return status, nil
}

func (f *fakeK8sControlPlane) ReleaseLifecycleInstall(_ context.Context, _ string, request lifecycleInstallCASRequest) (lifecycleInstallOperationStatus, error) {
	f.installMu.Lock()
	defer f.installMu.Unlock()
	f.installReleaseCount++
	status, ok := f.installOperations[request.operationID]
	if !ok || status.epoch != request.expectedEpoch {
		return lifecycleInstallOperationStatus{}, errors.New("fake lifecycle install release fenced")
	}
	if status.state == lifecycleInstallCompleted || status.state == lifecycleInstallAborted {
		return lifecycleInstallOperationStatus{}, errors.New("fake lifecycle install terminal")
	}
	now := time.Now().UTC()
	status.state = lifecycleInstallReleased
	status.releasedAt = &now
	status.serverTime = now
	f.installOperations[request.operationID] = status
	return status, nil
}

func (f *fakeK8sControlPlane) CompleteLifecycleInstall(_ context.Context, _ string, request lifecycleInstallCASRequest) (lifecycleInstallOperationStatus, error) {
	f.installMu.Lock()
	defer f.installMu.Unlock()
	f.installCompleteCount++
	status, ok := f.installOperations[request.operationID]
	if !ok || status.epoch != request.expectedEpoch {
		return lifecycleInstallOperationStatus{}, errors.New("fake lifecycle install completion fenced")
	}
	if status.state == lifecycleInstallCompleted {
		status.serverTime = time.Now().UTC()
		return status, nil
	}
	if status.state != lifecycleInstallActive || status.abortRequestedAt != nil {
		return lifecycleInstallOperationStatus{}, errors.New("fake lifecycle install completion refused")
	}
	now := time.Now().UTC()
	status.state = lifecycleInstallCompleted
	status.completedAt = &now
	status.serverTime = now
	f.installOperations[request.operationID] = status
	return status, nil
}

func (f *fakeK8sControlPlane) CoordinateLifecycleInstallAbort(_ context.Context, _ string, request lifecycleInstallCASRequest) (lifecycleInstallAbortResult, error) {
	f.installMu.Lock()
	defer f.installMu.Unlock()
	f.installAbortCount++
	status, ok := f.installOperations[request.operationID]
	if !ok || status.epoch != request.expectedEpoch {
		return lifecycleInstallAbortResult{}, errors.New("fake lifecycle install abort fenced")
	}
	now := time.Now().UTC()
	status.serverTime = now
	if status.state == lifecycleInstallAborted {
		claim := f.claims[request.claim]
		return lifecycleInstallAbortResult{claimStatus: &claim}, nil
	}
	if status.state == lifecycleInstallCompleted {
		return lifecycleInstallAbortResult{}, errors.New("fake completed lifecycle install cannot be aborted")
	}
	if status.abortRequestedAt == nil {
		status.abortRequestedAt = &now
	}
	if status.state == lifecycleInstallAborting {
		// An idempotent retry after CP takeover but before the Kubernetes mirror
		// must return the exact same takeover authority.
	} else if status.state == lifecycleInstallReleased || status.state == lifecycleInstallExpired || !status.notAfter.After(now) {
		status.state = lifecycleInstallAborting
		status.epoch++
		status.takenOverAt = &now
	} else {
		status.state = lifecycleInstallAbortRequested
	}
	f.installOperations[request.operationID] = status
	return lifecycleInstallAbortResult{operationStatus: &status, pending: true}, nil
}

func (f *fakeK8sControlPlane) FinalizeLifecycleInstallAbort(_ context.Context, _ string, request lifecycleInstallCASRequest) (k8sLifecycleClaimStatus, error) {
	f.installMu.Lock()
	defer f.installMu.Unlock()
	f.installFinalizeAbortCount++
	status, ok := f.installOperations[request.operationID]
	if !ok || status.epoch != request.expectedEpoch || status.state != lifecycleInstallAborting {
		return k8sLifecycleClaimStatus{}, errors.New("fake lifecycle install abort finalization fenced")
	}
	now := time.Now().UTC()
	status.state = lifecycleInstallAborted
	status.abortedAt = &now
	status.serverTime = now
	f.installOperations[request.operationID] = status
	claim := f.claims[request.claim]
	claim.state = "aborted"
	claim.abortedAt = &now
	if claim.expiresAt.After(now) {
		claim.expiresAt = now
	}
	f.claims[request.claim] = claim
	return claim, nil
}

func d13hIntentPrepared() preparedInstall {
	return preparedInstall{
		options: installOptions{
			release: "gateway-a", namespace: "tunnex", kubeContext: "aks-a", nodeName: "gateway-a", mode: "enroll",
			serviceType: "LoadBalancer", endpoint: "", timeout: "10m", storageClass: "managed-csi",
			serviceAnnotations: stringListFlag{"service.beta.kubernetes.io/azure-load-balancer-internal=true", "example.test/owner=tunnex"},
			imagePullSecrets:   stringListFlag{"pull-b", "pull-a"},
			gatewaySelectors:   stringListFlag{"topology.kubernetes.io/zone=1", "pool=gateway"},
			gatewayTolerations: []gatewayToleration{
				{Key: "dedicated", Operator: "Equal", Value: "tunnex", Effect: "NoSchedule"},
				{Key: "arm", Operator: "Exists"},
			},
		},
		plan: lifecyclePlan{
			Kubernetes:   lifecycleKubernetes{Context: "aks-a", Namespace: "tunnex", Release: "gateway-a"},
			ControlPlane: &lifecycleControlPlane{APIURL: "https://cp.example.test", AgentURL: "https://agent.example.test:8443", ServerName: "tunnex-control"},
			Gateway:      lifecycleGateway{BootstrapSecret: "gateway-a-bootstrap", BootstrapState: "new create-only lifecycle anchor and Secret"},
			Storage:      lifecycleStorage{Class: "managed-csi", State: "create new retained claim"},
		},
		org: k8sOrganization{id: "11111111-1111-1111-1111-111111111111", name: "Example"},
		anchor: lifecycleAnchorMetadata{
			orgID: "11111111-1111-1111-1111-111111111111", lifecycleClaim: testLifecycleClaim,
			requestID: testLifecycleRequest, expectedGeneration: 0, generation: 0, state: "pending",
		},
		image: imageValues{
			reference: "ghcr.io/tunnexio/tunnex-node-agent@sha256:" + strings.Repeat("b", 64),
			registry:  "ghcr.io/tunnexio", agent: "tunnex-node-agent", digest: "sha256:" + strings.Repeat("b", 64),
		},
		gatewayChart:    chartMetadata{Name: "tunnex-gateway", Version: "0.2.0", AppVersion: "v0.2.0"},
		gatewayArtifact: chartArtifact{SHA256: "sha256:" + strings.Repeat("a", 64)},
	}
}

func TestK8sLifecycleInstallIntentIsCanonicalAndLiveStateStable(t *testing.T) {
	base := d13hIntentPrepared()
	_, want, err := computeLifecycleInstallIntent(base)
	if err != nil {
		t.Fatalf("base intent: %v", err)
	}

	reordered := d13hIntentPrepared()
	reordered.options.serviceAnnotations[0], reordered.options.serviceAnnotations[1] = reordered.options.serviceAnnotations[1], reordered.options.serviceAnnotations[0]
	reordered.options.imagePullSecrets[0], reordered.options.imagePullSecrets[1] = reordered.options.imagePullSecrets[1], reordered.options.imagePullSecrets[0]
	reordered.options.gatewaySelectors[0], reordered.options.gatewaySelectors[1] = reordered.options.gatewaySelectors[1], reordered.options.gatewaySelectors[0]
	reordered.options.gatewayTolerations[0], reordered.options.gatewayTolerations[1] = reordered.options.gatewayTolerations[1], reordered.options.gatewayTolerations[0]
	if _, got, computeErr := computeLifecycleInstallIntent(reordered); computeErr != nil || got != want {
		t.Fatalf("reordered canonical intent=(%s,%v), want %s", got, computeErr, want)
	}

	resumed := d13hIntentPrepared()
	resumed.anchor.uid = "anchor-uid"
	resumed.anchor.resourceVersion = "91"
	resumed.anchor.state = "installing"
	resumed.anchor.generation = 1
	resumed.anchor.installOperationID = "77777777-7777-7777-7777-777777777777"
	resumed.anchor.installOperationEpoch = 4
	resumed.anchor.installOperationNotAfter = time.Date(2099, 1, 2, 4, 0, 0, 0, time.UTC)
	resumed.plan.Gateway.BootstrapState = "owned lifecycle operation recovery"
	resumed.plan.Storage.State = "existing bound retry claim"
	resumed.plan.Storage.PVCUID = "pvc-uid"
	resumed.plan.Storage.ResourceVersion = "82"
	resumed.plan.Operations = []string{"recover active operation"}
	if _, got, computeErr := computeLifecycleInstallIntent(resumed); computeErr != nil || got != want {
		t.Fatalf("live-state recovery intent=(%s,%v), want stable %s", got, computeErr, want)
	}
}

func TestK8sLifecycleInstallIntentRejectsEveryMutationInputDrift(t *testing.T) {
	base := d13hIntentPrepared()
	_, want, err := computeLifecycleInstallIntent(base)
	if err != nil {
		t.Fatalf("base intent: %v", err)
	}
	cases := map[string]func(*preparedInstall){
		"organization": func(p *preparedInstall) {
			p.org.id, p.anchor.orgID = "22222222-2222-2222-2222-222222222222", "22222222-2222-2222-2222-222222222222"
		},
		"claim":          func(p *preparedInstall) { p.anchor.lifecycleClaim = "77777777-7777-7777-7777-777777777777" },
		"generation":     func(p *preparedInstall) { p.anchor.expectedGeneration = 1 },
		"request":        func(p *preparedInstall) { p.anchor.requestID = "88888888-8888-8888-8888-888888888888" },
		"context":        func(p *preparedInstall) { p.plan.Kubernetes.Context = "aks-b" },
		"namespace":      func(p *preparedInstall) { p.plan.Kubernetes.Namespace, p.options.namespace = "tunnex-b", "tunnex-b" },
		"release":        func(p *preparedInstall) { p.plan.Kubernetes.Release, p.options.release = "gateway-b", "gateway-b" },
		"chart artifact": func(p *preparedInstall) { p.gatewayArtifact.SHA256 = "sha256:" + strings.Repeat("c", 64) },
		"image": func(p *preparedInstall) {
			p.image.digest, p.image.reference = "sha256:"+strings.Repeat("d", 64), "ghcr.io/tunnexio/tunnex-node-agent@sha256:"+strings.Repeat("d", 64)
		},
		"control plane":      func(p *preparedInstall) { p.plan.ControlPlane.APIURL = "https://other.example.test" },
		"node":               func(p *preparedInstall) { p.options.nodeName = "gateway-b" },
		"placement":          func(p *preparedInstall) { p.options.gatewaySelectors = stringListFlag{"pool=other"} },
		"service":            func(p *preparedInstall) { p.options.loadBalancerIP = "10.0.0.8" },
		"wireguard endpoint": func(p *preparedInstall) { p.options.endpoint = "20.30.40.50:51820" },
		"storage":            func(p *preparedInstall) { p.plan.Storage.Class = "premium-csi" },
		"timeout":            func(p *preparedInstall) { p.options.timeout = "9m" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := d13hIntentPrepared()
			mutate(&candidate)
			_, got, computeErr := computeLifecycleInstallIntent(candidate)
			if computeErr != nil {
				t.Fatalf("compute drifted intent: %v", computeErr)
			}
			if got == want {
				t.Fatalf("mutation %q did not change install intent %s", name, want)
			}
		})
	}
}

func TestK8sLifecycleInstallBudgetKeepsCompletionMargin(t *testing.T) {
	helm, seconds, err := lifecycleInstallBudget("10m")
	if err != nil {
		t.Fatalf("default budget: %v", err)
	}
	if helm != 10*time.Minute || seconds != 660 {
		t.Fatalf("default budget=(%s,%d), want (10m,660)", helm, seconds)
	}

	helm, seconds, err = lifecycleInstallBudget("13m59.5s")
	if err != nil {
		t.Fatalf("rounded near-limit budget: %v", err)
	}
	if helm != 13*time.Minute+59*time.Second+500*time.Millisecond || seconds != 900 {
		t.Fatalf("rounded budget=(%s,%d), want (13m59.5s,900)", helm, seconds)
	}

	if _, seconds, err = lifecycleInstallBudget("14m"); err != nil || seconds != 900 {
		t.Fatalf("exact maximum budget=(%d,%v), want (900,nil)", seconds, err)
	}
	if _, _, err = lifecycleInstallBudget("14m0.000000001s"); err == nil || !strings.Contains(err.Error(), "14m0s or less") {
		t.Fatalf("above-maximum error=%v, want actionable maximum", err)
	}
}

func TestK8sLifecycleInstallDeadlineUsesServerDeltaNotLocalWallClock(t *testing.T) {
	// Deliberately skew the local wall component centuries away from the CP
	// response. Only requestStart's monotonic progression plus the DB delta may
	// define local authority.
	requestStart := time.Now().Add(200 * 365 * 24 * time.Hour)
	serverTime := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	status := lifecycleInstallOperationStatus{
		serverTime: serverTime, requestedDurationSeconds: 660,
		// Model CP work/audit performed after the lease INSERT. The returned
		// DB delta is slightly less than the requested 11-minute budget.
		notAfter: serverTime.Add(11*time.Minute - 750*time.Millisecond),
	}
	deadlines, err := deriveLifecycleInstallDeadlines(requestStart, status, 10*time.Minute)
	if err != nil {
		t.Fatalf("derive deadlines under wall-clock skew: %v", err)
	}
	if got := deadlines.hard.Sub(requestStart); got != 11*time.Minute-750*time.Millisecond {
		t.Fatalf("hard deadline delta=%s, want 10m59.25s", got)
	}
}

func TestK8sLifecycleInstallDeadlineRejectsShortenedAuthority(t *testing.T) {
	requestStart := time.Now()
	serverTime := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	status := lifecycleInstallOperationStatus{
		serverTime: serverTime, requestedDurationSeconds: 660,
		notAfter: serverTime.Add(10*time.Minute + minLifecycleInstallFinishMargin - time.Nanosecond),
	}
	if _, err := deriveLifecycleInstallDeadlines(requestStart, status, 10*time.Minute); err == nil || !strings.Contains(err.Error(), "requires 10m30s") {
		t.Fatalf("short authority error=%v, want exact budget refusal", err)
	}
	status.notAfter = serverTime.Add(10*time.Minute + minLifecycleInstallFinishMargin)
	if _, err := deriveLifecycleInstallDeadlines(requestStart, status, 10*time.Minute); err != nil {
		t.Fatalf("exact token-shortened minimum margin refused: %v", err)
	}
	status.notAfter = serverTime.Add(11*time.Minute + time.Nanosecond)
	if _, err := deriveLifecycleInstallDeadlines(requestStart, status, 10*time.Minute); err == nil || !strings.Contains(err.Error(), "exceeds the approved") {
		t.Fatalf("oversized authority error=%v, want approved-budget refusal", err)
	}
}

func TestK8sLifecycleInstallAnchorRejectsMalformedIntentDigest(t *testing.T) {
	anchor := testLifecycleAnchor("gateway-a", "gateway-a", "installing")
	anchor.installOperationID = testStateFenceOpID
	anchor.installOperationEpoch = 1
	anchor.installOperationDurationSeconds = 660
	anchor.installOperationNotAfter = time.Now().Add(11 * time.Minute).UTC()
	anchor.releaseNamespace = defaultK8sNamespace
	anchor.releaseName = anchor.instance
	for _, digest := range []string{"", "sha256:short", "sha256:" + strings.Repeat("A", 64), strings.Repeat("a", 64)} {
		anchor.installIntentDigest = digest
		if _, err := lifecycleInstallBeginFromAnchor(anchor); err == nil || !strings.Contains(err.Error(), "incomplete install-operation identity") {
			t.Fatalf("malformed install intent %q error = %v", digest, err)
		}
	}
}

func TestK8sLifecycleInstallAbortTakesOverNativePendingInstallUninstallsFinalizesAndReruns(t *testing.T) {
	release := "tunnex-gateway"
	anchor := testLifecycleAnchor(release, "aks-gateway-a", "installing")
	now := time.Now().UTC()
	releasedAt := now.Add(-time.Minute)
	anchor.installOperationID = testStateFenceOpID
	anchor.installOperationEpoch = 1
	anchor.installOperationDurationSeconds = 660
	anchor.installOperationNotAfter = now.Add(10 * time.Minute)
	anchor.installIntentDigest = "sha256:" + strings.Repeat("c", 64)
	anchor.releaseNamespace = defaultK8sNamespace
	anchor.releaseName = release

	cp := baseK8sControlPlane()
	cp.claims[anchor.lifecycleClaim] = k8sLifecycleClaimStatus{
		claim: anchor.lifecycleClaim, state: "consumed", nodeName: anchor.nodeName, generation: anchor.generation,
		requestID: anchor.requestID, expiresAt: anchor.expiresAt, nodeID: testLifecycleNodeID,
	}
	cp.installOperations[anchor.installOperationID] = lifecycleInstallOperationStatus{
		claim: anchor.lifecycleClaim, generation: anchor.generation, requestID: anchor.requestID,
		operationID: anchor.installOperationID, epoch: anchor.installOperationEpoch, state: lifecycleInstallReleased,
		releaseNamespace: anchor.releaseNamespace, releaseName: anchor.releaseName, installIntentDigest: anchor.installIntentDigest,
		requestedDurationSeconds: anchor.installOperationDurationSeconds, notAfter: anchor.installOperationNotAfter,
		serverTime: now, heartbeatAt: now.Add(-time.Minute), releasedAt: &releasedAt,
	}

	claim := gatewayFullname(release) + "-state"
	releaseExists, secretExists := true, true
	uninstallCount := 0
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		switch {
		case command.name == "helm" && strings.HasPrefix(joined, "list --all "):
			if releaseExists {
				return stdout(`[ {"name":"tunnex-gateway","namespace":"tunnex","revision":"1","status":"pending-install","chart":"tunnex-gateway-0.2.0","app_version":"v0.2.0"} ]`), nil
			}
			return stdout(`[]`), nil
		case command.name == "helm" && strings.HasPrefix(joined, "history "):
			return stdout(`[{"revision":1,"updated":"now","status":"pending-install","chart":"tunnex-gateway-0.2.0","app_version":"v0.2.0","description":"Initial install underway"}]`), nil
		case command.name == "helm" && strings.HasPrefix(joined, "uninstall "):
			uninstallCount++
			releaseExists = false
			return stdout("release uninstalled\n"), nil
		case command.name == "kubectl" && strings.Contains(joined, "get secret "+release+"-bootstrap"):
			if secretExists {
				return stdout(bootstrapSecretMetadataLine(release)), nil
			}
			return stdout(""), nil
		case command.name == "kubectl" && strings.Contains(joined, "delete --raw=") && strings.Contains(joined, "/secrets/"):
			secretExists = false
			return stdout(`{"kind":"Status","status":"Success"}`), nil
		case command.name == "kubectl" && strings.Contains(joined, "get pvc "+claim):
			return stdout(readyPVCJSON(claim, release)), nil
		case command.name == "kubectl" && strings.Contains(joined, "get deployments,statefulsets,daemonsets,jobs,pods,services"):
			if releaseExists {
				return stdout("deployment.apps/tunnex-gateway\n"), nil
			}
			return stdout(""), nil
		case command.name == "kubectl" && strings.Contains(joined, "get pods"):
			if releaseExists {
				return stdout(`{"items":[` + claimPodJSON("gateway-pod", "Running", "", "Deployment", gatewayFullname(release), claim) + `]}`), nil
			}
			return stdout(`{"items":[]}`), nil
		default:
			return baseRunnerHandler(command)
		}
	}

	var out bytes.Buffer
	deps := baseK8sDeps(runner, cp, &out, &bytes.Buffer{})
	args := []string{"abort-install", "--release", release, "--claim", anchor.lifecycleClaim, "--confirm", "ABORT " + anchor.lifecycleClaim}
	if err := runK8s(context.Background(), args, deps); err != nil {
		t.Fatalf("coordinated lifecycle install abort: %v", err)
	}
	if uninstallCount != 1 || cp.installAbortCount != 1 || cp.installFinalizeAbortCount != 1 {
		t.Fatalf("abort mutation counts uninstall/request/finalize = %d/%d/%d", uninstallCount, cp.installAbortCount, cp.installFinalizeAbortCount)
	}
	if releaseExists || secretExists {
		t.Fatalf("successful coordinated abort retained release=%t secret=%t", releaseExists, secretExists)
	}
	if _, exists := runner.anchors[anchor.name]; exists {
		t.Fatal("successful coordinated abort retained lifecycle anchor")
	}
	if status := cp.claims[anchor.lifecycleClaim]; status.state != "aborted" || status.abortedAt == nil || status.nodeID != testLifecycleNodeID {
		t.Fatalf("finalized claim = %+v", status)
	}
	if operation := cp.installOperations[anchor.installOperationID]; operation.state != lifecycleInstallAborted || operation.epoch != 2 || operation.abortedAt == nil {
		t.Fatalf("finalized operation = %+v", operation)
	}
	for _, command := range runner.commands {
		if strings.Contains(strings.Join(command.args, " "), "/persistentvolumeclaims/") {
			t.Fatalf("coordinated abort deleted retained PVC: %+v", command)
		}
	}

	beforeAbortCalls, beforeFinalizeCalls := cp.installAbortCount, cp.installFinalizeAbortCount
	runner.commands = nil
	out.Reset()
	if err := runK8s(context.Background(), args, deps); err != nil {
		t.Fatalf("idempotent coordinated abort rerun: %v", err)
	}
	if cp.installAbortCount != beforeAbortCalls || cp.installFinalizeAbortCount != beforeFinalizeCalls || uninstallCount != 1 {
		t.Fatalf("rerun repeated abort/finalize/uninstall = %d/%d/%d", cp.installAbortCount, cp.installFinalizeAbortCount, uninstallCount)
	}
	if !strings.Contains(out.String(), "already aborted") {
		t.Fatalf("idempotent rerun output omitted completion truth:\n%s", out.String())
	}
}

func TestK8sLifecycleInstallAbortRefusesInexactNativePendingInstallBeforeMutation(t *testing.T) {
	release := "tunnex-gateway"
	anchor := testLifecycleAnchor(release, "aks-gateway-a", "installing")
	now := time.Now().UTC()
	anchor.installOperationID = testStateFenceOpID
	anchor.installOperationEpoch = 1
	anchor.installOperationDurationSeconds = 660
	anchor.installOperationNotAfter = now.Add(10 * time.Minute)
	anchor.installIntentDigest = "sha256:" + strings.Repeat("c", 64)
	anchor.releaseNamespace = defaultK8sNamespace
	anchor.releaseName = release
	cp := baseK8sControlPlane()
	cp.claims[anchor.lifecycleClaim] = k8sLifecycleClaimStatus{
		claim: anchor.lifecycleClaim, state: "issued", nodeName: anchor.nodeName, generation: anchor.generation,
		requestID: anchor.requestID, expiresAt: anchor.expiresAt,
	}
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		switch {
		case command.name == "helm" && strings.HasPrefix(joined, "list --all "):
			return stdout(`[{"name":"tunnex-gateway","namespace":"tunnex","revision":"1","status":"pending-install","chart":"tunnex-gateway-0.2.0","app_version":"v0.2.0"}]`), nil
		case command.name == "helm" && strings.HasPrefix(joined, "history "):
			return stdout(`[{"revision":1,"status":"pending-install","chart":"tunnex-gateway-0.2.0","app_version":"v0.2.0","description":"initial install underway"}]`), nil
		default:
			return baseRunnerHandler(command)
		}
	}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	args := []string{"abort-install", "--release", release, "--claim", anchor.lifecycleClaim, "--confirm", "ABORT " + anchor.lifecycleClaim}
	err := runK8s(context.Background(), args, deps)
	if err == nil || !strings.Contains(err.Error(), "unproven lifecycle description") {
		t.Fatalf("inexact pending-install provenance error = %v", err)
	}
	if got := runner.anchors[anchor.name]; got.state != "installing" || got.resourceVersion != anchor.resourceVersion {
		t.Fatalf("provenance refusal changed lifecycle anchor: %+v", got)
	}
	if cp.installBeginCount != 0 || cp.installAbortCount != 0 || cp.installFinalizeAbortCount != 0 {
		t.Fatalf("provenance refusal reached control-plane mutation: begin/abort/finalize=%d/%d/%d", cp.installBeginCount, cp.installAbortCount, cp.installFinalizeAbortCount)
	}
	for _, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		if command.name == "helm" && strings.HasPrefix(joined, "uninstall ") {
			t.Fatalf("provenance refusal uninstalled Helm release: %+v", command)
		}
		if command.name == "kubectl" && strings.Contains(joined, "replace --raw=") {
			t.Fatalf("provenance refusal fenced lifecycle anchor: %+v", command)
		}
	}
}

func d13hAbortFenceCrashFixture(initial lifecycleInstallOperationState) (lifecycleAnchorMetadata, *fakeK8sControlPlane, *fakeK8sRunner, k8sDeps, []string) {
	release := "tunnex-gateway"
	anchor := testLifecycleAnchor(release, "aks-gateway-a", "installing")
	now := time.Now().UTC()
	anchor.installOperationID = testStateFenceOpID
	anchor.installOperationEpoch = 1
	anchor.installOperationDurationSeconds = 660
	anchor.installOperationNotAfter = now.Add(10 * time.Minute)
	anchor.installIntentDigest = "sha256:" + strings.Repeat("c", 64)
	anchor.releaseNamespace = defaultK8sNamespace
	anchor.releaseName = release
	cp := baseK8sControlPlane()
	cp.claims[anchor.lifecycleClaim] = k8sLifecycleClaimStatus{
		claim: anchor.lifecycleClaim, state: "issued", nodeName: anchor.nodeName, generation: anchor.generation,
		requestID: anchor.requestID, expiresAt: anchor.expiresAt,
	}
	operation := lifecycleInstallOperationStatus{
		claim: anchor.lifecycleClaim, generation: anchor.generation, requestID: anchor.requestID,
		operationID: anchor.installOperationID, epoch: anchor.installOperationEpoch, state: initial,
		releaseNamespace: anchor.releaseNamespace, releaseName: anchor.releaseName, installIntentDigest: anchor.installIntentDigest,
		requestedDurationSeconds: anchor.installOperationDurationSeconds, notAfter: anchor.installOperationNotAfter,
		serverTime: now, heartbeatAt: now,
	}
	if initial == lifecycleInstallReleased {
		releasedAt := now
		operation.releasedAt = &releasedAt
	}
	cp.installOperations[anchor.installOperationID] = operation
	failFence := true
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if failFence && command.name == "kubectl" && strings.Contains(joined, "replace --raw=") && bytes.Contains(command.stdin, []byte(`"tunnex.io/lifecycle-state":"aborting"`)) {
			failFence = false
			return k8sCommandResult{}, errors.New("simulated crash before abort anchor mirror")
		}
		return baseRunnerHandler(command)
	}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	args := []string{"abort-install", "--release", release, "--claim", anchor.lifecycleClaim, "--confirm", "ABORT " + anchor.lifecycleClaim}
	return anchor, cp, runner, deps, args
}

func TestK8sLifecycleAbortRequestSurvivesCrashBeforeAnchorMirror(t *testing.T) {
	anchor, cp, runner, deps, args := d13hAbortFenceCrashFixture(lifecycleInstallActive)
	if err := runK8s(context.Background(), args, deps); err == nil || !strings.Contains(err.Error(), "CAS-fence lifecycle anchor") {
		t.Fatalf("pre-mirror crash error = %v", err)
	}
	if got := runner.anchors[anchor.name]; got.state != "installing" || got.installOperationEpoch != 1 {
		t.Fatalf("failed mirror changed anchor = %+v", got)
	}
	status := cp.installOperations[anchor.installOperationID]
	if status.state != lifecycleInstallAbortRequested || status.abortRequestedAt == nil {
		t.Fatalf("control-plane abort request was not durable before mirror failure: %+v", status)
	}
	heartbeat, err := cp.HeartbeatLifecycleInstall(context.Background(), anchor.orgID, lifecycleInstallCASFromStatus(status))
	if err != nil || heartbeat.state != lifecycleInstallAbortRequested {
		t.Fatalf("holder heartbeat after durable abort = %+v, %v", heartbeat, err)
	}
	if _, err := cp.CompleteLifecycleInstall(context.Background(), anchor.orgID, lifecycleInstallCASFromStatus(heartbeat)); err == nil {
		t.Fatal("holder completed after durable abort request")
	}
	if _, err := cp.ReleaseLifecycleInstall(context.Background(), anchor.orgID, lifecycleInstallCASFromStatus(heartbeat)); err != nil {
		t.Fatalf("holder release after abort request: %v", err)
	}
	if err := runK8s(context.Background(), args, deps); err != nil {
		t.Fatalf("abort resume after durable request/holder release: %v", err)
	}
	if _, exists := runner.anchors[anchor.name]; exists {
		t.Fatal("resumed abort retained lifecycle anchor")
	}
	if status := cp.claims[anchor.lifecycleClaim]; status.state != "aborted" || status.abortedAt == nil {
		t.Fatalf("resumed abort claim = %+v", status)
	}
}

func TestK8sLifecycleAbortRecoversTakeoverCommittedBeforeAnchorMirror(t *testing.T) {
	anchor, cp, runner, deps, args := d13hAbortFenceCrashFixture(lifecycleInstallReleased)
	if err := runK8s(context.Background(), args, deps); err == nil || !strings.Contains(err.Error(), "CAS-fence lifecycle anchor") {
		t.Fatalf("takeover pre-mirror crash error = %v", err)
	}
	if got := runner.anchors[anchor.name]; got.state != "installing" || got.installOperationEpoch != 1 {
		t.Fatalf("failed takeover mirror changed anchor = %+v", got)
	}
	takeover := cp.installOperations[anchor.installOperationID]
	if takeover.state != lifecycleInstallAborting || takeover.epoch != 2 || takeover.takenOverAt == nil {
		t.Fatalf("durable takeover before mirror = %+v", takeover)
	}
	if err := runK8s(context.Background(), args, deps); err != nil {
		t.Fatalf("abort resume after lost takeover mirror: %v", err)
	}
	if _, exists := runner.anchors[anchor.name]; exists {
		t.Fatal("takeover resume retained lifecycle anchor")
	}
	final := cp.installOperations[anchor.installOperationID]
	if final.state != lifecycleInstallAborted || final.epoch != 2 || final.abortedAt == nil {
		t.Fatalf("takeover resume final operation = %+v", final)
	}
}

func d13hFailureAuthority(cp *fakeK8sControlPlane, anchor lifecycleAnchorMetadata) lifecycleInstallAuthority {
	status := cp.installOperations[anchor.installOperationID]
	begin := lifecycleInstallBeginRequest{
		claim: anchor.lifecycleClaim, expectedGeneration: anchor.generation, requestID: anchor.requestID,
		operationID: anchor.installOperationID, releaseNamespace: anchor.releaseNamespace, releaseName: anchor.releaseName,
		installIntentDigest: anchor.installIntentDigest, requestedDurationSeconds: anchor.installOperationDurationSeconds,
	}
	return lifecycleInstallAuthority{
		cp: cp, orgID: anchor.orgID, begin: begin, cas: lifecycleInstallCASFromStatus(status), status: status, anchor: anchor,
	}
}

type d13hAtomicTimeoutRunner struct {
	base                   *fakeK8sRunner
	helmEntered            bool
	externallyCanceled     bool
	atomicCleanupCompleted bool
}

type d13hHardDeadlineRunner struct {
	base        *fakeK8sRunner
	helmEntered bool
	helmCause   error
}

func (r *d13hHardDeadlineRunner) LookPath(name string) (string, error) {
	return r.base.LookPath(name)
}

func (r *d13hHardDeadlineRunner) Run(ctx context.Context, command k8sCommand) (k8sCommandResult, error) {
	joined := strings.Join(command.args, " ")
	if command.name == "helm" && strings.HasPrefix(joined, "install tunnex-gateway ") {
		r.helmEntered = true
		r.base.commands = append(r.base.commands, k8sCommand{
			name: command.name, args: append([]string(nil), command.args...), stdin: append([]byte(nil), command.stdin...),
		})
		select {
		case <-ctx.Done():
			r.helmCause = context.Cause(ctx)
			return k8sCommandResult{}, ctx.Err()
		case <-time.After(5 * time.Second):
			return k8sCommandResult{}, errors.New("test timed out waiting for the lifecycle hard deadline")
		}
	}
	return r.base.Run(ctx, command)
}

func TestK8sLifecycleHardDeadlineCancelsBlockedHelmAndRetainsRecovery(t *testing.T) {
	cp := baseK8sControlPlane()
	baseRunner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{}, handler: baseRunnerHandler}
	runner := &d13hHardDeadlineRunner{base: baseRunner}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}).normalized()
	// A 100ms Helm timeout requests a 61-second server lease. Model 60 seconds
	// of conservative request transit so the local monotonic hard deadline is
	// near while the control-plane tuple remains valid.
	deps.now = func() time.Time { return time.Now().Add(-60 * time.Second) }
	err := runK8s(context.Background(), []string{
		"install", "--node-name", "aks-gateway-a", "--timeout", "100ms", "--yes",
	}, deps)
	if err == nil || !strings.Contains(err.Error(), errLifecycleInstallDeadline.Error()) {
		t.Fatalf("hard-deadline Helm error = %v", err)
	}
	if !runner.helmEntered || !errors.Is(runner.helmCause, errLifecycleInstallDeadline) {
		t.Fatalf("blocked Helm entered/cause=%t/%v", runner.helmEntered, runner.helmCause)
	}
	status := cp.installOperations[testStateFenceOpID]
	if cp.installCompleteCount != 0 || cp.installReleaseCount != 1 || status.state != lifecycleInstallReleased {
		t.Fatalf("hard deadline complete/release/state=%d/%d/%s", cp.installCompleteCount, cp.installReleaseCount, status.state)
	}
	if _, exists := baseRunner.anchors["tunnex-gateway-lifecycle"]; !exists {
		t.Fatal("hard deadline removed lifecycle recovery anchor")
	}
	for _, command := range baseRunner.commands {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "delete --raw=/api/v1/namespaces/tunnex/") {
			t.Fatalf("hard deadline deleted recovery metadata: %+v", command)
		}
	}
}

func (r *d13hAtomicTimeoutRunner) LookPath(name string) (string, error) {
	return r.base.LookPath(name)
}

func (r *d13hAtomicTimeoutRunner) Run(ctx context.Context, command k8sCommand) (k8sCommandResult, error) {
	joined := strings.Join(command.args, " ")
	if command.name == "helm" && strings.HasPrefix(joined, "install tunnex-gateway ") {
		r.helmEntered = true
		r.base.commands = append(r.base.commands, k8sCommand{
			name: command.name, args: append([]string(nil), command.args...), stdin: append([]byte(nil), command.stdin...),
		})
		timeout, err := time.ParseDuration(commandArgValue(command.args, "--timeout"))
		if err != nil {
			return k8sCommandResult{}, fmt.Errorf("test Helm command lacks a valid internal timeout: %w", err)
		}
		if timeout <= 0 {
			return k8sCommandResult{}, errors.New("test Helm command lacks a positive internal timeout")
		}
		timer := time.NewTimer(2 * timeout)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			r.externallyCanceled = true
			return k8sCommandResult{}, ctx.Err()
		case <-timer.C:
			r.atomicCleanupCompleted = true
			return k8sCommandResult{stderr: []byte("simulated ordinary Helm timeout after atomic cleanup")}, errors.New("exit 1")
		}
	}
	if r.atomicCleanupCompleted && command.name == "kubectl" && strings.Contains(joined, "rollout status deployment/tunnex-gateway") {
		return k8sCommandResult{stderr: []byte("deployment not found after atomic cleanup")}, errors.New("exit 1")
	}
	return r.base.Run(ctx, command)
}

func TestK8sLifecycleOrdinaryHelmTimeoutAllowsAtomicCleanupBeforeAuthorityRelease(t *testing.T) {
	cp := baseK8sControlPlane()
	baseRunner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{}, handler: baseRunnerHandler}
	runner := &d13hAtomicTimeoutRunner{base: baseRunner}
	err := runK8s(context.Background(), []string{
		"install", "--node-name", "aks-gateway-a", "--timeout", "40ms", "--yes",
	}, baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}))
	if err == nil || !strings.Contains(err.Error(), "simulated ordinary Helm timeout after atomic cleanup") ||
		!strings.Contains(err.Error(), `bootstrap Secret "tunnex-gateway-bootstrap" was retained`) {
		t.Fatalf("ordinary Helm timeout error = %v", err)
	}
	if !runner.helmEntered || runner.externallyCanceled || !runner.atomicCleanupCompleted {
		t.Fatalf("Helm timeout ownership entered/canceled/cleaned=%t/%t/%t", runner.helmEntered, runner.externallyCanceled, runner.atomicCleanupCompleted)
	}
	status := cp.installOperations[testStateFenceOpID]
	if cp.installCompleteCount != 0 || cp.installReleaseCount != 1 || status.state != lifecycleInstallReleased {
		t.Fatalf("ordinary timeout complete/release/state=%d/%d/%s", cp.installCompleteCount, cp.installReleaseCount, status.state)
	}
	if _, exists := baseRunner.anchors["tunnex-gateway-lifecycle"]; !exists {
		t.Fatal("ordinary timeout removed lifecycle recovery anchor")
	}
	for _, command := range baseRunner.commands {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "delete --raw=/api/v1/namespaces/tunnex/") {
			t.Fatalf("ordinary timeout deleted recovery metadata: %+v", command)
		}
	}
}

func TestK8sLifecycleInstallFailureReleaseIsPhaseAware(t *testing.T) {
	for _, tc := range []struct {
		name          string
		releaseExists bool
		readyConsumed bool
		helmStarted   bool
		holderStopped bool
		wantRelease   bool
		wantComplete  bool
	}{
		{name: "committed Helm lost response completes exact ready consumed install", releaseExists: true, readyConsumed: true, helmStarted: true, wantComplete: true},
		{name: "post install readback transient retains authority", releaseExists: true, helmStarted: true},
		{name: "definite exact absence releases authority", helmStarted: true, wantRelease: true},
		{name: "abort stopped holder releases for takeover", releaseExists: true, helmStarted: true, holderStopped: true, wantRelease: true},
		{name: "pre Helm failure releases authority", wantRelease: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			anchor := testLifecycleAnchor("tunnex-gateway", "aks-gateway-a", "installing")
			now := time.Now().UTC()
			anchor.installOperationID = testStateFenceOpID
			anchor.installOperationEpoch = 1
			anchor.installOperationDurationSeconds = 660
			anchor.installOperationNotAfter = now.Add(11 * time.Minute)
			anchor.installIntentDigest = "sha256:" + strings.Repeat("c", 64)
			anchor.releaseNamespace = defaultK8sNamespace
			anchor.releaseName = anchor.instance
			cp := baseK8sControlPlane()
			cp.installOperations[anchor.installOperationID] = lifecycleInstallOperationStatus{
				claim: anchor.lifecycleClaim, generation: anchor.generation, requestID: anchor.requestID,
				operationID: anchor.installOperationID, epoch: anchor.installOperationEpoch, state: lifecycleInstallActive,
				releaseNamespace: anchor.releaseNamespace, releaseName: anchor.releaseName, installIntentDigest: anchor.installIntentDigest,
				requestedDurationSeconds: anchor.installOperationDurationSeconds, notAfter: anchor.installOperationNotAfter,
				serverTime: now, heartbeatAt: now,
			}
			runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}}
			if tc.releaseExists {
				runner.handler = installedRunnerHandler
			} else {
				runner.handler = baseRunnerHandler
			}
			if tc.readyConsumed {
				cp.claims[anchor.lifecycleClaim] = k8sLifecycleClaimStatus{
					claim: anchor.lifecycleClaim, state: "consumed", nodeName: anchor.nodeName, nodeID: testLifecycleNodeID,
					generation: anchor.generation, requestID: anchor.requestID, expiresAt: anchor.expiresAt,
				}
			}
			claim := gatewayFullname(anchor.instance) + "-state"
			prepared := preparedInstall{
				options: installOptions{
					release: anchor.instance, namespace: defaultK8sNamespace, nodeName: anchor.nodeName, mode: "enroll",
					serviceType: "LoadBalancer", kubeContext: "walk-context", timeout: "10m",
				},
				plan: lifecyclePlan{Storage: lifecycleStorage{Claim: claim, Class: "managed-csi"}},
				org:  cp.orgs[0], cp: cp, anchor: anchor,
			}
			err := reconcileLifecycleInstallFailure(context.Background(), baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}), d13hFailureAuthority(cp, anchor), prepared, tc.helmStarted, tc.holderStopped)
			if tc.wantComplete {
				if err != nil || cp.installCompleteCount != 1 || cp.installReleaseCount != 0 || cp.installOperations[anchor.installOperationID].state != lifecycleInstallCompleted {
					t.Fatalf("phase-aware completion err=%v complete/release=%d/%d state=%s", err, cp.installCompleteCount, cp.installReleaseCount, cp.installOperations[anchor.installOperationID].state)
				}
				return
			}
			if tc.wantRelease {
				if err != nil || cp.installReleaseCount != 1 || cp.installOperations[anchor.installOperationID].state != lifecycleInstallReleased {
					t.Fatalf("phase-aware release result err=%v count=%d state=%s", err, cp.installReleaseCount, cp.installOperations[anchor.installOperationID].state)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "authority was retained") || cp.installReleaseCount != 0 {
				t.Fatalf("ambiguous post-Helm result err=%v releaseCount=%d", err, cp.installReleaseCount)
			}
		})
	}
}

type d13hAbortOrderControlPlane struct {
	*fakeK8sControlPlane
	runner             *fakeK8sRunner
	anchorName         string
	releaseSawAborting bool
	events             []string
}

type d13hResumeHeartbeatControlPlane struct {
	*fakeK8sControlPlane
	heartbeat chan struct{}
}

func (c *d13hResumeHeartbeatControlPlane) HeartbeatLifecycleInstall(ctx context.Context, orgID string, request lifecycleInstallCASRequest) (lifecycleInstallOperationStatus, error) {
	status, err := c.fakeK8sControlPlane.HeartbeatLifecycleInstall(ctx, orgID, request)
	c.heartbeat <- struct{}{}
	return status, err
}

type d13hResumeGateRunner struct {
	base    *fakeK8sRunner
	entered chan struct{}
	release chan struct{}
	blocked bool
}

func (r *d13hResumeGateRunner) LookPath(name string) (string, error) {
	return r.base.LookPath(name)
}

func (r *d13hResumeGateRunner) Run(ctx context.Context, command k8sCommand) (k8sCommandResult, error) {
	joined := strings.Join(command.args, " ")
	if !r.blocked && command.name == "kubectl" && strings.Contains(joined, "rollout status deployment/tunnex-gateway") {
		r.blocked = true
		close(r.entered)
		select {
		case <-r.release:
		case <-ctx.Done():
			if cause := context.Cause(ctx); cause != nil {
				return k8sCommandResult{}, cause
			}
			return k8sCommandResult{}, ctx.Err()
		}
	}
	return r.base.Run(ctx, command)
}

func d13hActiveResumePrepared(cp *fakeK8sControlPlane) (preparedInstall, lifecycleAnchorMetadata) {
	release := "tunnex-gateway"
	nodeName := "aks-gateway-a"
	anchor := testLifecycleAnchor(release, nodeName, "installing")
	now := time.Now().UTC()
	anchor.installOperationID = testStateFenceOpID
	anchor.installOperationEpoch = 1
	anchor.installOperationDurationSeconds = 660
	anchor.installOperationNotAfter = now.Add(11 * time.Minute)
	anchor.installIntentDigest = "sha256:" + strings.Repeat("c", 64)
	anchor.releaseNamespace = defaultK8sNamespace
	anchor.releaseName = release
	cp.installOperations[anchor.installOperationID] = lifecycleInstallOperationStatus{
		claim: anchor.lifecycleClaim, generation: anchor.generation, requestID: anchor.requestID,
		operationID: anchor.installOperationID, epoch: anchor.installOperationEpoch, state: lifecycleInstallActive,
		releaseNamespace: anchor.releaseNamespace, releaseName: anchor.releaseName, installIntentDigest: anchor.installIntentDigest,
		requestedDurationSeconds: anchor.installOperationDurationSeconds, notAfter: anchor.installOperationNotAfter,
		serverTime: now, heartbeatAt: now,
	}
	cp.claims[anchor.lifecycleClaim] = k8sLifecycleClaimStatus{
		claim: anchor.lifecycleClaim, state: "consumed", nodeName: anchor.nodeName, nodeID: testLifecycleNodeID,
		generation: anchor.generation, requestID: anchor.requestID, expiresAt: anchor.expiresAt,
	}
	claim := gatewayFullname(release) + "-state"
	prepared := preparedInstall{
		options: installOptions{
			release: release, namespace: defaultK8sNamespace, nodeName: nodeName, mode: "enroll",
			serviceType: "LoadBalancer", kubeContext: "walk-context", timeout: "10m",
		},
		plan: lifecyclePlan{Storage: lifecycleStorage{Claim: claim, Class: "managed-csi"}},
		org:  cp.orgs[0], cp: cp, anchor: anchor,
		state: installState{
			resumeCleanup: true,
			resumeRelease: helmReleaseSummary{Name: release, Namespace: defaultK8sNamespace, Revision: "3", Status: "deployed"},
			anchorExists:  true, anchorName: anchor.name, anchorUID: anchor.uid, anchorResourceVersion: anchor.resourceVersion,
			pvcExists: true, pvcName: claim, pvcUID: "uid-" + claim, pvcVolumeName: "pvc-id", pvcPhase: "Bound", pvcStorageClass: "managed-csi",
		},
	}
	return prepared, anchor
}

func TestK8sResumeCleanupHeartbeatsActiveAuthorityUntilComplete(t *testing.T) {
	base := baseK8sControlPlane()
	prepared, anchor := d13hActiveResumePrepared(base)
	baseRunner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}, handler: installedRunnerHandler}
	runner := &d13hResumeGateRunner{base: baseRunner, entered: make(chan struct{}), release: make(chan struct{})}
	cp := &d13hResumeHeartbeatControlPlane{fakeK8sControlPlane: base, heartbeat: make(chan struct{}, 1)}
	prepared.cp = cp
	ticker := newD13hCrashTicker()
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}).normalized()
	deps.newTicker = func(time.Duration) k8sTicker { return ticker }
	result := make(chan error, 1)
	go func() { result <- resumePostInstallCleanup(context.Background(), deps, prepared) }()
	<-runner.entered
	ticker.tick(time.Now())
	<-cp.heartbeat
	close(runner.release)
	if err := <-result; err != nil {
		t.Fatalf("resume cleanup under heartbeat authority: %v", err)
	}
	if base.installHeartbeatCount != 1 || base.installCompleteCount != 1 || base.installReleaseCount != 0 {
		t.Fatalf("resume heartbeat/complete/release=%d/%d/%d", base.installHeartbeatCount, base.installCompleteCount, base.installReleaseCount)
	}
	if _, exists := baseRunner.anchors[anchor.name]; exists {
		t.Fatal("completed resume retained lifecycle anchor")
	}
}

func TestK8sResumeCleanupAbortDuringVerificationReleasesAndRetainsMetadata(t *testing.T) {
	base := baseK8sControlPlane()
	prepared, anchor := d13hActiveResumePrepared(base)
	baseRunner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}, handler: installedRunnerHandler}
	runner := &d13hResumeGateRunner{base: baseRunner, entered: make(chan struct{}), release: make(chan struct{})}
	cp := &d13hResumeHeartbeatControlPlane{fakeK8sControlPlane: base, heartbeat: make(chan struct{}, 1)}
	prepared.cp = cp
	ticker := newD13hCrashTicker()
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}).normalized()
	deps.newTicker = func(time.Duration) k8sTicker { return ticker }
	result := make(chan error, 1)
	go func() { result <- resumePostInstallCleanup(context.Background(), deps, prepared) }()
	<-runner.entered
	base.installMu.Lock()
	status := base.installOperations[anchor.installOperationID]
	now := time.Now().UTC()
	status.abortRequestedAt = &now
	base.installOperations[anchor.installOperationID] = status
	base.installMu.Unlock()
	ticker.tick(now)
	<-cp.heartbeat
	err := <-result
	if err == nil || !strings.Contains(err.Error(), errLifecycleInstallAbortRequested.Error()) {
		t.Fatalf("resume abort during verification error = %v", err)
	}
	if base.installCompleteCount != 0 || base.installReleaseCount != 1 || base.installOperations[anchor.installOperationID].state != lifecycleInstallReleased {
		t.Fatalf("resume abort complete/release/state=%d/%d/%s", base.installCompleteCount, base.installReleaseCount, base.installOperations[anchor.installOperationID].state)
	}
	if _, exists := baseRunner.anchors[anchor.name]; !exists {
		t.Fatal("aborted resume verification deleted lifecycle recovery metadata")
	}
}

func TestK8sResumeCleanupHardDeadlineStopsVerificationReleasesAndRetainsMetadata(t *testing.T) {
	base := baseK8sControlPlane()
	prepared, anchor := d13hActiveResumePrepared(base)
	now := time.Now().UTC()
	anchor.installOperationNotAfter = now.Add(2 * time.Minute)
	prepared.anchor = anchor
	status := base.installOperations[anchor.installOperationID]
	status.notAfter = anchor.installOperationNotAfter
	status.serverTime = now
	base.installOperations[anchor.installOperationID] = status

	baseRunner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}, handler: installedRunnerHandler}
	runner := &d13hResumeGateRunner{base: baseRunner, entered: make(chan struct{}), release: make(chan struct{})}
	deps := baseK8sDeps(runner, base, &bytes.Buffer{}, &bytes.Buffer{}).normalized()
	// The CP grants a positive DB-clock remainder, but the persisted local
	// monotonic request start makes that hard deadline already elapsed. This
	// avoids sleeps while proving the full verification path obeys the bound.
	deps.now = func() time.Time { return now.Add(-time.Hour) }

	err := resumePostInstallCleanup(context.Background(), deps, prepared)
	if err == nil || !strings.Contains(err.Error(), errLifecycleInstallDeadline.Error()) {
		t.Fatalf("resume hard-deadline error = %v", err)
	}
	if base.installCompleteCount != 0 || base.installReleaseCount != 1 || base.installOperations[anchor.installOperationID].state != lifecycleInstallReleased {
		t.Fatalf("resume deadline complete/release/state=%d/%d/%s", base.installCompleteCount, base.installReleaseCount, base.installOperations[anchor.installOperationID].state)
	}
	if _, exists := baseRunner.anchors[anchor.name]; !exists {
		t.Fatal("hard-deadline resume deleted lifecycle recovery metadata")
	}
	for _, command := range baseRunner.commands {
		if command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "delete --raw=/api/v1/namespaces/tunnex/") {
			t.Fatalf("hard-deadline resume deleted recovery metadata: %+v", command)
		}
	}
}

func TestK8sInstallAbortDuringPostHelmVerificationReleasesImmediately(t *testing.T) {
	base := baseK8sControlPlane()
	baseRunner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{}, handler: baseRunnerHandler}
	runner := &d13hResumeGateRunner{base: baseRunner, entered: make(chan struct{}), release: make(chan struct{})}
	cp := &d13hResumeHeartbeatControlPlane{fakeK8sControlPlane: base, heartbeat: make(chan struct{}, 1)}
	ticker := newD13hCrashTicker()
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}).normalized()
	deps.newTicker = func(time.Duration) k8sTicker { return ticker }
	result := make(chan error, 1)
	go func() {
		result <- runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps)
	}()
	<-runner.entered
	base.installMu.Lock()
	status := base.installOperations[testStateFenceOpID]
	now := time.Now().UTC()
	status.abortRequestedAt = &now
	base.installOperations[testStateFenceOpID] = status
	base.installMu.Unlock()
	ticker.tick(now)
	<-cp.heartbeat
	err := <-result
	if err == nil || !strings.Contains(err.Error(), errLifecycleInstallAbortRequested.Error()) {
		t.Fatalf("post-Helm abort verification error = %v", err)
	}
	if base.installCompleteCount != 0 || base.installReleaseCount != 1 || base.installOperations[testStateFenceOpID].state != lifecycleInstallReleased {
		t.Fatalf("post-Helm abort complete/release/state=%d/%d/%s", base.installCompleteCount, base.installReleaseCount, base.installOperations[testStateFenceOpID].state)
	}
	if _, exists := baseRunner.anchors["tunnex-gateway-lifecycle"]; !exists {
		t.Fatal("post-Helm abort removed lifecycle recovery anchor")
	}
	for _, command := range baseRunner.commands {
		if command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "delete --raw=/api/v1/namespaces/tunnex/") {
			t.Fatalf("post-Helm abort deleted recovery metadata: %+v", command)
		}
	}
}

func TestK8sInstallLostHelmResponseCompletesReadyConsumedOperation(t *testing.T) {
	cp := baseK8sControlPlane()
	helmCommitted := false
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{}}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "helm" && len(command.args) > 0 && command.args[0] == "install" {
			helmCommitted = true
			status := cp.claims[testLifecycleClaim]
			consumedAt := time.Now().UTC()
			status.state = "consumed"
			status.nodeID = testLifecycleNodeID
			status.consumedAt = &consumedAt
			cp.claims[testLifecycleClaim] = status
			return k8sCommandResult{}, errors.New("synthetic committed Helm response lost")
		}
		if !helmCommitted && command.name == "kubectl" &&
			(strings.Contains(joined, "rollout status deployment/tunnex-gateway") ||
				strings.Contains(joined, "get deployment tunnex-gateway ") ||
				strings.Contains(joined, "get service tunnex-gateway-tunnex-gateway-wg ") ||
				(strings.Contains(joined, "get pvc tunnex-gateway-tunnex-gateway-state ") && !strings.Contains(joined, "--ignore-not-found=true"))) {
			return k8sCommandResult{}, errors.New("synthetic gateway resources are not committed")
		}
		return baseRunnerHandler(command)
	}
	err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}))
	if err == nil || !strings.Contains(err.Error(), "bootstrap Secret \"tunnex-gateway-bootstrap\" was retained") {
		t.Fatalf("lost Helm response error = %v", err)
	}
	status := cp.installOperations[testStateFenceOpID]
	if cp.installCompleteCount != 1 || cp.installReleaseCount != 0 || status.state != lifecycleInstallCompleted {
		t.Fatalf("lost Helm response complete/release/state=%d/%d/%s", cp.installCompleteCount, cp.installReleaseCount, status.state)
	}
	if !helmCommitted || cp.claims[testLifecycleClaim].state != "consumed" {
		t.Fatalf("lost Helm response test did not prove an explicit committed release/consumed claim")
	}
	if _, exists := runner.anchors["tunnex-gateway-lifecycle"]; !exists {
		t.Fatal("lost Helm response removed lifecycle recovery anchor before resumable cleanup")
	}
	for _, command := range runner.commands {
		if command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "delete --raw=/api/v1/namespaces/tunnex/") {
			t.Fatalf("lost Helm response deleted recovery metadata: %+v", command)
		}
	}
}

func (c *d13hAbortOrderControlPlane) ReleaseLifecycleInstall(ctx context.Context, orgID string, request lifecycleInstallCASRequest) (lifecycleInstallOperationStatus, error) {
	c.events = append(c.events, "release")
	c.releaseSawAborting = c.runner.anchors[c.anchorName].state == "aborting"
	return c.fakeK8sControlPlane.ReleaseLifecycleInstall(ctx, orgID, request)
}

func (c *d13hAbortOrderControlPlane) CoordinateLifecycleInstallAbort(ctx context.Context, orgID string, request lifecycleInstallCASRequest) (lifecycleInstallAbortResult, error) {
	c.events = append(c.events, "coordinate")
	return c.fakeK8sControlPlane.CoordinateLifecycleInstallAbort(ctx, orgID, request)
}

func d13hPreBeginAbortAnchor() lifecycleAnchorMetadata {
	anchor := testLifecycleAnchor("tunnex-gateway", "aks-gateway-a", "acknowledged")
	anchor.installOperationID = testStateFenceOpID
	anchor.installOperationDurationSeconds = 660
	anchor.installIntentDigest = "sha256:" + strings.Repeat("c", 64)
	anchor.releaseNamespace = defaultK8sNamespace
	anchor.releaseName = anchor.instance
	return anchor
}

func TestK8sLifecyclePreBeginAbortFencesThenReleasesWithoutWaiting(t *testing.T) {
	anchor := d13hPreBeginAbortAnchor()
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}, handler: baseRunnerHandler}
	base := baseK8sControlPlane()
	base.claims[anchor.lifecycleClaim] = k8sLifecycleClaimStatus{
		claim: anchor.lifecycleClaim, state: "acknowledged", nodeName: anchor.nodeName, generation: anchor.generation,
		requestID: anchor.requestID, expiresAt: anchor.expiresAt,
	}
	cp := &d13hAbortOrderControlPlane{fakeK8sControlPlane: base, runner: runner, anchorName: anchor.name}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}).normalized()
	deps.newTicker = func(time.Duration) k8sTicker {
		t.Fatal("pre-Begin no-holder abort waited for a heartbeat tick")
		return nil
	}
	args := []string{"abort-install", "--release", anchor.instance, "--claim", anchor.lifecycleClaim, "--confirm", "ABORT " + anchor.lifecycleClaim}
	if err := runK8s(context.Background(), args, deps); err != nil {
		t.Fatalf("pre-Begin no-holder abort: %v", err)
	}
	if !cp.releaseSawAborting || strings.Join(cp.events, ",") != "release,coordinate" {
		t.Fatalf("pre-Begin abort order events=%v releaseSawAborting=%t", cp.events, cp.releaseSawAborting)
	}
	if base.installReleaseCount != 1 || base.installAbortCount != 1 || base.installFinalizeAbortCount != 1 {
		t.Fatalf("pre-Begin release/request/finalize=%d/%d/%d", base.installReleaseCount, base.installAbortCount, base.installFinalizeAbortCount)
	}
	if _, exists := runner.anchors[anchor.name]; exists {
		t.Fatal("pre-Begin no-holder abort retained lifecycle anchor")
	}
}

func TestK8sLifecyclePreBeginAbortCASLoserNeverReleasesInstaller(t *testing.T) {
	anchor := d13hPreBeginAbortAnchor()
	base := baseK8sControlPlane()
	base.claims[anchor.lifecycleClaim] = k8sLifecycleClaimStatus{
		claim: anchor.lifecycleClaim, state: "acknowledged", nodeName: anchor.nodeName, generation: anchor.generation,
		requestID: anchor.requestID, expiresAt: anchor.expiresAt,
	}
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "replace --raw=") && bytes.Contains(command.stdin, []byte(`"tunnex.io/lifecycle-state":"aborting"`)) {
			winner := runner.anchors[anchor.name]
			operation := base.installOperations[anchor.installOperationID]
			winner.state = "installing"
			winner.installOperationEpoch = operation.epoch
			winner.installOperationNotAfter = operation.notAfter
			winner.resourceVersion = "10"
			runner.anchors[anchor.name] = winner
			return k8sCommandResult{stderr: []byte("Conflict")}, errors.New("synthetic installer won anchor CAS")
		}
		return baseRunnerHandler(command)
	}
	args := []string{"abort-install", "--release", anchor.instance, "--claim", anchor.lifecycleClaim, "--confirm", "ABORT " + anchor.lifecycleClaim}
	if err := runK8s(context.Background(), args, baseK8sDeps(runner, base, &bytes.Buffer{}, &bytes.Buffer{})); err == nil || !strings.Contains(err.Error(), "CAS-fence lifecycle anchor") {
		t.Fatalf("pre-Begin abort CAS-loser error = %v", err)
	}
	if base.installReleaseCount != 0 || base.installAbortCount != 0 || runner.anchors[anchor.name].state != "installing" {
		t.Fatalf("abort CAS loser mutated winner: releases=%d aborts=%d anchor=%+v", base.installReleaseCount, base.installAbortCount, runner.anchors[anchor.name])
	}
}

func TestK8sLifecyclePreBeginAbortResumesAfterFenceBeforeRelease(t *testing.T) {
	anchor := d13hPreBeginAbortAnchor()
	now := time.Now().UTC()
	anchor.state = "aborting"
	anchor.installOperationEpoch = 1
	anchor.installOperationNotAfter = now.Add(11 * time.Minute)
	base := baseK8sControlPlane()
	base.claims[anchor.lifecycleClaim] = k8sLifecycleClaimStatus{
		claim: anchor.lifecycleClaim, state: "acknowledged", nodeName: anchor.nodeName, generation: anchor.generation,
		requestID: anchor.requestID, expiresAt: anchor.expiresAt,
	}
	base.installOperations[anchor.installOperationID] = lifecycleInstallOperationStatus{
		claim: anchor.lifecycleClaim, generation: anchor.generation, requestID: anchor.requestID,
		operationID: anchor.installOperationID, epoch: 1, state: lifecycleInstallActive,
		releaseNamespace: anchor.releaseNamespace, releaseName: anchor.releaseName, installIntentDigest: anchor.installIntentDigest,
		requestedDurationSeconds: anchor.installOperationDurationSeconds, notAfter: anchor.installOperationNotAfter,
		serverTime: now, heartbeatAt: now,
	}
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}, handler: baseRunnerHandler}
	cp := &d13hAbortOrderControlPlane{fakeK8sControlPlane: base, runner: runner, anchorName: anchor.name}
	args := []string{"abort-install", "--release", anchor.instance, "--claim", anchor.lifecycleClaim, "--confirm", "ABORT " + anchor.lifecycleClaim}
	if err := runK8s(context.Background(), args, baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})); err != nil {
		t.Fatalf("resume pre-Begin fence before release: %v", err)
	}
	if !cp.releaseSawAborting || strings.Join(cp.events, ",") != "release,coordinate" || base.installFinalizeAbortCount != 1 {
		t.Fatalf("resumed no-holder abort order=%v releaseSawFence=%t finalize=%d", cp.events, cp.releaseSawAborting, base.installFinalizeAbortCount)
	}
}
