package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	d13hCrashOperationID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	d13hNextOperationID  = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	d13hNextRequestID    = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
)

type d13hCrashEventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *d13hCrashEventLog) add(event string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
}

func (l *d13hCrashEventLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

func d13hEventIndex(events []string, event string, occurrence int) int {
	seen := 0
	for index, candidate := range events {
		if candidate != event {
			continue
		}
		seen++
		if seen == occurrence {
			return index
		}
	}
	return -1
}

func d13hEventIndexAfter(events []string, event string, after int) int {
	for index := after + 1; index < len(events); index++ {
		if events[index] == event {
			return index
		}
	}
	return -1
}

type d13hCrashControlPlane struct {
	*fakeK8sControlPlane
	events                       *d13hCrashEventLog
	absentAfterExpiryOperationID string
	loseCompleteOnce             bool
	abortBeforeComplete          bool
	heartbeatMutation            func(*lifecycleInstallOperationStatus)
	completeMutation             func(*lifecycleInstallOperationStatus)
}

func (c *d13hCrashControlPlane) BeginLifecycleInstall(ctx context.Context, orgID string, request lifecycleInstallBeginRequest) (lifecycleInstallOperationStatus, error) {
	if c.events != nil {
		c.events.add("begin:" + request.operationID)
	}
	if request.operationID == c.absentAfterExpiryOperationID {
		c.installMu.Lock()
		_, exists := c.installOperations[request.operationID]
		c.installBeginCount++
		c.installMu.Unlock()
		if !exists {
			if c.events != nil {
				c.events.add("absent-after-expiry:" + request.operationID)
			}
			return lifecycleInstallOperationStatus{}, errLifecycleInstallOperationAbsentAfterExpiry
		}
	}
	return c.fakeK8sControlPlane.BeginLifecycleInstall(ctx, orgID, request)
}

func (c *d13hCrashControlPlane) RemintLifecycleClaim(ctx context.Context, orgID, claim, nodeName string, expectedGeneration int, requestID string) (k8sLifecycleRemintResult, error) {
	if c.events != nil {
		c.events.add("remint:" + requestID)
	}
	return c.fakeK8sControlPlane.RemintLifecycleClaim(ctx, orgID, claim, nodeName, expectedGeneration, requestID)
}

func (c *d13hCrashControlPlane) HeartbeatLifecycleInstall(ctx context.Context, orgID string, request lifecycleInstallCASRequest) (lifecycleInstallOperationStatus, error) {
	status, err := c.fakeK8sControlPlane.HeartbeatLifecycleInstall(ctx, orgID, request)
	if err == nil && c.heartbeatMutation != nil {
		c.heartbeatMutation(&status)
	}
	return status, err
}

func (c *d13hCrashControlPlane) ReleaseLifecycleInstall(ctx context.Context, orgID string, request lifecycleInstallCASRequest) (lifecycleInstallOperationStatus, error) {
	if c.events != nil {
		c.events.add("release:" + request.operationID)
	}
	return c.fakeK8sControlPlane.ReleaseLifecycleInstall(ctx, orgID, request)
}

func (c *d13hCrashControlPlane) CompleteLifecycleInstall(ctx context.Context, orgID string, request lifecycleInstallCASRequest) (lifecycleInstallOperationStatus, error) {
	if c.abortBeforeComplete {
		c.installMu.Lock()
		status := c.installOperations[request.operationID]
		now := time.Now().UTC()
		status.state = lifecycleInstallAbortRequested
		status.abortRequestedAt = &now
		status.serverTime = now
		c.installOperations[request.operationID] = status
		c.installCompleteCount++
		c.installMu.Unlock()
		if c.events != nil {
			c.events.add("complete-refused-abort-requested")
		}
		return lifecycleInstallOperationStatus{}, errors.New("lifecycle_install_completion_refused: abort requested")
	}
	status, err := c.fakeK8sControlPlane.CompleteLifecycleInstall(ctx, orgID, request)
	if err != nil {
		return status, err
	}
	if c.completeMutation != nil {
		c.completeMutation(&status)
	}
	if c.loseCompleteOnce {
		c.loseCompleteOnce = false
		if c.events != nil {
			c.events.add("complete-committed-response-lost")
		}
		return lifecycleInstallOperationStatus{}, errors.New("synthetic lost Complete response")
	}
	return status, nil
}

type d13hCrashTicker struct {
	ch chan time.Time
}

func newD13hCrashTicker() *d13hCrashTicker {
	return &d13hCrashTicker{ch: make(chan time.Time, 1)}
}

func (t *d13hCrashTicker) C() <-chan time.Time { return t.ch }
func (t *d13hCrashTicker) Stop()               {}
func (t *d13hCrashTicker) tick(now time.Time)  { t.ch <- now }

type d13hConcurrentAnchorRunner struct {
	mu           sync.Mutex
	anchor       lifecycleAnchorMetadata
	replaceCalls int
	helmInstalls int
	bothArrived  chan struct{}
	winnerDone   chan struct{}
}

func (r *d13hConcurrentAnchorRunner) LookPath(name string) (string, error) {
	if name != "kubectl" && name != "helm" {
		return "", errors.New("not found")
	}
	return "/fake/" + name, nil
}

func (r *d13hConcurrentAnchorRunner) Run(_ context.Context, command k8sCommand) (k8sCommandResult, error) {
	joined := strings.Join(command.args, " ")
	if command.name == "helm" && strings.HasPrefix(joined, "install ") {
		r.mu.Lock()
		r.helmInstalls++
		r.mu.Unlock()
		return stdout("installed\n"), nil
	}
	if command.name == "kubectl" && strings.Contains(joined, "get configmap ") {
		r.mu.Lock()
		anchor := r.anchor
		r.mu.Unlock()
		return stdout(lifecycleAnchorMetadataLine(anchor)), nil
	}
	if command.name == "kubectl" && strings.Contains(joined, "replace --raw=") && strings.Contains(joined, "/configmaps/") {
		desired, err := lifecycleAnchorFromTestManifest(command.stdin)
		if err != nil {
			return k8sCommandResult{}, err
		}
		r.mu.Lock()
		r.replaceCalls++
		index := r.replaceCalls
		if index == 2 {
			close(r.bothArrived)
		}
		r.mu.Unlock()
		<-r.bothArrived
		if index == 2 {
			<-r.winnerDone
			r.mu.Lock()
			current := r.anchor
			r.mu.Unlock()
			if current.resourceVersion != desired.resourceVersion {
				return k8sCommandResult{stderr: []byte("Conflict")}, errors.New("synthetic concurrent lifecycle anchor CAS conflict")
			}
			return k8sCommandResult{}, errors.New("second lifecycle anchor CAS unexpectedly remained current")
		}
		r.mu.Lock()
		if r.anchor.uid != desired.uid || r.anchor.resourceVersion != desired.resourceVersion {
			r.mu.Unlock()
			close(r.winnerDone)
			return k8sCommandResult{stderr: []byte("Conflict")}, errors.New("synthetic winner lifecycle anchor CAS conflict")
		}
		desired.resourceVersion = "10"
		r.anchor = desired
		r.mu.Unlock()
		close(r.winnerDone)
		return stdout(`{"kind":"ConfigMap"}`), nil
	}
	return baseRunnerHandler(command)
}

func d13hCrashPrepared(t *testing.T, runner *fakeK8sRunner, cp k8sControlPlane) preparedInstall {
	t.Helper()
	prepared := d13hIntentPrepared()
	prepared.cp = cp
	prepared.options.timeout = "10m"
	prepared.plan.Storage.Claim = gatewayFullname(prepared.options.release) + "-state"
	anchor := testLifecycleAnchor(prepared.options.release, prepared.options.nodeName, "acknowledged")
	prepared.anchor = anchor
	_, digest, err := computeLifecycleInstallIntent(prepared)
	if err != nil {
		t.Fatalf("compute crash-regression intent: %v", err)
	}
	prepared.installIntentDigest = digest
	prepared.plan.InstallIntentDigest = digest
	anchor.installOperationID = d13hCrashOperationID
	anchor.installOperationDurationSeconds = 660
	anchor.installIntentDigest = digest
	anchor.releaseNamespace = prepared.options.namespace
	anchor.releaseName = prepared.options.release
	prepared.anchor = anchor
	if runner.anchors == nil {
		runner.anchors = map[string]lifecycleAnchorMetadata{}
	}
	runner.anchors[anchor.name] = anchor
	return prepared
}

func d13hCrashActiveStatus(now time.Time) (lifecycleInstallBeginRequest, lifecycleInstallOperationStatus) {
	begin := lifecycleInstallBeginRequest{
		claim: testLifecycleClaim, expectedGeneration: 1, requestID: testLifecycleRequest,
		operationID: d13hCrashOperationID, releaseNamespace: "tunnex", releaseName: "gateway-a",
		installIntentDigest: "sha256:" + strings.Repeat("c", 64), requestedDurationSeconds: 660,
	}
	status := lifecycleInstallOperationStatus{
		claim: begin.claim, generation: begin.expectedGeneration, requestID: begin.requestID,
		operationID: begin.operationID, epoch: 3, state: lifecycleInstallActive,
		releaseNamespace: begin.releaseNamespace, releaseName: begin.releaseName,
		installIntentDigest: begin.installIntentDigest, requestedDurationSeconds: begin.requestedDurationSeconds,
		notAfter: now.Add(11 * time.Minute), serverTime: now, heartbeatAt: now,
	}
	return begin, status
}

func TestD13hPreMirrorExpiredCredentialReconcilesBeforeRemintAndNewInstall(t *testing.T) {
	expiredAt := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	events := &d13hCrashEventLog{}
	cp := &d13hCrashControlPlane{fakeK8sControlPlane: baseK8sControlPlane(), events: events}
	cp.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{
		claim: testLifecycleClaim, state: "expired", nodeName: "aks-gateway-a", generation: 1,
		requestID: testLifecycleRequest, expiresAt: expiredAt,
	}
	anchor := testLifecycleAnchor("tunnex-gateway", "aks-gateway-a", "acknowledged")
	anchor.expiresAt = expiredAt
	anchor.installOperationID = d13hCrashOperationID
	anchor.installOperationDurationSeconds = 660
	anchor.installIntentDigest = "sha256:" + strings.Repeat("d", 64)
	anchor.releaseNamespace = "tunnex"
	anchor.releaseName = "tunnex-gateway"
	cp.installOperations[d13hCrashOperationID] = lifecycleInstallOperationStatus{
		claim: testLifecycleClaim, generation: 1, requestID: testLifecycleRequest,
		operationID: d13hCrashOperationID, epoch: 1, state: lifecycleInstallExpired,
		releaseNamespace: "tunnex", releaseName: "tunnex-gateway", installIntentDigest: anchor.installIntentDigest,
		requestedDurationSeconds: 660, notAfter: expiredAt, serverTime: expiredAt.Add(time.Second), heartbeatAt: expiredAt.Add(-time.Minute),
	}
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		switch {
		case command.name == "kubectl" && strings.Contains(joined, "get secret tunnex-gateway-bootstrap"):
			return stdout(bootstrapSecretMetadataLineWith("tunnex-gateway", testLifecycleClaim, testLifecycleRequest, 1, expiredAt)), nil
		case command.name == "helm" && strings.HasPrefix(joined, "list --all "):
			events.add("release-absence")
		case command.name == "kubectl" && strings.Contains(joined, "get deployments,statefulsets,daemonsets,jobs,pods,services"):
			events.add("workload-absence")
		case command.name == "kubectl" && strings.Contains(joined, "get pods"):
			events.add("mount-absence")
		case command.name == "kubectl" && strings.Contains(joined, "replace --raw=") && strings.Contains(joined, "/configmaps/"):
			desired, err := lifecycleAnchorFromTestManifest(command.stdin)
			if err != nil {
				return k8sCommandResult{}, err
			}
			if desired.state == "pending" && desired.requestID == d13hNextRequestID && desired.installOperationID == "" {
				events.add("retire-operation-anchor")
			}
		}
		return baseRunnerHandler(command)
	}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	deps.newRequestID = func() string { return d13hNextRequestID }
	deps.newOperationID = func() string { return d13hNextOperationID }
	if err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps); err != nil {
		t.Fatalf("pre-mirror expiry recovery: %v", err)
	}
	got := events.snapshot()
	oldBegin := d13hEventIndex(got, "begin:"+d13hCrashOperationID, 1)
	release := d13hEventIndexAfter(got, "release:"+d13hCrashOperationID, oldBegin)
	releaseProof := d13hEventIndexAfter(got, "release-absence", release)
	workloadProof := d13hEventIndexAfter(got, "workload-absence", releaseProof)
	mountProof := d13hEventIndexAfter(got, "mount-absence", workloadProof)
	retire := d13hEventIndexAfter(got, "retire-operation-anchor", mountProof)
	remint := d13hEventIndexAfter(got, "remint:"+d13hNextRequestID, retire)
	newBegin := d13hEventIndexAfter(got, "begin:"+d13hNextOperationID, remint)
	if oldBegin < 0 || release <= oldBegin || releaseProof <= release || workloadProof <= releaseProof || mountProof <= workloadProof || retire <= mountProof || remint <= retire || newBegin <= remint {
		t.Fatalf("pre-mirror Release/absence/CAS-retire/remint/new-Begin order = %v", got)
	}
	if cp.installReleaseCount != 1 || cp.issueCount != 1 || cp.installCompleteCount != 1 {
		t.Fatalf("pre-mirror recovery releases=%d remints=%d completes=%d", cp.installReleaseCount, cp.issueCount, cp.installCompleteCount)
	}
	if status := cp.installOperations[d13hCrashOperationID]; status.state != lifecycleInstallReleased {
		t.Fatalf("old install operation state=%q, want released", status.state)
	}
	if status := cp.installOperations[d13hNextOperationID]; status.state != lifecycleInstallCompleted {
		t.Fatalf("new install operation state=%q, want completed", status.state)
	}
}

func TestD13hTypedAbsentAfterExpiryProvesKubernetesAbsenceBeforeRemint(t *testing.T) {
	expiredAt := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	events := &d13hCrashEventLog{}
	cp := &d13hCrashControlPlane{
		fakeK8sControlPlane:          baseK8sControlPlane(),
		events:                       events,
		absentAfterExpiryOperationID: d13hCrashOperationID,
	}
	cp.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{
		claim: testLifecycleClaim, state: "expired", nodeName: "aks-gateway-a", generation: 1,
		requestID: testLifecycleRequest, expiresAt: expiredAt,
	}
	anchor := testLifecycleAnchor("tunnex-gateway", "aks-gateway-a", "acknowledged")
	anchor.expiresAt = expiredAt
	anchor.installOperationID = d13hCrashOperationID
	anchor.installOperationDurationSeconds = 660
	anchor.installIntentDigest = "sha256:" + strings.Repeat("d", 64)
	anchor.releaseNamespace = defaultK8sNamespace
	anchor.releaseName = defaultK8sRelease
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		switch {
		case command.name == "kubectl" && strings.Contains(joined, "get secret tunnex-gateway-bootstrap"):
			return stdout(bootstrapSecretMetadataLineWith("tunnex-gateway", testLifecycleClaim, testLifecycleRequest, 1, expiredAt)), nil
		case command.name == "helm" && strings.HasPrefix(joined, "list --all "):
			events.add("release-absence")
		case command.name == "kubectl" && strings.Contains(joined, "get deployments,statefulsets,daemonsets,jobs,pods,services"):
			events.add("workload-absence")
		case command.name == "kubectl" && strings.Contains(joined, "get pods"):
			events.add("mount-absence")
		case command.name == "kubectl" && strings.Contains(joined, "replace --raw=") && strings.Contains(joined, "/configmaps/"):
			desired, err := lifecycleAnchorFromTestManifest(command.stdin)
			if err != nil {
				return k8sCommandResult{}, err
			}
			if desired.state == "pending" && desired.requestID == d13hNextRequestID && desired.installOperationID == "" {
				events.add("retire-operation-anchor")
			}
		}
		return baseRunnerHandler(command)
	}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	deps.newRequestID = func() string { return d13hNextRequestID }
	deps.newOperationID = func() string { return d13hNextOperationID }
	if err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps); err != nil {
		t.Fatalf("typed absent-after-expiry recovery: %v", err)
	}
	got := events.snapshot()
	oldBegin := d13hEventIndex(got, "begin:"+d13hCrashOperationID, 1)
	typedAbsent := d13hEventIndexAfter(got, "absent-after-expiry:"+d13hCrashOperationID, oldBegin)
	releaseProof := d13hEventIndexAfter(got, "release-absence", typedAbsent)
	workloadProof := d13hEventIndexAfter(got, "workload-absence", releaseProof)
	mountProof := d13hEventIndexAfter(got, "mount-absence", workloadProof)
	retire := d13hEventIndexAfter(got, "retire-operation-anchor", mountProof)
	remint := d13hEventIndexAfter(got, "remint:"+d13hNextRequestID, retire)
	newBegin := d13hEventIndexAfter(got, "begin:"+d13hNextOperationID, remint)
	if oldBegin < 0 || typedAbsent <= oldBegin || releaseProof <= typedAbsent || workloadProof <= releaseProof || mountProof <= workloadProof || retire <= mountProof || remint <= retire || newBegin <= remint {
		t.Fatalf("typed absence/proof/CAS-retire/remint/new-Begin order = %v", got)
	}
	if cp.installReleaseCount != 0 || cp.issueCount != 1 || cp.installCompleteCount != 1 {
		t.Fatalf("typed absence recovery releases=%d remints=%d completes=%d", cp.installReleaseCount, cp.issueCount, cp.installCompleteCount)
	}
	if status := cp.installOperations[d13hNextOperationID]; status.state != lifecycleInstallCompleted {
		t.Fatalf("new install operation state=%q, want completed", status.state)
	}
}

func TestD13hReleasedOperationRotatesOnlyAfterExactAbsenceProof(t *testing.T) {
	events := &d13hCrashEventLog{}
	baseCP := baseK8sControlPlane()
	cp := &d13hCrashControlPlane{fakeK8sControlPlane: baseCP, events: events}
	runner := &fakeK8sRunner{}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		switch {
		case command.name == "helm" && strings.HasPrefix(joined, "list --all "):
			events.add("release-absence")
		case command.name == "kubectl" && strings.Contains(joined, "get deployments,statefulsets,daemonsets,jobs,pods,services"):
			events.add("workload-absence")
		case command.name == "kubectl" && strings.Contains(joined, "get pods"):
			events.add("mount-absence")
		}
		return baseRunnerHandler(command)
	}
	prepared := d13hCrashPrepared(t, runner, cp)
	now := time.Now().UTC()
	releasedAt := now
	baseCP.installOperations[d13hCrashOperationID] = lifecycleInstallOperationStatus{
		claim: prepared.anchor.lifecycleClaim, generation: prepared.anchor.generation, requestID: prepared.anchor.requestID,
		operationID: d13hCrashOperationID, epoch: 1, state: lifecycleInstallReleased,
		releaseNamespace: prepared.options.namespace, releaseName: prepared.options.release,
		installIntentDigest: prepared.installIntentDigest, requestedDurationSeconds: prepared.anchor.installOperationDurationSeconds,
		notAfter: now.Add(11 * time.Minute), serverTime: now, heartbeatAt: now, releasedAt: &releasedAt,
	}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}).normalized()
	deps.newOperationID = func() string {
		events.add("rotate-operation-id")
		return d13hNextOperationID
	}
	authority, err := prepareLifecycleInstallAuthority(context.Background(), deps, prepared, prepared.anchor)
	if err != nil {
		t.Fatalf("rotate released lifecycle operation: %v", err)
	}
	if authority.begin.operationID != d13hNextOperationID || authority.status.epoch != 2 {
		t.Fatalf("rotated authority=(%s,%d), want (%s,2)", authority.begin.operationID, authority.status.epoch, d13hNextOperationID)
	}
	got := events.snapshot()
	releaseProof := d13hEventIndex(got, "release-absence", 1)
	workloadProof := d13hEventIndex(got, "workload-absence", 1)
	mountProof := d13hEventIndex(got, "mount-absence", 1)
	rotate := d13hEventIndex(got, "rotate-operation-id", 1)
	newBegin := d13hEventIndex(got, "begin:"+d13hNextOperationID, 1)
	if releaseProof < 0 || workloadProof <= releaseProof || mountProof <= workloadProof || rotate <= mountProof || newBegin <= rotate {
		t.Fatalf("released-operation proof/rotation order = %v", got)
	}
}

func TestD13hSharedOperationCASLoserNeverReleasesWinnerAuthority(t *testing.T) {
	baseCP := baseK8sControlPlane()
	cp := &d13hCrashControlPlane{fakeK8sControlPlane: baseCP}
	runner := &fakeK8sRunner{}
	prepared := d13hCrashPrepared(t, runner, cp)
	now := time.Now().UTC()
	baseCP.installOperations[d13hCrashOperationID] = lifecycleInstallOperationStatus{
		claim: prepared.anchor.lifecycleClaim, generation: prepared.anchor.generation, requestID: prepared.anchor.requestID,
		operationID: d13hCrashOperationID, epoch: 1, state: lifecycleInstallActive,
		releaseNamespace: prepared.options.namespace, releaseName: prepared.options.release,
		installIntentDigest: prepared.installIntentDigest, requestedDurationSeconds: prepared.anchor.installOperationDurationSeconds,
		notAfter: now.Add(11 * time.Minute), serverTime: now, heartbeatAt: now,
	}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "replace --raw=") && strings.Contains(joined, "/configmaps/") {
			// Another invocation shares the persisted operation UUID, wins the
			// anchor CAS, and owns the exact epoch. This invocation receives a
			// conflict and must not Release the winner's control-plane authority.
			winner, err := lifecycleAnchorFromTestManifest(command.stdin)
			if err != nil {
				return k8sCommandResult{}, err
			}
			winner.resourceVersion = "10"
			runner.anchors[winner.name] = winner
			return k8sCommandResult{stderr: []byte("Conflict")}, errors.New("synthetic anchor CAS conflict")
		}
		return baseRunnerHandler(command)
	}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}).normalized()
	_, err := prepareLifecycleInstallAuthority(context.Background(), deps, prepared, prepared.anchor)
	if err == nil || !strings.Contains(err.Error(), "another invocation won the lifecycle anchor CAS") {
		t.Fatalf("shared-operation CAS loser error = %v", err)
	}
	if baseCP.installReleaseCount != 0 {
		t.Fatalf("CAS loser released the winner's shared operation %d times", baseCP.installReleaseCount)
	}
	status := baseCP.installOperations[d13hCrashOperationID]
	if status.state != lifecycleInstallActive || status.epoch != 1 {
		t.Fatalf("CAS loser changed winner authority to state=%s epoch=%d", status.state, status.epoch)
	}
}

func TestD13hTwoInvocationsShareOperationButOnlyCASWinnerMutatesHelm(t *testing.T) {
	baseCP := baseK8sControlPlane()
	cp := &d13hCrashControlPlane{fakeK8sControlPlane: baseCP}
	seed := &fakeK8sRunner{}
	prepared := d13hCrashPrepared(t, seed, cp)
	prepared.gatewayArtifact.Path = "/private/tmp/tunnex-gateway.tgz"
	now := time.Now().UTC()
	baseCP.installOperations[d13hCrashOperationID] = lifecycleInstallOperationStatus{
		claim: prepared.anchor.lifecycleClaim, generation: prepared.anchor.generation, requestID: prepared.anchor.requestID,
		operationID: d13hCrashOperationID, epoch: 1, state: lifecycleInstallActive,
		releaseNamespace: prepared.options.namespace, releaseName: prepared.options.release,
		installIntentDigest: prepared.installIntentDigest, requestedDurationSeconds: prepared.anchor.installOperationDurationSeconds,
		notAfter: now.Add(11 * time.Minute), serverTime: now, heartbeatAt: now,
	}
	runner := &d13hConcurrentAnchorRunner{
		anchor: prepared.anchor, bothArrived: make(chan struct{}), winnerDone: make(chan struct{}),
	}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}).normalized()
	helmCommand, err := installHelmCommand(prepared)
	if err != nil {
		t.Fatalf("build deterministic Helm mutation: %v", err)
	}
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			authority, authorityErr := prepareLifecycleInstallAuthority(context.Background(), deps, prepared, prepared.anchor)
			if authorityErr != nil {
				results <- authorityErr
				return
			}
			if err := authority.proveAnchor(context.Background(), deps, prepared); err != nil {
				results <- err
				return
			}
			_, runErr := runCheckedSecrets(context.Background(), runner, "deterministic winner Helm install", helmCommand, "")
			results <- runErr
		}()
	}
	var successes, losers int
	for i := 0; i < 2; i++ {
		resultErr := <-results
		switch {
		case resultErr == nil:
			successes++
		case strings.Contains(resultErr.Error(), "another invocation won"):
			losers++
		default:
			runner.mu.Lock()
			liveAnchor := runner.anchor
			runner.mu.Unlock()
			t.Fatalf("unexpected concurrent invocation result: %v; live anchor=%+v", resultErr, liveAnchor)
		}
	}
	runner.mu.Lock()
	helmInstalls := runner.helmInstalls
	replaceCalls := runner.replaceCalls
	runner.mu.Unlock()
	if successes != 1 || losers != 1 || replaceCalls != 2 || helmInstalls != 1 {
		t.Fatalf("concurrent lifecycle results successes=%d losers=%d CAS=%d Helm=%d", successes, losers, replaceCalls, helmInstalls)
	}
	if baseCP.installReleaseCount != 0 {
		t.Fatalf("CAS loser released shared winner authority %d times", baseCP.installReleaseCount)
	}
}

func TestD13hLostCompleteResponseProvesCompletedBeforeMetadataCleanup(t *testing.T) {
	events := &d13hCrashEventLog{}
	cp := &d13hCrashControlPlane{fakeK8sControlPlane: baseK8sControlPlane(), events: events, loseCompleteOnce: true}
	runner := &fakeK8sRunner{}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "delete --raw=/api/v1/namespaces/tunnex/secrets/tunnex-gateway-bootstrap") {
			events.add("delete-secret")
		}
		if command.name == "kubectl" && strings.Contains(joined, "delete --raw=/api/v1/namespaces/tunnex/configmaps/tunnex-gateway-lifecycle") {
			events.add("delete-anchor")
		}
		return baseRunnerHandler(command)
	}
	var out bytes.Buffer
	err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, baseK8sDeps(runner, cp, &out, &bytes.Buffer{}))
	if err != nil {
		t.Fatalf("lost Complete response recovery: %v", err)
	}
	got := events.snapshot()
	lost := d13hEventIndex(got, "complete-committed-response-lost", 1)
	recoveryBegin := d13hEventIndex(got, "begin:"+testStateFenceOpID, 2)
	secretDelete := d13hEventIndex(got, "delete-secret", 1)
	anchorDelete := d13hEventIndex(got, "delete-anchor", 1)
	if lost < 0 || recoveryBegin <= lost || secretDelete <= recoveryBegin || anchorDelete <= secretDelete {
		t.Fatalf("lost Complete recovery/cleanup order = %v", got)
	}
	if cp.installCompleteCount != 1 || len(runner.anchors) != 0 {
		t.Fatalf("lost Complete recovery completeCalls=%d anchors=%d", cp.installCompleteCount, len(runner.anchors))
	}
}

func TestD13hCompleteAbortRaceReleasesForImmediateTakeover(t *testing.T) {
	now := time.Now().UTC()
	begin, status := d13hCrashActiveStatus(now)
	baseCP := baseK8sControlPlane()
	baseCP.installOperations[status.operationID] = status
	events := &d13hCrashEventLog{}
	cp := &d13hCrashControlPlane{
		fakeK8sControlPlane: baseCP,
		events:              events,
		abortBeforeComplete: true,
	}
	authority := lifecycleInstallAuthority{
		cp: cp, orgID: "11111111-1111-1111-1111-111111111111", begin: begin,
		cas: lifecycleInstallCASFromStatus(status), status: status,
	}
	completeErr := authority.complete(context.Background())
	if completeErr == nil || !strings.Contains(completeErr.Error(), "lifecycle_install_completion_refused") {
		t.Fatalf("Complete/abort race error = %v", completeErr)
	}
	completed, reconcileErr := reconcileLifecycleInstallCompleteError(context.Background(), authority)
	if completed || reconcileErr != nil {
		t.Fatalf("Complete/abort reconciliation = completed:%v err:%v", completed, reconcileErr)
	}
	if baseCP.installReleaseCount != 1 {
		t.Fatalf("abort-requested authority release calls=%d, want 1", baseCP.installReleaseCount)
	}
	released := baseCP.installOperations[status.operationID]
	if released.state != lifecycleInstallReleased || released.abortRequestedAt == nil {
		t.Fatalf("reconciled operation = state:%s abort:%v, want released with durable request", released.state, released.abortRequestedAt)
	}
	result, err := cp.CoordinateLifecycleInstallAbort(context.Background(), authority.orgID, lifecycleInstallCASFromStatus(status))
	if err != nil {
		t.Fatalf("coordinate immediate abort takeover: %v", err)
	}
	if !result.pending || result.operationStatus == nil || result.operationStatus.state != lifecycleInstallAborting || result.operationStatus.epoch != status.epoch+1 {
		t.Fatalf("immediate abort takeover = %+v", result)
	}
	if d13hEventIndex(events.snapshot(), "complete-refused-abort-requested", 1) < 0 {
		t.Fatalf("Complete refusal event missing: %v", events.snapshot())
	}
	// completed=false is the call-site gate: metadata cleanup and install
	// success remain forbidden while abort owns the incremented epoch.
}

func TestD13hContinuationDriftRefusesCompleteAndCancelsHeartbeat(t *testing.T) {
	mutations := map[string]func(*lifecycleInstallOperationStatus){
		"epoch":    func(status *lifecycleInstallOperationStatus) { status.epoch++ },
		"deadline": func(status *lifecycleInstallOperationStatus) { status.notAfter = status.notAfter.Add(time.Second) },
	}
	for name, mutate := range mutations {
		t.Run("Complete "+name, func(t *testing.T) {
			now := time.Now().UTC()
			begin, status := d13hCrashActiveStatus(now)
			baseCP := baseK8sControlPlane()
			baseCP.installOperations[status.operationID] = status
			cp := &d13hCrashControlPlane{fakeK8sControlPlane: baseCP, completeMutation: mutate}
			authority := lifecycleInstallAuthority{
				cp: cp, orgID: "11111111-1111-1111-1111-111111111111", begin: begin,
				cas: lifecycleInstallCASFromStatus(status), status: status,
			}
			if err := authority.complete(context.Background()); err == nil || !strings.Contains(err.Error(), "epoch or immutable deadline") {
				t.Fatalf("Complete %s drift error = %v", name, err)
			}
		})

		t.Run("Heartbeat "+name, func(t *testing.T) {
			now := time.Now().UTC()
			begin, status := d13hCrashActiveStatus(now)
			baseCP := baseK8sControlPlane()
			baseCP.installOperations[status.operationID] = status
			cp := &d13hCrashControlPlane{fakeK8sControlPlane: baseCP, heartbeatMutation: mutate}
			ticker := newD13hCrashTicker()
			deps := k8sDeps{newTicker: func(time.Duration) k8sTicker { return ticker }}.normalized()
			authority := lifecycleInstallAuthority{
				cp: cp, orgID: "11111111-1111-1111-1111-111111111111", begin: begin,
				cas: lifecycleInstallCASFromStatus(status), status: status,
				deadlines: lifecycleInstallDeadlines{hard: status.notAfter, helm: now.Add(10 * time.Minute)},
			}
			monitor, cancel := startLifecycleInstallMonitor(context.Background(), deps, authority)
			ticker.tick(now.Add(lifecycleInstallHeartbeatInterval))
			select {
			case <-monitor.mutationCtx.Done():
			case <-time.After(time.Second):
				cancel()
				t.Fatal("heartbeat continuation drift did not cancel mutation context")
			}
			if cause := context.Cause(monitor.mutationCtx); cause == nil || !strings.Contains(cause.Error(), "epoch or immutable deadline") {
				cancel()
				t.Fatalf("Heartbeat %s drift cause = %v", name, cause)
			}
			if err := monitor.stop(); err == nil || !strings.Contains(err.Error(), "epoch or immutable deadline") {
				cancel()
				t.Fatalf("Heartbeat %s monitor error = %v", name, err)
			}
			cancel()
		})
	}
}
