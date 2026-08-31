package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testJoinToken        = "one-time-TOP-SECRET-token"
	testLifecycleClaim   = "33333333-3333-3333-3333-333333333333"
	testLifecycleRequest = "44444444-4444-4444-4444-444444444444"
	testLifecycleNodeID  = "55555555-5555-5555-5555-555555555555"
	testLifecycleOldReq  = "66666666-6666-6666-6666-666666666666"
	testStateFenceOpID   = "77777777-7777-7777-7777-777777777777"
)

var testLifecycleExpiry = time.Date(2099, 1, 2, 3, 4, 5, 0, time.UTC)

type fakeK8sRunner struct {
	commands []k8sCommand
	handler  func(k8sCommand) (k8sCommandResult, error)
	anchors  map[string]lifecycleAnchorMetadata
	leases   map[string]stateFenceLease
}

func (r *fakeK8sRunner) LookPath(name string) (string, error) {
	if name != "kubectl" && name != "helm" {
		return "", errors.New("not found")
	}
	return "/fake/" + name, nil
}

func (r *fakeK8sRunner) Run(_ context.Context, command k8sCommand) (k8sCommandResult, error) {
	copyCommand := k8sCommand{name: command.name, args: append([]string(nil), command.args...), stdin: append([]byte(nil), command.stdin...)}
	r.commands = append(r.commands, copyCommand)
	if r.handler == nil {
		if emulated, ok, err := tryEmulateChartMaterialization(copyCommand); ok {
			return emulated, err
		}
		if emulated, ok, err := r.tryEmulateStateFence(copyCommand); ok {
			return emulated, err
		}
		return r.emulateLifecycleAnchor(copyCommand)
	}
	result, err := r.handler(copyCommand)
	if err != nil || len(result.stdout) != 0 || len(result.stderr) != 0 {
		return result, err
	}
	if emulated, ok, emulateErr := tryEmulateChartMaterialization(copyCommand); ok {
		return emulated, emulateErr
	}
	if emulated, ok, emulateErr := r.tryEmulateStateFence(copyCommand); ok {
		return emulated, emulateErr
	}
	emulated, ok, emulateErr := r.tryEmulateLifecycleAnchor(copyCommand)
	if ok {
		return emulated, emulateErr
	}
	return result, nil
}

func (r *fakeK8sRunner) tryEmulateStateFence(command k8sCommand) (k8sCommandResult, bool, error) {
	joined := strings.Join(command.args, " ")
	if command.name != "kubectl" || (!strings.Contains(joined, " lease ") &&
		!strings.Contains(joined, "/leases/") && !bytes.Contains(command.stdin, []byte(`"kind":"Lease"`))) {
		return k8sCommandResult{}, false, nil
	}
	if r.leases == nil {
		r.leases = map[string]stateFenceLease{}
	}
	switch {
	case strings.Contains(joined, "create -f -"):
		var lease stateFenceLease
		if err := json.Unmarshal(command.stdin, &lease); err != nil {
			return k8sCommandResult{}, true, err
		}
		if _, exists := r.leases[lease.Metadata.Name]; exists {
			return k8sCommandResult{stderr: []byte("AlreadyExists")}, true, errors.New("test retained-state Lease already exists")
		}
		lease.Metadata.UID = "uid-" + lease.Metadata.Name
		lease.Metadata.ResourceVersion = "1"
		r.leases[lease.Metadata.Name] = lease
		raw, _ := json.Marshal(lease)
		return stdout(string(raw)), true, nil
	case strings.Contains(joined, "replace --raw=") && strings.Contains(joined, "/leases/"):
		var lease stateFenceLease
		if err := json.Unmarshal(command.stdin, &lease); err != nil {
			return k8sCommandResult{}, true, err
		}
		current, exists := r.leases[lease.Metadata.Name]
		if !exists || current.Metadata.UID != lease.Metadata.UID || current.Metadata.ResourceVersion != lease.Metadata.ResourceVersion {
			return k8sCommandResult{stderr: []byte("Conflict")}, true, errors.New("test retained-state Lease CAS conflict")
		}
		rv, _ := strconv.Atoi(current.Metadata.ResourceVersion)
		lease.Metadata.ResourceVersion = strconv.Itoa(rv + 1)
		r.leases[lease.Metadata.Name] = lease
		raw, _ := json.Marshal(lease)
		return stdout(string(raw)), true, nil
	case strings.Contains(joined, "get lease "):
		for name, lease := range r.leases {
			if strings.Contains(joined, "get lease "+name+" ") {
				raw, _ := json.Marshal(lease)
				return stdout(string(raw)), true, nil
			}
		}
		return stdout(""), true, nil
	case strings.Contains(joined, "delete --raw=") && strings.Contains(joined, "/leases/"):
		var options struct {
			Preconditions struct {
				UID             string `json:"uid"`
				ResourceVersion string `json:"resourceVersion"`
			} `json:"preconditions"`
		}
		if err := json.Unmarshal(command.stdin, &options); err != nil {
			return k8sCommandResult{}, true, err
		}
		for name, lease := range r.leases {
			if !strings.Contains(joined, "/leases/"+name) {
				continue
			}
			if lease.Metadata.UID != options.Preconditions.UID || lease.Metadata.ResourceVersion != options.Preconditions.ResourceVersion {
				return k8sCommandResult{stderr: []byte("Conflict")}, true, errors.New("test retained-state Lease delete conflict")
			}
			delete(r.leases, name)
			return stdout(`{"kind":"Status","status":"Success"}`), true, nil
		}
		return k8sCommandResult{stderr: []byte("NotFound")}, true, errors.New("test retained-state Lease absent")
	default:
		return k8sCommandResult{}, false, nil
	}
}

type fakeChartArtifact struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	AppVersion string `json:"app_version"`
	Source     string `json:"source"`
}

func tryEmulateChartMaterialization(command k8sCommand) (k8sCommandResult, bool, error) {
	if command.name != "helm" || len(command.args) < 2 || (command.args[0] != "pull" && command.args[0] != "package") {
		return k8sCommandResult{}, false, nil
	}
	reference := command.args[1]
	destination := commandArgValue(command.args, "--destination")
	if destination == "" {
		return k8sCommandResult{}, true, errors.New("fake Helm materialization lacks --destination")
	}
	name := filepath.Base(filepath.Clean(strings.TrimPrefix(reference, "oci://")))
	version := commandArgValue(command.args, "--version")
	appVersion := version
	if command.args[0] == "package" {
		version = "0.2.0"
		appVersion = version
		if raw, err := os.ReadFile(filepath.Join(reference, "Chart.yaml")); err == nil {
			if metadata, parseErr := parseChartMetadata(raw); parseErr == nil {
				name, version, appVersion = metadata.Name, metadata.Version, metadata.AppVersion
			}
		}
	} else {
		appVersion = "v" + strings.TrimPrefix(version, "v")
	}
	payload, err := json.Marshal(fakeChartArtifact{Name: name, Version: version, AppVersion: appVersion, Source: reference})
	if err != nil {
		return k8sCommandResult{}, true, err
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return k8sCommandResult{}, true, err
	}
	path := filepath.Join(destination, name+"-"+version+".tgz")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return k8sCommandResult{}, true, err
	}
	return stdout("saved\n"), true, nil
}

func (r *fakeK8sRunner) emulateLifecycleAnchor(command k8sCommand) (k8sCommandResult, error) {
	result, _, err := r.tryEmulateLifecycleAnchor(command)
	return result, err
}

func (r *fakeK8sRunner) tryEmulateLifecycleAnchor(command k8sCommand) (k8sCommandResult, bool, error) {
	joined := strings.Join(command.args, " ")
	if command.name != "kubectl" || (!strings.Contains(joined, "configmap") && !bytes.Contains(command.stdin, []byte(`"kind":"ConfigMap"`))) {
		return k8sCommandResult{}, false, nil
	}
	if r.anchors == nil {
		r.anchors = map[string]lifecycleAnchorMetadata{}
	}
	switch {
	case strings.Contains(joined, "create -f -"):
		anchor, err := lifecycleAnchorFromTestManifest(command.stdin)
		if err != nil {
			return k8sCommandResult{}, true, err
		}
		anchor.uid = "uid-" + anchor.name
		anchor.resourceVersion = "1"
		r.anchors[anchor.name] = anchor
		return stdout(lifecycleAnchorMetadataLine(anchor)), true, nil
	case strings.Contains(joined, "replace --raw="):
		anchor, err := lifecycleAnchorFromTestManifest(command.stdin)
		if err != nil {
			return k8sCommandResult{}, true, err
		}
		current, ok := r.anchors[anchor.name]
		if !ok || current.uid != anchor.uid || current.resourceVersion != anchor.resourceVersion {
			return k8sCommandResult{}, true, errors.New("test lifecycle anchor CAS conflict")
		}
		rv, _ := strconv.Atoi(current.resourceVersion)
		anchor.resourceVersion = strconv.Itoa(rv + 1)
		r.anchors[anchor.name] = anchor
		return stdout(`{"kind":"ConfigMap"}`), true, nil
	case strings.Contains(joined, "get configmap"):
		for name, anchor := range r.anchors {
			if strings.Contains(joined, "get configmap "+name+" ") {
				return stdout(lifecycleAnchorMetadataLine(anchor)), true, nil
			}
		}
		return stdout(""), true, nil
	case strings.Contains(joined, "delete --raw=") && strings.Contains(joined, "/configmaps/"):
		for name := range r.anchors {
			if strings.Contains(joined, "/configmaps/"+name) {
				delete(r.anchors, name)
				break
			}
		}
		return stdout(`{"kind":"Status","status":"Success"}`), true, nil
	case strings.Contains(joined, "wait --for=delete configmap/"):
		return stdout("deleted\n"), true, nil
	default:
		return k8sCommandResult{}, false, nil
	}
}

func lifecycleAnchorFromTestManifest(raw []byte) (lifecycleAnchorMetadata, error) {
	var object struct {
		Immutable bool `json:"immutable"`
		Metadata  struct {
			Name            string            `json:"name"`
			UID             string            `json:"uid"`
			ResourceVersion string            `json:"resourceVersion"`
			Labels          map[string]string `json:"labels"`
			Annotations     map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &object); err != nil {
		return lifecycleAnchorMetadata{}, err
	}
	expectedGeneration, err := strconv.Atoi(object.Metadata.Annotations["tunnex.io/lifecycle-expected-generation"])
	if err != nil {
		return lifecycleAnchorMetadata{}, err
	}
	generation, err := strconv.Atoi(object.Metadata.Annotations["tunnex.io/lifecycle-generation"])
	if err != nil {
		return lifecycleAnchorMetadata{}, err
	}
	operationEpoch, err := strconv.ParseInt(object.Metadata.Annotations["tunnex.io/install-operation-epoch"], 10, 64)
	if err != nil {
		return lifecycleAnchorMetadata{}, err
	}
	operationDuration, err := strconv.Atoi(object.Metadata.Annotations["tunnex.io/install-operation-duration-seconds"])
	if err != nil {
		return lifecycleAnchorMetadata{}, err
	}
	expiresAt := time.Time{}
	if value := object.Metadata.Annotations["tunnex.io/lifecycle-expires-at"]; value != "" {
		expiresAt, err = time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return lifecycleAnchorMetadata{}, err
		}
	}
	operationNotAfter := time.Time{}
	if value := object.Metadata.Annotations["tunnex.io/install-operation-not-after"]; value != "" {
		operationNotAfter, err = time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return lifecycleAnchorMetadata{}, err
		}
	}
	return lifecycleAnchorMetadata{
		name: object.Metadata.Name, uid: object.Metadata.UID, resourceVersion: object.Metadata.ResourceVersion,
		appName: object.Metadata.Labels["app.kubernetes.io/name"], instance: object.Metadata.Labels["app.kubernetes.io/instance"],
		managedBy: object.Metadata.Labels["app.kubernetes.io/managed-by"], immutable: object.Immutable,
		orgID: object.Metadata.Annotations["tunnex.io/organization-id"], nodeName: object.Metadata.Annotations["tunnex.io/node-name"],
		lifecycleClaim: object.Metadata.Annotations["tunnex.io/lifecycle-claim"], requestID: object.Metadata.Annotations["tunnex.io/lifecycle-request-id"],
		expectedGeneration: expectedGeneration, generation: generation, state: object.Metadata.Annotations["tunnex.io/lifecycle-state"], expiresAt: expiresAt,
		installOperationID: object.Metadata.Annotations["tunnex.io/install-operation-id"], installOperationEpoch: operationEpoch, installOperationDurationSeconds: operationDuration,
		installOperationNotAfter: operationNotAfter, installIntentDigest: object.Metadata.Annotations["tunnex.io/install-intent-digest"],
		releaseNamespace: object.Metadata.Annotations["tunnex.io/release-namespace"], releaseName: object.Metadata.Annotations["tunnex.io/release-name"],
	}, nil
}

type fakeK8sControlPlane struct {
	installMu                 sync.Mutex
	meta                      k8sMeta
	orgs                      []k8sOrganization
	token                     string
	issueCount                int
	issuedOrg                 string
	issuedName                string
	metaCount                 int
	orgCount                  int
	claims                    map[string]k8sLifecycleClaimStatus
	ackCount                  map[string]int
	remintFailures            int
	remintOverride            *k8sLifecycleRemintResult
	abortOverride             *k8sLifecycleClaimStatus
	abortCount                int
	installOperations         map[string]lifecycleInstallOperationStatus
	installBeginCount         int
	installHeartbeatCount     int
	installReleaseCount       int
	installCompleteCount      int
	installAbortCount         int
	installFinalizeAbortCount int
}

func (f *fakeK8sControlPlane) GetMeta(context.Context) (k8sMeta, error) {
	f.metaCount++
	return f.meta, nil
}

func (f *fakeK8sControlPlane) ListOrganizations(context.Context) ([]k8sOrganization, error) {
	f.orgCount++
	return append([]k8sOrganization(nil), f.orgs...), nil
}

func (f *fakeK8sControlPlane) IssueGatewayJoinToken(_ context.Context, orgID, nodeName string) (string, error) {
	f.issueCount++
	f.issuedOrg = orgID
	f.issuedName = nodeName
	return f.token, nil
}

func (f *fakeK8sControlPlane) GetLifecycleClaimStatus(_ context.Context, _, claim string) (k8sLifecycleClaimStatus, error) {
	if status, ok := f.claims[claim]; ok {
		if status.state == "acknowledged" && f.ackCount[claim] > 0 {
			status.state = "consumed"
			status.nodeID = testLifecycleNodeID
			f.claims[claim] = status
		}
		return status, nil
	}
	return k8sLifecycleClaimStatus{}, errK8sLifecycleClaimNotFound
}

func (f *fakeK8sControlPlane) RemintLifecycleClaim(_ context.Context, orgID, claim, nodeName string, expectedGeneration int, requestID string) (k8sLifecycleRemintResult, error) {
	if f.remintOverride != nil {
		return *f.remintOverride, nil
	}
	if f.remintFailures > 0 {
		f.remintFailures--
		return k8sLifecycleRemintResult{}, errors.New("transient lifecycle remint failure")
	}
	f.issuedOrg = orgID
	f.issuedName = nodeName
	if f.claims == nil {
		f.claims = map[string]k8sLifecycleClaimStatus{}
	}
	if current, ok := f.claims[claim]; ok && current.requestID == requestID && current.generation == expectedGeneration+1 {
		return k8sLifecycleRemintResult{claim: claim, joinToken: f.token, generation: current.generation, requestID: current.requestID, expiresAt: current.expiresAt}, nil
	}
	f.issueCount++
	generation := expectedGeneration + 1
	expiresAt := testLifecycleExpiry
	f.claims[claim] = k8sLifecycleClaimStatus{claim: claim, state: "issued", nodeName: nodeName, generation: generation, requestID: requestID, expiresAt: expiresAt}
	return k8sLifecycleRemintResult{claim: claim, joinToken: f.token, generation: generation, requestID: requestID, expiresAt: expiresAt}, nil
}

func (f *fakeK8sControlPlane) AcknowledgeLifecycleClaim(_ context.Context, _, claim string, generation int, requestID string) (k8sLifecycleClaimStatus, error) {
	if f.ackCount == nil {
		f.ackCount = map[string]int{}
	}
	status := f.claims[claim]
	if status.state == "aborted" {
		return k8sLifecycleClaimStatus{}, errors.New("lifecycle claim is aborted and cannot be acknowledged")
	}
	status.state = "acknowledged"
	status.generation = generation
	status.requestID = requestID
	f.claims[claim] = status
	f.ackCount[claim]++
	return status, nil
}

func (f *fakeK8sControlPlane) AbortLifecycleClaim(_ context.Context, _, claim string, generation int, requestID string) (k8sLifecycleClaimStatus, error) {
	f.abortCount++
	if f.abortOverride != nil {
		return *f.abortOverride, nil
	}
	status := f.claims[claim]
	status.state = "aborted"
	status.generation = generation
	status.requestID = requestID
	if status.abortedAt == nil {
		abortedAt := time.Now().UTC()
		status.abortedAt = &abortedAt
		if status.expiresAt.After(abortedAt) {
			status.expiresAt = abortedAt
		}
	}
	f.claims[claim] = status
	return status, nil
}

func baseK8sControlPlane() *fakeK8sControlPlane {
	return &fakeK8sControlPlane{
		meta: k8sMeta{
			publicBaseURL:  "https://cp.example.test/ui/path",
			gatewayControl: "https://agent.example.test:8443",
			nodeAgentImage: "ghcr.io/tunnexio/tunnex-node-agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		orgs:  []k8sOrganization{{id: "11111111-1111-1111-1111-111111111111", name: "Example", slug: "example"}},
		token: testJoinToken, claims: map[string]k8sLifecycleClaimStatus{}, ackCount: map[string]int{}, installOperations: map[string]lifecycleInstallOperationStatus{},
	}
}

func baseK8sDeps(runner k8sRunner, cp k8sControlPlane, out, errOut ioWriter) k8sDeps {
	return k8sDeps{
		runner: runner,
		loadCredential: func() (Credential, error) {
			return Credential{Server: "https://login.example.test", Token: "stored-login-token", ExpiresAt: time.Now().Add(time.Hour)}, nil
		},
		newControlPlane:         func(Credential) (k8sControlPlane, error) { return cp, nil },
		in:                      strings.NewReader("yes\n"),
		out:                     out,
		errOut:                  errOut,
		buildVersion:            "v0.2.0",
		defaultChart:            DefaultK8sGatewayChart,
		defaultHostPostureChart: DefaultK8sHostPostureChart,
		newClaimID:              func() string { return testLifecycleClaim },
		newRequestID:            func() string { return testLifecycleRequest },
		newOperationID:          func() string { return testStateFenceOpID },
	}
}

// ioWriter keeps helper call sites short while accepting bytes.Buffer and
// io.Discard without exposing production implementation details.
type ioWriter interface {
	Write([]byte) (int, error)
}

func baseRunnerHandler(command k8sCommand) (k8sCommandResult, error) {
	joined := strings.Join(command.args, " ")
	switch {
	case command.name == "helm" && strings.HasPrefix(joined, "show chart "):
		if len(command.args) < 3 {
			return k8sCommandResult{}, errors.New("fake Helm show lacks chart artifact")
		}
		raw, err := os.ReadFile(command.args[2])
		if err != nil {
			return k8sCommandResult{}, err
		}
		var artifact fakeChartArtifact
		if err := json.Unmarshal(raw, &artifact); err != nil {
			return k8sCommandResult{}, err
		}
		return stdout(fmt.Sprintf("apiVersion: v2\nname: %s\nversion: %s\nappVersion: %q\n", artifact.Name, artifact.Version, artifact.AppVersion)), nil
	case command.name == "helm" && joined == "version --short":
		return stdout("v3.18.4+gfixture\n"), nil
	case command.name == "helm" && joined == "upgrade --help":
		return stdout("--reset-then-reuse-values\n"), nil
	case command.name == "kubectl" && joined == "config current-context":
		return stdout("walk-context\n"), nil
	case command.name == "kubectl" && strings.Contains(joined, "get --raw=/readyz"):
		return stdout("ok\n"), nil
	case command.name == "kubectl" && strings.Contains(joined, "get storageclass"):
		return stdout(defaultStorageClassJSON("WaitForFirstConsumer")), nil
	case command.name == "kubectl" && strings.Contains(joined, "get namespace tunnex"):
		return stdout("namespace/tunnex\n"), nil
	case command.name == "kubectl" && strings.Contains(joined, "get namespace tunnex-system"):
		return stdout("namespace/tunnex-system\n"), nil
	case command.name == "kubectl" && strings.Contains(joined, "get daemonset tunnex-host-posture"):
		return stdout(readyHostPostureDaemonSetJSON(nil)), nil
	case command.name == "kubectl" && strings.Contains(joined, "get sa tunnex-host-posture"):
		return stdout(readyHostPostureServiceAccountJSON()), nil
	case command.name == "kubectl" && strings.Contains(joined, "get clusterrole tunnex-host-posture-gateway-owner-reader"):
		return stdout(readyHostPostureClusterRoleJSON()), nil
	case command.name == "kubectl" && strings.Contains(joined, "get clusterrolebinding tunnex-host-posture-gateway-owner-reader"):
		return stdout(readyHostPostureClusterRoleBindingJSON()), nil
	case command.name == "kubectl" && strings.Contains(joined, "create -f -") && bytes.Contains(command.stdin, []byte(`"kind":"Secret"`)):
		return stdout(bootstrapSecretMetadataLineFromManifest(command.stdin)), nil
	case command.name == "kubectl" && strings.Contains(joined, "rollout status deployment/"):
		return stdout("deployment successfully rolled out\n"), nil
	case command.name == "kubectl" && strings.Contains(joined, "get deployments"):
		return stdout(""), nil
	case command.name == "kubectl" && strings.Contains(joined, "get deployment"):
		return stdout(readyDeploymentJSON("tunnex-gateway", "tunnex-gateway-tunnex-gateway-state")), nil
	case command.name == "kubectl" && strings.Contains(joined, "get service"):
		return stdout(readyServiceJSON("tunnex-gateway", "LoadBalancer")), nil
	case command.name == "kubectl" && strings.Contains(joined, "get pvc"):
		if strings.Contains(joined, "--ignore-not-found=true") {
			return stdout(""), nil
		}
		if strings.Contains(joined, "retained-state-a") {
			return stdout(readyPVCJSON("retained-state-a", "tunnex-gateway")), nil
		}
		return stdout(readyPVCJSON("tunnex-gateway-tunnex-gateway-state", "tunnex-gateway")), nil
	case command.name == "helm" && strings.HasPrefix(joined, "list --all-namespaces"):
		return stdout(`[ {"name":"tunnex-host-posture","namespace":"tunnex-system","revision":"1","status":"deployed","chart":"tunnex-host-posture-0.2.0","app_version":"v0.2.0"} ]`), nil
	case command.name == "helm" && strings.HasPrefix(joined, "list "):
		return stdout(`[]`), nil
	case command.name == "helm" && strings.HasPrefix(joined, "history "):
		return stdout(`[{"revision":1,"updated":"before","status":"superseded","chart":"tunnex-gateway-0.2.0","app_version":"0.2.0","description":"tunnex-zero-touch/v1"},{"revision":2,"updated":"before","status":"superseded","chart":"tunnex-gateway-0.2.0","app_version":"0.2.0","description":"tunnex-zero-touch/v1"},{"revision":3,"updated":"now","status":"deployed","chart":"tunnex-gateway-0.2.0","app_version":"0.2.0","description":"tunnex-zero-touch/v1"}]`), nil
	case command.name == "kubectl" && strings.Contains(joined, "get pods"):
		return stdout(`{"items":[{"metadata":{"name":"gateway-pod"},"spec":{"nodeName":"node-a"},"status":{"phase":"Running","containerStatuses":[{"name":"gateway","ready":true,"restartCount":0}]}}]}`), nil
	case command.name == "kubectl" && strings.Contains(joined, "get events"):
		return stdout(`{"items":[]}`), nil
	default:
		return k8sCommandResult{}, nil
	}
}

func installedRunnerHandler(command k8sCommand) (k8sCommandResult, error) {
	joined := strings.Join(command.args, " ")
	if command.name == "helm" && strings.HasPrefix(joined, "list --all-namespaces") {
		return baseRunnerHandler(command)
	}
	if command.name == "helm" && strings.HasPrefix(joined, "list ") {
		return stdout(`[ {"name":"tunnex-gateway","namespace":"tunnex","revision":"3","status":"deployed","chart":"tunnex-gateway-0.2.0","app_version":"0.2.0"} ]`), nil
	}
	return baseRunnerHandler(command)
}

func readyHostPostureDaemonSetJSON(pullSecrets []string) string {
	pulls := make([]string, 0, len(pullSecrets))
	for _, name := range pullSecrets {
		pulls = append(pulls, fmt.Sprintf(`{"name":%q}`, name))
	}
	manifest := fmt.Sprintf(`{"metadata":{"name":"tunnex-host-posture","namespace":"tunnex-system","uid":"host-posture-uid","resourceVersion":"17","generation":2,"labels":{"app.kubernetes.io/name":"tunnex-host-posture","app.kubernetes.io/instance":"tunnex-host-posture","app.kubernetes.io/managed-by":"Helm","app.kubernetes.io/component":"host-posture"},"annotations":{"tunnex.io/host-posture-contract":"tunnex-host-posture/v1","meta.helm.sh/release-name":"tunnex-host-posture","meta.helm.sh/release-namespace":"tunnex-system"}},"spec":{"updateStrategy":{"type":"RollingUpdate","rollingUpdate":{"maxUnavailable":1,"maxSurge":0}},"selector":{"matchLabels":{"app.kubernetes.io/name":"tunnex-host-posture","app.kubernetes.io/instance":"tunnex-host-posture","app.kubernetes.io/component":"host-posture"}},"template":{"metadata":{"labels":{"app.kubernetes.io/name":"tunnex-host-posture","app.kubernetes.io/instance":"tunnex-host-posture","app.kubernetes.io/component":"host-posture"},"annotations":{"tunnex.io/host-posture-contract":"tunnex-host-posture/v1","tunnex.io/rollout-revision":"approved-digest"}},"spec":{"serviceAccountName":"tunnex-host-posture","automountServiceAccountToken":false,"hostNetwork":true,"dnsPolicy":"ClusterFirstWithHostNet","terminationGracePeriodSeconds":10,"nodeSelector":{"kubernetes.io/os":"linux"},"tolerations":[{"operator":"Exists"}],"affinity":{},"imagePullSecrets":[%s],"containers":[{"name":"host-posture-manager","image":"ghcr.io/tunnexio/tunnex-node-agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","imagePullPolicy":"IfNotPresent","command":["/usr/local/bin/tunnex-node","k8s-host-posture-manager","--run"],"securityContext":{"privileged":true,"runAsUser":0,"runAsNonRoot":false,"allowPrivilegeEscalation":true,"readOnlyRootFilesystem":true,"seccompProfile":{"type":"RuntimeDefault"}},"env":[{"name":"TUNNEX_HOST_POSTURE_NODE_NAME","valueFrom":{"fieldRef":{"fieldPath":"spec.nodeName"}}},{"name":"TUNNEX_HOST_POSTURE_MANAGER_UID","valueFrom":{"fieldRef":{"fieldPath":"metadata.uid"}}},{"name":"TUNNEX_HOST_POSTURE_STATE_DIR","value":"/var/lib/tunnex/host-posture/v1"},{"name":"TUNNEX_HOST_POSTURE_PROC_SYS","value":"/host/proc/sys"},{"name":"TUNNEX_HOST_POSTURE_RECONCILE_INTERVAL","value":"2s"},{"name":"TUNNEX_HOST_POSTURE_API_TIMEOUT","value":"10s"},{"name":"TUNNEX_HOST_POSTURE_MAX_OWNERS","value":"32"}],"volumeMounts":[{"name":"host-posture-state","mountPath":"/var/lib/tunnex/host-posture/v1"},{"name":"host-proc-sys","mountPath":"/host/proc/sys"},{"name":"k8s-api-token","mountPath":"/var/run/secrets/kubernetes.io/serviceaccount","readOnly":true}],"resources":{}}],"volumes":[{"name":"host-posture-state","hostPath":{"path":"/var/lib/tunnex/host-posture/v1","type":"DirectoryOrCreate"}},{"name":"host-proc-sys","hostPath":{"path":"/proc/sys","type":"Directory"}},{"name":"k8s-api-token","projected":{"defaultMode":420,"sources":[{"serviceAccountToken":{"path":"token","expirationSeconds":3600}},{"configMap":{"name":"kube-root-ca.crt","items":[{"key":"ca.crt","path":"ca.crt"}]}}]}}]}}},"status":{"observedGeneration":2,"desiredNumberScheduled":2,"currentNumberScheduled":2,"updatedNumberScheduled":2,"numberReady":2,"numberUnavailable":0}}`, strings.Join(pulls, ","))
	return strings.Replace(manifest, `],"volumeMounts"`, `],"startupProbe":{"exec":{"command":["/usr/local/bin/tunnex-node","k8s-host-posture-check","--ready"]},"periodSeconds":2,"timeoutSeconds":2,"successThreshold":1,"failureThreshold":45},"readinessProbe":{"exec":{"command":["/usr/local/bin/tunnex-node","k8s-host-posture-check","--ready"]},"periodSeconds":2,"timeoutSeconds":2,"successThreshold":1,"failureThreshold":3},"livenessProbe":{"exec":{"command":["/usr/local/bin/tunnex-node","k8s-host-posture-check","--live"]},"periodSeconds":10,"timeoutSeconds":2,"successThreshold":1,"failureThreshold":3},"volumeMounts"`, 1)
}

func readyHostPostureServiceAccountJSON() string {
	return `{"metadata":{"name":"tunnex-host-posture","namespace":"tunnex-system","uid":"host-posture-sa-uid","resourceVersion":"21","labels":{"app.kubernetes.io/name":"tunnex-host-posture","app.kubernetes.io/instance":"tunnex-host-posture","app.kubernetes.io/managed-by":"Helm","app.kubernetes.io/component":"host-posture"},"annotations":{"meta.helm.sh/release-name":"tunnex-host-posture","meta.helm.sh/release-namespace":"tunnex-system"}},"automountServiceAccountToken":false}`
}

func readyHostPostureClusterRoleJSON() string {
	return `{"metadata":{"name":"tunnex-host-posture-gateway-owner-reader","uid":"host-posture-role-uid","resourceVersion":"22","labels":{"app.kubernetes.io/name":"tunnex-host-posture","app.kubernetes.io/instance":"tunnex-host-posture","app.kubernetes.io/managed-by":"Helm","app.kubernetes.io/component":"host-posture"},"annotations":{"meta.helm.sh/release-name":"tunnex-host-posture","meta.helm.sh/release-namespace":"tunnex-system"}},"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get","list"]}]}`
}

func readyHostPostureClusterRoleBindingJSON() string {
	return `{"metadata":{"name":"tunnex-host-posture-gateway-owner-reader","uid":"host-posture-binding-uid","resourceVersion":"23","labels":{"app.kubernetes.io/name":"tunnex-host-posture","app.kubernetes.io/instance":"tunnex-host-posture","app.kubernetes.io/managed-by":"Helm","app.kubernetes.io/component":"host-posture"},"annotations":{"meta.helm.sh/release-name":"tunnex-host-posture","meta.helm.sh/release-namespace":"tunnex-system"}},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"tunnex-host-posture-gateway-owner-reader"},"subjects":[{"kind":"ServiceAccount","name":"tunnex-host-posture","namespace":"tunnex-system"}]}`
}

func stdout(value string) k8sCommandResult { return k8sCommandResult{stdout: []byte(value)} }

func defaultStorageClassJSON(bindingMode string) string {
	return fmt.Sprintf(`{"items":[{"metadata":{"name":"managed-csi","annotations":{"storageclass.kubernetes.io/is-default-class":"true"}},"provisioner":"disk.csi.example.test","volumeBindingMode":%q}]}`, bindingMode)
}

func readyDeploymentJSON(release, claim string) string {
	name := gatewayFullname(release)
	return fmt.Sprintf(`{"metadata":{"name":%q,"uid":"uid-%s","resourceVersion":"31","generation":4,"annotations":{"tunnex.io/zero-touch-contract":"tunnex-zero-touch/v1"}},"spec":{"replicas":1,"template":{"spec":{"containers":[{"name":"gateway","image":"ghcr.io/tunnexio/tunnex-node-agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","imagePullPolicy":"IfNotPresent"}],"volumes":[{"name":"state","persistentVolumeClaim":{"claimName":%q}}]}}},"status":{"observedGeneration":4,"readyReplicas":1,"availableReplicas":1,"updatedReplicas":1}}`, name, name, claim)
}

func readyDeploymentWithPlacementJSON(release, claim string, selectors map[string]string, tolerations []gatewayToleration) string {
	selectorJSON, _ := json.Marshal(selectors)
	tolerationJSON, _ := json.Marshal(tolerations)
	return strings.Replace(readyDeploymentJSON(release, claim), `"spec":{"containers"`, `"spec":{"nodeSelector":`+string(selectorJSON)+`,"tolerations":`+string(tolerationJSON)+`,"containers"`, 1)
}

func readyDeploymentRuntimeJSON(release, claim, image string, selectors map[string]string, tolerations []gatewayToleration, pullSecrets []string) string {
	body := readyDeploymentWithPlacementJSON(release, claim, selectors, tolerations)
	body = strings.Replace(body, "ghcr.io/tunnexio/tunnex-node-agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", image, 1)
	pulls := make([]map[string]string, 0, len(pullSecrets))
	for _, name := range pullSecrets {
		pulls = append(pulls, map[string]string{"name": name})
	}
	pullJSON, _ := json.Marshal(pulls)
	return strings.Replace(body, `"spec":{"nodeSelector"`, `"spec":{"imagePullSecrets":`+string(pullJSON)+`,"nodeSelector"`, 1)
}

func readyServiceJSON(release, serviceType string) string {
	status := `"loadBalancer":{"ingress":[{"ip":"203.0.113.7"}]}`
	port := `{"name":"wireguard","port":51820,"protocol":"UDP"}`
	if serviceType == "NodePort" {
		status = `"loadBalancer":{}`
		port = `{"name":"wireguard","port":51820,"nodePort":30182,"protocol":"UDP"}`
	}
	return fmt.Sprintf(`{"metadata":{"name":%q},"spec":{"type":%q,"ports":[%s]},"status":{%s}}`, gatewayFullname(release)+"-wg", serviceType, port, status)
}

func readyPVCJSON(claim, release string) string {
	return fmt.Sprintf(`{"metadata":{"name":%q,"namespace":"tunnex","uid":"uid-%s","resourceVersion":"42","labels":{"app.kubernetes.io/name":"tunnex-gateway","app.kubernetes.io/instance":%q,"app.kubernetes.io/managed-by":"Helm"},"annotations":{"helm.sh/resource-policy":"keep","meta.helm.sh/release-name":%q,"meta.helm.sh/release-namespace":"tunnex","tunnex.io/organization-id":"11111111-1111-1111-1111-111111111111","tunnex.io/lifecycle-claim":%q}},"spec":{"storageClassName":"managed-csi","volumeName":"pvc-id"},"status":{"phase":"Bound"}}`, claim, claim, release, release, testLifecycleClaim)
}

func readyLegacyPVCJSON(claim, release string) string {
	return strings.Replace(strings.Replace(readyPVCJSON(claim, release), `,"tunnex.io/organization-id":"11111111-1111-1111-1111-111111111111"`, "", 1), `,"tunnex.io/lifecycle-claim":"`+testLifecycleClaim+`"`, "", 1)
}

func bootstrapSecretMetadataLine(release string) string {
	return bootstrapSecretMetadataLineWith(release, testLifecycleClaim, testLifecycleRequest, 1, testLifecycleExpiry)
}

func bootstrapSecretMetadataLineWith(release, claim, request string, generation int, expiresAt time.Time) string {
	return fmt.Sprintf("%s-bootstrap\tuid-%s-bootstrap\t17\ttunnex-gateway-bootstrap\t%s\ttunnex-lifecycle\ttrue\t%s\t%s\t%d\t%s\tv1|ConfigMap|%s-lifecycle|uid-%s-lifecycle;\n", release, release, release, claim, request, generation, expiresAt.UTC().Format(time.RFC3339Nano), release, release)
}

func bootstrapSecretMetadataLineFromManifest(raw []byte) string {
	var object struct {
		Metadata struct {
			Name            string            `json:"name"`
			Labels          map[string]string `json:"labels"`
			Annotations     map[string]string `json:"annotations"`
			OwnerReferences []struct {
				APIVersion string `json:"apiVersion"`
				Kind       string `json:"kind"`
				Name       string `json:"name"`
				UID        string `json:"uid"`
			} `json:"ownerReferences"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &object); err != nil || len(object.Metadata.OwnerReferences) != 1 {
		return "malformed\n"
	}
	owner := object.Metadata.OwnerReferences[0]
	return fmt.Sprintf("%s\tuid-%s\t17\t%s\t%s\t%s\ttrue\t%s\t%s\t%s\t%s\t%s|%s|%s|%s;\n",
		object.Metadata.Name, object.Metadata.Name,
		object.Metadata.Labels["app.kubernetes.io/name"], object.Metadata.Labels["app.kubernetes.io/instance"], object.Metadata.Labels["app.kubernetes.io/managed-by"],
		object.Metadata.Annotations["tunnex.io/lifecycle-claim"], object.Metadata.Annotations["tunnex.io/lifecycle-request-id"],
		object.Metadata.Annotations["tunnex.io/lifecycle-generation"], object.Metadata.Annotations["tunnex.io/lifecycle-expires-at"],
		owner.APIVersion, owner.Kind, owner.Name, owner.UID)
}

func lifecycleAnchorMetadataLine(anchor lifecycleAnchorMetadata) string {
	expiresAt := ""
	if !anchor.expiresAt.IsZero() {
		expiresAt = anchor.expiresAt.UTC().Format(time.RFC3339Nano)
	}
	operationNotAfter := ""
	if !anchor.installOperationNotAfter.IsZero() {
		operationNotAfter = anchor.installOperationNotAfter.UTC().Format(time.RFC3339Nano)
	}
	return fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%t\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s\t%s\n",
		anchor.name, anchor.uid, anchor.resourceVersion, anchor.appName, anchor.instance, anchor.managedBy, anchor.immutable,
		anchor.orgID, anchor.nodeName, anchor.lifecycleClaim, anchor.requestID, anchor.expectedGeneration, anchor.generation, anchor.state, expiresAt,
		anchor.installOperationID, anchor.installOperationEpoch, anchor.installOperationDurationSeconds, operationNotAfter, anchor.installIntentDigest, anchor.releaseNamespace, anchor.releaseName)
}

func testLifecycleAnchor(release, nodeName, state string) lifecycleAnchorMetadata {
	return lifecycleAnchorMetadata{
		name: release + "-lifecycle", uid: "uid-" + release + "-lifecycle", resourceVersion: "9",
		appName: "tunnex-gateway-lifecycle", instance: release, managedBy: "tunnex-lifecycle", immutable: true,
		orgID: "11111111-1111-1111-1111-111111111111", nodeName: nodeName, lifecycleClaim: testLifecycleClaim,
		requestID: testLifecycleRequest, expectedGeneration: 0, generation: 1, state: state, expiresAt: testLifecycleExpiry,
	}
}

func testCompletedLifecycleAnchor(cp *fakeK8sControlPlane, release, nodeName string) lifecycleAnchorMetadata {
	anchor := testLifecycleAnchor(release, nodeName, "installing")
	now := time.Now().UTC()
	completedAt := now
	anchor.installOperationID = testStateFenceOpID
	anchor.installOperationEpoch = 1
	anchor.installOperationDurationSeconds = 660
	anchor.installOperationNotAfter = now.Add(11 * time.Minute)
	anchor.installIntentDigest = "sha256:" + strings.Repeat("c", 64)
	anchor.releaseNamespace = defaultK8sNamespace
	anchor.releaseName = release
	if cp.installOperations == nil {
		cp.installOperations = map[string]lifecycleInstallOperationStatus{}
	}
	cp.installOperations[anchor.installOperationID] = lifecycleInstallOperationStatus{
		claim: anchor.lifecycleClaim, generation: anchor.generation, requestID: anchor.requestID,
		operationID: anchor.installOperationID, epoch: anchor.installOperationEpoch, state: lifecycleInstallCompleted,
		releaseNamespace: anchor.releaseNamespace, releaseName: anchor.releaseName, installIntentDigest: anchor.installIntentDigest,
		requestedDurationSeconds: anchor.installOperationDurationSeconds, notAfter: anchor.installOperationNotAfter,
		serverTime: now, heartbeatAt: now, completedAt: &completedAt,
	}
	return anchor
}

func claimPodJSON(name, phase, deletionTimestamp, ownerKind, ownerName, claim string) string {
	metadata := fmt.Sprintf(`"name":%q`, name)
	if deletionTimestamp != "" {
		metadata += fmt.Sprintf(`,"deletionTimestamp":%q`, deletionTimestamp)
	}
	if ownerKind != "" {
		metadata += fmt.Sprintf(`,"ownerReferences":[{"kind":%q,"name":%q}]`, ownerKind, ownerName)
	}
	return fmt.Sprintf(`{"metadata":{%s},"spec":{"volumes":[{"persistentVolumeClaim":{"claimName":%q}}]},"status":{"phase":%q}}`, metadata, claim, phase)
}

func TestK8sUsageListsUninstallOnce(t *testing.T) {
	if got := strings.Count(k8sUsage, "tunnex k8s uninstall"); got != 1 {
		t.Fatalf("uninstall appears %d times in k8s usage, want once", got)
	}
}

func TestK8sPlanIsStableAndRedacted(t *testing.T) {
	cp := baseK8sControlPlane()
	runner := &fakeK8sRunner{handler: baseRunnerHandler}
	var first bytes.Buffer
	deps := baseK8sDeps(runner, cp, &first, &bytes.Buffer{})
	args := []string{"plan", "--node-name", "aks-gateway-a"}
	if err := runK8s(context.Background(), args, deps); err != nil {
		t.Fatalf("first plan: %v", err)
	}
	var second bytes.Buffer
	deps.out = &second
	if err := runK8s(context.Background(), args, deps); err != nil {
		t.Fatalf("second plan: %v", err)
	}
	if first.String() != second.String() {
		t.Fatalf("plan was not stable\nfirst:\n%s\nsecond:\n%s", first.String(), second.String())
	}
	if !strings.Contains(first.String(), "Plan digest: sha256:") || !strings.Contains(first.String(), `"binding_mode": "WaitForFirstConsumer"`) {
		t.Fatalf("plan lacks digest or accepted binding mode:\n%s", first.String())
	}
	for _, secret := range []string{testJoinToken, "stored-login-token"} {
		if strings.Contains(first.String(), secret) {
			t.Fatalf("plan leaked secret %q", secret)
		}
	}
	if cp.issueCount != 0 {
		t.Fatalf("plan minted %d join tokens; plan must be read-only", cp.issueCount)
	}
}

func TestK8sProviderNeutralStaticLoadBalancerInputsArePlannedAppliedAndReadBack(t *testing.T) {
	argsA := []string{"plan", "--node-name", "aks-gateway-a", "--load-balancer-ip", "20.115.124.74", "--service-annotation", "service.beta.kubernetes.io/azure-load-balancer-resource-group=rg-a", "--service-annotation", "example.net/tier=edge", "--image-pull-secret", "z-pull", "--image-pull-secret", "acr-pull"}
	argsB := []string{"plan", "--node-name", "aks-gateway-a", "--load-balancer-ip", "20.115.124.74", "--service-annotation", "example.net/tier=edge", "--service-annotation", "service.beta.kubernetes.io/azure-load-balancer-resource-group=rg-a", "--image-pull-secret", "acr-pull", "--image-pull-secret", "z-pull"}
	var planA, planB bytes.Buffer
	if err := runK8s(context.Background(), argsA, baseK8sDeps(&fakeK8sRunner{handler: baseRunnerHandler}, baseK8sControlPlane(), &planA, &bytes.Buffer{})); err != nil {
		t.Fatal(err)
	}
	if err := runK8s(context.Background(), argsB, baseK8sDeps(&fakeK8sRunner{handler: baseRunnerHandler}, baseK8sControlPlane(), &planB, &bytes.Buffer{})); err != nil {
		t.Fatal(err)
	}
	if planA.String() != planB.String() || !strings.Contains(planA.String(), `"load_balancer_ip": "20.115.124.74"`) || !strings.Contains(planA.String(), `"acr-pull"`) {
		t.Fatalf("provider-neutral plan is not canonical/bound:\nA=%s\nB=%s", planA.String(), planB.String())
	}

	deployment := readyDeploymentJSON("tunnex-gateway", "tunnex-gateway-tunnex-gateway-state")
	deployment = strings.Replace(deployment, `"spec":{"containers":`, `"spec":{"imagePullSecrets":[{"name":"acr-pull"},{"name":"z-pull"}],"containers":`, 1)
	service := readyServiceJSON("tunnex-gateway", "LoadBalancer")
	service = strings.Replace(service, `"metadata":{"name":"tunnex-gateway-tunnex-gateway-wg"}`, `"metadata":{"name":"tunnex-gateway-tunnex-gateway-wg","annotations":{"example.net/tier":"edge","service.beta.kubernetes.io/azure-load-balancer-resource-group":"rg-a"}}`, 1)
	service = strings.Replace(service, `"spec":{"type":"LoadBalancer"`, `"spec":{"type":"LoadBalancer","loadBalancerIP":"20.115.124.74"`, 1)
	runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "get daemonset tunnex-host-posture") {
			return stdout(readyHostPostureDaemonSetJSON([]string{"acr-pull", "z-pull"})), nil
		}
		if command.name == "kubectl" && strings.Contains(joined, "get deployment") {
			return stdout(deployment), nil
		}
		if command.name == "kubectl" && strings.Contains(joined, "get service") {
			return stdout(service), nil
		}
		return baseRunnerHandler(command)
	}}
	cp := baseK8sControlPlane()
	installArgs := append([]string{"install"}, argsA[1:]...)
	installArgs = append(installArgs, "--yes")
	if err := runK8s(context.Background(), installArgs, baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})); err != nil {
		t.Fatalf("provider-neutral install: %v", err)
	}
	foundHelm := false
	for _, command := range runner.commands {
		if command.name != "helm" || len(command.args) == 0 || command.args[0] != "install" {
			continue
		}
		foundHelm = true
		for _, want := range []string{`"loadBalancerIP":"20.115.124.74"`, `"service.beta.kubernetes.io/azure-load-balancer-resource-group":"rg-a"`, `"pullSecrets":[{"name":"acr-pull"},{"name":"z-pull"}]`} {
			if !bytes.Contains(command.stdin, []byte(want)) {
				t.Fatalf("Helm values missing %s: %s", want, command.stdin)
			}
		}
	}
	if !foundHelm {
		t.Fatal("provider-neutral install did not reach Helm")
	}
}

func TestK8sProviderNeutralGatewayPlacementIsPlannedAppliedAndReadBack(t *testing.T) {
	tests := []struct {
		name        string
		flags       []string
		selectors   map[string]string
		tolerations []gatewayToleration
	}{
		{
			name:        "gateway a",
			flags:       []string{"--gateway-node-selector", "topology.kubernetes.io/zone=eastus-1", "--gateway-node-selector", "pool=tunnex-a", "--gateway-toleration", "dedicated=tunnex:NoSchedule"},
			selectors:   map[string]string{"pool": "tunnex-a", "topology.kubernetes.io/zone": "eastus-1"},
			tolerations: []gatewayToleration{{Key: "dedicated", Operator: "Equal", Value: "tunnex", Effect: "NoSchedule"}},
		},
		{
			name:        "gateway b",
			flags:       []string{"--gateway-node-selector", "pool=tunnex-b", "--gateway-toleration", "spot:PreferNoSchedule", "--gateway-toleration", "gateway"},
			selectors:   map[string]string{"pool": "tunnex-b"},
			tolerations: []gatewayToleration{{Key: "gateway", Operator: "Exists"}, {Key: "spot", Operator: "Exists", Effect: "PreferNoSchedule"}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cp := baseK8sControlPlane()
			runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
				joined := strings.Join(command.args, " ")
				if command.name == "kubectl" && strings.Contains(joined, "get deployment") {
					return stdout(readyDeploymentWithPlacementJSON("tunnex-gateway", "tunnex-gateway-tunnex-gateway-state", tc.selectors, tc.tolerations)), nil
				}
				return baseRunnerHandler(command)
			}}
			var out bytes.Buffer
			deps := baseK8sDeps(runner, cp, &out, &bytes.Buffer{})
			args := append([]string{"install", "--node-name", strings.ReplaceAll(tc.name, " ", "-"), "--yes"}, tc.flags...)
			if err := runK8s(context.Background(), args, deps); err != nil {
				t.Fatalf("placement install: %v", err)
			}
			selectorJSON, _ := json.Marshal(tc.selectors)
			tolerationJSON, _ := json.Marshal(tc.tolerations)
			for key, value := range tc.selectors {
				if !strings.Contains(out.String(), fmt.Sprintf("%q: %q", key, value)) {
					t.Fatalf("plan missing canonical selector %s=%s:\n%s", key, value, out.String())
				}
			}
			for _, toleration := range tc.tolerations {
				if !strings.Contains(out.String(), fmt.Sprintf(`"key": %q`, toleration.Key)) || !strings.Contains(out.String(), fmt.Sprintf(`"operator": %q`, toleration.Operator)) {
					t.Fatalf("plan missing canonical toleration %+v:\n%s", toleration, out.String())
				}
			}
			foundGateway := false
			for _, command := range runner.commands {
				joined := strings.Join(command.args, " ")
				if command.name != "helm" || !strings.HasPrefix(joined, "install tunnex-gateway ") {
					continue
				}
				foundGateway = true
				for _, want := range []string{`"nodeSelector":` + string(selectorJSON), `"tolerations":` + string(tolerationJSON)} {
					if !bytes.Contains(command.stdin, []byte(want)) {
						t.Fatalf("gateway Helm values missing %s: %s", want, command.stdin)
					}
				}
			}
			if !foundGateway || cp.issueCount != 1 {
				t.Fatalf("gateway Helm=%t token mints=%d", foundGateway, cp.issueCount)
			}
		})
	}
}

func TestK8sGatewayPlacementDriftFailsExactReadbackWithoutTokenInReuseMode(t *testing.T) {
	cp := baseK8sControlPlane()
	runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "get deployment") {
			return stdout(readyDeploymentWithPlacementJSON("tunnex-gateway", "retained-state-a", map[string]string{"pool": "wrong"}, nil)), nil
		}
		return baseRunnerHandler(command)
	}}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"install", "--mode", "reuse", "--existing-claim", "retained-state-a", "--node-name", "gateway-a", "--gateway-node-selector", "pool=approved", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "nodeSelector") {
		t.Fatalf("placement drift error = %v", err)
	}
	if cp.issueCount != 0 {
		t.Fatalf("reuse placement drift minted %d tokens", cp.issueCount)
	}
}

func TestK8sGatewayPlacementValidationIsCanonicalAndFailClosed(t *testing.T) {
	tests := [][]string{
		{"--gateway-node-selector", "bad"},
		{"--gateway-node-selector", "pool=a", "--gateway-node-selector", "pool=b"},
		{"--gateway-toleration", "pool=value:Sometimes"},
		{"--gateway-toleration", "bad key"},
		{"--gateway-toleration", "pool", "--gateway-toleration", "pool"},
	}
	for _, flags := range tests {
		args := append([]string{"--node-name", "gateway-a"}, flags...)
		if _, err := parseInstallOptions(args, baseK8sDeps(&fakeK8sRunner{}, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})); err == nil {
			t.Fatalf("invalid placement accepted: %v", flags)
		}
	}
}

func TestK8sInstallRejectsControlCharacterNodeNameBeforeAnyMutation(t *testing.T) {
	cp := baseK8sControlPlane()
	runner := &fakeK8sRunner{handler: baseRunnerHandler}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"install", "--node-name", "gateway\twedged", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "control characters") {
		t.Fatalf("tab node-name error = %v", err)
	}
	if len(runner.commands) != 0 || cp.issueCount != 0 || cp.metaCount != 0 || cp.orgCount != 0 {
		t.Fatalf("invalid node-name mutated state: commands=%d cp=%d/%d/%d", len(runner.commands), cp.issueCount, cp.metaCount, cp.orgCount)
	}
}

func TestK8sAbortInstallRequiresExactTypedClaimAndLeavesPVCExplicit(t *testing.T) {
	anchor := testLifecycleAnchor("tunnex-gateway", "aks-gateway-a", "issued")
	cp := baseK8sControlPlane()
	cp.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{claim: testLifecycleClaim, state: "issued", nodeName: "aks-gateway-a", generation: 1, requestID: testLifecycleRequest, expiresAt: testLifecycleExpiry}
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}, handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "get secret tunnex-gateway-bootstrap") {
			return stdout(bootstrapSecretMetadataLine("tunnex-gateway")), nil
		}
		if command.name == "kubectl" && strings.Contains(joined, "get pvc tunnex-gateway-tunnex-gateway-state") && strings.Contains(joined, "--ignore-not-found=true") {
			return stdout(readyPVCJSON("tunnex-gateway-tunnex-gateway-state", "tunnex-gateway")), nil
		}
		return baseRunnerHandler(command)
	}}
	var out bytes.Buffer
	deps := baseK8sDeps(runner, cp, &out, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"abort-install", "--release", "tunnex-gateway", "--claim", testLifecycleClaim, "--confirm", "ABORT wrong"}, deps)
	if err == nil || !strings.Contains(err.Error(), "confirmation did not match exactly") {
		t.Fatalf("wrong abort confirmation error = %v", err)
	}
	if cp.claims[testLifecycleClaim].state != "issued" {
		t.Fatalf("wrong confirmation aborted claim: %+v", cp.claims[testLifecycleClaim])
	}
	for _, command := range runner.commands {
		if command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "delete --raw=") {
			t.Fatalf("wrong confirmation deleted Kubernetes state: %+v", command)
		}
	}

	runner.commands = nil
	out.Reset()
	err = runK8s(context.Background(), []string{"abort-install", "--release", "tunnex-gateway", "--claim", testLifecycleClaim, "--confirm", "ABORT " + testLifecycleClaim}, deps)
	if err != nil {
		t.Fatalf("exact abort-install: %v", err)
	}
	if cp.claims[testLifecycleClaim].state != "aborted" {
		t.Fatalf("exact claim was not aborted: %+v", cp.claims[testLifecycleClaim])
	}
	if !strings.Contains(out.String(), `"context": "walk-context"`) || !strings.Contains(out.String(), `"namespace": "tunnex"`) || !strings.Contains(out.String(), `"release": "tunnex-gateway"`) || !strings.Contains(out.String(), `"lifecycle_claim": "`+testLifecycleClaim+`"`) || !strings.Contains(out.String(), "retain any PVC") {
		t.Fatalf("abort impact omitted exact scope/recoverability:\n%s", out.String())
	}
	secretDeleted, anchorDeleted := false, false
	for _, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "/secrets/tunnex-gateway-bootstrap") {
			secretDeleted = true
		}
		if command.name == "kubectl" && strings.Contains(joined, "/configmaps/tunnex-gateway-lifecycle") {
			anchorDeleted = true
		}
		if bytes.Contains(command.stdin, []byte(testJoinToken)) {
			t.Fatalf("abort transported raw token: %+v", command)
		}
	}
	if !secretDeleted || !anchorDeleted {
		t.Fatalf("abort CAS cleanup secret=%t anchor=%t", secretDeleted, anchorDeleted)
	}
}

func TestK8sAbortInstallRetainsKubernetesMetadataOnInexactCPResponse(t *testing.T) {
	anchor := testLifecycleAnchor("tunnex-gateway", "aks-gateway-a", "issued")
	cp := baseK8sControlPlane()
	cp.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{claim: testLifecycleClaim, state: "issued", nodeName: "aks-gateway-a", generation: 1, requestID: testLifecycleRequest, expiresAt: testLifecycleExpiry}
	cp.abortOverride = &k8sLifecycleClaimStatus{claim: testLifecycleClaim, state: "issued", nodeName: "aks-gateway-a", generation: 1, requestID: testLifecycleRequest, expiresAt: testLifecycleExpiry}
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}, handler: func(command k8sCommand) (k8sCommandResult, error) {
		if command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "get secret tunnex-gateway-bootstrap") {
			return stdout(bootstrapSecretMetadataLine("tunnex-gateway")), nil
		}
		return baseRunnerHandler(command)
	}}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"abort-install", "--release", "tunnex-gateway", "--claim", testLifecycleClaim, "--confirm", "ABORT " + testLifecycleClaim}, deps)
	if err == nil || !strings.Contains(err.Error(), "not aborted") {
		t.Fatalf("inexact abort response error = %v", err)
	}
	for _, command := range runner.commands {
		if command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "delete --raw=") {
			t.Fatalf("inexact abort response deleted Kubernetes metadata: %+v", command)
		}
	}
}

func TestK8sAbortInstallHandlesPendingNextAndRerunsIdempotently(t *testing.T) {
	expiredAt := time.Now().Add(-time.Hour).UTC()
	anchor := testLifecycleAnchor("tunnex-gateway", "aks-gateway-a", "pending")
	anchor.expectedGeneration, anchor.generation, anchor.expiresAt = 1, 1, expiredAt
	cp := baseK8sControlPlane()
	cp.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{
		claim: testLifecycleClaim, state: "issued", nodeName: "aks-gateway-a", generation: 2,
		requestID: testLifecycleRequest, expiresAt: testLifecycleExpiry,
	}
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}, handler: baseRunnerHandler}
	var out bytes.Buffer
	deps := baseK8sDeps(runner, cp, &out, &bytes.Buffer{})
	args := []string{"abort-install", "--release", "tunnex-gateway", "--claim", testLifecycleClaim, "--confirm", "ABORT " + testLifecycleClaim}
	if err := runK8s(context.Background(), args, deps); err != nil {
		t.Fatalf("pending-next abort: %v", err)
	}
	if cp.abortCount != 1 || cp.claims[testLifecycleClaim].state != "aborted" {
		t.Fatalf("pending-next abort count/state = %d/%+v", cp.abortCount, cp.claims[testLifecycleClaim])
	}
	if _, exists := runner.anchors[anchor.name]; exists {
		t.Fatal("successful pending-next abort retained lifecycle anchor")
	}
	out.Reset()
	runner.commands = nil
	if err := runK8s(context.Background(), args, deps); err != nil {
		t.Fatalf("idempotent abort rerun: %v", err)
	}
	if cp.abortCount != 1 {
		t.Fatalf("idempotent rerun called control-plane abort %d times", cp.abortCount)
	}
	if !strings.Contains(out.String(), "already aborted") || !strings.Contains(out.String(), "Any retained PVC was not deleted") {
		t.Fatalf("idempotent abort output omitted exact completion/recovery truth:\n%s", out.String())
	}
	for _, command := range runner.commands {
		if command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "delete --raw=") {
			t.Fatalf("idempotent rerun deleted Kubernetes state: %+v", command)
		}
	}
}

func TestK8sImplicitImageUsesOnlyDigestPinnedMetadata(t *testing.T) {
	t.Run("mutable metadata is ignored for version matched chart default", func(t *testing.T) {
		cp := baseK8sControlPlane()
		cp.meta.nodeAgentImage = "ghcr.io/tunnexio/tunnex-node-agent:latest"
		runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
			joined := strings.Join(command.args, " ")
			if command.name == "kubectl" && strings.Contains(joined, "get daemonset tunnex-host-posture") {
				return stdout(strings.Replace(readyHostPostureDaemonSetJSON(nil), "ghcr.io/tunnexio/tunnex-node-agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ghcr.io/tunnexio/tunnex-node-agent:v0.2.0", 1)), nil
			}
			if command.name == "kubectl" && strings.Contains(joined, "get deployment") {
				return stdout(strings.Replace(readyDeploymentJSON("tunnex-gateway", "tunnex-gateway-tunnex-gateway-state"), "ghcr.io/tunnexio/tunnex-node-agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ghcr.io/tunnexio/tunnex-node-agent:v0.2.0", 1)), nil
			}
			return baseRunnerHandler(command)
		}}
		var out bytes.Buffer
		deps := baseK8sDeps(runner, cp, &out, &bytes.Buffer{})
		if err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps); err != nil {
			t.Fatalf("install with mutable metadata: %v", err)
		}
		if !strings.Contains(out.String(), `"image": "ghcr.io/tunnexio/tunnex-node-agent:v0.2.0"`) || strings.Contains(out.String(), ":latest") {
			t.Fatalf("plan did not fall back to packaged chart image:\n%s", out.String())
		}
		for _, command := range runner.commands {
			if command.name == "helm" && len(command.stdin) != 0 && (bytes.Contains(command.stdin, []byte(`:latest`)) || !bytes.Contains(command.stdin, []byte(`"registry":"ghcr.io/tunnexio"`)) || !bytes.Contains(command.stdin, []byte(`"agent":"tunnex-node-agent"`)) || !bytes.Contains(command.stdin, []byte(`"digest":""`)) || !bytes.Contains(command.stdin, []byte(`"tag":""`))) {
				t.Fatalf("chart-default image values were not authoritative: %s", command.stdin)
			}
		}
	})

	t.Run("digest metadata is used", func(t *testing.T) {
		cp := baseK8sControlPlane()
		runner := &fakeK8sRunner{handler: baseRunnerHandler}
		var out bytes.Buffer
		deps := baseK8sDeps(runner, cp, &out, &bytes.Buffer{})
		if err := runK8s(context.Background(), []string{"plan", "--node-name", "aks-gateway-a"}, deps); err != nil {
			t.Fatalf("digest plan: %v", err)
		}
		if !strings.Contains(out.String(), "@sha256:aaaaaaaaaaaaaaaa") {
			t.Fatalf("digest metadata absent from plan:\n%s", out.String())
		}
	})
}

func TestK8sPlanRequiresExplicitOrganizationWhenMultiple(t *testing.T) {
	cp := baseK8sControlPlane()
	cp.orgs = append(cp.orgs, k8sOrganization{id: "22222222-2222-2222-2222-222222222222", name: "Second", slug: "second"})
	runner := &fakeK8sRunner{handler: baseRunnerHandler}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"plan", "--node-name", "aks-gateway-a"}, deps)
	if err == nil || !strings.Contains(err.Error(), "multiple organizations") {
		t.Fatalf("multi-org plan error = %v", err)
	}
	if err := runK8s(context.Background(), []string{"plan", "--node-name", "aks-gateway-a", "--org", "second"}, deps); err != nil {
		t.Fatalf("explicit org: %v", err)
	}
}

func TestSelectStorageClassIsDeterministicAndAcceptsWaitForFirstConsumer(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		requested string
		want      string
		wantErr   string
	}{
		{name: "wait for consumer", raw: defaultStorageClassJSON("WaitForFirstConsumer"), want: "managed-csi"},
		{name: "no default", raw: `{"items":[{"metadata":{"name":"manual"},"provisioner":"csi"}]}`, wantErr: "no default"},
		{name: "multiple defaults", raw: `{"items":[{"metadata":{"name":"a","annotations":{"storageclass.kubernetes.io/is-default-class":"true"}},"provisioner":"csi"},{"metadata":{"name":"b","annotations":{"storageclass.kubernetes.io/is-default-class":"true"}},"provisioner":"csi"}]}`, wantErr: "multiple default"},
		{name: "explicit resolves ambiguity", raw: `{"items":[{"metadata":{"name":"a","annotations":{"storageclass.kubernetes.io/is-default-class":"true"}},"provisioner":"csi-a"},{"metadata":{"name":"b","annotations":{"storageclass.kubernetes.io/is-default-class":"true"}},"provisioner":"csi-b","volumeBindingMode":"WaitForFirstConsumer"}]}`, requested: "b", want: "b"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, _, _, err := selectStorageClass([]byte(test.raw), test.requested)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, test.wantErr)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("selected = %q, err=%v, want %q", got, err, test.want)
			}
		})
	}
}

func TestVerifyHelmClientMinimumVersion(t *testing.T) {
	cases := []struct {
		name    string
		version string
		wantErr bool
	}{
		{name: "below boundary", version: "v3.13.3+gfixture", wantErr: true},
		{name: "at boundary", version: "v3.14.0+gfixture"},
		{name: "boundary prerelease format", version: "3.14.0-rc.1+gfixture"},
		{name: "next major", version: "v4.0.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
				if command.name != "helm" || strings.Join(command.args, " ") != "version --short" {
					t.Fatalf("unexpected command: %+v", command)
				}
				return stdout(tc.version + "\n"), nil
			}}
			err := verifyHelmClient(context.Background(), runner)
			if tc.wantErr && (err == nil || !strings.Contains(err.Error(), "Helm 3.14 or newer")) {
				t.Fatalf("error = %v, want minimum-version rejection", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("verifyHelmClient(%q): %v", tc.version, err)
			}
		})
	}
}

func TestDeriveControlPlaneEndpointsRequiresHTTPSOutsideLoopback(t *testing.T) {
	for _, tc := range []struct {
		name string
		meta k8sMeta
		want bool
	}{
		{name: "remote API http rejected", meta: k8sMeta{publicBaseURL: "http://cp.example.test", gatewayControl: "https://agent.example.test:8443"}},
		{name: "remote agent http rejected", meta: k8sMeta{publicBaseURL: "https://cp.example.test", gatewayControl: "http://agent.example.test:8443"}},
		{name: "https accepted", meta: k8sMeta{publicBaseURL: "https://cp.example.test", gatewayControl: "https://agent.example.test:8443"}, want: true},
		{name: "IPv4 loopback dev accepted", meta: k8sMeta{publicBaseURL: "http://127.0.0.1:8080", gatewayControl: "http://127.0.0.1:8443"}, want: true},
		{name: "IPv6 loopback dev accepted", meta: k8sMeta{publicBaseURL: "http://[::1]:8080", gatewayControl: "http://[::1]:8443"}, want: true},
		{name: "localhost dev accepted", meta: k8sMeta{publicBaseURL: "http://localhost:8080", gatewayControl: "http://localhost:8443"}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := deriveControlPlaneEndpoints(tc.meta, "https://fallback.example.test")
			if tc.want && err != nil {
				t.Fatalf("deriveControlPlaneEndpoints: %v", err)
			}
			if !tc.want && (err == nil || !strings.Contains(err.Error(), "must use https")) {
				t.Fatalf("error = %v, want HTTPS rejection", err)
			}
		})
	}
}

func TestApplyNamespaceDoesNotMutateExistingAndAcceptsCreateRace(t *testing.T) {
	t.Run("existing namespace is read only", func(t *testing.T) {
		runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
			return stdout("namespace/tunnex\n"), nil
		}}
		if err := applyNamespace(context.Background(), runner, "ctx", "tunnex"); err != nil {
			t.Fatal(err)
		}
		if len(runner.commands) != 1 || strings.Contains(strings.Join(runner.commands[0].args, " "), "apply") || len(runner.commands[0].stdin) != 0 {
			t.Fatalf("existing namespace was mutated: %+v", runner.commands)
		}
	})

	t.Run("concurrent creator wins", func(t *testing.T) {
		reads := 0
		runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
			joined := strings.Join(command.args, " ")
			if strings.Contains(joined, "get namespace") {
				reads++
				if reads == 1 {
					return stdout(""), nil
				}
				return stdout("namespace/tunnex\n"), nil
			}
			if strings.Contains(joined, "create namespace") {
				return k8sCommandResult{stderr: []byte("AlreadyExists")}, errors.New("exit 1")
			}
			return k8sCommandResult{}, nil
		}}
		if err := applyNamespace(context.Background(), runner, "ctx", "tunnex"); err != nil {
			t.Fatalf("create race: %v", err)
		}
		for _, command := range runner.commands {
			if strings.Contains(strings.Join(command.args, " "), "apply") || len(command.stdin) != 0 {
				t.Fatalf("namespace race used invasive apply: %+v", command)
			}
		}
	})
}

func TestK8sInstallKeepsTokenOnlyInKubectlSecretStdin(t *testing.T) {
	cp := baseK8sControlPlane()
	runner := &fakeK8sRunner{handler: baseRunnerHandler}
	var out bytes.Buffer
	deps := baseK8sDeps(runner, cp, &out, &bytes.Buffer{})
	if err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps); err != nil {
		t.Fatalf("install: %v", err)
	}
	if cp.issueCount != 1 || cp.issuedName != "aks-gateway-a" || cp.issuedOrg != cp.orgs[0].id {
		t.Fatalf("token mint = count %d org %q name %q", cp.issueCount, cp.issuedOrg, cp.issuedName)
	}
	secretStdin := 0
	helmIndex, rolloutIndex, serviceIndex, deleteIndex := -1, -1, -1, -1
	for i, command := range runner.commands {
		joined := command.name + " " + strings.Join(command.args, " ")
		if strings.Contains(joined, testJoinToken) {
			t.Fatalf("join token leaked into argv: %s", joined)
		}
		if bytes.Contains(command.stdin, []byte(testJoinToken)) {
			secretStdin++
			if command.name != "kubectl" || !strings.Contains(joined, "create -f -") || !bytes.Contains(command.stdin, []byte(`"kind":"Secret"`)) || !bytes.Contains(command.stdin, []byte(`"immutable":true`)) {
				t.Fatalf("token was sent outside Secret stdin: %s stdin=%s", joined, command.stdin)
			}
		}
		if command.name == "helm" && strings.Contains(joined, "install tunnex-gateway") {
			helmIndex = i
			if !strings.Contains(joined, "--description "+zeroTouchContract) || strings.Contains(joined, "joinToken") || bytes.Contains(command.stdin, []byte("joinToken")) || !bytes.Contains(command.stdin, []byte(`"existingSecret":"tunnex-gateway-bootstrap"`)) || !bytes.Contains(command.stdin, []byte(`"wireguard":{"port":51820}`)) {
				t.Fatalf("unsafe Helm values: %s stdin=%s", joined, command.stdin)
			}
		}
		if strings.Contains(joined, "rollout status") {
			rolloutIndex = i
		}
		if strings.Contains(joined, "get service") {
			serviceIndex = i
		}
		if strings.Contains(joined, "delete --raw=/api/v1/namespaces/tunnex/secrets/tunnex-gateway-bootstrap") {
			deleteIndex = i
		}
	}
	if secretStdin != 1 {
		t.Fatalf("token appeared in %d stdin payloads, want exactly one", secretStdin)
	}
	if helmIndex < 0 || rolloutIndex < helmIndex || serviceIndex < rolloutIndex || deleteIndex < serviceIndex {
		t.Fatalf("unsafe install ordering helm=%d rollout=%d service=%d delete=%d", helmIndex, rolloutIndex, serviceIndex, deleteIndex)
	}
	if strings.Contains(out.String(), testJoinToken) || strings.Contains(out.String(), "stored-login-token") {
		t.Fatalf("install output leaked a token:\n%s", out.String())
	}
}

func TestK8sInstallFailureRetainsSecretAndRedactsToken(t *testing.T) {
	cp := baseK8sControlPlane()
	runner := &fakeK8sRunner{}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		if command.name == "helm" && strings.HasPrefix(strings.Join(command.args, " "), "install tunnex-gateway ") {
			return k8sCommandResult{stderr: []byte("bad install " + testJoinToken)}, errors.New("exit 1")
		}
		return baseRunnerHandler(command)
	}
	var out bytes.Buffer
	deps := baseK8sDeps(runner, cp, &out, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), `bootstrap Secret "tunnex-gateway-bootstrap" was retained`) {
		t.Fatalf("install error = %v", err)
	}
	if strings.Contains(err.Error(), testJoinToken) || strings.Contains(out.String(), testJoinToken) {
		t.Fatalf("failure leaked token: err=%v out=%s", err, out.String())
	}
	for _, command := range runner.commands {
		if strings.Contains(strings.Join(command.args, " "), "/secrets/tunnex-gateway-bootstrap") {
			t.Fatalf("failure deleted retry Secret: %+v", command)
		}
	}
}

func TestK8sInstallRefusesExistingReleaseTakeover(t *testing.T) {
	cp := baseK8sControlPlane()
	runner := &fakeK8sRunner{handler: installedRunnerHandler}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "anchorless completion replay is unsafe") {
		t.Fatalf("existing release error = %v", err)
	}
	if cp.issueCount != 0 {
		t.Fatalf("existing release minted %d tokens", cp.issueCount)
	}
	for _, command := range runner.commands {
		if command.name == "helm" && strings.HasPrefix(strings.Join(command.args, " "), "install ") {
			t.Fatalf("existing release was taken over: %+v", command)
		}
	}
}

func TestK8sInstallResumesPostHelmVerificationWithoutTokenAccess(t *testing.T) {
	cp := baseK8sControlPlane()
	cp.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{claim: testLifecycleClaim, state: "consumed", nodeName: "aks-gateway-a", generation: 1, requestID: testLifecycleRequest, expiresAt: testLifecycleExpiry, nodeID: testLifecycleNodeID}
	rolloutAttempts := 0
	anchor := testCompletedLifecycleAnchor(cp, "tunnex-gateway", "aks-gateway-a")
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "get secret tunnex-gateway-bootstrap") {
			return stdout(bootstrapSecretMetadataLine("tunnex-gateway")), nil
		}
		if command.name == "kubectl" && strings.Contains(joined, "get pvc tunnex-gateway-tunnex-gateway-state") && strings.Contains(joined, "--ignore-not-found=true") {
			return stdout(readyPVCJSON("tunnex-gateway-tunnex-gateway-state", "tunnex-gateway")), nil
		}
		if command.name == "kubectl" && strings.Contains(joined, "rollout status") {
			rolloutAttempts++
			if rolloutAttempts == 1 {
				return k8sCommandResult{stderr: []byte("transient apiserver timeout")}, errors.New("exit 1")
			}
		}
		return installedRunnerHandler(command)
	}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "retained") {
		t.Fatalf("transient resume error = %v", err)
	}
	var out bytes.Buffer
	deps.out = &out
	if err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps); err != nil {
		t.Fatalf("verification retry: %v", err)
	}
	if cp.issueCount != 0 || cp.metaCount == 0 || cp.orgCount == 0 {
		t.Fatalf("resume control-plane proof calls token=%d meta=%d orgs=%d", cp.issueCount, cp.metaCount, cp.orgCount)
	}
	if !strings.Contains(out.String(), "No token was read or minted") {
		t.Fatalf("resume output did not state token-blind cleanup:\n%s", out.String())
	}
	for _, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		if command.name == "helm" && strings.HasPrefix(joined, "install ") {
			t.Fatalf("resume attempted Helm install: %+v", command)
		}
		if command.name == "kubectl" && strings.Contains(joined, "get secret") && !strings.Contains(joined, "jsonpath=") {
			t.Fatalf("resume read Secret body: %+v", command)
		}
		if bytes.Contains(command.stdin, []byte(testJoinToken)) {
			t.Fatalf("resume transported token: %+v", command)
		}
	}
}

func TestK8sInstallRetriesOwnedSecretDeleteAfterReadyRelease(t *testing.T) {
	cp := baseK8sControlPlane()
	cp.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{claim: testLifecycleClaim, state: "consumed", nodeName: "aks-gateway-a", generation: 1, requestID: testLifecycleRequest, expiresAt: testLifecycleExpiry, nodeID: testLifecycleNodeID}
	deleteAttempts := 0
	anchor := testCompletedLifecycleAnchor(cp, "tunnex-gateway", "aks-gateway-a")
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "get secret tunnex-gateway-bootstrap") {
			return stdout(bootstrapSecretMetadataLine("tunnex-gateway")), nil
		}
		if command.name == "kubectl" && strings.Contains(joined, "get pvc tunnex-gateway-tunnex-gateway-state") && strings.Contains(joined, "--ignore-not-found=true") {
			return stdout(readyPVCJSON("tunnex-gateway-tunnex-gateway-state", "tunnex-gateway")), nil
		}
		if command.name == "kubectl" && strings.Contains(joined, "delete --raw=/api/v1/namespaces/tunnex/secrets/tunnex-gateway-bootstrap") {
			deleteAttempts++
			if deleteAttempts == 1 {
				return k8sCommandResult{stderr: []byte("transient delete conflict")}, errors.New("exit 1")
			}
			if !bytes.Contains(command.stdin, []byte(`"uid":"uid-tunnex-gateway-bootstrap"`)) || !bytes.Contains(command.stdin, []byte(`"resourceVersion":"17"`)) {
				t.Fatalf("delete lacks Secret CAS preconditions: %s", command.stdin)
			}
		}
		return installedRunnerHandler(command)
	}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "rerun the same install command") {
		t.Fatalf("delete retry error = %v", err)
	}
	if err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps); err != nil {
		t.Fatalf("delete retry: %v", err)
	}
	if deleteAttempts != 2 || cp.issueCount != 0 || cp.metaCount == 0 || cp.orgCount == 0 {
		t.Fatalf("delete attempts=%d control-plane calls token=%d meta=%d orgs=%d", deleteAttempts, cp.issueCount, cp.metaCount, cp.orgCount)
	}
}

func TestK8sInstallRefusesOrphanClaimWithoutRetrySecret(t *testing.T) {
	cp := baseK8sControlPlane()
	runner := &fakeK8sRunner{}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "get pvc tunnex-gateway-tunnex-gateway-state") && strings.Contains(joined, "--ignore-not-found=true") {
			return stdout(readyPVCJSON("tunnex-gateway-tunnex-gateway-state", "tunnex-gateway")), nil
		}
		return baseRunnerHandler(command)
	}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "without retry Secret") || !strings.Contains(err.Error(), "--mode reuse") {
		t.Fatalf("orphan claim error = %v", err)
	}
	if cp.issueCount != 0 {
		t.Fatalf("orphan claim minted %d tokens", cp.issueCount)
	}
}

func TestK8sInstallReusesOwnedRetrySecretWithoutReadingOrMinting(t *testing.T) {
	cp := baseK8sControlPlane()
	cp.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{claim: testLifecycleClaim, state: "issued", nodeName: "aks-gateway-a", generation: 1, requestID: testLifecycleRequest, expiresAt: testLifecycleExpiry}
	anchor := testLifecycleAnchor("tunnex-gateway", "aks-gateway-a", "issued")
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "get secret tunnex-gateway-bootstrap") {
			return stdout(bootstrapSecretMetadataLine("tunnex-gateway")), nil
		}
		if command.name == "kubectl" && strings.Contains(joined, "get pvc tunnex-gateway-tunnex-gateway-state") && strings.Contains(joined, "--ignore-not-found=true") {
			return stdout(readyPVCJSON("tunnex-gateway-tunnex-gateway-state", "tunnex-gateway")), nil
		}
		return baseRunnerHandler(command)
	}
	var out bytes.Buffer
	deps := baseK8sDeps(runner, cp, &out, &bytes.Buffer{})
	if err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps); err != nil {
		t.Fatalf("retry install: %v", err)
	}
	if cp.issueCount != 0 {
		t.Fatalf("retry minted %d tokens", cp.issueCount)
	}
	if !strings.Contains(out.String(), "bounded retry using existing Tunnex-owned Secret") {
		t.Fatalf("retry plan did not disclose state:\n%s", out.String())
	}
	foundHelm := false
	for _, command := range runner.commands {
		joined := command.name + " " + strings.Join(command.args, " ")
		readsSecretJSON := false
		for _, arg := range command.args {
			if arg == "json" {
				readsSecretJSON = true
			}
		}
		if strings.Contains(joined, "get secret") && (readsSecretJSON || !strings.Contains(joined, "jsonpath=")) {
			t.Fatalf("retry read Secret body: %s", joined)
		}
		if command.name == "kubectl" && strings.Contains(joined, "create -f -") && bytes.Contains(command.stdin, []byte(`"kind":"Secret"`)) {
			t.Fatalf("retry overwrote Secret: %s", command.stdin)
		}
		if command.name == "helm" && strings.HasPrefix(strings.Join(command.args, " "), "install tunnex-gateway ") {
			foundHelm = true
			if !bytes.Contains(command.stdin, []byte(`"existingSecret":"tunnex-gateway-bootstrap"`)) {
				t.Fatalf("retry did not reference existing Secret: %s", command.stdin)
			}
		}
	}
	if !foundHelm {
		t.Fatal("retry never ran Helm install")
	}
}

func TestK8sInstallRecoversExactPendingRotationAfterAnchorCAS(t *testing.T) {
	expiredAt := time.Now().Add(-time.Hour).UTC()
	anchor := testLifecycleAnchor("tunnex-gateway", "aks-gateway-a", "acknowledged")
	anchor.requestID, anchor.expiresAt = testLifecycleOldReq, expiredAt
	cp := baseK8sControlPlane()
	cp.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{claim: testLifecycleClaim, state: "expired", nodeName: "aks-gateway-a", generation: 1, requestID: testLifecycleOldReq, expiresAt: expiredAt}
	deleteAttempts := 0
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "get secret tunnex-gateway-bootstrap") {
			return stdout(bootstrapSecretMetadataLineWith("tunnex-gateway", testLifecycleClaim, testLifecycleOldReq, 1, expiredAt)), nil
		}
		if command.name == "kubectl" && strings.Contains(joined, "get pvc tunnex-gateway-tunnex-gateway-state") && strings.Contains(joined, "--ignore-not-found=true") {
			return stdout(readyPVCJSON("tunnex-gateway-tunnex-gateway-state", "tunnex-gateway")), nil
		}
		if command.name == "kubectl" && strings.Contains(joined, "delete --raw=/api/v1/namespaces/tunnex/secrets/tunnex-gateway-bootstrap") {
			deleteAttempts++
			if deleteAttempts == 1 {
				return k8sCommandResult{stderr: []byte("simulated crash after pending anchor CAS")}, errors.New("exit 1")
			}
		}
		return baseRunnerHandler(command)
	}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "CAS-delete expired bootstrap Secret") {
		t.Fatalf("pending-anchor crash error = %v", err)
	}
	pending := runner.anchors[anchor.name]
	if pending.state != "pending" || pending.requestID != testLifecycleRequest || pending.expectedGeneration != 1 || pending.generation != 1 || cp.issueCount != 0 {
		t.Fatalf("persisted pending transition = %+v, mint_count=%d", pending, cp.issueCount)
	}
	if err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps); err != nil {
		t.Fatalf("pending-anchor recovery: %v", err)
	}
	if cp.issueCount != 1 || deleteAttempts < 3 {
		t.Fatalf("pending recovery mint/delete counts = %d/%d", cp.issueCount, deleteAttempts)
	}
}

func TestK8sInstallRecoversAfterExpiredSecretDeleteBeforeRemint(t *testing.T) {
	expiredAt := time.Now().Add(-time.Hour).UTC()
	anchor := testLifecycleAnchor("tunnex-gateway", "aks-gateway-a", "pending")
	anchor.requestID, anchor.expectedGeneration, anchor.generation, anchor.expiresAt = testLifecycleRequest, 1, 1, expiredAt
	cp := baseK8sControlPlane()
	cp.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{claim: testLifecycleClaim, state: "expired", nodeName: "aks-gateway-a", generation: 1, requestID: testLifecycleOldReq, expiresAt: expiredAt}
	cp.remintFailures = 1
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}, handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "get pvc tunnex-gateway-tunnex-gateway-state") && strings.Contains(joined, "--ignore-not-found=true") {
			return stdout(readyPVCJSON("tunnex-gateway-tunnex-gateway-state", "tunnex-gateway")), nil
		}
		return baseRunnerHandler(command)
	}}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	if err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps); err == nil || !strings.Contains(err.Error(), "transient lifecycle remint failure") {
		t.Fatalf("post-delete remint crash error = %v", err)
	}
	if err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps); err != nil {
		t.Fatalf("post-delete pending recovery: %v", err)
	}
}

func TestK8sInstallRedeliversAfterCPRemintBeforeSecretCreate(t *testing.T) {
	anchor := testLifecycleAnchor("tunnex-gateway", "aks-gateway-a", "pending")
	anchor.expectedGeneration, anchor.generation, anchor.expiresAt = 1, 1, time.Now().Add(-time.Hour).UTC()
	cp := baseK8sControlPlane()
	cp.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{claim: testLifecycleClaim, state: "issued", nodeName: "aks-gateway-a", generation: 2, requestID: testLifecycleRequest, expiresAt: testLifecycleExpiry}
	createAttempts := 0
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}, handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "get pvc tunnex-gateway-tunnex-gateway-state") && strings.Contains(joined, "--ignore-not-found=true") {
			return stdout(readyPVCJSON("tunnex-gateway-tunnex-gateway-state", "tunnex-gateway")), nil
		}
		if command.name == "kubectl" && strings.Contains(joined, "create -f -") && bytes.Contains(command.stdin, []byte(`"kind":"Secret"`)) {
			createAttempts++
			if createAttempts == 1 {
				return k8sCommandResult{stderr: []byte("simulated crash before Secret create")}, errors.New("exit 1")
			}
		}
		return baseRunnerHandler(command)
	}}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	if err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps); err == nil || !strings.Contains(err.Error(), "recover the same sealed response") {
		t.Fatalf("post-remint Secret crash error = %v", err)
	}
	issued := runner.anchors[anchor.name]
	if issued.state != "issued" || issued.generation != 2 || issued.requestID != testLifecycleRequest {
		t.Fatalf("post-remint anchor = %+v", issued)
	}
	if err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps); err != nil {
		t.Fatalf("sealed response recovery: %v", err)
	}
	if cp.issueCount != 0 || createAttempts != 2 {
		t.Fatalf("redelivery minted=%d create_attempts=%d", cp.issueCount, createAttempts)
	}
}

func TestK8sInstallRotatesExpiredSealedResponseAfterCPMintBeforeSecret(t *testing.T) {
	expiredAt := time.Now().Add(-time.Hour).UTC()
	anchor := testLifecycleAnchor("tunnex-gateway", "aks-gateway-a", "pending")
	anchor.requestID, anchor.expectedGeneration, anchor.generation, anchor.expiresAt = testLifecycleOldReq, 1, 1, expiredAt
	cp := baseK8sControlPlane()
	cp.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{
		claim: testLifecycleClaim, state: "expired", nodeName: "aks-gateway-a", generation: 2, requestID: testLifecycleOldReq, expiresAt: expiredAt,
	}
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}, handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "get pvc tunnex-gateway-tunnex-gateway-state") && strings.Contains(joined, "--ignore-not-found=true") {
			return stdout(readyPVCJSON("tunnex-gateway-tunnex-gateway-state", "tunnex-gateway")), nil
		}
		return baseRunnerHandler(command)
	}}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	if err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps); err != nil {
		t.Fatalf("expired sealed response recovery: %v", err)
	}
	if cp.issueCount != 1 {
		t.Fatalf("fresh generation mints = %d, want one", cp.issueCount)
	}
	foundGenerationThree := false
	for _, command := range runner.commands {
		if command.name == "kubectl" && bytes.Contains(command.stdin, []byte(`"kind":"Secret"`)) {
			if bytes.Contains(command.stdin, []byte(`"tunnex.io/lifecycle-request-id":"`+testLifecycleRequest+`"`)) && bytes.Contains(command.stdin, []byte(`"tunnex.io/lifecycle-generation":"3"`)) {
				foundGenerationThree = true
			}
			if bytes.Contains(command.stdin, []byte(expiredAt.Format(time.RFC3339Nano))) {
				t.Fatalf("expired sealed response reached Secret transport: %s", command.stdin)
			}
		}
	}
	if !foundGenerationThree {
		t.Fatal("replacement immutable Secret did not carry the fresh request/generation")
	}
}

func TestK8sInstallRejectsExpiredRemintResponseBeforeSecretTransport(t *testing.T) {
	expiredAt := time.Now().Add(-time.Minute).UTC()
	cp := baseK8sControlPlane()
	cp.remintOverride = &k8sLifecycleRemintResult{
		claim: testLifecycleClaim, joinToken: testJoinToken, generation: 1, requestID: testLifecycleRequest, expiresAt: expiredAt,
	}
	runner := &fakeK8sRunner{handler: baseRunnerHandler}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "did not match the persisted lifecycle request") {
		t.Fatalf("expired remint error = %v", err)
	}
	for _, command := range runner.commands {
		if command.name == "kubectl" && bytes.Contains(command.stdin, []byte(`"kind":"Secret"`)) {
			t.Fatalf("expired raw token reached Secret stdin: %s", command.stdin)
		}
	}
}

func TestK8sInstallSecretCreateIsAtomicAndConcurrencyFailureDoesNotOverwrite(t *testing.T) {
	cp := baseK8sControlPlane()
	runner := &fakeK8sRunner{}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "create -f -") && bytes.Contains(command.stdin, []byte(`"kind":"Secret"`)) {
			return k8sCommandResult{stderr: []byte("AlreadyExists " + testJoinToken)}, errors.New("exit 1")
		}
		return baseRunnerHandler(command)
	}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "not read or overwritten") || strings.Contains(err.Error(), testJoinToken) {
		t.Fatalf("create concurrency error = %v", err)
	}
	for _, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		if strings.Contains(joined, "apply -f -") && bytes.Contains(command.stdin, []byte(`"kind":"Secret"`)) {
			t.Fatalf("Secret used overwrite-capable apply: %+v", command)
		}
		if command.name == "helm" && strings.HasPrefix(joined, "install ") {
			t.Fatalf("Helm ran after Secret create conflict: %+v", command)
		}
	}
}

func TestK8sReuseMintsNoTokenAndUsesExactClaim(t *testing.T) {
	cp := baseK8sControlPlane()
	runner := &fakeK8sRunner{}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		if command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "get deployment") {
			return stdout(readyDeploymentJSON("tunnex-gateway", "retained-state-a")), nil
		}
		return baseRunnerHandler(command)
	}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--mode", "reuse", "--existing-claim", "retained-state-a", "--yes"}, deps)
	if err != nil {
		t.Fatalf("reuse: %v", err)
	}
	if cp.issueCount != 0 {
		t.Fatalf("reuse minted %d tokens", cp.issueCount)
	}
	for _, command := range runner.commands {
		joined := command.name + " " + strings.Join(command.args, " ")
		if bytes.Contains(command.stdin, []byte("TUNNEX_JOIN_TOKEN")) || strings.Contains(joined, "delete secret") || strings.Contains(joined, "enrollment.existingSecret") || bytes.Contains(command.stdin, []byte("existingSecret")) {
			t.Fatalf("reuse touched bootstrap secret: %s stdin=%s", joined, command.stdin)
		}
		if command.name == "helm" && strings.Contains(joined, "install tunnex-gateway") {
			if !bytes.Contains(command.stdin, []byte(`"mode":"reuse"`)) || !bytes.Contains(command.stdin, []byte(`"existingClaim":"retained-state-a"`)) {
				t.Fatalf("reuse Helm values missing exact state: %s stdin=%s", joined, command.stdin)
			}
		}
	}
}

func TestK8sReuseRejectsCrossReleaseAndLiveMountedClaims(t *testing.T) {
	t.Run("cross release", func(t *testing.T) {
		runner := &fakeK8sRunner{}
		runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
			if command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "get pvc retained-state-a") {
				return stdout(readyLegacyPVCJSON("retained-state-a", "gateway-a")), nil
			}
			return baseRunnerHandler(command)
		}
		deps := baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})
		err := runK8s(context.Background(), []string{"install", "--release", "gateway-b", "--node-name", "gateway-b", "--mode", "reuse", "--existing-claim", "retained-state-a", "--yes"}, deps)
		if err == nil || !strings.Contains(err.Error(), "cross-release identity reuse") {
			t.Fatalf("cross-release error = %v", err)
		}
	})

	t.Run("live mounted", func(t *testing.T) {
		runner := &fakeK8sRunner{}
		runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
			joined := strings.Join(command.args, " ")
			if command.name == "kubectl" && strings.Contains(joined, "get pvc retained-state-a") {
				return stdout(readyLegacyPVCJSON("retained-state-a", "gateway-a")), nil
			}
			if command.name == "kubectl" && strings.Contains(joined, "get pods") {
				return stdout(`{"items":[` + claimPodJSON("live-gateway-a", "Running", "", "Deployment", "gateway-a", "retained-state-a") + `]}`), nil
			}
			return baseRunnerHandler(command)
		}
		deps := baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})
		err := runK8s(context.Background(), []string{"install", "--release", "gateway-a", "--node-name", "gateway-a", "--mode", "reuse", "--existing-claim", "retained-state-a", "--yes"}, deps)
		if err == nil || !strings.Contains(err.Error(), "still mounted by Pod") {
			t.Fatalf("live mounted error = %v", err)
		}
	})
}

func TestK8sReuseUsesLivePodsAsAuthoritativeClaimGuard(t *testing.T) {
	cases := []struct {
		name               string
		pod                string
		wantErrorSubstring string
	}{
		{
			name:               "terminating stateful pod",
			pod:                claimPodJSON("gateway-0", "Running", "2026-08-30T12:00:00Z", "StatefulSet", "gateway", "retained-state-a"),
			wantErrorSubstring: "terminating",
		},
		{
			name:               "standalone pod",
			pod:                claimPodJSON("manual-gateway", "Pending", "", "", "", "retained-state-a"),
			wantErrorSubstring: "owner standalone",
		},
		{
			name:               "job owned pod",
			pod:                claimPodJSON("gateway-job-abc", "Unknown", "", "Job", "gateway-job", "retained-state-a"),
			wantErrorSubstring: "owner Job/gateway-job",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeK8sRunner{}
			runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
				joined := strings.Join(command.args, " ")
				if command.name == "kubectl" && strings.Contains(joined, "get pvc retained-state-a") {
					return stdout(readyPVCJSON("retained-state-a", "gateway-a")), nil
				}
				if command.name == "kubectl" && strings.Contains(joined, "get pods") {
					return stdout(`{"items":[` + tc.pod + `]}`), nil
				}
				return baseRunnerHandler(command)
			}
			deps := baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})
			err := runK8s(context.Background(), []string{"install", "--release", "gateway-a", "--node-name", "gateway-a", "--mode", "reuse", "--existing-claim", "retained-state-a", "--yes"}, deps)
			if err == nil || !strings.Contains(err.Error(), tc.wantErrorSubstring) {
				t.Fatalf("error = %v, want %q", err, tc.wantErrorSubstring)
			}
		})
	}

	t.Run("terminal pods are safe to ignore", func(t *testing.T) {
		runner := &fakeK8sRunner{}
		runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
			joined := strings.Join(command.args, " ")
			if command.name == "kubectl" && strings.Contains(joined, "get deployment") {
				return stdout(readyDeploymentJSON("tunnex-gateway", "retained-state-a")), nil
			}
			if command.name == "kubectl" && strings.Contains(joined, "get pvc retained-state-a") {
				return stdout(readyLegacyPVCJSON("retained-state-a", "gateway-a")), nil
			}
			if command.name == "kubectl" && strings.Contains(joined, "get pods") {
				return stdout(`{"items":[` +
					claimPodJSON("completed-job", "Succeeded", "", "Job", "gateway-job", "retained-state-a") + `,` +
					claimPodJSON("failed-job", "Failed", "", "Job", "gateway-job", "retained-state-a") + `]}`), nil
			}
			return baseRunnerHandler(command)
		}
		cp := baseK8sControlPlane()
		deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
		if err := runK8s(context.Background(), []string{"install", "--release", "gateway-a", "--node-name", "gateway-a", "--mode", "reuse", "--existing-claim", "retained-state-a", "--yes"}, deps); err != nil {
			t.Fatalf("terminal pods should not block reuse: %v", err)
		}
		if cp.issueCount != 0 {
			t.Fatalf("reuse minted %d tokens", cp.issueCount)
		}
	})
}

func TestK8sNodePortUsesAndVerifiesExplicitEndpointPort(t *testing.T) {
	cp := baseK8sControlPlane()
	runner := &fakeK8sRunner{}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		if command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "get service") {
			return stdout(readyServiceJSON("tunnex-gateway", "NodePort")), nil
		}
		return baseRunnerHandler(command)
	}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	if err := runK8s(context.Background(), []string{"install", "--node-name", "baremetal-gateway", "--service-type", "NodePort", "--endpoint", "node.example.test:30182", "--node-port", "30182", "--yes"}, deps); err != nil {
		t.Fatalf("NodePort install: %v", err)
	}
	for _, command := range runner.commands {
		if command.name == "helm" && strings.HasPrefix(strings.Join(command.args, " "), "install tunnex-gateway ") {
			if !bytes.Contains(command.stdin, []byte(`"nodePort":30182`)) || !bytes.Contains(command.stdin, []byte(`"endpoint":"node.example.test:30182"`)) || !bytes.Contains(command.stdin, []byte(`"wireguard":{"port":51820}`)) {
				t.Fatalf("NodePort endpoint was not bound to Service port: %s", command.stdin)
			}
			return
		}
	}
	t.Fatal("Helm install command not found")
}

func TestDevBuildRequiresExplicitOCIChartVersionOrLocalChart(t *testing.T) {
	deps := k8sDeps{errOut: &bytes.Buffer{}, defaultChart: DefaultK8sGatewayChart, buildVersion: "dev"}.normalized()
	if _, err := parseInstallOptions([]string{"--node-name", "gateway-a"}, deps); err == nil || !strings.Contains(err.Error(), "cannot guess") {
		t.Fatalf("dev default error = %v", err)
	}
	if _, err := parseInstallOptions([]string{"--node-name", "gateway-a", "--chart-version", "0.2.0"}, deps); err != nil {
		t.Fatalf("explicit OCI version: %v", err)
	}
	if options, err := parseInstallOptions([]string{"--node-name", "gateway-a", "--chart", "../../deploy/helm/tunnex-gateway"}, deps); err != nil || options.chartVersion != "" {
		t.Fatalf("local chart = %+v err=%v", options, err)
	}
}

func TestK8sNodePortRequiresExplicitMatchingSelection(t *testing.T) {
	deps := baseK8sDeps(&fakeK8sRunner{handler: baseRunnerHandler}, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})
	for _, args := range [][]string{
		{"install", "--node-name", "baremetal-gateway", "--service-type", "NodePort", "--endpoint", "node.example.test:30182", "--yes"},
		{"install", "--node-name", "baremetal-gateway", "--service-type", "NodePort", "--endpoint", "node.example.test:30182", "--node-port", "30183", "--yes"},
	} {
		if err := runK8s(context.Background(), args, deps); err == nil || !strings.Contains(err.Error(), "--node-port") {
			t.Fatalf("args %v error = %v, want explicit nodePort rejection", args, err)
		}
	}
}

func TestK8sLoadBalancerExplicitEndpointMustMatchWireGuardPort(t *testing.T) {
	deps := baseK8sDeps(&fakeK8sRunner{handler: baseRunnerHandler}, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})
	if _, err := parseInstallOptions([]string{"--node-name", "gateway-a", "--endpoint", "lb.example.test:51820"}, deps); err != nil {
		t.Fatalf("matching LoadBalancer endpoint: %v", err)
	}
	if _, err := parseInstallOptions([]string{"--node-name", "gateway-a", "--endpoint", "lb.example.test:9999"}, deps); err == nil || !strings.Contains(err.Error(), "wireguard") {
		t.Fatalf("mismatched LoadBalancer endpoint error = %v", err)
	}
}

func TestK8sStatusReportsRealReadinessAndEndpoint(t *testing.T) {
	cp := baseK8sControlPlane()
	runner := &fakeK8sRunner{handler: installedRunnerHandler}
	var out bytes.Buffer
	deps := baseK8sDeps(runner, cp, &out, &bytes.Buffer{})
	if err := runK8s(context.Background(), []string{"status"}, deps); err != nil {
		t.Fatalf("status: %v", err)
	}
	for _, want := range []string{`"status": "deployed"`, `"ready": 1`, `"endpoint": "203.0.113.7:51820"`, `"state_claim": "tunnex-gateway-tunnex-gateway-state"`} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("status lacks %s:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), testJoinToken) {
		t.Fatalf("status leaked token: %s", out.String())
	}
}

func TestK8sUpgradeIsAtomicWaitsAndUsesNonSecretValuesStdin(t *testing.T) {
	cp := baseK8sControlPlane()
	runner := &fakeK8sRunner{handler: installedRunnerHandler}
	var out bytes.Buffer
	deps := baseK8sDeps(runner, cp, &out, &bytes.Buffer{})
	if err := runK8s(context.Background(), []string{"upgrade", "--yes"}, deps); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	found := false
	materializedChart := ""
	for _, command := range runner.commands {
		joined := command.name + " " + strings.Join(command.args, " ")
		if command.name == "helm" && len(command.args) > 2 && command.args[0] == "show" && command.args[1] == "chart" {
			materializedChart = command.args[2]
		}
		if command.name == "helm" && strings.HasPrefix(strings.Join(command.args, " "), "upgrade tunnex-gateway ") {
			found = true
			for _, flag := range []string{"--description " + zeroTouchContract, "--reset-then-reuse-values", "--atomic", "--wait", "--values -"} {
				if !strings.Contains(joined, flag) {
					t.Fatalf("upgrade missing %q: %s", flag, joined)
				}
			}
			if strings.Contains(joined, "--version") || filepath.Ext(command.args[2]) != ".tgz" {
				t.Fatalf("upgrade did not use the exact materialized chart without refetch flags: %s", joined)
			}
			if command.args[2] != materializedChart {
				t.Fatalf("upgrade used %q, want exact approved artifact %q", command.args[2], materializedChart)
			}
			if !bytes.Contains(command.stdin, []byte(`"digest":"sha256:aaaaaaaa`)) || bytes.Contains(command.stdin, []byte(testJoinToken)) {
				t.Fatalf("upgrade values are not digest-pinned/non-secret: %s", command.stdin)
			}
			for _, want := range []string{`"tag":""`, `"pullSecrets":[]`, `"pullPolicy":"IfNotPresent"`, `"preflight":""`, `"nodeSelector":{}`, `"tolerations":[]`} {
				if !bytes.Contains(command.stdin, []byte(want)) {
					t.Fatalf("upgrade values omitted authoritative empty %s: %s", want, command.stdin)
				}
			}
		}
	}
	if !found {
		t.Fatal("Helm upgrade command was not run")
	}
	if materializedChart == "" {
		t.Fatal("upgrade chart artifact was not observed")
	}
	if _, err := os.Stat(filepath.Dir(filepath.Dir(materializedChart))); !os.IsNotExist(err) {
		t.Fatalf("upgrade chart staging root remains after success: %v", err)
	}
	if cp.issueCount != 0 || strings.Contains(out.String(), testJoinToken) {
		t.Fatalf("upgrade touched join token: issue=%d output=%s", cp.issueCount, out.String())
	}
	if !strings.Contains(out.String(), `"pvc_uid": "uid-tunnex-gateway-tunnex-gateway-state"`) || !strings.Contains(out.String(), `"resource_version": "42"`) {
		t.Fatalf("upgrade plan omitted identity snapshot:\n%s", out.String())
	}
}

func TestK8sUpgradeCarriesApprovedRuntimeAndRejectsImageDrift(t *testing.T) {
	selectors := map[string]string{"pool": "gateway-a"}
	tolerations := []gatewayToleration{{Key: "dedicated", Operator: "Equal", Value: "tunnex", Effect: "NoSchedule"}}
	pullSecrets := []string{"acr-pull"}
	currentImage := "ghcr.io/tunnexio/tunnex-node-agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	targetImage := "ghcr.io/tunnexio/tunnex-node-agent:v9.8.7"

	t.Run("exact target", func(t *testing.T) {
		upgraded := false
		runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
			joined := strings.Join(command.args, " ")
			if command.name == "helm" && strings.HasPrefix(joined, "upgrade tunnex-gateway ") {
				upgraded = true
				return stdout("upgraded\n"), nil
			}
			if command.name == "kubectl" && strings.Contains(joined, "get deployment") {
				image := currentImage
				policy := "Always"
				if upgraded {
					image = targetImage
					policy = defaultNodeImagePullPolicy
				}
				body := readyDeploymentRuntimeJSON("tunnex-gateway", "tunnex-gateway-tunnex-gateway-state", image, selectors, tolerations, pullSecrets)
				return stdout(strings.Replace(body, `"imagePullPolicy":"IfNotPresent"`, `"imagePullPolicy":"`+policy+`"`, 1)), nil
			}
			return installedRunnerHandler(command)
		}}
		var out bytes.Buffer
		deps := baseK8sDeps(runner, baseK8sControlPlane(), &out, &bytes.Buffer{})
		if err := runK8s(context.Background(), []string{"upgrade", "--image", targetImage, "--yes"}, deps); err != nil {
			t.Fatalf("runtime-bound upgrade: %v", err)
		}
		for _, want := range []string{`"current_runtime"`, `"target_runtime"`, `"image": "` + currentImage + `"`, `"image": "` + targetImage + `"`, `"image_pull_policy": "Always"`, `"image_pull_policy": "IfNotPresent"`, `"pool": "gateway-a"`, `"acr-pull"`} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("upgrade plan omitted %s:\n%s", want, out.String())
			}
		}
		for _, command := range runner.commands {
			joined := strings.Join(command.args, " ")
			if command.name != "helm" || !strings.HasPrefix(joined, "upgrade tunnex-gateway ") {
				continue
			}
			for _, want := range []string{`"nodeSelector":{"pool":"gateway-a"}`, `"tolerations":[{"key":"dedicated","operator":"Equal","value":"tunnex","effect":"NoSchedule"}]`, `"pullSecrets":[{"name":"acr-pull"}]`, `"pullPolicy":"IfNotPresent"`, `"preflight":""`, `"tag":"v9.8.7"`, `"digest":""`} {
				if !bytes.Contains(command.stdin, []byte(want)) {
					t.Fatalf("upgrade values omitted approved runtime %s: %s", want, command.stdin)
				}
			}
		}
	})

	t.Run("wrong live image", func(t *testing.T) {
		mutated := false
		runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
			joined := strings.Join(command.args, " ")
			if command.name == "helm" && strings.HasPrefix(joined, "upgrade tunnex-gateway ") {
				mutated = true
				return stdout("upgraded\n"), nil
			}
			if command.name == "kubectl" && strings.Contains(joined, "get deployment") {
				return stdout(readyDeploymentRuntimeJSON("tunnex-gateway", "tunnex-gateway-tunnex-gateway-state", currentImage, selectors, tolerations, pullSecrets)), nil
			}
			return installedRunnerHandler(command)
		}}
		deps := baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})
		err := runK8s(context.Background(), []string{"upgrade", "--image", targetImage, "--yes"}, deps)
		if err == nil || !strings.Contains(err.Error(), "expected approved") {
			t.Fatalf("wrong live image error = %v", err)
		}
		if !mutated {
			t.Fatal("wrong live image regression never reached Helm upgrade")
		}
	})
}

func TestK8sUpgradeRefusesRuntimeDriftAfterApproval(t *testing.T) {
	deploymentReads := 0
	runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "get deployment") {
			deploymentReads++
			pool := "approved"
			if deploymentReads >= 2 {
				pool = "changed"
			}
			return stdout(readyDeploymentRuntimeJSON("tunnex-gateway", "tunnex-gateway-tunnex-gateway-state", "ghcr.io/tunnexio/tunnex-node-agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", map[string]string{"pool": pool}, nil, nil)), nil
		}
		return installedRunnerHandler(command)
	}}
	deps := baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"upgrade", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "changed while awaiting approval") {
		t.Fatalf("runtime CAS error = %v", err)
	}
	for _, command := range runner.commands {
		if command.name == "helm" && strings.HasPrefix(strings.Join(command.args, " "), "upgrade tunnex-gateway ") {
			t.Fatalf("runtime drift reached Helm mutation: %+v", command)
		}
	}
}

func TestK8sUpgradeRefusesPVCChangeAfterApproval(t *testing.T) {
	pvcReads := 0
	runner := &fakeK8sRunner{}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "get pvc tunnex-gateway-tunnex-gateway-state") {
			pvcReads++
			body := readyPVCJSON("tunnex-gateway-tunnex-gateway-state", "tunnex-gateway")
			if pvcReads >= 2 {
				body = strings.Replace(body, `"resourceVersion":"42"`, `"resourceVersion":"43"`, 1)
			}
			return stdout(body), nil
		}
		return installedRunnerHandler(command)
	}
	deps := baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"upgrade", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "changed while awaiting approval") {
		t.Fatalf("upgrade CAS error = %v", err)
	}
	for _, command := range runner.commands {
		if command.name == "helm" && strings.HasPrefix(strings.Join(command.args, " "), "upgrade tunnex-gateway ") {
			t.Fatalf("upgrade ran after PVC CAS change: %+v", command)
		}
	}
}

func TestK8sRollbackUsesExactRevisionAndVerifies(t *testing.T) {
	runner := &fakeK8sRunner{handler: installedRunnerHandler}
	deps := baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})
	if err := runK8s(context.Background(), []string{"rollback", "--revision", "2", "--yes"}, deps); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	helmIndex, rolloutIndex := -1, -1
	for i, command := range runner.commands {
		joined := command.name + " " + strings.Join(command.args, " ")
		if strings.Contains(joined, "helm rollback tunnex-gateway 2") {
			helmIndex = i
			if !strings.Contains(joined, "--wait") || !strings.Contains(joined, "--cleanup-on-fail") {
				t.Fatalf("rollback is not guarded: %s", joined)
			}
		}
		if strings.Contains(joined, "rollout status") {
			rolloutIndex = i
		}
	}
	if helmIndex < 0 || rolloutIndex < helmIndex {
		t.Fatalf("rollback did not verify after Helm: helm=%d rollout=%d", helmIndex, rolloutIndex)
	}
}

func TestK8sRollbackRejectsPostMutationIdentitySwap(t *testing.T) {
	pvcReads := 0
	runner := &fakeK8sRunner{}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "get pvc tunnex-gateway-tunnex-gateway-state") {
			pvcReads++
			body := readyPVCJSON("tunnex-gateway-tunnex-gateway-state", "tunnex-gateway")
			if pvcReads >= 3 {
				body = strings.Replace(body, `"uid":"uid-tunnex-gateway-tunnex-gateway-state"`, `"uid":"uid-replaced"`, 1)
			}
			return stdout(body), nil
		}
		return installedRunnerHandler(command)
	}
	deps := baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"rollback", "--revision", "2", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "state identity changed") {
		t.Fatalf("rollback identity error = %v", err)
	}
	foundRollback := false
	for _, command := range runner.commands {
		if command.name == "helm" && strings.HasPrefix(strings.Join(command.args, " "), "rollback tunnex-gateway 2") {
			foundRollback = true
		}
	}
	if !foundRollback {
		t.Fatal("rollback identity test never applied the Helm mutation")
	}
}

func TestK8sRollbackRefusesReleaseChangeAfterApproval(t *testing.T) {
	releaseReads := 0
	runner := &fakeK8sRunner{}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "helm" && strings.HasPrefix(joined, "list ") && !strings.HasPrefix(joined, "list --all-namespaces") {
			releaseReads++
			revision := "3"
			if releaseReads >= 2 {
				revision = "4"
			}
			return stdout(fmt.Sprintf(`[{"name":"tunnex-gateway","namespace":"tunnex","revision":%q,"status":"deployed","chart":"tunnex-gateway-0.2.0","app_version":"0.2.0"}]`, revision)), nil
		}
		return installedRunnerHandler(command)
	}
	deps := baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"rollback", "--revision", "2", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "changed while awaiting approval") {
		t.Fatalf("rollback release CAS error = %v", err)
	}
	for _, command := range runner.commands {
		if command.name == "helm" && strings.HasPrefix(strings.Join(command.args, " "), "rollback tunnex-gateway 2") {
			t.Fatalf("rollback ran after release revision changed: %+v", command)
		}
	}
}

func TestK8sDiagnosticsNeverReadsSecretsOrHelmValuesAndRedactsEvents(t *testing.T) {
	runner := &fakeK8sRunner{}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "get events") {
			return stdout(`{"items":[{"type":"Warning","reason":"Rejected","message":"TUNNEX_JOIN_TOKEN=event-secret","count":1}]}`), nil
		}
		return installedRunnerHandler(command)
	}
	var out bytes.Buffer
	deps := baseK8sDeps(runner, baseK8sControlPlane(), &out, &bytes.Buffer{})
	if err := runK8s(context.Background(), []string{"diagnostics"}, deps); err != nil {
		t.Fatalf("diagnostics: %v", err)
	}
	for _, command := range runner.commands {
		joined := strings.ToLower(command.name + " " + strings.Join(command.args, " "))
		if strings.Contains(joined, "helm get values") || strings.Contains(joined, "get secret") || strings.Contains(joined, "describe secret") {
			t.Fatalf("diagnostics read a secret-bearing surface: %s", joined)
		}
	}
	if strings.Contains(out.String(), "event-secret") || !strings.Contains(out.String(), "<redacted>") {
		t.Fatalf("diagnostics did not redact event secret:\n%s", out.String())
	}
}

func TestK8sUninstallRequiresAndVerifiesRetainedState(t *testing.T) {
	uninstalled := false
	runner := &fakeK8sRunner{}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "helm" && strings.HasPrefix(joined, "list ") && !strings.HasPrefix(joined, "list --all-namespaces") {
			if uninstalled {
				return stdout(`[]`), nil
			}
			return installedRunnerHandler(command)
		}
		if command.name == "helm" && strings.HasPrefix(joined, "uninstall ") {
			uninstalled = true
			return k8sCommandResult{}, nil
		}
		return installedRunnerHandler(command)
	}
	var out bytes.Buffer
	deps := baseK8sDeps(runner, baseK8sControlPlane(), &out, &bytes.Buffer{})
	if err := runK8s(context.Background(), []string{"uninstall", "--yes"}, deps); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if !strings.Contains(out.String(), `State claim "tunnex-gateway-tunnex-gateway-state" remains`) {
		t.Fatalf("uninstall did not name retained claim:\n%s", out.String())
	}
	for _, command := range runner.commands {
		if strings.Contains(strings.Join(command.args, " "), "delete pvc") {
			t.Fatalf("uninstall deleted state: %+v", command)
		}
	}
}

func TestK8sUninstallRefusesPostApprovalResourceChange(t *testing.T) {
	pvcReads := 0
	runner := &fakeK8sRunner{}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "get pvc tunnex-gateway-tunnex-gateway-state") {
			pvcReads++
			body := readyPVCJSON("tunnex-gateway-tunnex-gateway-state", "tunnex-gateway")
			if pvcReads >= 2 {
				body = strings.Replace(body, `"resourceVersion":"42"`, `"resourceVersion":"43"`, 1)
			}
			return stdout(body), nil
		}
		return installedRunnerHandler(command)
	}
	deps := baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"uninstall", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "changed while awaiting approval") {
		t.Fatalf("uninstall CAS error = %v", err)
	}
	for _, command := range runner.commands {
		if command.name == "helm" && strings.HasPrefix(strings.Join(command.args, " "), "uninstall ") {
			t.Fatalf("uninstall ran after resource change: %+v", command)
		}
	}
}

func TestK8sUninstallRefusesClaimWithoutKeepPolicy(t *testing.T) {
	runner := &fakeK8sRunner{}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		if command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "get pvc") {
			return stdout(`{"metadata":{"name":"tunnex-gateway-tunnex-gateway-state","labels":{"app.kubernetes.io/name":"tunnex-gateway","app.kubernetes.io/instance":"tunnex-gateway"}},"status":{"phase":"Bound"}}`), nil
		}
		return installedRunnerHandler(command)
	}
	deps := baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"uninstall", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "not the retained Tunnex identity claim") {
		t.Fatalf("uninstall without keep policy error = %v", err)
	}
	for _, command := range runner.commands {
		if command.name == "helm" && strings.Contains(strings.Join(command.args, " "), "uninstall") {
			t.Fatalf("unsafe uninstall executed: %+v", command)
		}
	}
}

func TestK8sPurgeRequiresAbsentReleaseExactOwnershipAndTypedConfirmation(t *testing.T) {
	newRunner := func() *fakeK8sRunner {
		runner := &fakeK8sRunner{}
		runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
			joined := strings.Join(command.args, " ")
			if command.name == "helm" && strings.HasPrefix(joined, "list ") {
				return stdout(`[]`), nil
			}
			if command.name == "kubectl" && strings.Contains(joined, "get pvc retained-state-a") {
				return stdout(readyLegacyPVCJSON("retained-state-a", "gateway-a")), nil
			}
			return baseRunnerHandler(command)
		}
		return runner
	}

	runner := newRunner()
	deps := baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"purge-state", "--release", "gateway-a", "--claim", "retained-state-a", "--legacy-without-lifecycle-proof", "--confirm", "yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "did not match exactly") {
		t.Fatalf("wrong confirmation error = %v", err)
	}
	for _, command := range runner.commands {
		if strings.Contains(strings.Join(command.args, " "), "delete pvc") {
			t.Fatalf("wrong confirmation deleted state: %+v", command)
		}
	}

	runner = newRunner()
	var out bytes.Buffer
	deps = baseK8sDeps(runner, baseK8sControlPlane(), &out, &bytes.Buffer{})
	if err := runK8s(context.Background(), []string{"purge-state", "--release", "gateway-a", "--claim", "retained-state-a", "--legacy-without-lifecycle-proof", "--confirm", "DELETE LEGACY retained-state-a"}, deps); err != nil {
		t.Fatalf("exact purge: %v", err)
	}
	foundDelete := false
	for _, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		if strings.Contains(joined, "delete --raw=/api/v1/namespaces/tunnex/persistentvolumeclaims/retained-state-a -f -") {
			foundDelete = true
			if !bytes.Contains(command.stdin, []byte(`"uid":"uid-retained-state-a"`)) ||
				!bytes.Contains(command.stdin, []byte(`"resourceVersion":"42"`)) {
				t.Fatalf("purge delete lacked exact UID/resourceVersion preconditions: %s", command.stdin)
			}
		}
	}
	if !foundDelete || !strings.Contains(out.String(), "cannot be recovered") {
		t.Fatalf("purge evidence missing delete=%v output=%s", foundDelete, out.String())
	}
}

func TestK8sPurgeRefusesLiveMountAndConfirmationRace(t *testing.T) {
	t.Run("live mount", func(t *testing.T) {
		runner := &fakeK8sRunner{}
		runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
			joined := strings.Join(command.args, " ")
			switch {
			case command.name == "helm" && strings.HasPrefix(joined, "list "):
				return stdout(`[]`), nil
			case command.name == "kubectl" && strings.Contains(joined, "get pvc retained-state-a"):
				return stdout(readyLegacyPVCJSON("retained-state-a", "gateway-a")), nil
			case command.name == "kubectl" && strings.Contains(joined, "get pods"):
				return stdout(`{"items":[` + claimPodJSON("old-gateway", "Running", "2026-08-30T00:00:00Z", "ReplicaSet", "old", "retained-state-a") + `]}`), nil
			default:
				return baseRunnerHandler(command)
			}
		}
		deps := baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})
		err := runK8s(context.Background(), []string{"purge-state", "--release", "gateway-a", "--claim", "retained-state-a", "--legacy-without-lifecycle-proof", "--confirm", "DELETE LEGACY retained-state-a"}, deps)
		if err == nil || !strings.Contains(err.Error(), "still mounted") {
			t.Fatalf("live mount purge error = %v", err)
		}
	})

	t.Run("PVC changed after approval", func(t *testing.T) {
		reads := 0
		runner := &fakeK8sRunner{}
		runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
			joined := strings.Join(command.args, " ")
			switch {
			case command.name == "helm" && strings.HasPrefix(joined, "list "):
				return stdout(`[]`), nil
			case command.name == "kubectl" && strings.Contains(joined, "get pvc retained-state-a"):
				reads++
				body := readyLegacyPVCJSON("retained-state-a", "gateway-a")
				if reads == 2 {
					body = strings.Replace(body, `"resourceVersion":"42"`, `"resourceVersion":"43"`, 1)
				}
				return stdout(body), nil
			case command.name == "kubectl" && strings.Contains(joined, "get pods"):
				return stdout(`{"items":[]}`), nil
			default:
				return baseRunnerHandler(command)
			}
		}
		deps := baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})
		err := runK8s(context.Background(), []string{"purge-state", "--release", "gateway-a", "--claim", "retained-state-a", "--legacy-without-lifecycle-proof", "--confirm", "DELETE LEGACY retained-state-a"}, deps)
		if err == nil || !strings.Contains(err.Error(), "changed while awaiting confirmation") {
			t.Fatalf("PVC race purge error = %v", err)
		}
		for _, command := range runner.commands {
			if strings.Contains(strings.Join(command.args, " "), "/persistentvolumeclaims/") {
				t.Fatalf("raced purge issued PVC delete: %+v", command)
			}
		}
	})
}
