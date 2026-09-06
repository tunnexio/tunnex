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

type d13eK8sControlPlane struct {
	*fakeK8sControlPlane
	beforeAbort     func() error
	failAfterCommit int
}

func (f *d13eK8sControlPlane) AbortLifecycleClaim(ctx context.Context, orgID, claim string, generation int, requestID string) (k8sLifecycleClaimStatus, error) {
	if f.beforeAbort != nil {
		if err := f.beforeAbort(); err != nil {
			return k8sLifecycleClaimStatus{}, err
		}
	}
	status, err := f.fakeK8sControlPlane.AbortLifecycleClaim(ctx, orgID, claim, generation, requestID)
	if err != nil {
		return k8sLifecycleClaimStatus{}, err
	}
	if f.failAfterCommit > 0 {
		f.failAfterCommit--
		return k8sLifecycleClaimStatus{}, errors.New("simulated lost positive-generation abort response")
	}
	return status, nil
}

func TestK8sPositiveGenerationAbortUniversallyFencesBeforeCP(t *testing.T) {
	tests := []struct {
		name   string
		anchor lifecycleAnchorMetadata
		status k8sLifecycleClaimStatus
	}{
		{
			name:   "issued",
			anchor: testLifecycleAnchor("tunnex-gateway", "aks-gateway-a", "issued"),
			status: k8sLifecycleClaimStatus{claim: testLifecycleClaim, state: "issued", nodeName: "aks-gateway-a", generation: 1, requestID: testLifecycleRequest, expiresAt: testLifecycleExpiry},
		},
		{
			name:   "acknowledged",
			anchor: testLifecycleAnchor("tunnex-gateway", "aks-gateway-a", "acknowledged"),
			status: k8sLifecycleClaimStatus{claim: testLifecycleClaim, state: "acknowledged", nodeName: "aks-gateway-a", generation: 1, requestID: testLifecycleRequest, expiresAt: testLifecycleExpiry},
		},
		{
			name: "pending next generation",
			anchor: func() lifecycleAnchorMetadata {
				anchor := testLifecycleAnchor("tunnex-gateway", "aks-gateway-a", "pending")
				anchor.expectedGeneration = 1
				anchor.generation = 1
				anchor.expiresAt = time.Now().Add(-time.Hour).UTC()
				return anchor
			}(),
			status: k8sLifecycleClaimStatus{claim: testLifecycleClaim, state: "issued", nodeName: "aks-gateway-a", generation: 2, requestID: testLifecycleRequest, expiresAt: testLifecycleExpiry},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{tt.anchor.name: tt.anchor}, handler: baseRunnerHandler}
			base := baseK8sControlPlane()
			base.claims[testLifecycleClaim] = tt.status
			cp := &d13eK8sControlPlane{fakeK8sControlPlane: base}
			cp.beforeAbort = func() error {
				fenced, ok := runner.anchors[tt.anchor.name]
				if !ok || fenced.state != "aborting" || fenced.uid != tt.anchor.uid || fenced.resourceVersion == tt.anchor.resourceVersion {
					return fmt.Errorf("control-plane abort observed unfenced anchor: %+v exists=%t", fenced, ok)
				}
				return nil
			}
			deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
			args := []string{"abort-install", "--release", tt.anchor.instance, "--claim", tt.anchor.lifecycleClaim, "--confirm", "ABORT " + tt.anchor.lifecycleClaim}
			if err := runK8s(context.Background(), args, deps); err != nil {
				t.Fatalf("positive-generation abort: %v", err)
			}
			if _, exists := runner.anchors[tt.anchor.name]; exists {
				t.Fatal("successful positive-generation abort retained lifecycle anchor")
			}
		})
	}
}

func TestK8sBootstrapSecretRequiresFinalAnchorProofAndExactOwner(t *testing.T) {
	expected := testLifecycleAnchor("tunnex-gateway", "aks-gateway-a", "issued")
	o := installOptions{release: expected.instance, namespace: defaultK8sNamespace, kubeContext: "walk-context"}

	t.Run("fenced before proof refuses create", func(t *testing.T) {
		actual := expected
		actual.state = "aborting"
		actual.resourceVersion = "10"
		runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{actual.name: actual}, handler: baseRunnerHandler}
		if _, err := createBootstrapSecret(context.Background(), runner, o, expected, testJoinToken); err == nil || !strings.Contains(err.Error(), "UID/resourceVersion changed") {
			t.Fatalf("stale anchor create error = %v", err)
		}
		for _, command := range runner.commands {
			if bytes.Contains(command.stdin, []byte(`"kind":"Secret"`)) {
				t.Fatalf("stale installer created Secret: %+v", command)
			}
		}
	})

	t.Run("residual read-create race is GC-owned", func(t *testing.T) {
		var runner *fakeK8sRunner
		runner = &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{expected.name: expected}}
		runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
			joined := strings.Join(command.args, " ")
			if command.name == "kubectl" && strings.Contains(joined, "get configmap "+expected.name) {
				result, ok, err := runner.tryEmulateLifecycleAnchor(command)
				if !ok {
					return k8sCommandResult{}, errors.New("test did not emulate final anchor proof")
				}
				delete(runner.anchors, expected.name)
				return result, err
			}
			return baseRunnerHandler(command)
		}
		secret, err := createBootstrapSecret(context.Background(), runner, o, expected, testJoinToken)
		if err != nil {
			t.Fatalf("residual owner-reference create: %v", err)
		}
		if secret.ownerAPIVersion != "v1" || secret.ownerKind != "ConfigMap" || secret.ownerName != expected.name || secret.ownerUID != expected.uid {
			t.Fatalf("late Secret owner = %+v", secret)
		}
		if _, exists := runner.anchors[expected.name]; exists {
			t.Fatal("test did not delete anchor in residual read/create window")
		}
		manifestFound := false
		for _, command := range runner.commands {
			if !bytes.Contains(command.stdin, []byte(`"kind":"Secret"`)) {
				continue
			}
			manifestFound = bytes.Contains(command.stdin, []byte(`"ownerReferences":[{"apiVersion":"v1","blockOwnerDeletion":false,"controller":false,"kind":"ConfigMap","name":"`+expected.name+`","uid":"`+expected.uid+`"}]`))
		}
		if !manifestFound {
			t.Fatal("late bootstrap Secret did not carry exact anchor ownerReference")
		}
	})
}

func TestK8sPositiveAbortValidatesCanonicalShortenedExpiry(t *testing.T) {
	anchor := testLifecycleAnchor("tunnex-gateway", "aks-gateway-a", "issued")
	previous := k8sLifecycleClaimStatus{claim: anchor.lifecycleClaim, state: "issued", nodeName: anchor.nodeName, generation: 1, requestID: anchor.requestID, expiresAt: testLifecycleExpiry}
	abortedAt := time.Date(2098, 12, 31, 1, 2, 3, 0, time.UTC)
	response := previous
	response.state = "aborted"
	response.abortedAt = &abortedAt
	response.expiresAt = abortedAt
	if err := validatePositiveAbortResponse(response, previous, anchor); err != nil {
		t.Fatalf("canonical shortened expiry: %v", err)
	}
	response.expiresAt = previous.expiresAt
	if err := validatePositiveAbortResponse(response, previous, anchor); err == nil || !strings.Contains(err.Error(), "canonical minimum") {
		t.Fatalf("unshortened abort expiry error = %v", err)
	}
	previous.expiresAt = abortedAt.Add(-time.Hour)
	response.expiresAt = previous.expiresAt
	if err := validatePositiveAbortResponse(response, previous, anchor); err != nil {
		t.Fatalf("already-expired canonical response: %v", err)
	}
}

func TestK8sPositiveAbortResumesAfterLostCPResponseAndSecretCleanup(t *testing.T) {
	anchor := testLifecycleAnchor("tunnex-gateway", "aks-gateway-a", "issued")
	base := baseK8sControlPlane()
	base.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{claim: testLifecycleClaim, state: "issued", nodeName: anchor.nodeName, generation: 1, requestID: anchor.requestID, expiresAt: anchor.expiresAt}
	cp := &d13eK8sControlPlane{fakeK8sControlPlane: base, failAfterCommit: 1}
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}, handler: baseRunnerHandler}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	args := []string{"abort-install", "--release", anchor.instance, "--claim", anchor.lifecycleClaim, "--confirm", "ABORT " + anchor.lifecycleClaim}
	if err := runK8s(context.Background(), args, deps); err == nil || !strings.Contains(err.Error(), "lost positive-generation abort response") {
		t.Fatalf("lost response error = %v", err)
	}
	fenced := runner.anchors[anchor.name]
	if fenced.state != "aborting" || base.claims[testLifecycleClaim].state != "aborted" {
		t.Fatalf("lost response fence/CP = %+v / %+v", fenced, base.claims[testLifecycleClaim])
	}
	if err := runK8s(context.Background(), args, deps); err != nil {
		t.Fatalf("resume positive abort: %v", err)
	}
	if _, exists := runner.anchors[anchor.name]; exists {
		t.Fatal("resumed positive abort retained lifecycle anchor")
	}
}

func TestK8sPositiveAbortResumesAfterSecretDeleteBeforeAnchorDelete(t *testing.T) {
	anchor := testLifecycleAnchor("tunnex-gateway", "aks-gateway-a", "acknowledged")
	cp := baseK8sControlPlane()
	cp.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{claim: testLifecycleClaim, state: "acknowledged", nodeName: anchor.nodeName, generation: 1, requestID: anchor.requestID, expiresAt: anchor.expiresAt}
	secretExists := true
	failAnchorDelete := true
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		switch {
		case command.name == "kubectl" && strings.Contains(joined, "get secret "+anchor.instance+"-bootstrap"):
			if secretExists {
				return stdout(bootstrapSecretMetadataLine(anchor.instance)), nil
			}
			return stdout(""), nil
		case command.name == "kubectl" && strings.Contains(joined, "delete --raw=") && strings.Contains(joined, "/secrets/"):
			secretExists = false
			return stdout(`{"kind":"Status","status":"Success"}`), nil
		case command.name == "kubectl" && strings.Contains(joined, "delete --raw=") && strings.Contains(joined, "/configmaps/") && failAnchorDelete:
			failAnchorDelete = false
			return k8sCommandResult{}, errors.New("simulated anchor delete interruption")
		default:
			return baseRunnerHandler(command)
		}
	}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	args := []string{"abort-install", "--release", anchor.instance, "--claim", anchor.lifecycleClaim, "--confirm", "ABORT " + anchor.lifecycleClaim}
	if err := runK8s(context.Background(), args, deps); err == nil || !strings.Contains(err.Error(), "lifecycle anchor cleanup failed") {
		t.Fatalf("interrupted cleanup error = %v", err)
	}
	if secretExists || runner.anchors[anchor.name].state != "aborting" {
		t.Fatalf("interrupted cleanup state: secret=%t anchor=%+v", secretExists, runner.anchors[anchor.name])
	}
	if err := runK8s(context.Background(), args, deps); err != nil {
		t.Fatalf("resume after Secret cleanup: %v", err)
	}
	if _, exists := runner.anchors[anchor.name]; exists {
		t.Fatal("resumed cleanup retained lifecycle anchor")
	}
}

func TestK8sAbortRetainsExactUnmountedPendingPVC(t *testing.T) {
	anchor := testLifecycleAnchor("tunnex-gateway", "aks-gateway-a", "issued")
	cp := baseK8sControlPlane()
	cp.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{claim: testLifecycleClaim, state: "issued", nodeName: anchor.nodeName, generation: 1, requestID: anchor.requestID, expiresAt: anchor.expiresAt}
	claim := gatewayFullname(anchor.instance) + "-state"
	pendingPVC := fmt.Sprintf(`{"metadata":{"name":%q,"namespace":"tunnex","uid":"uid-pending","resourceVersion":"12","labels":{"app.kubernetes.io/name":"tunnex-gateway","app.kubernetes.io/instance":%q,"app.kubernetes.io/managed-by":"Helm"},"annotations":{"helm.sh/resource-policy":"keep","meta.helm.sh/release-name":%q,"meta.helm.sh/release-namespace":"tunnex"}},"spec":{"storageClassName":"managed-csi","volumeName":""},"status":{"phase":"Pending"}}`, claim, anchor.instance, anchor.instance)
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}, handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "get pvc "+claim) {
			return stdout(pendingPVC), nil
		}
		return baseRunnerHandler(command)
	}}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	args := []string{"abort-install", "--release", anchor.instance, "--claim", anchor.lifecycleClaim, "--confirm", "ABORT " + anchor.lifecycleClaim}
	if err := runK8s(context.Background(), args, deps); err != nil {
		t.Fatalf("abort with Pending PVC: %v", err)
	}
	for _, command := range runner.commands {
		if strings.Contains(strings.Join(command.args, " "), "/persistentvolumeclaims/") {
			t.Fatalf("abort deleted retained Pending PVC: %+v", command)
		}
	}
	bad := pvcView{}
	bad.Metadata.Name = claim
	bad.Metadata.Namespace = "tunnex"
	bad.Metadata.UID = "uid-pending"
	bad.Metadata.ResourceVersion = "12"
	bad.Metadata.Labels = map[string]string{"app.kubernetes.io/name": "tunnex-gateway", "app.kubernetes.io/instance": anchor.instance, "app.kubernetes.io/managed-by": "Helm"}
	bad.Metadata.Annotations = map[string]string{"helm.sh/resource-policy": "keep", "meta.helm.sh/release-name": anchor.instance, "meta.helm.sh/release-namespace": "tunnex"}
	bad.Status.Phase = "Pending"
	bad.Spec.VolumeName = "unexpected-volume"
	if err := validateAbortRetainedPVC(bad, claim, anchor.instance, "tunnex"); err != nil {
		t.Fatalf("Pending PVC with binding-in-progress volume: %v", err)
	}
	bad.Spec.VolumeName = ""
	bad.Status.Phase = "Lost"
	if err := validateAbortRetainedPVC(bad, claim, anchor.instance, "tunnex"); err == nil || !strings.Contains(err.Error(), "expected Pending or Bound") {
		t.Fatalf("unexpected PVC phase error = %v", err)
	}
}

func TestK8sAbortRefusesMountedPendingPVCBeforeFence(t *testing.T) {
	anchor := testLifecycleAnchor("tunnex-gateway", "aks-gateway-a", "issued")
	cp := baseK8sControlPlane()
	cp.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{claim: testLifecycleClaim, state: "issued", nodeName: anchor.nodeName, generation: 1, requestID: anchor.requestID, expiresAt: anchor.expiresAt}
	claim := gatewayFullname(anchor.instance) + "-state"
	pendingPVC := fmt.Sprintf(`{"metadata":{"name":%q,"namespace":"tunnex","uid":"uid-pending","resourceVersion":"12","labels":{"app.kubernetes.io/name":"tunnex-gateway","app.kubernetes.io/instance":%q,"app.kubernetes.io/managed-by":"Helm"},"annotations":{"helm.sh/resource-policy":"keep","meta.helm.sh/release-name":%q,"meta.helm.sh/release-namespace":"tunnex"}},"spec":{"storageClassName":"managed-csi","volumeName":""},"status":{"phase":"Pending"}}`, claim, anchor.instance, anchor.instance)
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}, handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		switch {
		case command.name == "kubectl" && strings.Contains(joined, "get pvc "+claim):
			return stdout(pendingPVC), nil
		case command.name == "kubectl" && strings.Contains(joined, "get pods"):
			return stdout(`{"items":[` + claimPodJSON("gateway-pending", "Pending", "", "Deployment", "gateway", claim) + `]}`), nil
		default:
			return baseRunnerHandler(command)
		}
	}}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	args := []string{"abort-install", "--release", anchor.instance, "--claim", anchor.lifecycleClaim, "--confirm", "ABORT " + anchor.lifecycleClaim}
	if err := runK8s(context.Background(), args, deps); err == nil || !strings.Contains(err.Error(), "still mounted") {
		t.Fatalf("mounted Pending PVC abort error = %v", err)
	}
	if runner.anchors[anchor.name].state != "issued" || cp.abortCount != 0 {
		t.Fatalf("mounted Pending PVC mutated fence/CP: anchor=%+v aborts=%d", runner.anchors[anchor.name], cp.abortCount)
	}
}

func TestK8sPurgeRefusesLifecycleAnchorOrBootstrapSecret(t *testing.T) {
	anchor := testLifecycleAnchor("gateway-a", "aks-gateway-a", "issued")
	args := []string{"purge-state", "--release", anchor.instance, "--claim", "retained-state-a", "--confirm", "DELETE retained-state-a"}
	t.Run("anchor remains", func(t *testing.T) {
		runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}, handler: baseRunnerHandler}
		err := runK8s(context.Background(), args, baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{}))
		if err == nil || !strings.Contains(err.Error(), "lifecycle anchor") {
			t.Fatalf("purge anchor refusal = %v", err)
		}
	})
	t.Run("orphan owner-bound Secret remains", func(t *testing.T) {
		runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
			joined := strings.Join(command.args, " ")
			if command.name == "kubectl" && strings.Contains(joined, "get secret "+anchor.instance+"-bootstrap") {
				return stdout(bootstrapSecretMetadataLine(anchor.instance)), nil
			}
			return baseRunnerHandler(command)
		}}
		err := runK8s(context.Background(), args, baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{}))
		if err == nil || !strings.Contains(err.Error(), "bootstrap Secret") {
			t.Fatalf("purge Secret refusal = %v", err)
		}
	})
}

func TestK8sBootstrapSecretOwnerReadbackRefusesMissingOrSpoofedOwner(t *testing.T) {
	line := bootstrapSecretMetadataLine("tunnex-gateway")
	withoutOwner := strings.Replace(line, "v1|ConfigMap|tunnex-gateway-lifecycle|uid-tunnex-gateway-lifecycle;", "", 1)
	if _, err := parseBootstrapSecretMetadata(withoutOwner); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("missing owner readback error = %v", err)
	}
	secret, err := parseBootstrapSecretMetadata(line)
	if err != nil {
		t.Fatal(err)
	}
	secret.ownerUID = "spoofed-anchor-uid"
	anchor := testLifecycleAnchor("tunnex-gateway", "aks-gateway-a", "issued")
	if err := validateBootstrapSecretAnchor(*secret, anchor); err == nil || !strings.Contains(err.Error(), "owner does not match") {
		t.Fatalf("spoofed owner validation error = %v", err)
	}
}
