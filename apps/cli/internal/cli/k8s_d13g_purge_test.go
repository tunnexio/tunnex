package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func lifecyclePVCJSON(t *testing.T, claim, release, organizationID, lifecycleClaim string) string {
	t.Helper()
	var pvc pvcView
	if err := json.Unmarshal([]byte(readyPVCJSON(claim, release)), &pvc); err != nil {
		t.Fatal(err)
	}
	delete(pvc.Metadata.Annotations, lifecycleOrganizationAnnotation)
	delete(pvc.Metadata.Annotations, lifecycleClaimAnnotation)
	if organizationID != "" {
		pvc.Metadata.Annotations[lifecycleOrganizationAnnotation] = organizationID
	}
	if lifecycleClaim != "" {
		pvc.Metadata.Annotations[lifecycleClaimAnnotation] = lifecycleClaim
	}
	raw, err := json.Marshal(pvc)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func purgeRunner(pvcJSON string) *fakeK8sRunner {
	return &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		switch {
		case command.name == "helm" && strings.HasPrefix(joined, "list "):
			return stdout(`[]`), nil
		case command.name == "kubectl" && strings.Contains(joined, "get pvc retained-state-a"):
			return stdout(pvcJSON), nil
		case command.name == "kubectl" && strings.Contains(joined, "get pods"):
			return stdout(`{"items":[]}`), nil
		default:
			return baseRunnerHandler(command)
		}
	}}
}

func lifecyclePurgeArgs(confirm string) []string {
	return []string{"purge-state", "--release", "gateway-a", "--claim", "retained-state-a", "--confirm", confirm}
}

func TestK8sPurgeRequiresExactTerminalLifecycleProvenance(t *testing.T) {
	organizationID := baseK8sControlPlane().orgs[0].id
	terminalAt := time.Now().UTC().Add(-time.Minute)
	for _, test := range []struct {
		name   string
		status k8sLifecycleClaimStatus
	}{
		{
			name: "consumed",
			status: k8sLifecycleClaimStatus{
				claim: testLifecycleClaim, state: "consumed", nodeName: "gateway-a", nodeID: testLifecycleNodeID,
				generation: 1, requestID: testLifecycleRequest, expiresAt: terminalAt.Add(-time.Minute), consumedAt: &terminalAt,
			},
		},
		{
			name: "aborted",
			status: k8sLifecycleClaimStatus{
				claim: testLifecycleClaim, state: "aborted", nodeName: "gateway-a",
				generation: 1, requestID: testLifecycleRequest, expiresAt: terminalAt, abortedAt: &terminalAt,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			pvc := lifecyclePVCJSON(t, "retained-state-a", "gateway-a", organizationID, testLifecycleClaim)
			runner := purgeRunner(pvc)
			cp := baseK8sControlPlane()
			cp.claims[testLifecycleClaim] = test.status
			if err := runK8s(context.Background(), lifecyclePurgeArgs("DELETE retained-state-a"), baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})); err != nil {
				t.Fatalf("terminal lifecycle purge: %v", err)
			}
			if cp.orgCount != 2 {
				t.Fatalf("organization proof reads = %d, want before and post-confirmation", cp.orgCount)
			}
			deleted := false
			for _, command := range runner.commands {
				if strings.Contains(strings.Join(command.args, " "), "/persistentvolumeclaims/retained-state-a") {
					deleted = true
				}
			}
			if !deleted {
				t.Fatal("terminal lifecycle purge did not issue preconditioned PVC deletion")
			}
		})
	}
}

func TestK8sPurgeRefusesNonterminalOrSpoofedLifecycleProvenance(t *testing.T) {
	organizationID := baseK8sControlPlane().orgs[0].id
	for _, state := range []string{"pending", "issued", "acknowledged", "expired"} {
		t.Run("nonterminal "+state, func(t *testing.T) {
			pvc := lifecyclePVCJSON(t, "retained-state-a", "gateway-a", organizationID, testLifecycleClaim)
			runner := purgeRunner(pvc)
			cp := baseK8sControlPlane()
			cp.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{
				claim: testLifecycleClaim, state: state, nodeName: "gateway-a", generation: 1,
				requestID: testLifecycleRequest, expiresAt: testLifecycleExpiry,
			}
			err := runK8s(context.Background(), lifecyclePurgeArgs("DELETE retained-state-a"), baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}))
			if err == nil || !strings.Contains(err.Error(), "not consumed or aborted") {
				t.Fatalf("nonterminal %s error = %v", state, err)
			}
			assertNoPVCDelete(t, runner)
		})
	}

	t.Run("spoofed organization", func(t *testing.T) {
		pvc := lifecyclePVCJSON(t, "retained-state-a", "gateway-a", "99999999-9999-9999-9999-999999999999", testLifecycleClaim)
		runner := purgeRunner(pvc)
		err := runK8s(context.Background(), lifecyclePurgeArgs("DELETE retained-state-a"), baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{}))
		if err == nil || !strings.Contains(err.Error(), "resolve exact lifecycle provenance organization") {
			t.Fatalf("spoofed organization error = %v", err)
		}
		assertNoPVCDelete(t, runner)
	})

	t.Run("spoofed claim response", func(t *testing.T) {
		pvc := lifecyclePVCJSON(t, "retained-state-a", "gateway-a", organizationID, testLifecycleClaim)
		runner := purgeRunner(pvc)
		cp := baseK8sControlPlane()
		terminalAt := time.Now().UTC()
		cp.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{
			claim: "55555555-5555-5555-5555-555555555555", state: "aborted", nodeName: "other",
			generation: 1, requestID: testLifecycleRequest, expiresAt: terminalAt, abortedAt: &terminalAt,
		}
		err := runK8s(context.Background(), lifecyclePurgeArgs("DELETE retained-state-a"), baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}))
		if err == nil || !strings.Contains(err.Error(), "does not match the exact PVC provenance") {
			t.Fatalf("spoofed claim error = %v", err)
		}
		assertNoPVCDelete(t, runner)
	})
}

func TestK8sPurgeLegacyAndMalformedProvenanceFailClosed(t *testing.T) {
	legacyPVC := readyLegacyPVCJSON("retained-state-a", "gateway-a")
	t.Run("legacy default refuses", func(t *testing.T) {
		runner := purgeRunner(legacyPVC)
		err := runK8s(context.Background(), lifecyclePurgeArgs("DELETE retained-state-a"), baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{}))
		if err == nil || !strings.Contains(err.Error(), "--legacy-without-lifecycle-proof") {
			t.Fatalf("legacy default error = %v", err)
		}
		assertNoPVCDelete(t, runner)
	})
	t.Run("legacy requires stronger confirmation", func(t *testing.T) {
		runner := purgeRunner(legacyPVC)
		args := append(lifecyclePurgeArgs("DELETE retained-state-a"), "--legacy-without-lifecycle-proof")
		err := runK8s(context.Background(), args, baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{}))
		if err == nil || !strings.Contains(err.Error(), `"DELETE LEGACY retained-state-a"`) {
			t.Fatalf("legacy confirmation error = %v", err)
		}
		assertNoPVCDelete(t, runner)
	})
	t.Run("legacy explicit path", func(t *testing.T) {
		runner := purgeRunner(legacyPVC)
		args := append(lifecyclePurgeArgs("DELETE LEGACY retained-state-a"), "--legacy-without-lifecycle-proof")
		if err := runK8s(context.Background(), args, baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})); err != nil {
			t.Fatalf("explicit legacy purge: %v", err)
		}
	})

	for _, test := range []struct {
		name, org, claim string
	}{
		{name: "partial", org: baseK8sControlPlane().orgs[0].id},
		{name: "malformed", org: baseK8sControlPlane().orgs[0].id, claim: "not-a-uuid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := purgeRunner(lifecyclePVCJSON(t, "retained-state-a", "gateway-a", test.org, test.claim))
			args := append(lifecyclePurgeArgs("DELETE LEGACY retained-state-a"), "--legacy-without-lifecycle-proof")
			err := runK8s(context.Background(), args, baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{}))
			if err == nil || (!strings.Contains(err.Error(), "partial or malformed") && !strings.Contains(err.Error(), "canonical UUIDs")) {
				t.Fatalf("%s provenance error = %v", test.name, err)
			}
			assertNoPVCDelete(t, runner)
		})
	}
}

func TestK8sAbortAndPurgeRequireExactHelmPVCOwnership(t *testing.T) {
	base := lifecyclePVCJSON(t, "retained-state-a", "gateway-a", baseK8sControlPlane().orgs[0].id, testLifecycleClaim)
	for _, test := range []struct {
		name   string
		mutate func(*pvcView)
	}{
		{name: "namespace", mutate: func(p *pvcView) { p.Metadata.Namespace = "other" }},
		{name: "manager", mutate: func(p *pvcView) { p.Metadata.Labels["app.kubernetes.io/managed-by"] = "manual" }},
		{name: "release annotation", mutate: func(p *pvcView) { p.Metadata.Annotations["meta.helm.sh/release-name"] = "other" }},
		{name: "namespace annotation", mutate: func(p *pvcView) { p.Metadata.Annotations["meta.helm.sh/release-namespace"] = "other" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var pvc pvcView
			if err := json.Unmarshal([]byte(base), &pvc); err != nil {
				t.Fatal(err)
			}
			test.mutate(&pvc)
			raw, _ := json.Marshal(pvc)
			runner := purgeRunner(string(raw))
			cp := baseK8sControlPlane()
			err := runK8s(context.Background(), lifecyclePurgeArgs("DELETE retained-state-a"), baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}))
			if err == nil || !strings.Contains(err.Error(), "exact retained Helm-owned") {
				t.Fatalf("foreign PVC error = %v", err)
			}
			if cp.orgCount != 0 {
				t.Fatalf("foreign PVC reached control plane %d times", cp.orgCount)
			}
			assertNoPVCDelete(t, runner)
		})
	}
}

func TestK8sAbortRefusesForeignPVCOwnershipBeforeFenceOrControlPlaneAbort(t *testing.T) {
	anchor := testLifecycleAnchor("gateway-a", "gateway-a", "issued")
	claim := gatewayFullname(anchor.instance) + "-state"
	var pvc pvcView
	if err := json.Unmarshal([]byte(readyPVCJSON(claim, anchor.instance)), &pvc); err != nil {
		t.Fatal(err)
	}
	pvc.Metadata.Annotations["meta.helm.sh/release-name"] = "foreign"
	raw, _ := json.Marshal(pvc)
	cp := baseK8sControlPlane()
	cp.claims[anchor.lifecycleClaim] = k8sLifecycleClaimStatus{
		claim: anchor.lifecycleClaim, state: "issued", nodeName: anchor.nodeName,
		generation: anchor.generation, requestID: anchor.requestID, expiresAt: anchor.expiresAt,
	}
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}, handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "get pvc "+claim) {
			return stdout(string(raw)), nil
		}
		return baseRunnerHandler(command)
	}}
	args := []string{"abort-install", "--release", anchor.instance, "--claim", anchor.lifecycleClaim, "--confirm", "ABORT " + anchor.lifecycleClaim}
	err := runK8s(context.Background(), args, baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}))
	if err == nil || !strings.Contains(err.Error(), "exact retained Helm-owned") {
		t.Fatalf("foreign abort PVC error = %v", err)
	}
	if cp.abortCount != 0 || runner.anchors[anchor.name].state != "issued" {
		t.Fatalf("foreign PVC reached abort mutation: aborts=%d anchor=%+v", cp.abortCount, runner.anchors[anchor.name])
	}
}

func TestInstallHelmValuesCarryLifecycleProvenanceOnlyForEnroll(t *testing.T) {
	installAnchor := testLifecycleAnchor("gateway-a", "gateway-a", "installing")
	installAnchor.installOperationID = testStateFenceOpID
	installAnchor.installOperationEpoch = 1
	installAnchor.installOperationDurationSeconds = 660
	installAnchor.installOperationNotAfter = time.Date(2099, 1, 2, 3, 4, 5, 0, time.UTC)
	installAnchor.installIntentDigest = "sha256:" + strings.Repeat("a", 64)
	installAnchor.releaseNamespace = "tunnex"
	installAnchor.releaseName = "gateway-a"
	base := preparedInstall{
		options: installOptions{release: "gateway-a", namespace: "tunnex", kubeContext: "walk", mode: "enroll", nodeName: "gateway-a", timeout: "10m", serviceType: "LoadBalancer"},
		plan: lifecyclePlan{
			ControlPlane: &lifecycleControlPlane{APIURL: "https://cp.example.test", AgentURL: "https://cp.example.test:8443", ServerName: "tunnex-control"},
			Gateway:      lifecycleGateway{BootstrapSecret: "gateway-a-bootstrap"}, Storage: lifecycleStorage{Class: "managed-csi"},
			InstallIntentDigest: "sha256:" + strings.Repeat("a", 64),
		},
		org:             k8sOrganization{id: "11111111-1111-1111-1111-111111111111"},
		anchor:          installAnchor,
		gatewayArtifact: chartArtifact{Path: "/tmp/tunnex-gateway.tgz"}, digest: "sha256:" + strings.Repeat("a", 64), installIntentDigest: "sha256:" + strings.Repeat("a", 64),
	}
	command, err := installHelmCommand(base)
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]any
	if err := json.Unmarshal(command.stdin, &values); err != nil {
		t.Fatal(err)
	}
	persistence := values["persistence"].(map[string]any)
	provenance := persistence["provenance"].(map[string]any)
	if provenance["organizationID"] != base.anchor.orgID || provenance["lifecycleClaim"] != base.anchor.lifecycleClaim {
		t.Fatalf("enroll provenance = %#v", provenance)
	}
	lifecycle := values["lifecycle"].(map[string]any)
	if proof, _ := lifecycle["installProof"].(string); !validCanonicalSHA256Digest(proof) {
		t.Fatalf("enroll lifecycle install proof = %#v", lifecycle)
	}

	base.options.mode = "reuse"
	base.options.existingClaim = "retained-state-a"
	base.anchor = lifecycleAnchorMetadata{}
	command, err = installHelmCommand(base)
	if err != nil {
		t.Fatal(err)
	}
	values = nil
	if err := json.Unmarshal(command.stdin, &values); err != nil {
		t.Fatal(err)
	}
	persistence = values["persistence"].(map[string]any)
	if _, exists := persistence["provenance"]; exists {
		t.Fatalf("reuse invented lifecycle provenance: %#v", persistence)
	}
	if _, exists := values["lifecycle"]; exists {
		t.Fatalf("reuse invented lifecycle install proof: %#v", values["lifecycle"])
	}
}

func TestK8sInstallRefusesMutatedPVCLifecycleProvenanceBeforeRecoveryCleanup(t *testing.T) {
	claim := gatewayFullname("tunnex-gateway") + "-state"
	for _, test := range []struct {
		name string
		pvc  func(*testing.T) string
	}{
		{name: "missing", pvc: func(*testing.T) string { return readyLegacyPVCJSON(claim, "tunnex-gateway") }},
		{name: "wrong organization", pvc: func(t *testing.T) string {
			return lifecyclePVCJSON(t, claim, "tunnex-gateway", "99999999-9999-9999-9999-999999999999", testLifecycleClaim)
		}},
		{name: "wrong claim", pvc: func(t *testing.T) string {
			return lifecyclePVCJSON(t, claim, "tunnex-gateway", baseK8sControlPlane().orgs[0].id, "55555555-5555-5555-5555-555555555555")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &fakeK8sRunner{}
			runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
				joined := strings.Join(command.args, " ")
				if command.name == "kubectl" && strings.Contains(joined, "get pvc "+claim) && !strings.Contains(joined, "--ignore-not-found=true") {
					return stdout(test.pvc(t)), nil
				}
				return baseRunnerHandler(command)
			}
			err := runK8s(context.Background(), []string{"install", "--node-name", "gateway-a", "--yes"}, baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{}))
			if err == nil || !strings.Contains(err.Error(), "lifecycle provenance") {
				t.Fatalf("mutated provenance install error = %v", err)
			}
			for _, command := range runner.commands {
				joined := strings.Join(command.args, " ")
				if strings.Contains(joined, "delete --raw=/api/v1/namespaces/tunnex/secrets/tunnex-gateway-bootstrap") || strings.Contains(joined, "delete --raw=/api/v1/namespaces/tunnex/configmaps/tunnex-gateway-lifecycle") {
					t.Fatalf("mutated provenance triggered recovery cleanup: %+v", command)
				}
			}
		})
	}
}

func TestK8sResumeCleanupRefusesMutatedPVCLifecycleProvenanceBeforeMetadataDeletion(t *testing.T) {
	claim := gatewayFullname("tunnex-gateway") + "-state"
	cp := baseK8sControlPlane()
	anchor := testCompletedLifecycleAnchor(cp, "tunnex-gateway", "gateway-a")
	cp.claims[anchor.lifecycleClaim] = k8sLifecycleClaimStatus{
		claim: anchor.lifecycleClaim, state: "consumed", nodeName: anchor.nodeName, nodeID: testLifecycleNodeID,
		generation: anchor.generation, requestID: anchor.requestID, expiresAt: anchor.expiresAt,
	}
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		switch {
		case command.name == "kubectl" && strings.Contains(joined, "get secret tunnex-gateway-bootstrap"):
			return stdout(bootstrapSecretMetadataLine("tunnex-gateway")), nil
		case command.name == "kubectl" && strings.Contains(joined, "get pvc "+claim):
			return stdout(readyLegacyPVCJSON(claim, "tunnex-gateway")), nil
		default:
			return installedRunnerHandler(command)
		}
	}
	err := runK8s(context.Background(), []string{"install", "--node-name", anchor.nodeName, "--yes"}, baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}))
	if err == nil || !strings.Contains(err.Error(), "lifecycle provenance") {
		t.Fatalf("resume cleanup provenance error = %v", err)
	}
	for _, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		if strings.Contains(joined, "delete --raw=/api/v1/namespaces/tunnex/secrets/tunnex-gateway-bootstrap") || strings.Contains(joined, "delete --raw=/api/v1/namespaces/tunnex/configmaps/tunnex-gateway-lifecycle") {
			t.Fatalf("resume cleanup deleted recovery metadata after provenance mismatch: %+v", command)
		}
	}
}

func assertNoPVCDelete(t *testing.T, runner *fakeK8sRunner) {
	t.Helper()
	for _, command := range runner.commands {
		if strings.Contains(strings.Join(command.args, " "), "/persistentvolumeclaims/") {
			t.Fatalf("refused purge issued PVC delete: %+v", command)
		}
	}
}

func TestValidateGenerationOneMintRaceAbortRequiresCanonicalTerminalShape(t *testing.T) {
	anchor := testLifecycleAnchor("gateway-a", "gateway-a", "pending")
	anchor.expectedGeneration = 0
	anchor.generation = 0
	anchor.expiresAt = time.Time{}
	previous := k8sLifecycleClaimStatus{
		claim: anchor.lifecycleClaim, state: "issued", nodeName: anchor.nodeName,
		generation: 1, requestID: anchor.requestID, expiresAt: testLifecycleExpiry,
	}
	abortedAt := time.Now().UTC()
	valid := previous
	valid.state = "aborted"
	valid.abortedAt = &abortedAt
	valid.expiresAt = abortedAt
	if err := validateGenerationZeroAbortResponse(valid, previous, anchor); err != nil {
		t.Fatalf("canonical generation-one abort: %v", err)
	}
	for _, mutate := range []func(*k8sLifecycleClaimStatus){
		func(s *k8sLifecycleClaimStatus) { s.abortedAt = nil },
		func(s *k8sLifecycleClaimStatus) { zero := time.Time{}; s.abortedAt = &zero },
		func(s *k8sLifecycleClaimStatus) { s.expiresAt = abortedAt.Add(time.Second) },
	} {
		candidate := valid
		mutate(&candidate)
		if err := validateGenerationZeroAbortResponse(candidate, previous, anchor); err == nil {
			t.Fatalf("accepted malformed mint-race abort: %+v", candidate)
		}
	}
}

func TestLifecyclePurgeFixtureIsStable(t *testing.T) {
	// Guard the helper against silently dropping token-blind annotations during
	// future pvcView refactors.
	raw := lifecyclePVCJSON(t, "retained-state-a", "gateway-a", "11111111-1111-1111-1111-111111111111", testLifecycleClaim)
	if !strings.Contains(raw, fmt.Sprintf(`"%s":"%s"`, lifecycleClaimAnnotation, testLifecycleClaim)) {
		t.Fatalf("fixture lost lifecycle provenance: %s", raw)
	}
}
