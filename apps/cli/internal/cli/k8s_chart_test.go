package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestK8sChartMetadataUsesVerbatimAppVersionForOCIAndLocal(t *testing.T) {
	for _, tc := range []struct {
		name      string
		reference string
		requested string
		wantImage string
		wantVerb  string
	}{
		{name: "packaged OCI", reference: DefaultK8sGatewayChart, requested: "0.2.0", wantImage: "ghcr.io/tunnexio/tunnex-node-agent:v0.2.0", wantVerb: "pull"},
		{name: "local source", reference: "../../deploy/helm/tunnex-gateway", wantImage: "ghcr.io/tunnexio/tunnex-node-agent:0.2.0", wantVerb: "package"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, err := createChartStagingRoot()
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			runner := &fakeK8sRunner{handler: baseRunnerHandler}
			artifact, err := materializeChartArtifact(context.Background(), runner, "walk-context", root, "gateway", tc.reference, tc.requested, "tunnex-gateway")
			if err != nil {
				t.Fatalf("materialize chart: %v", err)
			}
			if got := resolvedImageReference(imageValues{}, artifact.Metadata.AppVersion); got != tc.wantImage {
				t.Fatalf("resolved image = %q, want %q", got, tc.wantImage)
			}
			if !strings.HasPrefix(artifact.SHA256, "sha256:") || filepath.Ext(artifact.Path) != ".tgz" {
				t.Fatalf("artifact = %+v, want hashed tgz", artifact)
			}
			info, statErr := os.Stat(artifact.Path)
			if statErr != nil || info.Mode().Perm() != 0o400 {
				t.Fatalf("artifact mode = %v / %v, want 0400", info, statErr)
			}
			if len(runner.commands) < 2 || runner.commands[0].args[0] != tc.wantVerb || runner.commands[1].args[2] != artifact.Path {
				t.Fatalf("materialization commands = %+v", runner.commands)
			}
			if strings.Contains(strings.Join(runner.commands[1].args, " "), tc.reference) {
				t.Fatalf("metadata was read from mutable source instead of artifact: %+v", runner.commands[1])
			}
		})
	}
}

func TestK8sChartMetadataRejectsAmbiguousOrIncompleteIdentity(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{name: "missing appVersion", raw: "name: tunnex-gateway\nversion: 0.2.0\n", want: "missing non-empty top-level appVersion"},
		{name: "duplicate appVersion", raw: "name: tunnex-gateway\nversion: 0.2.0\nappVersion: v0.2.0\nappVersion: attacker\n", want: "duplicate top-level appVersion"},
		{name: "structured appVersion", raw: "name: tunnex-gateway\nversion: 0.2.0\nappVersion: [v0.2.0]\n", want: "only one plain or quoted scalar"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseChartMetadata([]byte(tc.raw))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("parse error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestK8sChartMetadataRejectsAppVersionImageInjection(t *testing.T) {
	for _, appVersion := range []string{"v0.2.0/attacker", `"v0.2.0/attacker"`, "v0.2.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", strings.Repeat("a", 129)} {
		t.Run(appVersion, func(t *testing.T) {
			runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
				return stdout("name: tunnex-gateway\nversion: 0.2.0\nappVersion: " + appVersion + "\n"), nil
			}}
			_, err := readMaterializedChartMetadata(context.Background(), runner, "walk-context", "/private/chart.tgz", DefaultK8sGatewayChart, "0.2.0", "tunnex-gateway")
			if err == nil || !strings.Contains(err.Error(), "not an exact OCI image tag") {
				t.Fatalf("appVersion %q error = %v", appVersion, err)
			}
		})
	}
}

func TestK8sChartMetadataChangeAfterApprovalRefusesAllMutation(t *testing.T) {
	cp := baseK8sControlPlane()
	gatewayArtifact := ""
	runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "helm" && strings.HasPrefix(joined, "show chart ") && strings.Contains(joined, "tunnex-gateway") {
			gatewayArtifact = command.args[2]
		}
		return baseRunnerHandler(command)
	}}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	deps.in = &artifactTamperApprovalReader{path: &gatewayArtifact}
	err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a"}, deps)
	if err == nil || !strings.Contains(err.Error(), "changed after plan approval") {
		t.Fatalf("install error = %v, want chart artifact drift refusal", err)
	}
	if cp.issueCount != 0 {
		t.Fatalf("lifecycle token mints = %d, want zero", cp.issueCount)
	}
	for _, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		if (command.name == "helm" && (strings.HasPrefix(joined, "install ") || strings.HasPrefix(joined, "upgrade "))) ||
			(command.name == "kubectl" && (strings.Contains(joined, "create -f -") || strings.Contains(joined, "replace --raw="))) {
			t.Fatalf("mutation ran after chart metadata drift: %s %s", command.name, joined)
		}
	}
}

func TestK8sChartArtifactsArePlanBoundReusedAndCleaned(t *testing.T) {
	t.Run("plan hash and cleanup", func(t *testing.T) {
		var out bytes.Buffer
		roots := map[string]struct{}{}
		runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
			if command.name == "helm" && len(command.args) > 0 && (command.args[0] == "pull" || command.args[0] == "package") {
				destination := commandArgValue(command.args, "--destination")
				roots[filepath.Dir(destination)] = struct{}{}
			}
			return baseRunnerHandler(command)
		}}
		deps := baseK8sDeps(runner, baseK8sControlPlane(), &out, &bytes.Buffer{})
		if err := runK8s(context.Background(), []string{"plan", "--node-name", "aks-gateway-a"}, deps); err != nil {
			t.Fatalf("plan: %v", err)
		}
		if count := strings.Count(out.String(), `"artifact_sha256": "sha256:`); count != 2 {
			t.Fatalf("plan artifact hashes = %d, want gateway and host manager:\n%s", count, out.String())
		}
		if strings.Contains(out.String(), "tunnex-k8s-charts-") {
			t.Fatalf("plan leaked private artifact path: %s", out.String())
		}
		assertChartRootsRemoved(t, roots)
	})

	t.Run("same files reach both Helm mutations", func(t *testing.T) {
		installedManager := false
		artifactByName := map[string]string{}
		roots := map[string]struct{}{}
		runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
			joined := strings.Join(command.args, " ")
			if command.name == "helm" && len(command.args) > 2 && command.args[0] == "show" {
				if strings.Contains(command.args[2], "tunnex-host-posture") {
					artifactByName["host"] = command.args[2]
				} else {
					artifactByName["gateway"] = command.args[2]
				}
				roots[filepath.Dir(filepath.Dir(command.args[2]))] = struct{}{}
			}
			switch {
			case command.name == "helm" && strings.HasPrefix(joined, "list --all-namespaces"):
				if !installedManager {
					return stdout(`[]`), nil
				}
				return baseRunnerHandler(command)
			case command.name == "kubectl" && (strings.Contains(joined, "get daemonset tunnex-host-posture") || strings.Contains(joined, "get sa tunnex-host-posture") || strings.Contains(joined, "get clusterrole tunnex-host-posture-gateway-owner-reader") || strings.Contains(joined, "get clusterrolebinding tunnex-host-posture-gateway-owner-reader")):
				if !installedManager {
					return stdout(""), nil
				}
			case command.name == "helm" && strings.HasPrefix(joined, "upgrade --install tunnex-host-posture "):
				if command.args[3] != artifactByName["host"] {
					t.Fatalf("host manager used %q, want materialized %q", command.args[3], artifactByName["host"])
				}
				installedManager = true
				return stdout("installed\n"), nil
			case command.name == "helm" && strings.HasPrefix(joined, "install tunnex-gateway "):
				if command.args[2] != artifactByName["gateway"] {
					t.Fatalf("gateway used %q, want materialized %q", command.args[2], artifactByName["gateway"])
				}
			}
			return baseRunnerHandler(command)
		}}
		deps := baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})
		if err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps); err != nil {
			t.Fatalf("install: %v", err)
		}
		if !installedManager || artifactByName["gateway"] == "" || artifactByName["host"] == "" {
			t.Fatalf("artifact flow incomplete: manager=%t paths=%v", installedManager, artifactByName)
		}
		assertChartRootsRemoved(t, roots)
	})

	t.Run("approval refusal cleanup", func(t *testing.T) {
		roots := map[string]struct{}{}
		cp := baseK8sControlPlane()
		runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
			if command.name == "helm" && len(command.args) > 0 && (command.args[0] == "pull" || command.args[0] == "package") {
				roots[filepath.Dir(commandArgValue(command.args, "--destination"))] = struct{}{}
			}
			return baseRunnerHandler(command)
		}}
		deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
		deps.in = strings.NewReader("no\n")
		err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a"}, deps)
		if err == nil || !strings.Contains(err.Error(), "not approved") {
			t.Fatalf("approval refusal = %v", err)
		}
		if cp.issueCount != 0 {
			t.Fatalf("approval refusal minted %d tokens", cp.issueCount)
		}
		assertChartRootsRemoved(t, roots)
	})
}

func TestK8sLocalChartSourceDriftAfterPlanDoesNotChangeApprovedArtifact(t *testing.T) {
	sourceRoot := t.TempDir()
	gatewayDir := filepath.Join(sourceRoot, "tunnex-gateway")
	hostDir := filepath.Join(sourceRoot, "tunnex-host-posture")
	for _, item := range []struct{ path, name string }{{gatewayDir, "tunnex-gateway"}, {hostDir, "tunnex-host-posture"}} {
		if err := os.Mkdir(item.path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(item.path, "Chart.yaml"), []byte("name: "+item.name+"\nversion: 0.2.0\nappVersion: 0.2.0\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	artifactPath := ""
	runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "helm" && strings.HasPrefix(joined, "show chart ") && strings.Contains(command.args[2], "tunnex-gateway") {
			artifactPath = command.args[2]
		}
		if command.name == "helm" && strings.HasPrefix(joined, "list --all-namespaces") {
			return stdout(`[ {"name":"tunnex-host-posture","namespace":"tunnex-system","revision":"1","status":"deployed","chart":"tunnex-host-posture-0.2.0","app_version":"0.2.0"} ]`), nil
		}
		return baseRunnerHandler(command)
	}}
	deps := baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})
	deps.in = &callbackApprovalReader{callback: func() {
		_ = os.WriteFile(filepath.Join(gatewayDir, "Chart.yaml"), []byte("name: attacker\nversion: 9.9.9\nappVersion: attacker\n"), 0o600)
	}}
	if err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--chart", gatewayDir}, deps); err != nil {
		t.Fatalf("install from already materialized local chart: %v", err)
	}
	if artifactPath == "" {
		t.Fatal("gateway artifact path was not observed")
	}
	for _, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		if command.name == "helm" && strings.HasPrefix(joined, "install tunnex-gateway ") && command.args[2] != artifactPath {
			t.Fatalf("Helm re-read mutable source %q instead of approved artifact %q", command.args[2], artifactPath)
		}
	}
}

func TestK8sChartMaterializationFailureCleansAndRefusesMutation(t *testing.T) {
	roots := map[string]struct{}{}
	cp := baseK8sControlPlane()
	runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "helm" && len(command.args) > 0 && command.args[0] == "pull" {
			roots[filepath.Dir(commandArgValue(command.args, "--destination"))] = struct{}{}
			if strings.Contains(joined, "tunnex-host-posture") {
				return k8sCommandResult{}, errors.New("registry unavailable")
			}
		}
		return baseRunnerHandler(command)
	}}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "materialize exact host-posture Helm chart failed") {
		t.Fatalf("materialization error = %v", err)
	}
	if cp.issueCount != 0 {
		t.Fatalf("materialization failure minted %d tokens", cp.issueCount)
	}
	for _, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		if command.name == "helm" && (strings.HasPrefix(joined, "install ") || strings.HasPrefix(joined, "upgrade ")) {
			t.Fatalf("materialization failure reached Helm mutation: %s", joined)
		}
	}
	assertChartRootsRemoved(t, roots)
}

func TestK8sChartMaterializationReportsCleanupFailureBeforeMutation(t *testing.T) {
	root := ""
	cleanup := func(path string) error {
		root = path
		_ = removeChartStagingRoot(path)
		return errors.New("simulated cleanup denial")
	}
	runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "helm" && len(command.args) > 0 && command.args[0] == "pull" && strings.Contains(joined, "tunnex-host-posture") {
			return k8sCommandResult{}, errors.New("simulated registry failure")
		}
		return baseRunnerHandler(command)
	}}
	options, err := parseInstallOptions([]string{"--node-name", "gateway-a"}, baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = materializeInstallChartsWithCleanup(context.Background(), runner, "walk-context", options, cleanup)
	if err == nil || !strings.Contains(err.Error(), "materialize exact host-posture Helm chart failed") || !strings.Contains(err.Error(), "simulated cleanup denial") || !strings.Contains(err.Error(), root) {
		t.Fatalf("materialization+cleanup error = %v, root=%q", err, root)
	}
	if root == "" {
		t.Fatal("cleanup hook did not receive the private chart root")
	}
	if _, statErr := os.Stat(root); !os.IsNotExist(statErr) {
		t.Fatalf("test cleanup hook left root %q: %v", root, statErr)
	}
}

func TestK8sChartCleanupFailurePolicyBeforeAndAfterHelmMutation(t *testing.T) {
	cleanupErr := errors.New("simulated cleanup denial")
	cleanup := func(string) error { return cleanupErr }
	t.Run("before mutation is an error", func(t *testing.T) {
		var warnings bytes.Buffer
		err := finalizeChartCleanup("/private/exact-chart-root", cleanup, false, &warnings)
		if err == nil || !strings.Contains(err.Error(), `/private/exact-chart-root`) || !strings.Contains(err.Error(), cleanupErr.Error()) {
			t.Fatalf("pre-mutation cleanup error = %v", err)
		}
		if warnings.Len() != 0 {
			t.Fatalf("pre-mutation cleanup emitted warning instead of failing: %s", warnings.String())
		}
	})
	t.Run("after mutation is a warning", func(t *testing.T) {
		var warnings bytes.Buffer
		if err := finalizeChartCleanup("/private/exact-chart-root", cleanup, true, &warnings); err != nil {
			t.Fatalf("post-mutation cleanup reported Helm failure: %v", err)
		}
		for _, want := range []string{"Warning: Helm mutation succeeded", `/private/exact-chart-root`, cleanupErr.Error(), "Remove that exact directory manually"} {
			if !strings.Contains(warnings.String(), want) {
				t.Fatalf("post-mutation cleanup warning missing %q: %s", want, warnings.String())
			}
		}
	})
}

func TestK8sChartCleanupFailureIsReturnedBeforeMutation(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		in   string
		want string
	}{
		{name: "plan", args: []string{"plan", "--node-name", "gateway-a"}, want: "before any Helm mutation"},
		{name: "approval refusal", args: []string{"install", "--node-name", "gateway-a"}, in: "no\n", want: "plan was not approved"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cp := baseK8sControlPlane()
			runner := &fakeK8sRunner{handler: baseRunnerHandler}
			var errOut bytes.Buffer
			deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &errOut)
			if tc.in != "" {
				deps.in = strings.NewReader(tc.in)
			}
			root := ""
			deps.cleanupChartRoot = simulatedChartCleanupFailure(t, &root)
			err := runK8s(context.Background(), tc.args, deps)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "simulated cleanup denial") || root == "" || !strings.Contains(err.Error(), root) {
				t.Fatalf("%s cleanup error = %v, root=%q", tc.name, err, root)
			}
			if errOut.Len() != 0 {
				t.Fatalf("pre-mutation cleanup warned instead of failing: %s", errOut.String())
			}
			if cp.issueCount != 0 {
				t.Fatalf("pre-mutation cleanup path minted %d tokens", cp.issueCount)
			}
			assertNoGatewayOrManagerHelmMutation(t, runner)
		})
	}
}

func TestK8sSuccessfulHelmMutationWarnsOnChartCleanupFailure(t *testing.T) {
	t.Run("gateway install", func(t *testing.T) {
		runner := &fakeK8sRunner{handler: baseRunnerHandler}
		var errOut bytes.Buffer
		deps := baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &errOut)
		root := ""
		deps.cleanupChartRoot = simulatedChartCleanupFailure(t, &root)
		if err := runK8s(context.Background(), []string{"install", "--node-name", "gateway-a", "--yes"}, deps); err != nil {
			t.Fatalf("successful install reported cleanup as mutation failure: %v", err)
		}
		assertChartCleanupWarning(t, errOut.String(), root)
	})

	t.Run("gateway upgrade", func(t *testing.T) {
		runner := &fakeK8sRunner{handler: installedRunnerHandler}
		var errOut bytes.Buffer
		deps := baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &errOut)
		root := ""
		deps.cleanupChartRoot = simulatedChartCleanupFailure(t, &root)
		if err := runK8s(context.Background(), []string{"upgrade", "--yes"}, deps); err != nil {
			t.Fatalf("successful upgrade reported cleanup as mutation failure: %v", err)
		}
		assertChartCleanupWarning(t, errOut.String(), root)
	})
}

func TestK8sHostManagerMutationMakesLaterCleanupFailureWarningOnly(t *testing.T) {
	cp := baseK8sControlPlane()
	cp.remintFailures = 1
	managerInstalled := false
	runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		switch {
		case command.name == "helm" && strings.HasPrefix(joined, "list --all-namespaces"):
			if !managerInstalled {
				return stdout(`[]`), nil
			}
		case command.name == "kubectl" && (strings.Contains(joined, "get daemonset tunnex-host-posture") || strings.Contains(joined, "get sa tunnex-host-posture") || strings.Contains(joined, "get clusterrole tunnex-host-posture-gateway-owner-reader") || strings.Contains(joined, "get clusterrolebinding tunnex-host-posture-gateway-owner-reader")):
			if !managerInstalled {
				return stdout(""), nil
			}
		case command.name == "helm" && strings.HasPrefix(joined, "upgrade --install tunnex-host-posture "):
			managerInstalled = true
			return stdout("installed\n"), nil
		}
		return baseRunnerHandler(command)
	}}
	var errOut bytes.Buffer
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &errOut)
	root := ""
	deps.cleanupChartRoot = simulatedChartCleanupFailure(t, &root)
	err := runK8s(context.Background(), []string{"install", "--node-name", "gateway-a", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "lifecycle remint failure") || strings.Contains(err.Error(), "simulated cleanup denial") {
		t.Fatalf("post-manager failure = %v", err)
	}
	if !managerInstalled {
		t.Fatal("host manager mutation did not occur")
	}
	assertChartCleanupWarning(t, errOut.String(), root)
}

func simulatedChartCleanupFailure(t *testing.T, root *string) func(string) error {
	t.Helper()
	return func(path string) error {
		*root = path
		if err := removeChartStagingRoot(path); err != nil {
			t.Errorf("remove simulated chart root: %v", err)
		}
		return errors.New("simulated cleanup denial")
	}
}

func assertChartCleanupWarning(t *testing.T, warning, root string) {
	t.Helper()
	if root == "" {
		t.Fatal("cleanup hook did not receive a chart root")
	}
	for _, want := range []string{"Warning: Helm mutation succeeded", root, "simulated cleanup denial", "Remove that exact directory manually"} {
		if !strings.Contains(warning, want) {
			t.Fatalf("cleanup warning missing %q: %s", want, warning)
		}
	}
}

func assertNoGatewayOrManagerHelmMutation(t *testing.T, runner *fakeK8sRunner) {
	t.Helper()
	for _, command := range runner.commands {
		if command.name == "helm" && len(command.args) > 0 && (command.args[0] == "install" || command.args[0] == "upgrade") {
			t.Fatalf("pre-mutation cleanup path ran Helm mutation: %+v", command)
		}
	}
}

func TestK8sResumeCleanupDoesNotFetchOrApplyCharts(t *testing.T) {
	cp := baseK8sControlPlane()
	cp.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{claim: testLifecycleClaim, state: "consumed", nodeName: "aks-gateway-a", generation: 1, requestID: testLifecycleRequest, expiresAt: testLifecycleExpiry, nodeID: testLifecycleNodeID}
	anchor := testCompletedLifecycleAnchor(cp, "tunnex-gateway", "aks-gateway-a")
	chartFetches := 0
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		switch {
		case command.name == "helm" && len(command.args) > 0 && (command.args[0] == "pull" || command.args[0] == "package"):
			chartFetches++
			return k8sCommandResult{}, errors.New("registry unavailable")
		case command.name == "kubectl" && strings.Contains(joined, "get secret tunnex-gateway-bootstrap"):
			return stdout(bootstrapSecretMetadataLine("tunnex-gateway")), nil
		case command.name == "kubectl" && strings.Contains(joined, "get pvc tunnex-gateway-tunnex-gateway-state") && strings.Contains(joined, "--ignore-not-found=true"):
			return stdout(readyPVCJSON("tunnex-gateway-tunnex-gateway-state", "tunnex-gateway")), nil
		default:
			return installedRunnerHandler(command)
		}
	}
	var out bytes.Buffer
	deps := baseK8sDeps(runner, cp, &out, &bytes.Buffer{})
	if err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps); err != nil {
		t.Fatalf("resume cleanup with unavailable chart sources: %v", err)
	}
	if chartFetches != 0 || cp.issueCount != 0 {
		t.Fatalf("resume cleanup chart fetches=%d token mints=%d, want zero", chartFetches, cp.issueCount)
	}
	if strings.Contains(out.String(), "artifact_sha256") || !strings.Contains(out.String(), `"action": "resume-install-cleanup"`) {
		t.Fatalf("resume cleanup plan did not truthfully omit chart mutation artifacts:\n%s", out.String())
	}
	if _, exists := runner.anchors[anchor.name]; exists {
		t.Fatal("resume cleanup returned success but retained the owned lifecycle anchor")
	}
	secretDeleted := false
	for _, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		if command.name == "helm" && (strings.HasPrefix(joined, "install ") || strings.HasPrefix(joined, "upgrade ")) {
			t.Fatalf("resume cleanup applied a chart: %s", joined)
		}
		if command.name == "kubectl" && strings.Contains(joined, "delete --raw=/api/v1/namespaces/tunnex/secrets/tunnex-gateway-bootstrap") {
			secretDeleted = true
			if !bytes.Contains(command.stdin, []byte(`"uid":"uid-tunnex-gateway-bootstrap"`)) || !bytes.Contains(command.stdin, []byte(`"resourceVersion":"17"`)) {
				t.Fatalf("resume cleanup Secret deletion lacks exact UID/resourceVersion CAS preconditions: %s", command.stdin)
			}
		}
	}
	if !secretDeleted {
		t.Fatal("resume cleanup returned success without deleting the owned bootstrap Secret")
	}
}

func assertChartRootsRemoved(t *testing.T, roots map[string]struct{}) {
	t.Helper()
	if len(roots) == 0 {
		t.Fatal("no chart staging roots were observed")
	}
	for root := range roots {
		if _, err := os.Stat(root); !os.IsNotExist(err) {
			t.Fatalf("private chart staging root %q remains after command: %v", root, err)
		}
	}
}

type callbackApprovalReader struct {
	callback func()
	reader   *strings.Reader
}

func (r *callbackApprovalReader) Read(p []byte) (int, error) {
	if r.reader == nil {
		if r.callback != nil {
			r.callback()
		}
		r.reader = strings.NewReader("yes\n")
	}
	return r.reader.Read(p)
}

type artifactTamperApprovalReader struct {
	path *string
	done bool
}

func (r *artifactTamperApprovalReader) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		if r.path != nil && *r.path != "" {
			_ = os.Chmod(*r.path, 0o600)
			_ = os.WriteFile(*r.path, []byte("changed-after-approval"), 0o600)
		}
	}
	return strings.NewReader("yes\n").Read(p)
}
