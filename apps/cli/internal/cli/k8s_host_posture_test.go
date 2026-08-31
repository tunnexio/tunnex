package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestK8sHostPostureSingletonIsReusedAcrossGatewayNamespaces(t *testing.T) {
	for _, namespace := range []string{"gateway-a", "gateway-b"} {
		var out bytes.Buffer
		runner := &fakeK8sRunner{handler: baseRunnerHandler}
		deps := baseK8sDeps(runner, baseK8sControlPlane(), &out, &bytes.Buffer{})
		if err := runK8s(context.Background(), []string{"plan", "--node-name", "node-" + namespace, "--namespace", namespace}, deps); err != nil {
			t.Fatalf("%s plan: %v", namespace, err)
		}
		for _, want := range []string{`"action": "reuse"`, `"release": "tunnex-host-posture"`, `"namespace": "tunnex-system"`, `"daemon_set": "tunnex-host-posture"`} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("%s plan missing singleton %s:\n%s", namespace, want, out.String())
			}
		}
		for _, command := range runner.commands {
			if command.name == "helm" && len(command.args) > 0 && command.args[0] == "upgrade" {
				t.Fatalf("read-only plan mutated singleton: %+v", command)
			}
		}
	}
}

func TestK8sHostPostureCleanInstallCompletesBeforeGatewayTokenMint(t *testing.T) {
	installed := false
	cp := baseK8sControlPlane()
	runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		switch {
		case command.name == "helm" && strings.HasPrefix(joined, "list --all-namespaces"):
			if !installed {
				return stdout(`[]`), nil
			}
			return stdout(`[ {"name":"tunnex-host-posture","namespace":"tunnex-system","revision":"1","status":"deployed","chart":"tunnex-host-posture-0.2.0","app_version":"v0.2.0"} ]`), nil
		case command.name == "kubectl" && strings.Contains(joined, "get daemonset tunnex-host-posture"):
			if !installed {
				return stdout(""), nil
			}
			return stdout(readyHostPostureDaemonSetJSON(nil)), nil
		case command.name == "kubectl" && (strings.Contains(joined, "get sa tunnex-host-posture") || strings.Contains(joined, "get clusterrole tunnex-host-posture-gateway-owner-reader") || strings.Contains(joined, "get clusterrolebinding tunnex-host-posture-gateway-owner-reader")):
			if !installed {
				return stdout(""), nil
			}
			return baseRunnerHandler(command)
		case command.name == "helm" && strings.HasPrefix(joined, "upgrade --install tunnex-host-posture "):
			if cp.issueCount != 0 {
				t.Fatalf("gateway token minted before host posture install: %d", cp.issueCount)
			}
			installed = true
			return stdout("Release upgraded\n"), nil
		default:
			return baseRunnerHandler(command)
		}
	}}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	if err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps); err != nil {
		t.Fatalf("clean singleton install: %v", err)
	}
	if !installed || cp.issueCount != 1 {
		t.Fatalf("singleton installed=%t gateway mint count=%d", installed, cp.issueCount)
	}
	for _, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		if command.name == "helm" && strings.HasPrefix(joined, "upgrade --install tunnex-host-posture ") {
			for _, want := range []string{"--namespace tunnex-system", "--description tunnex-zero-touch/v1", "--atomic", "--wait"} {
				if !strings.Contains(joined, want) {
					t.Fatalf("host posture Helm command missing %q: %s", want, joined)
				}
			}
			if !bytes.Contains(command.stdin, []byte(`"acknowledgePrivileged":true`)) {
				t.Fatalf("host posture values missing privilege acknowledgement: %s", command.stdin)
			}
		}
	}
}

func TestK8sHostPostureCleanInstallWaitsForTransientDaemonSetConvergenceBeforeMint(t *testing.T) {
	installed, rolloutComplete := false, false
	cp := baseK8sControlPlane()
	unready := strings.Replace(readyHostPostureDaemonSetJSON(nil), `"numberReady":2`, `"numberReady":1`, 1)
	unready = strings.Replace(unready, `"numberUnavailable":0`, `"numberUnavailable":1`, 1)
	runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		switch {
		case command.name == "helm" && strings.HasPrefix(joined, "list --all-namespaces"):
			if !installed {
				return stdout(`[]`), nil
			}
			return stdout(`[{"name":"tunnex-host-posture","namespace":"tunnex-system","revision":"1","status":"deployed","chart":"tunnex-host-posture-0.2.0","app_version":"v0.2.0"}]`), nil
		case command.name == "kubectl" && strings.Contains(joined, "get daemonset tunnex-host-posture"):
			if !installed {
				return stdout(""), nil
			}
			if !rolloutComplete {
				return stdout(unready), nil
			}
			return stdout(readyHostPostureDaemonSetJSON(nil)), nil
		case command.name == "kubectl" && (strings.Contains(joined, "get sa tunnex-host-posture") || strings.Contains(joined, "get clusterrole tunnex-host-posture-gateway-owner-reader") || strings.Contains(joined, "get clusterrolebinding tunnex-host-posture-gateway-owner-reader")):
			if !installed {
				return stdout(""), nil
			}
			return baseRunnerHandler(command)
		case command.name == "helm" && strings.HasPrefix(joined, "upgrade --install tunnex-host-posture "):
			installed = true
			return stdout("Release upgraded\n"), nil
		case command.name == "kubectl" && strings.Contains(joined, "rollout status daemonset/tunnex-host-posture"):
			if !installed || cp.issueCount != 0 {
				t.Fatalf("host posture rollout wait ran outside the pre-mint post-Helm window: installed=%t mints=%d", installed, cp.issueCount)
			}
			for _, want := range []string{"--namespace tunnex-system", "--timeout 10m", "--context walk-context"} {
				if !strings.Contains(joined, want) {
					t.Fatalf("host posture rollout wait missing %q: %s", want, joined)
				}
			}
			rolloutComplete = true
			return stdout("daemon set successfully rolled out\n"), nil
		default:
			return baseRunnerHandler(command)
		}
	}}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	if err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps); err != nil {
		t.Fatalf("transient host posture convergence: %v", err)
	}
	if !rolloutComplete || cp.issueCount != 1 {
		t.Fatalf("rollout complete=%t gateway token mints=%d", rolloutComplete, cp.issueCount)
	}
}

func TestK8sHostPostureRolloutWaitFailureBlocksGatewayMint(t *testing.T) {
	installed := false
	cp := baseK8sControlPlane()
	runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		switch {
		case command.name == "helm" && strings.HasPrefix(joined, "list --all-namespaces"):
			if !installed {
				return stdout(`[]`), nil
			}
			return stdout(`[{"name":"tunnex-host-posture","namespace":"tunnex-system","revision":"1","status":"deployed","chart":"tunnex-host-posture-0.2.0","app_version":"v0.2.0"}]`), nil
		case command.name == "kubectl" && strings.Contains(joined, "get daemonset tunnex-host-posture"):
			if !installed {
				return stdout(""), nil
			}
			return stdout(readyHostPostureDaemonSetJSON(nil)), nil
		case command.name == "kubectl" && (strings.Contains(joined, "get sa tunnex-host-posture") || strings.Contains(joined, "get clusterrole tunnex-host-posture-gateway-owner-reader") || strings.Contains(joined, "get clusterrolebinding tunnex-host-posture-gateway-owner-reader")):
			if !installed {
				return stdout(""), nil
			}
			return baseRunnerHandler(command)
		case command.name == "helm" && strings.HasPrefix(joined, "upgrade --install tunnex-host-posture "):
			installed = true
			return stdout("Release upgraded\n"), nil
		case command.name == "kubectl" && strings.Contains(joined, "rollout status daemonset/tunnex-host-posture"):
			return k8sCommandResult{}, fmt.Errorf("simulated host posture rollout timeout")
		default:
			return baseRunnerHandler(command)
		}
	}}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "wait for cluster-wide host posture manager rollout failed") {
		t.Fatalf("host posture rollout wait error = %v", err)
	}
	if cp.issueCount != 0 {
		t.Fatalf("failed host posture rollout minted %d gateway tokens", cp.issueCount)
	}
	for _, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		if command.name == "helm" && strings.HasPrefix(joined, "install tunnex-gateway ") {
			t.Fatalf("failed host posture rollout reached gateway Helm: %+v", command)
		}
		if command.name == "kubectl" && bytes.Contains(command.stdin, []byte(`"kind":"ConfigMap"`)) {
			t.Fatalf("failed host posture rollout created lifecycle anchor: %+v", command)
		}
	}
}

func TestK8sHostPostureUnreadyAfterUpgradeBlocksGatewayMint(t *testing.T) {
	cp := baseK8sControlPlane()
	unready := strings.Replace(readyHostPostureDaemonSetJSON(nil), `"numberReady":2`, `"numberReady":1`, 1)
	runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "get daemonset tunnex-host-posture") {
			return stdout(unready), nil
		}
		return baseRunnerHandler(command)
	}}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "not converged") {
		t.Fatalf("unready manager error = %v", err)
	}
	if cp.issueCount != 0 {
		t.Fatalf("unready manager minted %d gateway tokens", cp.issueCount)
	}
	for _, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		if (command.name == "kubectl" && bytes.Contains(command.stdin, []byte(`"kind":"ConfigMap"`))) || (command.name == "helm" && strings.HasPrefix(joined, "install tunnex-gateway ")) {
			t.Fatalf("unready manager reached gateway mutation: %+v", command)
		}
	}
}

func TestK8sHostPostureRefusesConflictingOrUnownedManagersBeforeMutation(t *testing.T) {
	tests := []struct {
		name    string
		list    string
		daemon  string
		wantErr string
	}{
		{name: "wrong release", list: `[{"name":"custom-manager","namespace":"other","revision":"1","status":"deployed","chart":"tunnex-host-posture-0.2.0","app_version":"0.2.0"}]`, wantErr: "must be exact release"},
		{name: "release without fixed daemonset", list: `[{"name":"tunnex-host-posture","namespace":"tunnex-system","revision":"1","status":"deployed","chart":"tunnex-host-posture-0.2.0","app_version":"0.2.0"}]`, wantErr: "missing its fixed DaemonSet"},
		{name: "inexact helm ownership", list: `[{"name":"tunnex-host-posture","namespace":"tunnex-system","revision":"1","status":"deployed","chart":"tunnex-host-posture-0.2.0","app_version":"0.2.0"}]`, daemon: strings.Replace(readyHostPostureDaemonSetJSON(nil), `"meta.helm.sh/release-name":"tunnex-host-posture"`, `"meta.helm.sh/release-name":"attacker"`, 1), wantErr: "lacks exact fixed Helm ownership"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cp := baseK8sControlPlane()
			runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
				joined := strings.Join(command.args, " ")
				if command.name == "helm" && strings.HasPrefix(joined, "list --all-namespaces") {
					return stdout(tc.list), nil
				}
				if command.name == "kubectl" && strings.Contains(joined, "get daemonset tunnex-host-posture") {
					return stdout(tc.daemon), nil
				}
				return baseRunnerHandler(command)
			}}
			deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
			err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("conflict error = %v, want %q", err, tc.wantErr)
			}
			if cp.issueCount != 0 {
				t.Fatalf("conflicting manager minted %d tokens", cp.issueCount)
			}
			for _, command := range runner.commands {
				if command.name == "helm" && len(command.args) > 0 && (command.args[0] == "upgrade" || command.args[0] == "install") {
					t.Fatalf("conflict mutated Helm: %+v", command)
				}
			}
		})
	}
}

func TestK8sLocalGatewayChartDerivesSiblingHostPostureChart(t *testing.T) {
	deps := k8sDeps{errOut: &bytes.Buffer{}, defaultChart: DefaultK8sGatewayChart, defaultHostPostureChart: DefaultK8sHostPostureChart, buildVersion: "dev"}.normalized()
	options, err := parseInstallOptions([]string{"--node-name", "gateway-a", "--chart", "../../deploy/helm/tunnex-gateway"}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if options.hostPostureChart != "../../deploy/helm/tunnex-host-posture" || options.hostPostureVersion != "" {
		t.Fatalf("derived host posture chart/version = %q/%q", options.hostPostureChart, options.hostPostureVersion)
	}
}

func TestK8sHostPostureUpgradeRetainsNonSecretValuesAndPinsCanonicalPlacement(t *testing.T) {
	upgraded := false
	cp := baseK8sControlPlane()
	runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		switch {
		case command.name == "helm" && strings.HasPrefix(joined, "list --all-namespaces"):
			version := "0.1.0"
			if upgraded {
				version = "0.2.0"
			}
			return stdout(`[ {"name":"tunnex-host-posture","namespace":"tunnex-system","revision":"1","status":"deployed","chart":"tunnex-host-posture-` + version + `","app_version":"v` + version + `"} ]`), nil
		case command.name == "helm" && strings.HasPrefix(joined, "upgrade --install tunnex-host-posture "):
			if !strings.Contains(joined, "--reset-then-reuse-values") {
				t.Fatalf("shared manager upgrade did not retain prior non-secret values: %s", joined)
			}
			for _, want := range []string{`"nodeSelector":{"kubernetes.io/os":"linux"}`, `"tolerations":[{"operator":"Exists"}]`} {
				if !bytes.Contains(command.stdin, []byte(want)) {
					t.Fatalf("shared manager values missing canonical placement %s: %s", want, command.stdin)
				}
			}
			upgraded = true
			return stdout("upgraded\n"), nil
		default:
			return baseRunnerHandler(command)
		}
	}}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	if err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps); err != nil {
		t.Fatalf("upgrade shared manager: %v", err)
	}
	if !upgraded || cp.issueCount != 1 {
		t.Fatalf("upgraded=%t gateway token mints=%d", upgraded, cp.issueCount)
	}
}

func TestK8sHostPostureUpgradeAuthoritativelyClearsPullSecretsAndImageSelector(t *testing.T) {
	t.Run("remove pull secret", func(t *testing.T) {
		upgraded := false
		cp := baseK8sControlPlane()
		runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
			joined := strings.Join(command.args, " ")
			if command.name == "helm" && strings.HasPrefix(joined, "upgrade --install tunnex-host-posture ") {
				if !bytes.Contains(command.stdin, []byte(`"pullSecrets":[]`)) {
					t.Fatalf("host upgrade did not clear approved empty pullSecrets: %s", command.stdin)
				}
				upgraded = true
				return stdout("upgraded\n"), nil
			}
			if command.name == "kubectl" && strings.Contains(joined, "get daemonset tunnex-host-posture") {
				if upgraded {
					return stdout(readyHostPostureDaemonSetJSON(nil)), nil
				}
				return stdout(readyHostPostureDaemonSetJSON([]string{"old-pull"})), nil
			}
			return baseRunnerHandler(command)
		}}
		deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
		if err := runK8s(context.Background(), []string{"install", "--node-name", "gateway-a", "--yes"}, deps); err != nil {
			t.Fatalf("clear pull Secret: %v", err)
		}
		if !upgraded || cp.issueCount != 1 {
			t.Fatalf("upgraded=%t token mints=%d", upgraded, cp.issueCount)
		}
	})

	t.Run("digest to tag", func(t *testing.T) {
		upgraded := false
		target := "ghcr.io/tunnexio/tunnex-node-agent:v9.8.7"
		cp := baseK8sControlPlane()
		runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
			joined := strings.Join(command.args, " ")
			if command.name == "helm" && strings.HasPrefix(joined, "upgrade --install tunnex-host-posture ") {
				for _, want := range []string{`"tag":"v9.8.7"`, `"digest":""`} {
					if !bytes.Contains(command.stdin, []byte(want)) {
						t.Fatalf("host image transition omitted %s: %s", want, command.stdin)
					}
				}
				upgraded = true
				return stdout("upgraded\n"), nil
			}
			if command.name == "kubectl" && strings.Contains(joined, "get daemonset tunnex-host-posture") {
				body := readyHostPostureDaemonSetJSON(nil)
				if upgraded {
					body = strings.Replace(body, "ghcr.io/tunnexio/tunnex-node-agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", target, 1)
				}
				return stdout(body), nil
			}
			if command.name == "kubectl" && strings.Contains(joined, "get deployment") {
				return stdout(strings.Replace(readyDeploymentJSON("tunnex-gateway", "tunnex-gateway-tunnex-gateway-state"), "ghcr.io/tunnexio/tunnex-node-agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", target, 1)), nil
			}
			return baseRunnerHandler(command)
		}}
		deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
		if err := runK8s(context.Background(), []string{"install", "--node-name", "gateway-a", "--image", target, "--yes"}, deps); err != nil {
			t.Fatalf("digest-to-tag manager upgrade: %v", err)
		}
		if !upgraded || cp.issueCount != 1 {
			t.Fatalf("upgraded=%t token mints=%d", upgraded, cp.issueCount)
		}
	})
}

func TestK8sHostPostureNewerManagerRefusesDowngradeBeforeMutation(t *testing.T) {
	cp := baseK8sControlPlane()
	runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "helm" && strings.HasPrefix(joined, "list --all-namespaces") {
			return stdout(`[{"name":"tunnex-host-posture","namespace":"tunnex-system","revision":"4","status":"deployed","chart":"tunnex-host-posture-0.3.0","app_version":"0.3.0"}]`), nil
		}
		if command.name == "helm" && strings.HasPrefix(joined, "history tunnex-host-posture ") {
			return stdout(`[{"revision":4,"description":"tunnex-zero-touch/v1"}]`), nil
		}
		return baseRunnerHandler(command)
	}}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "refusing a shared-manager downgrade") {
		t.Fatalf("downgrade error = %v", err)
	}
	if cp.issueCount != 0 {
		t.Fatalf("downgrade path minted %d gateway tokens", cp.issueCount)
	}
	assertNoHostPostureMutation(t, runner)
}

func TestK8sHostPostureCriticalShapeDriftRefusesBeforeMutation(t *testing.T) {
	base := readyHostPostureDaemonSetJSON(nil)
	tests := []struct {
		name string
		old  string
		new  string
	}{
		{name: "command", old: `"k8s-host-posture-manager"`, new: `"other-command"`},
		{name: "service account", old: `"serviceAccountName":"tunnex-host-posture"`, new: `"serviceAccountName":"other"`},
		{name: "automount", old: `"automountServiceAccountToken":false`, new: `"automountServiceAccountToken":true`},
		{name: "host network", old: `"hostNetwork":true`, new: `"hostNetwork":false`},
		{name: "privileged", old: `"privileged":true`, new: `"privileged":false`},
		{name: "root user", old: `"runAsUser":0`, new: `"runAsUser":1000`},
		{name: "state hostpath", old: `"path":"/var/lib/tunnex/host-posture/v1"`, new: `"path":"/tmp/other"`},
		{name: "projected token", old: `"expirationSeconds":3600`, new: `"expirationSeconds":7200`},
		{name: "rolling strategy", old: `"maxUnavailable":1`, new: `"maxUnavailable":2`},
		{name: "canonical toleration", old: `"tolerations":[{"operator":"Exists"}]`, new: `"tolerations":[]`},
		{name: "restricting affinity", old: `"affinity":{}`, new: `"affinity":{"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{}}}`},
		{name: "startup probe", old: `"k8s-host-posture-check"`, new: `"untrusted-check"`},
		{name: "image pull policy", old: `"imagePullPolicy":"IfNotPresent"`, new: `"imagePullPolicy":"Always"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			drifted := strings.Replace(base, tc.old, tc.new, 1)
			if drifted == base {
				t.Fatalf("fixture replacement %q not found", tc.old)
			}
			cp := baseK8sControlPlane()
			runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
				joined := strings.Join(command.args, " ")
				if command.name == "kubectl" && strings.Contains(joined, "get daemonset tunnex-host-posture") {
					return stdout(drifted), nil
				}
				return baseRunnerHandler(command)
			}}
			deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
			err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps)
			if err == nil {
				t.Fatal("critical shape drift unexpectedly accepted")
			}
			if cp.issueCount != 0 {
				t.Fatalf("shape drift minted %d gateway tokens", cp.issueCount)
			}
			assertNoHostPostureMutation(t, runner)
		})
	}
}

func TestK8sHostPostureAccessDriftRefusesBeforeMutation(t *testing.T) {
	tests := []struct {
		name        string
		objectMatch string
		body        string
	}{
		{name: "missing ServiceAccount", objectMatch: "get sa tunnex-host-posture", body: ""},
		{name: "spoofed ServiceAccount ownership", objectMatch: "get sa tunnex-host-posture", body: strings.Replace(readyHostPostureServiceAccountJSON(), `"meta.helm.sh/release-name":"tunnex-host-posture"`, `"meta.helm.sh/release-name":"attacker"`, 1)},
		{name: "broadened ClusterRole resources", objectMatch: "get clusterrole tunnex-host-posture-gateway-owner-reader", body: strings.Replace(readyHostPostureClusterRoleJSON(), `"resources":["pods"]`, `"resources":["pods","secrets"]`, 1)},
		{name: "aggregated ClusterRole", objectMatch: "get clusterrole tunnex-host-posture-gateway-owner-reader", body: strings.Replace(readyHostPostureClusterRoleJSON(), `"rules":`, `"aggregationRule":{"clusterRoleSelectors":[]},"rules":`, 1)},
		{name: "wrong binding subject", objectMatch: "get clusterrolebinding tunnex-host-posture-gateway-owner-reader", body: strings.Replace(readyHostPostureClusterRoleBindingJSON(), `"name":"tunnex-host-posture","namespace":"tunnex-system"`, `"name":"other","namespace":"tunnex-system"`, 1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cp := baseK8sControlPlane()
			runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
				joined := strings.Join(command.args, " ")
				if command.name == "kubectl" && strings.Contains(joined, tc.objectMatch) {
					return stdout(tc.body), nil
				}
				return baseRunnerHandler(command)
			}}
			deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
			err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps)
			if err == nil {
				t.Fatal("access-object drift unexpectedly accepted")
			}
			if cp.issueCount != 0 {
				t.Fatalf("access drift minted %d gateway tokens", cp.issueCount)
			}
			assertNoHostPostureMutation(t, runner)
		})
	}
}

func assertNoHostPostureMutation(t *testing.T, runner *fakeK8sRunner) {
	t.Helper()
	for _, command := range runner.commands {
		if command.name == "helm" && len(command.args) > 0 && (command.args[0] == "upgrade" || command.args[0] == "install") && !(len(command.args) > 1 && command.args[1] == "--help") {
			t.Fatalf("host posture failure mutated Helm: %+v", command)
		}
	}
}

func TestK8sHostPostureDiscoveryReadsEveryBoundedHelmPage(t *testing.T) {
	page := make([]helmReleaseSummary, hostPostureHelmPageSize)
	for i := range page {
		page[i] = helmReleaseSummary{Name: fmt.Sprintf("unrelated-%03d", i), Namespace: "apps", Revision: "1", Status: "deployed", Chart: "other-1.0.0"}
	}
	pageJSON, _ := json.Marshal(page)
	cp := baseK8sControlPlane()
	runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "helm" && strings.HasPrefix(joined, "list --all-namespaces") {
			if commandArgValue(command.args, "--offset") == "0" {
				return stdout(string(pageJSON)), nil
			}
			return stdout(`[{"name":"legacy-manager","namespace":"legacy","revision":"1","status":"deployed","chart":"tunnex-host-posture-0.1.0","app_version":"0.1.0"}]`), nil
		}
		return baseRunnerHandler(command)
	}}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"install", "--node-name", "gateway-a", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "must be exact release") {
		t.Fatalf("page-two conflict error = %v", err)
	}
	if cp.issueCount != 0 {
		t.Fatalf("page-two conflict minted %d tokens", cp.issueCount)
	}
	assertNoHostPostureMutation(t, runner)
}

func TestK8sHostPostureDiscoveryFailsClosedAtInventoryCap(t *testing.T) {
	cp := baseK8sControlPlane()
	runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "helm" && strings.HasPrefix(joined, "list --all-namespaces") {
			offset, _ := strconv.Atoi(commandArgValue(command.args, "--offset"))
			page := make([]helmReleaseSummary, hostPostureHelmPageSize)
			for i := range page {
				page[i] = helmReleaseSummary{Name: fmt.Sprintf("unrelated-%04d", offset+i), Namespace: "apps", Revision: "1", Status: "deployed", Chart: "other-1.0.0"}
			}
			body, _ := json.Marshal(page)
			return stdout(string(body)), nil
		}
		return baseRunnerHandler(command)
	}}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"install", "--node-name", "gateway-a", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "fail-closed limit") {
		t.Fatalf("inventory cap error = %v", err)
	}
	if cp.issueCount != 0 {
		t.Fatalf("inventory cap minted %d tokens", cp.issueCount)
	}
	assertNoHostPostureMutation(t, runner)
}

func commandArgValue(args []string, name string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}

func TestK8sHostPostureRBACChangeAfterApprovalBlocksAllMutation(t *testing.T) {
	roleReads := 0
	cp := baseK8sControlPlane()
	runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "get clusterrole tunnex-host-posture-gateway-owner-reader") {
			roleReads++
			body := readyHostPostureClusterRoleJSON()
			if roleReads >= 2 {
				body = strings.Replace(body, `"resourceVersion":"22"`, `"resourceVersion":"23"`, 1)
			}
			return stdout(body), nil
		}
		return baseRunnerHandler(command)
	}}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"install", "--node-name", "gateway-a", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "changed after plan approval") {
		t.Fatalf("RBAC CAS error = %v", err)
	}
	if cp.issueCount != 0 {
		t.Fatalf("RBAC drift minted %d tokens", cp.issueCount)
	}
	assertNoHostPostureMutation(t, runner)
}
