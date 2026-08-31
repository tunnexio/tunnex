package cli

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestProveZeroTouchRevision(t *testing.T) {
	tests := []struct {
		name    string
		history []historyEntry
		target  int
		wantErr string
	}{
		{
			name:    "direct marker",
			history: []historyEntry{{Revision: 3, Description: zeroTouchContract}},
			target:  3,
		},
		{
			name: "bounded rollback ancestry",
			history: []historyEntry{
				{Revision: 1, Description: zeroTouchContract},
				{Revision: 2, Description: "Rollback to 1"},
				{Revision: 3, Description: "Rollback to 2"},
			},
			target: 3,
		},
		{
			name:    "missing ancestor",
			history: []historyEntry{{Revision: 3, Description: "Rollback to 2"}},
			target:  3,
			wantErr: "revision 2 is missing",
		},
		{
			name:    "malformed description",
			history: []historyEntry{{Revision: 3, Description: "rollback to 2"}},
			target:  3,
			wantErr: "unproven lifecycle description",
		},
		{
			name: "forward edge",
			history: []historyEntry{
				{Revision: 2, Description: "Rollback to 3"},
				{Revision: 3, Description: zeroTouchContract},
			},
			target:  2,
			wantErr: "unsafe forward rollback edge",
		},
		{
			name:    "self cycle",
			history: []historyEntry{{Revision: 2, Description: "Rollback to 2"}},
			target:  2,
			wantErr: "cycle",
		},
		{
			name: "duplicate revision",
			history: []historyEntry{
				{Revision: 1, Description: zeroTouchContract},
				{Revision: 1, Description: zeroTouchContract},
			},
			target:  1,
			wantErr: "duplicate revision",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := proveZeroTouchRevision(tt.history, tt.target)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("proveZeroTouchRevision: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestExactHelmInitialInstallIsAbortOnly(t *testing.T) {
	o := releaseOptions{release: "gateway-a", namespace: "tunnex"}
	release := helmReleaseSummary{
		Name: "gateway-a", Namespace: "tunnex", Revision: "1", Status: "pending-install",
		Chart: "tunnex-gateway-0.2.0", AppVersion: "v0.2.0",
	}
	history := []historyEntry{{
		Revision: 1, Status: "pending-install", Chart: release.Chart, AppVersion: release.AppVersion,
		Description: helmInitialInstallDescription,
	}}
	if err := proveZeroTouchRevision(history, 1); err == nil {
		t.Fatal("generic zero-touch provenance accepted Helm's initial pending marker")
	}
	if !isExactHelmInitialInstall(history, o, release, 1) {
		t.Fatal("abort-only proof rejected the exact Helm-native first-install tuple")
	}

	tests := []struct {
		name     string
		release  helmReleaseSummary
		history  []historyEntry
		revision int
	}{
		{name: "deployed status", release: func() helmReleaseSummary { value := release; value.Status = "deployed"; return value }(), history: history, revision: 1},
		{name: "second revision", release: func() helmReleaseSummary { value := release; value.Revision = "2"; return value }(), history: history, revision: 2},
		{name: "extra history", release: release, history: append(history, historyEntry{Revision: 2, Status: "pending-upgrade", Description: "Preparing upgrade"}), revision: 1},
		{name: "description spelling", release: release, history: []historyEntry{{Revision: 1, Status: "pending-install", Chart: release.Chart, AppVersion: release.AppVersion, Description: "initial install underway"}}, revision: 1},
		{name: "history status", release: release, history: []historyEntry{{Revision: 1, Status: "failed", Chart: release.Chart, AppVersion: release.AppVersion, Description: helmInitialInstallDescription}}, revision: 1},
		{name: "foreign chart", release: func() helmReleaseSummary { value := release; value.Chart = "other-0.2.0"; return value }(), history: history, revision: 1},
		{name: "chart mismatch", release: release, history: []historyEntry{{Revision: 1, Status: "pending-install", Chart: "tunnex-gateway-0.3.0", AppVersion: release.AppVersion, Description: helmInitialInstallDescription}}, revision: 1},
		{name: "app version mismatch", release: release, history: []historyEntry{{Revision: 1, Status: "pending-install", Chart: release.Chart, AppVersion: "v0.3.0", Description: helmInitialInstallDescription}}, revision: 1},
		{name: "blank app version", release: func() helmReleaseSummary { value := release; value.AppVersion = ""; return value }(), history: history, revision: 1},
		{name: "release mismatch", release: func() helmReleaseSummary { value := release; value.Name = "gateway-b"; return value }(), history: history, revision: 1},
		{name: "namespace mismatch", release: func() helmReleaseSummary { value := release; value.Namespace = "other"; return value }(), history: history, revision: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if isExactHelmInitialInstall(tt.history, o, tt.release, tt.revision) {
				t.Fatal("abort-only proof accepted an inexact Helm initial-install tuple")
			}
		})
	}
}

func TestProveZeroTouchRevisionRejectsBoundExhaustion(t *testing.T) {
	history := make([]historyEntry, maxZeroTouchHistoryDepth+1)
	history[0] = historyEntry{Revision: 1, Description: zeroTouchContract}
	for revision := 2; revision <= len(history); revision++ {
		history[revision-1] = historyEntry{Revision: revision, Description: fmt.Sprintf("Rollback to %d", revision-1)}
	}
	err := proveZeroTouchRevision(history, len(history))
	if err == nil || !strings.Contains(err.Error(), "exceeded the bounded history depth") {
		t.Fatalf("bound error = %v", err)
	}
}

func TestK8sUpgradeRefusesUnprovenSourceBeforeMutation(t *testing.T) {
	runner := &fakeK8sRunner{}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "helm" && strings.HasPrefix(joined, "history tunnex-gateway ") {
			return stdout(`[{"revision":3,"description":"Upgrade complete"}]`), nil
		}
		return installedRunnerHandler(command)
	}
	deps := baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"upgrade", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "unproven lifecycle description") {
		t.Fatalf("upgrade provenance error = %v", err)
	}
	assertNoHelmLifecycleMutation(t, runner)
}

func TestK8sUpgradeRefusesMissingLiveContractBeforeMutation(t *testing.T) {
	runner := &fakeK8sRunner{}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "get deployment") {
			return stdout(strings.Replace(readyDeploymentJSON("tunnex-gateway", "tunnex-gateway-tunnex-gateway-state"), `,"annotations":{"tunnex.io/zero-touch-contract":"tunnex-zero-touch/v1"}`, "", 1)), nil
		}
		return installedRunnerHandler(command)
	}
	deps := baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"upgrade", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), zeroTouchContractAnnotationKey) {
		t.Fatalf("upgrade live contract error = %v", err)
	}
	assertNoHelmLifecycleMutation(t, runner)
}

func TestK8sRollbackAcceptsProvenNativeAncestry(t *testing.T) {
	runner := &fakeK8sRunner{}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "helm" && strings.HasPrefix(joined, "history tunnex-gateway ") {
			return stdout(`[{"revision":1,"description":"tunnex-zero-touch/v1"},{"revision":2,"description":"Rollback to 1"},{"revision":3,"description":"Rollback to 2"}]`), nil
		}
		return installedRunnerHandler(command)
	}
	deps := baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})
	if err := runK8s(context.Background(), []string{"rollback", "--revision", "3", "--yes"}, deps); err != nil {
		t.Fatalf("rollback proven ancestry: %v", err)
	}
}

func TestK8sRollbackRefusesUnprovenTargetBeforeMutation(t *testing.T) {
	runner := &fakeK8sRunner{}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "helm" && strings.HasPrefix(joined, "history tunnex-gateway ") {
			return stdout(`[{"revision":2,"description":"legacy"},{"revision":3,"description":"tunnex-zero-touch/v1"}]`), nil
		}
		return installedRunnerHandler(command)
	}
	deps := baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"rollback", "--revision", "2", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "unproven lifecycle description") {
		t.Fatalf("rollback target error = %v", err)
	}
	assertNoHelmLifecycleMutation(t, runner)
}

func TestK8sRollbackRequiresLiveContractAfterMutation(t *testing.T) {
	rolledBack := false
	runner := &fakeK8sRunner{}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "helm" && strings.HasPrefix(joined, "rollback ") {
			rolledBack = true
			return stdout(""), nil
		}
		if rolledBack && command.name == "kubectl" && strings.Contains(joined, "get deployment") {
			return stdout(strings.Replace(readyDeploymentJSON("tunnex-gateway", "tunnex-gateway-tunnex-gateway-state"), `,"annotations":{"tunnex.io/zero-touch-contract":"tunnex-zero-touch/v1"}`, "", 1)), nil
		}
		return installedRunnerHandler(command)
	}
	deps := baseK8sDeps(runner, baseK8sControlPlane(), &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"rollback", "--revision", "2", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), zeroTouchContractAnnotationKey) {
		t.Fatalf("post-rollback live contract error = %v", err)
	}
	if !rolledBack {
		t.Fatal("rollback mutation was not reached")
	}
}

func TestK8sResumeCleanupRequiresProvenanceBeforeSecretDelete(t *testing.T) {
	cp := baseK8sControlPlane()
	anchor := testCompletedLifecycleAnchor(cp, "tunnex-gateway", "aks-gateway-a")
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}}
	runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		switch {
		case command.name == "kubectl" && strings.Contains(joined, "get secret tunnex-gateway-bootstrap"):
			return stdout(bootstrapSecretMetadataLine("tunnex-gateway")), nil
		case command.name == "kubectl" && strings.Contains(joined, "get pvc tunnex-gateway-tunnex-gateway-state") && strings.Contains(joined, "--ignore-not-found=true"):
			return stdout(readyPVCJSON("tunnex-gateway-tunnex-gateway-state", "tunnex-gateway")), nil
		case command.name == "helm" && strings.HasPrefix(joined, "history tunnex-gateway "):
			return stdout(`[{"revision":3,"description":"legacy"}]`), nil
		default:
			return installedRunnerHandler(command)
		}
	}
	cp.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{claim: testLifecycleClaim, state: "consumed", nodeName: "aks-gateway-a", generation: 1, requestID: testLifecycleRequest, expiresAt: testLifecycleExpiry, nodeID: testLifecycleNodeID}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"install", "--node-name", "aks-gateway-a", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "unproven lifecycle description") {
		t.Fatalf("resume provenance error = %v", err)
	}
	for _, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "delete --raw=") {
			t.Fatalf("unproven resume deleted Secret: %+v", command)
		}
		if command.name == "helm" && (strings.Contains(joined, "get values") || strings.Contains(joined, "get manifest")) {
			t.Fatalf("provenance read forbidden Helm payload: %+v", command)
		}
	}
}

func assertNoHelmLifecycleMutation(t *testing.T, runner *fakeK8sRunner) {
	t.Helper()
	for _, command := range runner.commands {
		if command.name != "helm" || len(command.args) == 0 {
			continue
		}
		if command.args[0] == "install" || command.args[0] == "rollback" || command.args[0] == "uninstall" ||
			(command.args[0] == "upgrade" && len(command.args) > 1 && command.args[1] != "--help") {
			t.Fatalf("unproven lifecycle executed Helm mutation: %+v", command)
		}
	}
}
