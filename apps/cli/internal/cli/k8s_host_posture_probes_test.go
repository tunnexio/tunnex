package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// K8N-1, "Hardening after the live install": the manager's exec probes got a
// 5 s timeout and a slower liveness restart. A manager installed before that
// still carries the 2 s probes. It must be recognised and upgraded, never
// refused and never reused; any third shape is still refused.

// previousProbesHostPostureDaemonSetJSON is the manager as every chart before
// the change rendered it.
func previousProbesHostPostureDaemonSetJSON(t *testing.T) string {
	t.Helper()
	current := readyHostPostureDaemonSetJSON(nil)
	previous := current
	for _, change := range [][2]string{
		{`"periodSeconds":2,"timeoutSeconds":5,"successThreshold":1,"failureThreshold":45`, `"periodSeconds":2,"timeoutSeconds":2,"successThreshold":1,"failureThreshold":45`},
		{`"periodSeconds":5,"timeoutSeconds":5,"successThreshold":1,"failureThreshold":3`, `"periodSeconds":2,"timeoutSeconds":2,"successThreshold":1,"failureThreshold":3`},
		{`"periodSeconds":10,"timeoutSeconds":5,"successThreshold":1,"failureThreshold":6`, `"periodSeconds":10,"timeoutSeconds":2,"successThreshold":1,"failureThreshold":3`},
	} {
		next := strings.Replace(previous, change[0], change[1], 1)
		if next == previous {
			t.Fatalf("the manager fixture has no probe %s", change[0])
		}
		previous = next
	}
	return previous
}

func TestK8sHostPostureManagerWithPreviousProbesIsUpgradedNotReused(t *testing.T) {
	live := previousProbesHostPostureDaemonSetJSON(t)
	applies := 0
	cp := baseK8sControlPlane()
	handler := func(command k8sCommand) (k8sCommandResult, error) {
		switch {
		case command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "get daemonset tunnex-host-posture"):
			return stdout(live), nil
		case isHostPostureHelmApply(command):
			applies++
			if cp.issueCount != 0 {
				t.Fatal("gateway token minted before the host posture apply")
			}
			live = readyHostPostureDaemonSetJSON(nil)
			return stdout("Release upgraded\n"), nil
		default:
			return baseRunnerHandler(command)
		}
	}

	var planOut bytes.Buffer
	planRunner := &fakeK8sRunner{handler: handler}
	if err := runK8s(context.Background(), []string{"plan", "--node-name", "gateway-a"}, baseK8sDeps(planRunner, baseK8sControlPlane(), &planOut, &bytes.Buffer{})); err != nil {
		t.Fatalf("plan refused a manager with the previous probes: %v", err)
	}
	if !strings.Contains(planOut.String(), `"action": "upgrade"`) || applies != 0 {
		t.Fatalf("plan must upgrade a manager with the previous probes without applying (applies=%d):\n%s", applies, planOut.String())
	}

	runner := &fakeK8sRunner{handler: handler}
	if err := runK8s(context.Background(), []string{"install", "--node-name", "gateway-a", "--yes"}, baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})); err != nil {
		t.Fatalf("install: %v", err)
	}
	if applies != 1 || cp.issueCount != 1 {
		t.Fatalf("applies=%d, want 1; gateway token mints=%d", applies, cp.issueCount)
	}
}

// A chart that still renders the previous probes is not what the plan
// approved: no gateway token is minted behind it.
func TestK8sHostPosturePreviousProbesAfterApplyBlockGatewayMint(t *testing.T) {
	previous := previousProbesHostPostureDaemonSetJSON(t)
	cp := baseK8sControlPlane()
	applies := 0
	runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		switch {
		case command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "get daemonset tunnex-host-posture"):
			return stdout(previous), nil
		case isHostPostureHelmApply(command):
			applies++
			return stdout("Release upgraded\n"), nil
		default:
			return baseRunnerHandler(command)
		}
	}}
	err := runK8s(context.Background(), []string{"install", "--node-name", "gateway-a", "--yes"}, baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}))
	if err == nil || !strings.Contains(err.Error(), "still carries the previous 2s health probes after apply") {
		t.Fatalf("install: %v", err)
	}
	if applies != 1 || cp.issueCount != 0 {
		t.Fatalf("applies=%d, want 1; gateway token mints=%d, want 0", applies, cp.issueCount)
	}
}

func TestK8sHostPostureAnyOtherProbeTimingRefusesBeforeMutation(t *testing.T) {
	current := readyHostPostureDaemonSetJSON(nil)
	for name, change := range map[string][2]string{
		"liveness never restarts":       {`"timeoutSeconds":5,"successThreshold":1,"failureThreshold":6`, `"timeoutSeconds":5,"successThreshold":1,"failureThreshold":600`},
		"longer timeout":                {`"periodSeconds":10,"timeoutSeconds":5`, `"periodSeconds":10,"timeoutSeconds":30`},
		"current and previous mixed":    {`"periodSeconds":5,"timeoutSeconds":5,"successThreshold":1,"failureThreshold":3`, `"periodSeconds":2,"timeoutSeconds":2,"successThreshold":1,"failureThreshold":3`},
		"initial delay":                 {`"periodSeconds":10,`, `"initialDelaySeconds":300,"periodSeconds":10,`},
		"readiness needs two successes": {`"periodSeconds":5,"timeoutSeconds":5,"successThreshold":1`, `"periodSeconds":5,"timeoutSeconds":5,"successThreshold":2`},
	} {
		t.Run(name, func(t *testing.T) {
			drifted := strings.Replace(current, change[0], change[1], 1)
			if drifted == current {
				t.Fatalf("fixture replacement %q not found", change[0])
			}
			cp := baseK8sControlPlane()
			runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
				if command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "get daemonset tunnex-host-posture") {
					return stdout(drifted), nil
				}
				return baseRunnerHandler(command)
			}}
			err := runK8s(context.Background(), []string{"install", "--node-name", "gateway-a", "--yes"}, baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}))
			if err == nil || !strings.Contains(err.Error(), "not the exact executable health contract") {
				t.Fatalf("probe drift was not refused: %v", err)
			}
			if cp.issueCount != 0 {
				t.Fatalf("probe drift minted %d gateway tokens", cp.issueCount)
			}
			assertNoHostPostureMutation(t, runner)
		})
	}
}
