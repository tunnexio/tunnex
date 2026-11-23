package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// K8N-2: on a cluster that runs Cilium the installer gives the host-posture
// manager two more host paths, both read-only, by setting the chart value
// cilium.enabled. Every other cluster keeps the manager it had.

const (
	ciliumMountsJSON  = `,{"name":"cilium-run","mountPath":"/var/run/cilium","readOnly":true},{"name":"host-bpf","mountPath":"/sys/fs/bpf","readOnly":true,"mountPropagation":"HostToContainer"}],"resources"`
	ciliumVolumesJSON = `{"name":"cilium-run","hostPath":{"path":"/var/run/cilium","type":"Directory"}},{"name":"host-bpf","hostPath":{"path":"/sys/fs/bpf","type":"Directory"}},{"name":"k8s-api-token","projected"`
)

// ciliumHostPostureDaemonSetJSON is the manager as the chart renders it with
// cilium.enabled=true.
func ciliumHostPostureDaemonSetJSON(t *testing.T) string {
	t.Helper()
	base := readyHostPostureDaemonSetJSON(nil)
	withMounts := strings.Replace(base, `],"resources"`, ciliumMountsJSON, 1)
	withVolumes := strings.Replace(withMounts, `{"name":"k8s-api-token","projected"`, ciliumVolumesJSON, 1)
	if withMounts == base || withVolumes == withMounts {
		t.Fatal("the manager fixture has no place for the Cilium host paths")
	}
	return withVolumes
}

func isCiliumLookup(command k8sCommand) bool {
	return command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "get daemonset cilium --namespace kube-system --ignore-not-found=true --output name")
}

func isHostPostureHelmApply(command k8sCommand) bool {
	return command.name == "helm" && strings.HasPrefix(strings.Join(command.args, " "), "upgrade --install tunnex-host-posture ")
}

func TestK8sHostPostureGetsCiliumHostPathsOnlyOnACiliumCluster(t *testing.T) {
	for name, tc := range map[string]struct {
		cilium   bool
		existing string // "", "plain" or "cilium": the manager before the install
		action   string
		values   string // what the Helm values must say about cilium; "" for nothing
	}{
		"clean install, Cilium":             {cilium: true, action: "install", values: `"cilium":{"enabled":true}`},
		"clean install, no Cilium":          {action: "install"},
		"manager without the paths, Cilium": {cilium: true, existing: "plain", action: "upgrade", values: `"cilium":{"enabled":true}`},
		"manager with the paths, Cilium":    {cilium: true, existing: "cilium", action: "reuse"},
		"manager with the paths, no Cilium": {existing: "cilium", action: "upgrade", values: `"cilium":{"enabled":false}`},
		"manager without the paths":         {existing: "plain", action: "reuse"},
	} {
		t.Run(name, func(t *testing.T) {
			plain, withPaths := readyHostPostureDaemonSetJSON(nil), ciliumHostPostureDaemonSetJSON(t)
			live := map[string]string{"": "", "plain": plain, "cilium": withPaths}[tc.existing]
			lookups, applies := 0, 0
			cp := baseK8sControlPlane()
			handler := func(command k8sCommand) (k8sCommandResult, error) {
				joined := strings.Join(command.args, " ")
				switch {
				case isCiliumLookup(command):
					lookups++
					if tc.cilium {
						return stdout("daemonset.apps/cilium\n"), nil
					}
					return stdout(""), nil
				case command.name == "helm" && strings.HasPrefix(joined, "list --all-namespaces"):
					if live == "" {
						return stdout(`[]`), nil
					}
					return baseRunnerHandler(command)
				case command.name == "kubectl" && strings.Contains(joined, "get daemonset tunnex-host-posture"):
					return stdout(live), nil
				case command.name == "kubectl" && (strings.Contains(joined, "get sa tunnex-host-posture") || strings.Contains(joined, "get clusterrole tunnex-host-posture-gateway-owner-reader") || strings.Contains(joined, "get clusterrolebinding tunnex-host-posture-gateway-owner-reader")):
					if live == "" {
						return stdout(""), nil
					}
					return baseRunnerHandler(command)
				case isHostPostureHelmApply(command):
					applies++
					if cp.issueCount != 0 {
						t.Fatalf("gateway token minted before the host posture apply")
					}
					if tc.values == "" && bytes.Contains(command.stdin, []byte("cilium")) {
						t.Fatalf("Helm values name Cilium on a cluster without it: %s", command.stdin)
					}
					if tc.values != "" && !bytes.Contains(command.stdin, []byte(tc.values)) {
						t.Fatalf("Helm values lack %s: %s", tc.values, command.stdin)
					}
					// Helm applies what the value says.
					live = plain
					if tc.cilium {
						live = withPaths
					}
					return stdout("Release upgraded\n"), nil
				default:
					return baseRunnerHandler(command)
				}
			}

			// The plan, which the operator approves, says it.
			var planOut bytes.Buffer
			planRunner := &fakeK8sRunner{handler: handler}
			if err := runK8s(context.Background(), []string{"plan", "--node-name", "gateway-a"}, baseK8sDeps(planRunner, baseK8sControlPlane(), &planOut, &bytes.Buffer{})); err != nil {
				t.Fatalf("plan: %v", err)
			}
			if !strings.Contains(planOut.String(), `"action": "`+tc.action+`"`) {
				t.Fatalf("plan action is not %s:\n%s", tc.action, planOut.String())
			}
			if got := strings.Contains(planOut.String(), `"cilium_host_paths": true`); got != tc.cilium {
				t.Fatalf("plan cilium_host_paths=%t, want %t:\n%s", got, tc.cilium, planOut.String())
			}
			wantOperation := tc.cilium && tc.action != "reuse"
			if got := strings.Contains(planOut.String(), "with read-only host mounts of /var/run/cilium and /sys/fs/bpf because this cluster runs Cilium"); got != wantOperation {
				t.Fatalf("plan operation names the Cilium mounts=%t, want %t:\n%s", got, wantOperation, planOut.String())
			}
			if applies != 0 || lookups != 1 {
				t.Fatalf("plan: applies=%d Cilium lookups=%d", applies, lookups)
			}

			runner := &fakeK8sRunner{handler: handler}
			if err := runK8s(context.Background(), []string{"install", "--node-name", "gateway-a", "--yes"}, baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})); err != nil {
				t.Fatalf("install: %v", err)
			}
			wantApplies := 1
			if tc.action == "reuse" {
				wantApplies = 0
			}
			if applies != wantApplies || cp.issueCount != 1 {
				t.Fatalf("applies=%d, want %d; gateway token mints=%d", applies, wantApplies, cp.issueCount)
			}
		})
	}
}

// The installer names what it applied. A manager that does not have the paths
// the approved plan promised is not accepted, and no gateway token is minted.
func TestK8sHostPostureCiliumHostPathsMustBePresentAfterApply(t *testing.T) {
	cp := baseK8sControlPlane()
	installed := false
	runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		switch {
		case isCiliumLookup(command):
			return stdout("daemonset.apps/cilium\n"), nil
		case command.name == "helm" && strings.HasPrefix(joined, "list --all-namespaces"):
			if !installed {
				return stdout(`[]`), nil
			}
			return baseRunnerHandler(command)
		case command.name == "kubectl" && strings.Contains(joined, "get daemonset tunnex-host-posture"):
			if !installed {
				return stdout(""), nil
			}
			// An older chart ignored the value: the manager has no Cilium path.
			return stdout(readyHostPostureDaemonSetJSON(nil)), nil
		case command.name == "kubectl" && (strings.Contains(joined, "get sa tunnex-host-posture") || strings.Contains(joined, "get clusterrole tunnex-host-posture-gateway-owner-reader") || strings.Contains(joined, "get clusterrolebinding tunnex-host-posture-gateway-owner-reader")):
			if !installed {
				return stdout(""), nil
			}
			return baseRunnerHandler(command)
		case isHostPostureHelmApply(command):
			installed = true
			return stdout("Release upgraded\n"), nil
		default:
			return baseRunnerHandler(command)
		}
	}}
	err := runK8s(context.Background(), []string{"install", "--node-name", "gateway-a", "--yes"}, baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}))
	if err == nil || !strings.Contains(err.Error(), "Cilium host paths are mounted=false after apply, expected approved true") {
		t.Fatalf("install: %v", err)
	}
	if cp.issueCount != 0 {
		t.Fatalf("gateway token minted without the approved manager: %d", cp.issueCount)
	}
}

func TestK8sCiliumLookupFailsClosed(t *testing.T) {
	for name, answer := range map[string]k8sCommandResult{
		"another object":  stdout("daemonset.apps/cilium-envoy\n"),
		"several objects": stdout("daemonset.apps/cilium\ndaemonset.apps/cilium\n"),
	} {
		cp := baseK8sControlPlane()
		runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
			if isCiliumLookup(command) {
				return answer, nil
			}
			return baseRunnerHandler(command)
		}}
		err := runK8s(context.Background(), []string{"install", "--node-name", "gateway-a", "--yes"}, baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}))
		if err == nil || !strings.Contains(err.Error(), "while looking for the Cilium agent DaemonSet") || cp.issueCount != 0 {
			t.Errorf("%s: %v, mints=%d", name, err, cp.issueCount)
		}
		assertNoHostPostureMutation(t, runner)
	}
}

// With the Cilium paths the manager's shape is as fixed as without them: both
// paths or neither, the exact host paths, read-only, and nothing that
// propagates from the container to the host.
func TestK8sHostPostureCiliumShapeDriftRefusesBeforeMutation(t *testing.T) {
	base := ciliumHostPostureDaemonSetJSON(t)
	for _, tc := range []struct{ name, old, new string }{
		{name: "socket directory mounted writable", old: `"mountPath":"/var/run/cilium","readOnly":true`, new: `"mountPath":"/var/run/cilium","readOnly":false`},
		{name: "pinned maps mounted writable", old: `"mountPath":"/sys/fs/bpf","readOnly":true`, new: `"mountPath":"/sys/fs/bpf"`},
		{name: "pinned maps propagate to the host", old: `"mountPropagation":"HostToContainer"`, new: `"mountPropagation":"Bidirectional"`},
		{name: "socket directory follows the host", old: `{"name":"cilium-run","mountPath":"/var/run/cilium","readOnly":true}`, new: `{"name":"cilium-run","mountPath":"/var/run/cilium","readOnly":true,"mountPropagation":"HostToContainer"}`},
		{name: "another mount path", old: `"mountPath":"/var/run/cilium"`, new: `"mountPath":"/var/run"`},
		{name: "another host path", old: `"hostPath":{"path":"/var/run/cilium","type":"Directory"}`, new: `"hostPath":{"path":"/var/run","type":"Directory"}`},
		{name: "host path created when absent", old: `"hostPath":{"path":"/var/run/cilium","type":"Directory"}`, new: `"hostPath":{"path":"/var/run/cilium","type":"DirectoryOrCreate"}`},
		{name: "whole BPF filesystem replaced by sysfs", old: `"hostPath":{"path":"/sys/fs/bpf","type":"Directory"}`, new: `"hostPath":{"path":"/sys","type":"Directory"}`},
		{name: "only one of the two volumes", old: `{"name":"cilium-run","hostPath":{"path":"/var/run/cilium","type":"Directory"}},`, new: ``},
		{name: "only one of the two mounts", old: `,{"name":"cilium-run","mountPath":"/var/run/cilium","readOnly":true}`, new: ``},
		{name: "a third host path", old: `{"name":"host-bpf","hostPath"`, new: `{"name":"host-run","hostPath":{"path":"/run","type":"Directory"}},{"name":"host-bpf","hostPath"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			drifted := strings.Replace(base, tc.old, tc.new, 1)
			if drifted == base {
				t.Fatalf("fixture replacement %q not found", tc.old)
			}
			cp := baseK8sControlPlane()
			runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
				switch {
				case isCiliumLookup(command):
					return stdout("daemonset.apps/cilium\n"), nil
				case command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "get daemonset tunnex-host-posture"):
					return stdout(drifted), nil
				}
				return baseRunnerHandler(command)
			}}
			err := runK8s(context.Background(), []string{"install", "--node-name", "gateway-a", "--yes"}, baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}))
			if err == nil {
				t.Fatal("Cilium shape drift unexpectedly accepted")
			}
			if cp.issueCount != 0 {
				t.Fatalf("shape drift minted %d gateway tokens", cp.issueCount)
			}
			assertNoHostPostureMutation(t, runner)
		})
	}
	// The same paths on a manager that also mounts the base set are accepted.
	var ds hostPostureDaemonSet
	if err := jsonUnmarshalStrictForTest(base, &ds); err != nil {
		t.Fatal(err)
	}
	if err := verifyHostPostureFixedShape(&ds); err != nil || !hostPostureCiliumHostPaths(&ds) {
		t.Fatalf("the chart's own Cilium shape is refused: %v", err)
	}
}

func jsonUnmarshalStrictForTest(raw string, into any) error {
	return json.Unmarshal([]byte(raw), into)
}
