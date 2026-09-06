package cli

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestK8sInstallPinsResolvedContextAcrossApproval(t *testing.T) {
	cp := baseK8sControlPlane()
	const approvedContext = "approved-cluster-a"
	runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && joined == "config current-context" {
			return stdout(approvedContext + "\n"), nil
		}
		return baseRunnerHandler(command)
	}}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	if err := runK8s(context.Background(), []string{"install", "--node-name", "gateway-a", "--yes"}, deps); err != nil {
		t.Fatalf("install: %v", err)
	}

	foundSecretCreate := false
	foundHelmInstall := false
	for _, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		switch {
		case command.name == "kubectl" && joined == "config current-context":
			continue
		case command.name == "kubectl":
			if got := hardeningArgValue(command.args, "--context"); got != approvedContext {
				t.Fatalf("kubectl action escaped approved context: args=%v context=%q", command.args, got)
			}
			if strings.Contains(joined, "create -f -") && bytes.Contains(command.stdin, []byte(testJoinToken)) {
				foundSecretCreate = true
			}
		case command.name == "helm" && joined == "version --short":
			continue
		case command.name == "helm":
			if got := hardeningArgValue(command.args, "--kube-context"); got != approvedContext {
				t.Fatalf("Helm action escaped approved context: args=%v context=%q", command.args, got)
			}
			if len(command.args) > 0 && command.args[0] == "install" {
				foundHelmInstall = true
			}
		}
	}
	if !foundSecretCreate || !foundHelmInstall {
		t.Fatalf("install did not exercise both Secret and Helm mutations: secret=%v helm=%v", foundSecretCreate, foundHelmInstall)
	}
}

func hardeningArgValue(args []string, name string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}

func TestAuthedClientRefusesBearerRedirects(t *testing.T) {
	for _, tc := range []struct {
		name     string
		location func(string) string
	}{
		{
			name:     "same host HTTPS to HTTP downgrade",
			location: func(target string) string { return target },
		},
		{
			name: "cross origin",
			location: func(target string) string {
				return strings.Replace(target, "127.0.0.1", "localhost", 1)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targetCalls := 0
			targetAuthorization := ""
			target := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
				targetCalls++
				targetAuthorization = request.Header.Get("Authorization")
			}))
			defer target.Close()

			sourceCalls := 0
			source := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				sourceCalls++
				if got := request.Header.Get("Authorization"); got != "Bearer cli-secret" {
					t.Errorf("source Authorization = %q", got)
				}
				response.Header().Set("Location", tc.location(target.URL))
				response.WriteHeader(http.StatusTemporaryRedirect)
			}))
			defer source.Close()

			client, err := newAuthedClientWithTransport(Credential{Server: source.URL, Token: "cli-secret"}, source.Client().Transport)
			if err != nil {
				t.Fatalf("new client: %v", err)
			}
			response, err := client.GetMetaWithResponse(context.Background())
			if err != nil {
				t.Fatalf("GetMeta: %v", err)
			}
			if response.StatusCode() != http.StatusTemporaryRedirect || sourceCalls != 1 {
				t.Fatalf("response=%d source calls=%d, want one un-followed 307", response.StatusCode(), sourceCalls)
			}
			if targetCalls != 0 || targetAuthorization != "" {
				t.Fatalf("redirect target received calls=%d Authorization=%q", targetCalls, targetAuthorization)
			}
		})
	}
}

func TestK8sControlPlaneRejectsRemoteHTTPBeforeClientUse(t *testing.T) {
	client, err := newAPIK8sControlPlane(Credential{Server: "http://cp.example.test", Token: "must-not-be-sent"})
	if err == nil || client != nil || !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("client=%v error=%v, want pre-client HTTPS refusal", client, err)
	}
	if _, err := newAPIK8sControlPlane(Credential{Server: "http://127.0.0.1:8080", Token: "dev"}); err != nil {
		t.Fatalf("loopback development endpoint: %v", err)
	}
}

func TestVerifyGatewayExplicitEndpointDoesNotRequireLoadBalancerIngress(t *testing.T) {
	runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		if command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "get service") {
			return stdout(serviceJSONWithIngress("gateway-a", "LoadBalancer", "")), nil
		}
		return baseRunnerHandler(command)
	}}
	if err := verifyGateway(context.Background(), runner, "ctx", "tunnex", "gateway-a", "LoadBalancer", "static.example.test:51820", 0, "10m"); err != nil {
		t.Fatalf("explicit endpoint verification: %v", err)
	}
	if err := verifyGateway(context.Background(), runner, "ctx", "tunnex", "gateway-a", "LoadBalancer", "", 0, "10m"); err == nil || !strings.Contains(err.Error(), "no status.loadBalancer.ingress") {
		t.Fatalf("discovered endpoint error=%v, want missing ingress refusal", err)
	}
}

func TestVerifyGatewayRejectsDiscoveredLoadBalancerPortDrift(t *testing.T) {
	runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		if command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "get service") {
			service := serviceJSONWithIngress("gateway-a", "LoadBalancer", "203.0.113.8")
			return stdout(strings.Replace(service, `"port":51820`, `"port":51821`, 1)), nil
		}
		if command.name == "helm" && strings.HasPrefix(strings.Join(command.args, " "), "list ") && !strings.Contains(strings.Join(command.args, " "), "--all-namespaces") {
			return stdout(`[{"name":"gateway-a","namespace":"tunnex","revision":"3","status":"deployed","chart":"tunnex-gateway-0.2.0","app_version":"0.2.0"}]`), nil
		}
		return baseRunnerHandler(command)
	}}
	err := verifyGateway(context.Background(), runner, "ctx", "tunnex", "gateway-a", "LoadBalancer", "", 0, "10m")
	if err == nil || !strings.Contains(err.Error(), "expected approved port 51820") {
		t.Fatalf("verification error=%v, want discovered Service port drift refusal", err)
	}
	var out bytes.Buffer
	deps := baseK8sDeps(runner, baseK8sControlPlane(), &out, &bytes.Buffer{})
	if err := runK8s(context.Background(), []string{"status", "--release", "gateway-a"}, deps); err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(out.String(), "not ready: gateway Service wireguard port is 51821") {
		t.Fatalf("status did not expose Service port drift:\n%s", out.String())
	}
}

func TestVerifyGatewayRejectsUnsafeReplicaCounts(t *testing.T) {
	for _, replicas := range []int{0, 2} {
		t.Run(fmt.Sprintf("replicas-%d", replicas), func(t *testing.T) {
			runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
				if command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "get deployment") {
					deployment := fmt.Sprintf(`{"metadata":{"name":"gateway-a-tunnex-gateway","generation":4},"spec":{"replicas":%d},"status":{"observedGeneration":4,"readyReplicas":%d,"availableReplicas":%d,"updatedReplicas":%d}}`, replicas, replicas, replicas, replicas)
					return stdout(deployment), nil
				}
				return baseRunnerHandler(command)
			}}
			err := verifyGateway(context.Background(), runner, "ctx", "tunnex", "gateway-a", "LoadBalancer", "", 0, "10m")
			if err == nil || !strings.Contains(err.Error(), "exactly one replica") {
				t.Fatalf("verification error=%v, want single-identity replica refusal", err)
			}
		})
	}
}

func TestK8sIPv6LoadBalancerEndpointIsCanonicalInStatusAndVerification(t *testing.T) {
	runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		if command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "get service") {
			return stdout(serviceJSONWithIngress("tunnex-gateway", "LoadBalancer", "2001:db8::7")), nil
		}
		return installedRunnerHandler(command)
	}}
	var out bytes.Buffer
	deps := baseK8sDeps(runner, baseK8sControlPlane(), &out, &bytes.Buffer{})
	if err := runK8s(context.Background(), []string{"status"}, deps); err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(out.String(), `"endpoint": "[2001:db8::7]:51820"`) {
		t.Fatalf("status did not render canonical IPv6 endpoint:\n%s", out.String())
	}
	if err := verifyGateway(context.Background(), runner, "walk-context", "tunnex", "tunnex-gateway", "LoadBalancer", "", 0, "10m"); err != nil {
		t.Fatalf("IPv6 verification: %v", err)
	}
}

func serviceJSONWithIngress(release, serviceType, ingress string) string {
	status := `"loadBalancer":{}`
	if ingress != "" {
		status = fmt.Sprintf(`"loadBalancer":{"ingress":[{"ip":%q}]}`, ingress)
	}
	return fmt.Sprintf(`{"metadata":{"name":%q},"spec":{"type":%q,"ports":[{"name":"wireguard","port":51820,"protocol":"UDP"}]},"status":{%s}}`, gatewayFullname(release)+"-wg", serviceType, status)
}

func TestK8sInstallRequiresExactPersistentIdentityBeforeSuccess(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "fresh enrollment", args: []string{"install", "--node-name", "gateway-a", "--yes"}},
		{name: "retained reuse", args: []string{"install", "--node-name", "gateway-a", "--mode", "reuse", "--existing-claim", "retained-state-a", "--yes"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cp := baseK8sControlPlane()
			if strings.Contains(tc.name, "reuse") {
				cp = retainedReuseControlPlane()
			}
			runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
				joined := strings.Join(command.args, " ")
				if command.name == "kubectl" && strings.Contains(joined, "get deployment") {
					return stdout(readyDeploymentJSON("tunnex-gateway", "wrong-state-claim")), nil
				}
				return baseRunnerHandler(command)
			}}
			deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
			err := runK8s(context.Background(), tc.args, deps)
			if err == nil || !strings.Contains(err.Error(), "expected approved claim") {
				t.Fatalf("install error=%v, want wrong-claim refusal", err)
			}
			for _, command := range runner.commands {
				if strings.Contains(strings.Join(command.args, " "), "/secrets/") && command.name == "kubectl" && len(command.stdin) != 0 {
					t.Fatalf("bootstrap Secret was deleted after identity refusal: %+v", command)
				}
			}
			if strings.Contains(tc.name, "reuse") && cp.issueCount != 0 {
				t.Fatalf("reuse minted %d tokens", cp.issueCount)
			}
		})
	}
}

func TestK8sInstallReuseRequiresPreflightPVCIdentityAfterReady(t *testing.T) {
	cp := retainedReuseControlPlane()
	pvcReads := 0
	runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "get deployment") {
			return stdout(readyDeploymentJSON("tunnex-gateway", "retained-state-a")), nil
		}
		if command.name == "kubectl" && strings.Contains(joined, "get pvc retained-state-a") {
			pvcReads++
			if pvcReads > 2 {
				return stdout(strings.Replace(readyPVCJSON("retained-state-a", "tunnex-gateway"), `"uid":"uid-retained-state-a"`, `"uid":"replacement-uid"`, 1)), nil
			}
		}
		return baseRunnerHandler(command)
	}}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"install", "--node-name", "gateway-a", "--mode", "reuse", "--existing-claim", "retained-state-a", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "UID changed") {
		t.Fatalf("install error=%v, want reuse identity swap refusal", err)
	}
	if cp.issueCount != 0 {
		t.Fatalf("reuse minted %d tokens", cp.issueCount)
	}
}

func TestK8sInstallRejectsUnapprovedStorageClassBeforeSecretDeletion(t *testing.T) {
	runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "get pvc") && !strings.Contains(joined, "--ignore-not-found=true") {
			pvc := strings.Replace(readyPVCJSON("tunnex-gateway-tunnex-gateway-state", "tunnex-gateway"), `"storageClassName":"managed-csi"`, `"storageClassName":"unencrypted-default"`, 1)
			return stdout(pvc), nil
		}
		return baseRunnerHandler(command)
	}}
	cp := baseK8sControlPlane()
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"install", "--node-name", "gateway-a", "--storage-class", "managed-csi", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), `expected approved StorageClass "managed-csi"`) {
		t.Fatalf("install error=%v, want StorageClass readback refusal", err)
	}
	for _, command := range runner.commands {
		if command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "/secrets/") && len(command.stdin) != 0 {
			t.Fatalf("bootstrap Secret was deleted after StorageClass refusal: %+v", command)
		}
	}
}

func TestBootstrapSecretIsImmutable(t *testing.T) {
	anchor := testLifecycleAnchor("gateway", "gateway-a", "issued")
	manifest, err := bootstrapSecretManifest("tunnex", "gateway-bootstrap", "gateway", "secret-token", anchor)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(manifest, []byte(`"immutable":true`)) || !bytes.Contains(manifest, []byte(`"TUNNEX_JOIN_TOKEN":"secret-token"`)) {
		t.Fatalf("bootstrap Secret lacks immutable token transport: %s", manifest)
	}
}

func TestK8sInstallRejectsMutableRetrySecretBeforeHelm(t *testing.T) {
	anchor := testLifecycleAnchor("tunnex-gateway", "gateway-a", "issued")
	runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}, handler: func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "get secret tunnex-gateway-bootstrap") {
			return stdout(strings.Replace(bootstrapSecretMetadataLine("tunnex-gateway"), "\ttrue\t", "\tfalse\t", 1)), nil
		}
		return baseRunnerHandler(command)
	}}
	cp := baseK8sControlPlane()
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	err := runK8s(context.Background(), []string{"install", "--node-name", "gateway-a", "--yes"}, deps)
	if err == nil || !strings.Contains(err.Error(), "is mutable") {
		t.Fatalf("install error=%v, want mutable retry refusal", err)
	}
	if cp.issueCount != 0 {
		t.Fatalf("mutable retry minted %d tokens", cp.issueCount)
	}
	for _, command := range runner.commands {
		if command.name == "helm" && len(command.args) > 0 && command.args[0] == "install" {
			t.Fatalf("mutable retry reached Helm: %+v", command)
		}
	}
}
