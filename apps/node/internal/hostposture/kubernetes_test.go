package hostposture

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func authoritativePodFixture() map[string]any {
	return map[string]any{
		"metadata": map[string]any{
			"uid": "11111111-2222-3333-4444-555555555555", "name": "gw-a", "namespace": "tunnex-system",
			"labels": map[string]string{
				OwnerLabelKey: OwnerLabelValue, "app.kubernetes.io/name": "tunnex-gateway", "app.kubernetes.io/component": "gateway",
				"app.kubernetes.io/managed-by": "Helm", "app.kubernetes.io/instance": "gw-a",
			},
			"annotations": map[string]string{OwnerContractAnnotation: Contract, OwnerServiceAccountAnnotation: "gw-a-tunnex-gateway"},
		},
		"spec": map[string]any{
			"nodeName": "worker-a", "serviceAccountName": "gw-a-tunnex-gateway", "hostNetwork": true, "automountServiceAccountToken": false,
			"initContainers": []any{map[string]any{
				"name": "host-posture-check", "command": []string{"/usr/local/bin/tunnex-node", "k8s-host-posture-check", "--wait"},
				"securityContext": map[string]any{
					"privileged": false, "allowPrivilegeEscalation": false, "runAsNonRoot": true, "runAsUser": 65532, "readOnlyRootFilesystem": true,
					"capabilities":   map[string]any{"drop": []string{"ALL"}},
					"seccompProfile": map[string]any{"type": "RuntimeDefault"},
				},
				"env": []any{
					map[string]any{"name": "TUNNEX_HOST_POSTURE_NODE_NAME", "valueFrom": map[string]any{"fieldRef": map[string]any{"fieldPath": "spec.nodeName"}}},
					map[string]any{"name": "TUNNEX_HOST_POSTURE_OWNER_UID", "valueFrom": map[string]any{"fieldRef": map[string]any{"fieldPath": "metadata.uid"}}},
					map[string]any{"name": "TUNNEX_HOST_POSTURE_STATE_DIR", "value": DefaultStateDir},
				},
				"volumeMounts": []any{map[string]any{"name": "host-posture-state", "mountPath": DefaultStateDir, "readOnly": true}},
			}},
			"containers": []any{map[string]any{
				"name": "gateway",
				"env":  []any{map[string]any{"name": "TUNNEX_K8S_MODE", "value": "true"}, map[string]any{"name": "TUNNEX_WG_BACKEND", "value": "wgctrl"}},
				"securityContext": map[string]any{
					"privileged": false, "allowPrivilegeEscalation": false, "runAsNonRoot": false,
					"seccompProfile": map[string]any{"type": "RuntimeDefault"},
					"capabilities":   map[string]any{"add": []string{"NET_ADMIN", "NET_BIND_SERVICE"}, "drop": []string{"ALL"}},
				},
				"volumeMounts": []any{map[string]any{"name": "dev-net-tun", "mountPath": "/dev/net/tun"}},
			}},
			"volumes": []any{
				map[string]any{"name": "dev-net-tun", "hostPath": map[string]any{"path": "/dev/net/tun", "type": "CharDevice"}},
				map[string]any{"name": "host-posture-state", "hostPath": map[string]any{"path": DefaultStateDir, "type": "Directory"}},
			},
		},
		"status": map[string]any{"phase": "Running"},
	}
}

type postureRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn postureRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func newOwnerSourceFixture(t *testing.T, response *string) *KubernetesOwnerSource {
	t.Helper()
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("rotating-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	client.Transport = postureRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer rotating-token" || r.Header.Get("Accept") != "application/json" {
			return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader("unauthorized")), Header: make(http.Header)}, nil
		}
		want := url.Values{}
		want.Set("fieldSelector", "spec.nodeName=worker-a")
		want.Set("labelSelector", OwnerLabelKey+"="+OwnerLabelValue)
		want.Set("limit", "257")
		if r.URL.Path != "/api/v1/pods" || r.URL.Query().Encode() != want.Encode() {
			return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader("wrong exact owner query")), Header: make(http.Header)}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(*response)), Header: http.Header{"Content-Type": []string{"application/json"}}}, nil
	})
	return &KubernetesOwnerSource{
		base: "https://kubernetes.test", tokenPath: tokenPath,
		client: client,
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)), ignored: map[string]string{},
	}
}

func marshalPodList(t *testing.T, pods ...map[string]any) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"metadata": map[string]any{"continue": ""}, "items": pods})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestKubernetesOwnerSourceCountsOnlyExactEquivalentHostAuthority(t *testing.T) {
	response := marshalPodList(t, authoritativePodFixture())
	source := newOwnerSourceFixture(t, &response)
	owners, err := source.List(t.Context(), "worker-a", 4)
	if err != nil || len(owners) != 1 || owners[0] != testOwner() {
		t.Fatalf("owners=%+v err=%v", owners, err)
	}
}

func TestKubernetesOwnerSourceExcludesTerminatingGatewayOwner(t *testing.T) {
	pod := authoritativePodFixture()
	pod["metadata"].(map[string]any)["deletionTimestamp"] = "2026-08-30T12:34:56Z"
	response := marshalPodList(t, pod)
	source := newOwnerSourceFixture(t, &response)
	owners, err := source.List(t.Context(), "worker-a", 4)
	if err != nil || len(owners) != 0 {
		t.Fatalf("terminating gateway retained host ownership: owners=%+v err=%v", owners, err)
	}
	if len(source.ignored) != 0 {
		t.Fatalf("terminating gateway should be excluded, not treated as malformed: ignored=%v", source.ignored)
	}
}

func TestKubernetesOwnerSourceIgnoresLabelOnlySpoofWithoutBlockingRealOwner(t *testing.T) {
	spoof := authoritativePodFixture()
	metadata := spoof["metadata"].(map[string]any)
	metadata["uid"], metadata["name"] = "99999999-2222-3333-4444-555555555555", "label-spoof"
	delete(metadata, "annotations")
	spec := spoof["spec"].(map[string]any)
	spec["hostNetwork"] = false
	spec["containers"] = []any{map[string]any{"name": "ordinary"}}
	response := marshalPodList(t, spoof, authoritativePodFixture())
	source := newOwnerSourceFixture(t, &response)
	owners, err := source.List(t.Context(), "worker-a", 4)
	if err != nil || len(owners) != 1 || owners[0] != testOwner() {
		t.Fatalf("label spoof gained authority or blocked real owner: owners=%+v err=%v", owners, err)
	}
	if len(source.ignored) != 1 {
		t.Fatalf("ignored diagnostics=%v, want one bounded candidate", source.ignored)
	}
}

func TestKubernetesOwnerSourceMalformedCandidateDoesNotConsumeValidOwnerLimit(t *testing.T) {
	spoof := authoritativePodFixture()
	spoofMetadata := spoof["metadata"].(map[string]any)
	spoofMetadata["uid"], spoofMetadata["name"] = "99999999-2222-3333-4444-555555555555", "label-spoof"
	delete(spoofMetadata, "annotations")
	spoof["spec"].(map[string]any)["hostNetwork"] = false
	pods := []map[string]any{spoof}
	for i := 0; i < 4; i++ {
		pod := authoritativePodFixture()
		metadata := pod["metadata"].(map[string]any)
		letter := string(rune('a' + i))
		metadata["uid"] = strings.Repeat(letter, 8) + "-2222-3333-4444-555555555555"
		metadata["name"] = "gw-" + letter
		pods = append(pods, pod)
	}
	response := marshalPodList(t, pods...)
	source := newOwnerSourceFixture(t, &response)
	owners, err := source.List(t.Context(), "worker-a", 4)
	if err != nil || len(owners) != 4 {
		t.Fatalf("malformed candidate consumed valid owner limit: owners=%+v err=%v", owners, err)
	}
}

func TestKubernetesOwnerSourceRefusesConflictingDuplicateUID(t *testing.T) {
	conflict := authoritativePodFixture()
	conflict["metadata"].(map[string]any)["name"] = "gw-conflict"
	response := marshalPodList(t, authoritativePodFixture(), conflict)
	source := newOwnerSourceFixture(t, &response)
	if owners, err := source.List(t.Context(), "worker-a", 4); err == nil || len(owners) != 0 || !strings.Contains(err.Error(), "duplicate Pod UID") {
		t.Fatalf("conflicting UID owners=%+v err=%v", owners, err)
	}
}

func TestKubernetesOwnerSourceIgnoresExpandedGatewayCapabilities(t *testing.T) {
	pod := authoritativePodFixture()
	gateway := pod["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
	gateway["securityContext"].(map[string]any)["capabilities"].(map[string]any)["add"] = []string{"NET_ADMIN", "NET_BIND_SERVICE", "SYS_ADMIN"}
	response := marshalPodList(t, pod)
	source := newOwnerSourceFixture(t, &response)
	owners, err := source.List(t.Context(), "worker-a", 4)
	if err != nil || len(owners) != 0 || len(source.ignored) != 1 {
		t.Fatalf("expanded capability gateway gained authority: owners=%+v ignored=%v err=%v", owners, source.ignored, err)
	}
}

func TestKubernetesOwnerSourceIgnoresWritableOrCredentialedAdmissionInit(t *testing.T) {
	for _, mutate := range []func(map[string]any){
		func(init map[string]any) { init["volumeMounts"].([]any)[0].(map[string]any)["readOnly"] = false },
		func(init map[string]any) {
			init["env"] = append(init["env"].([]any), map[string]any{"name": "TOKEN", "value": "credential"})
		},
	} {
		pod := authoritativePodFixture()
		init := pod["spec"].(map[string]any)["initContainers"].([]any)[0].(map[string]any)
		mutate(init)
		response := marshalPodList(t, pod)
		source := newOwnerSourceFixture(t, &response)
		owners, err := source.List(t.Context(), "worker-a", 4)
		if err != nil || len(owners) != 0 || len(source.ignored) != 1 {
			t.Fatalf("unsafe init gained authority: owners=%+v ignored=%v err=%v", owners, source.ignored, err)
		}
	}
}

func TestKubernetesOwnerSourceIgnoresAmbiguousGatewayModeEnvironment(t *testing.T) {
	pod := authoritativePodFixture()
	gateway := pod["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
	gateway["env"] = append(gateway["env"].([]any), map[string]any{"name": "TUNNEX_K8S_MODE", "value": "false"})
	response := marshalPodList(t, pod)
	source := newOwnerSourceFixture(t, &response)
	owners, err := source.List(t.Context(), "worker-a", 4)
	if err != nil || len(owners) != 0 || len(source.ignored) != 1 {
		t.Fatalf("ambiguous gateway mode gained authority: owners=%+v ignored=%v err=%v", owners, source.ignored, err)
	}
}
