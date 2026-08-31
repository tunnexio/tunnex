package hostposture

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	serviceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	serviceAccountCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	maxTokenBytes           = 64 << 10
)

type OwnerSource interface {
	List(context.Context, string, int) ([]Owner, error)
}

type KubernetesOwnerSource struct {
	base      string
	tokenPath string
	client    *http.Client
	log       *slog.Logger
	mu        sync.Mutex
	ignored   map[string]string
}

func NewInClusterOwnerSource(requestTimeout time.Duration) (*KubernetesOwnerSource, error) {
	host := strings.Trim(strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST")), "[]")
	port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
	if host == "" || port == "" {
		return nil, fmt.Errorf("Kubernetes API coordinates are unavailable")
	}
	if _, err := readBoundedToken(serviceAccountTokenPath); err != nil {
		return nil, fmt.Errorf("read projected ServiceAccount token: %w", err)
	}
	caPEM, err := os.ReadFile(serviceAccountCAPath)
	if err != nil {
		return nil, fmt.Errorf("read projected ServiceAccount CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("projected ServiceAccount CA contains no certificate")
	}
	if requestTimeout <= 0 {
		requestTimeout = DefaultAPIRequestTimeout
	}
	return &KubernetesOwnerSource{
		base:      "https://" + net.JoinHostPort(host, port),
		tokenPath: serviceAccountTokenPath,
		client: &http.Client{
			Timeout: requestTimeout,
			Transport: &http.Transport{
				TLSClientConfig:       &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
				TLSHandshakeTimeout:   requestTimeout,
				ResponseHeaderTimeout: requestTimeout,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		log:     slog.Default(),
		ignored: map[string]string{},
	}, nil
}

type podList struct {
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
	Items []struct {
		Metadata struct {
			UID               string            `json:"uid"`
			Name              string            `json:"name"`
			Namespace         string            `json:"namespace"`
			DeletionTimestamp *string           `json:"deletionTimestamp"`
			Labels            map[string]string `json:"labels"`
			Annotations       map[string]string `json:"annotations"`
		} `json:"metadata"`
		Spec struct {
			NodeName                     string         `json:"nodeName"`
			ServiceAccountName           string         `json:"serviceAccountName"`
			HostNetwork                  bool           `json:"hostNetwork"`
			AutomountServiceAccountToken *bool          `json:"automountServiceAccountToken"`
			InitContainers               []podContainer `json:"initContainers"`
			Containers                   []podContainer `json:"containers"`
			Volumes                      []struct {
				Name     string `json:"name"`
				HostPath *struct {
					Path string `json:"path"`
					Type string `json:"type"`
				} `json:"hostPath"`
			} `json:"volumes"`
		} `json:"spec"`
		Status struct {
			Phase string `json:"phase"`
		} `json:"status"`
	} `json:"items"`
}

type podContainer struct {
	Name            string   `json:"name"`
	Command         []string `json:"command"`
	Env             []podEnv `json:"env"`
	SecurityContext struct {
		Privileged               *bool  `json:"privileged"`
		AllowPrivilegeEscalation *bool  `json:"allowPrivilegeEscalation"`
		RunAsNonRoot             *bool  `json:"runAsNonRoot"`
		RunAsUser                *int64 `json:"runAsUser"`
		ReadOnlyRootFilesystem   *bool  `json:"readOnlyRootFilesystem"`
		SeccompProfile           struct {
			Type string `json:"type"`
		} `json:"seccompProfile"`
		Capabilities struct {
			Add  []string `json:"add"`
			Drop []string `json:"drop"`
		} `json:"capabilities"`
	} `json:"securityContext"`
	VolumeMounts []struct {
		Name      string `json:"name"`
		MountPath string `json:"mountPath"`
		ReadOnly  bool   `json:"readOnly"`
	} `json:"volumeMounts"`
}

type podEnv struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	ValueFrom *struct {
		FieldRef *struct {
			FieldPath string `json:"fieldPath"`
		} `json:"fieldRef"`
	} `json:"valueFrom"`
}

var (
	nodeNameRE = regexp.MustCompile(`^[A-Za-z0-9](?:[-A-Za-z0-9._]*[A-Za-z0-9])?$`)
	uidRE      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	dnsNameRE  = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$`)
)

func (s *KubernetesOwnerSource) List(ctx context.Context, nodeName string, maxOwners int) ([]Owner, error) {
	if s == nil || s.client == nil || strings.TrimSpace(s.base) == "" || strings.TrimSpace(s.tokenPath) == "" {
		return nil, fmt.Errorf("Kubernetes owner source is incomplete")
	}
	if !validNodeName(nodeName) {
		return nil, fmt.Errorf("invalid exact Kubernetes node name")
	}
	if maxOwners < 1 || maxOwners > DefaultMaxOwners {
		return nil, fmt.Errorf("max owners must be between 1 and %d", DefaultMaxOwners)
	}
	query := url.Values{}
	query.Set("fieldSelector", "spec.nodeName="+nodeName)
	query.Set("labelSelector", OwnerLabelKey+"="+OwnerLabelValue)
	query.Set("limit", strconv.Itoa(DefaultMaxOwnerCandidates+1))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base+"/api/v1/pods?"+query.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("build Pod owner readback: %w", err)
	}
	token, err := readBoundedToken(s.tokenPath)
	if err != nil {
		return nil, fmt.Errorf("reload projected ServiceAccount token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list live gateway Pods: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("list live gateway Pods returned HTTP %d", resp.StatusCode)
	}
	var listed podList
	dec := json.NewDecoder(io.LimitReader(resp.Body, MaxKubernetesResponse+1))
	if err := dec.Decode(&listed); err != nil {
		return nil, fmt.Errorf("decode live gateway Pod list: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("live gateway Pod list contained trailing or oversized JSON")
	}
	if listed.Metadata.Continue != "" || len(listed.Items) > DefaultMaxOwnerCandidates {
		return nil, fmt.Errorf("label-selected gateway candidate set exceeds bounded scan maximum %d", DefaultMaxOwnerCandidates)
	}
	owners := make([]Owner, 0, min(len(listed.Items), maxOwners))
	seenCandidates := make(map[string]Owner, len(listed.Items))
	seenOwners := make(map[string]Owner, len(listed.Items))
	ignored := make(map[string]string)
	for _, pod := range listed.Items {
		if pod.Spec.NodeName != nodeName || pod.Metadata.Labels[OwnerLabelKey] != OwnerLabelValue {
			return nil, fmt.Errorf("Kubernetes API returned a Pod outside the exact owner selector")
		}
		if pod.Metadata.DeletionTimestamp != nil || pod.Status.Phase == "Succeeded" || pod.Status.Phase == "Failed" {
			continue
		}
		owner := Owner{UID: pod.Metadata.UID, Namespace: pod.Metadata.Namespace, Name: pod.Metadata.Name}
		if !validOwner(owner) {
			return nil, fmt.Errorf("Kubernetes API returned an invalid owner identity")
		}
		if prior, ok := seenCandidates[owner.UID]; ok && prior != owner {
			return nil, fmt.Errorf("duplicate Pod UID maps to conflicting owner identities")
		}
		seenCandidates[owner.UID] = owner
		if err := validateGatewayAuthority(pod.Metadata.Labels, pod.Metadata.Annotations, pod.Spec.ServiceAccountName,
			pod.Spec.NodeName, pod.Spec.HostNetwork, pod.Spec.AutomountServiceAccountToken,
			pod.Spec.InitContainers, pod.Spec.Containers, pod.Spec.Volumes); err != nil {
			ignored[owner.Namespace+"/"+owner.Name+"/"+owner.UID] = boundedReason(err.Error())
			continue
		}
		seenOwners[owner.UID] = owner
		if len(seenOwners) > maxOwners {
			return nil, fmt.Errorf("live valid gateway owner set exceeds bounded maximum %d", maxOwners)
		}
	}
	s.publishIgnored(ignored)
	for _, owner := range seenOwners {
		owners = append(owners, owner)
	}
	sort.Slice(owners, func(i, j int) bool { return owners[i].UID < owners[j].UID })
	return owners, nil
}

func (s *KubernetesOwnerSource) publishIgnored(next map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.log == nil {
		s.log = slog.Default()
	}
	for key, reason := range next {
		if s.ignored[key] != reason {
			s.log.Warn("k8s_host_posture_candidate_ignored", "pod", boundedReason(key), "reason", reason)
		}
	}
	for key := range s.ignored {
		if _, ok := next[key]; !ok {
			s.log.Info("k8s_host_posture_candidate_no_longer_ignored", "pod", boundedReason(key))
		}
	}
	s.ignored = next
}

func validateGatewayAuthority(labels, annotations map[string]string, serviceAccount, nodeName string, hostNetwork bool,
	automount *bool, initContainers, containers []podContainer, volumes []struct {
		Name     string `json:"name"`
		HostPath *struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"hostPath"`
	}) error {
	if labels["app.kubernetes.io/name"] != "tunnex-gateway" || labels["app.kubernetes.io/component"] != "gateway" ||
		labels["app.kubernetes.io/managed-by"] != "Helm" || strings.TrimSpace(labels["app.kubernetes.io/instance"]) == "" {
		return fmt.Errorf("managed gateway labels are missing")
	}
	if annotations[OwnerContractAnnotation] != Contract {
		return fmt.Errorf("exact host-posture contract annotation is missing")
	}
	if !validNodeName(nodeName) || serviceAccount == "" || annotations[OwnerServiceAccountAnnotation] != serviceAccount {
		return fmt.Errorf("ServiceAccount identity is missing or conflicting")
	}
	if !hostNetwork || automount == nil || *automount {
		return fmt.Errorf("hostNetwork or explicit credential boundary is missing")
	}
	deviceVolume := false
	postureVolume := false
	for _, volume := range volumes {
		if volume.Name == "dev-net-tun" && volume.HostPath != nil && volume.HostPath.Path == "/dev/net/tun" && volume.HostPath.Type == "CharDevice" {
			deviceVolume = true
		}
		if volume.Name == "host-posture-state" && volume.HostPath != nil && volume.HostPath.Path == DefaultStateDir && volume.HostPath.Type == "Directory" {
			postureVolume = true
		}
	}
	if !deviceVolume || !postureVolume {
		return fmt.Errorf("exact /dev/net/tun and host-posture hostPaths are missing")
	}
	if len(initContainers) != 1 || initContainers[0].Name != "host-posture-check" ||
		!equalStrings(initContainers[0].Command, []string{"/usr/local/bin/tunnex-node", "k8s-host-posture-check", "--wait"}) {
		return fmt.Errorf("fixed host-posture admission init is missing")
	}
	init := &initContainers[0]
	if boolValue(init.SecurityContext.Privileged) || init.SecurityContext.AllowPrivilegeEscalation == nil || *init.SecurityContext.AllowPrivilegeEscalation ||
		init.SecurityContext.RunAsNonRoot == nil || !*init.SecurityContext.RunAsNonRoot || init.SecurityContext.RunAsUser == nil || *init.SecurityContext.RunAsUser != 65532 ||
		init.SecurityContext.ReadOnlyRootFilesystem == nil || !*init.SecurityContext.ReadOnlyRootFilesystem ||
		init.SecurityContext.SeccompProfile.Type != "RuntimeDefault" ||
		len(init.SecurityContext.Capabilities.Add) != 0 || !equalStringSet(init.SecurityContext.Capabilities.Drop, []string{"ALL"}) ||
		len(init.VolumeMounts) != 1 || !hasExactMount(init.VolumeMounts, "host-posture-state", DefaultStateDir, true) ||
		!validPostureCheckEnv(init.Env) {
		return fmt.Errorf("credentialless host-posture admission init contract is missing")
	}
	var gateway *podContainer
	for i := range containers {
		if containers[i].Name == "gateway" {
			if gateway != nil {
				return fmt.Errorf("gateway container identity is ambiguous")
			}
			gateway = &containers[i]
		}
	}
	if gateway == nil || boolValue(gateway.SecurityContext.Privileged) ||
		gateway.SecurityContext.AllowPrivilegeEscalation == nil || *gateway.SecurityContext.AllowPrivilegeEscalation ||
		gateway.SecurityContext.RunAsNonRoot == nil || *gateway.SecurityContext.RunAsNonRoot || gateway.SecurityContext.SeccompProfile.Type != "RuntimeDefault" ||
		!equalStringSet(gateway.SecurityContext.Capabilities.Add, []string{"NET_ADMIN", "NET_BIND_SERVICE"}) ||
		!equalStringSet(gateway.SecurityContext.Capabilities.Drop, []string{"ALL"}) {
		return fmt.Errorf("gateway NET_ADMIN security contract is missing")
	}
	if !hasMount(gateway.VolumeMounts, "dev-net-tun", "/dev/net/tun") ||
		!hasExactLiteralEnv(gateway.Env, "TUNNEX_K8S_MODE", "true") ||
		!hasExactLiteralEnv(gateway.Env, "TUNNEX_WG_BACKEND", "wgctrl") {
		return fmt.Errorf("gateway host dataplane contract is missing")
	}
	return nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func boolValue(value *bool) bool { return value != nil && *value }

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func equalStringSet(values, want []string) bool {
	if len(values) != len(want) {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	for _, value := range want {
		if _, ok := seen[value]; !ok {
			return false
		}
	}
	return true
}

func hasMount(mounts []struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
	ReadOnly  bool   `json:"readOnly"`
}, name, path string) bool {
	for _, mount := range mounts {
		if mount.Name == name && mount.MountPath == path {
			return true
		}
	}
	return false
}

func hasExactMount(mounts []struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
	ReadOnly  bool   `json:"readOnly"`
}, name, path string, readOnly bool) bool {
	for _, mount := range mounts {
		if mount.Name == name && mount.MountPath == path && mount.ReadOnly == readOnly {
			return true
		}
	}
	return false
}

func validPostureCheckEnv(env []podEnv) bool {
	if len(env) != 3 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range env {
		if seen[value.Name] {
			return false
		}
		seen[value.Name] = true
		switch value.Name {
		case "TUNNEX_HOST_POSTURE_NODE_NAME":
			if value.Value != "" || value.ValueFrom == nil || value.ValueFrom.FieldRef == nil || value.ValueFrom.FieldRef.FieldPath != "spec.nodeName" {
				return false
			}
		case "TUNNEX_HOST_POSTURE_OWNER_UID":
			if value.Value != "" || value.ValueFrom == nil || value.ValueFrom.FieldRef == nil || value.ValueFrom.FieldRef.FieldPath != "metadata.uid" {
				return false
			}
		case "TUNNEX_HOST_POSTURE_STATE_DIR":
			if value.Value != DefaultStateDir || value.ValueFrom != nil {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func hasExactLiteralEnv(env []podEnv, name, want string) bool {
	count := 0
	for _, value := range env {
		if value.Name == name {
			if value.ValueFrom != nil || value.Value != want {
				return false
			}
			count++
		}
	}
	return count == 1
}

func readBoundedToken(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, maxTokenBytes+1))
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(body))
	if value == "" || len(body) > maxTokenBytes || strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("projected token is empty, multiline, or oversized")
	}
	return value, nil
}

func validNodeName(value string) bool {
	return len(value) <= 253 && nodeNameRE.MatchString(value)
}

func validOwner(owner Owner) bool {
	return len(owner.UID) <= MaxOwnerUIDBytes && uidRE.MatchString(owner.UID) &&
		len(owner.Name) <= 253 && dnsNameRE.MatchString(owner.Name) &&
		len(owner.Namespace) <= 253 && dnsNameRE.MatchString(owner.Namespace)
}
