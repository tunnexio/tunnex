package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	hostPostureContractKey   = "tunnex.io/host-posture-contract"
	hostPostureContractValue = "tunnex-host-posture/v1"
	hostPostureDaemonSetName = "tunnex-host-posture"
	hostPostureRBACName      = "tunnex-host-posture-gateway-owner-reader"
	hostPostureHelmPageSize  = 256
	hostPostureHelmMaxItems  = 4096
)

type lifecycleHostPosture struct {
	Action           string   `json:"action"`
	Release          string   `json:"release"`
	Namespace        string   `json:"namespace"`
	DaemonSet        string   `json:"daemon_set"`
	Chart            string   `json:"chart"`
	ChartName        string   `json:"chart_name"`
	Version          string   `json:"version,omitempty"`
	AppVersion       string   `json:"app_version"`
	ArtifactSHA256   string   `json:"artifact_sha256,omitempty"`
	Contract         string   `json:"contract"`
	Image            string   `json:"image"`
	ImagePullSecrets []string `json:"image_pull_secrets,omitempty"`
}

type hostPostureDaemonSet struct {
	Metadata struct {
		Name            string            `json:"name"`
		Namespace       string            `json:"namespace"`
		UID             string            `json:"uid"`
		ResourceVersion string            `json:"resourceVersion"`
		Generation      int64             `json:"generation"`
		Labels          map[string]string `json:"labels"`
		Annotations     map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		UpdateStrategy struct {
			Type          string `json:"type"`
			RollingUpdate struct {
				MaxUnavailable json.RawMessage `json:"maxUnavailable"`
				MaxSurge       json.RawMessage `json:"maxSurge"`
			} `json:"rollingUpdate"`
		} `json:"updateStrategy"`
		Selector struct {
			MatchLabels map[string]string `json:"matchLabels"`
		} `json:"selector"`
		Template struct {
			Metadata struct {
				Labels      map[string]string `json:"labels"`
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
			Spec struct {
				ServiceAccountName           string            `json:"serviceAccountName"`
				AutomountServiceAccountToken *bool             `json:"automountServiceAccountToken"`
				HostNetwork                  bool              `json:"hostNetwork"`
				DNSPolicy                    string            `json:"dnsPolicy"`
				TerminationGracePeriod       *int64            `json:"terminationGracePeriodSeconds"`
				NodeSelector                 map[string]string `json:"nodeSelector"`
				Tolerations                  []struct {
					Key               string `json:"key"`
					Operator          string `json:"operator"`
					Value             string `json:"value"`
					Effect            string `json:"effect"`
					TolerationSeconds *int64 `json:"tolerationSeconds"`
				} `json:"tolerations"`
				Affinity         json.RawMessage `json:"affinity"`
				ImagePullSecrets []struct {
					Name string `json:"name"`
				} `json:"imagePullSecrets"`
				Containers []struct {
					Name            string   `json:"name"`
					Image           string   `json:"image"`
					ImagePullPolicy string   `json:"imagePullPolicy"`
					Command         []string `json:"command"`
					SecurityContext struct {
						Privileged               *bool  `json:"privileged"`
						RunAsUser                *int64 `json:"runAsUser"`
						RunAsNonRoot             *bool  `json:"runAsNonRoot"`
						AllowPrivilegeEscalation *bool  `json:"allowPrivilegeEscalation"`
						ReadOnlyRootFilesystem   *bool  `json:"readOnlyRootFilesystem"`
						SeccompProfile           struct {
							Type string `json:"type"`
						} `json:"seccompProfile"`
					} `json:"securityContext"`
					Env []struct {
						Name      string `json:"name"`
						Value     string `json:"value"`
						ValueFrom struct {
							FieldRef struct {
								FieldPath string `json:"fieldPath"`
							} `json:"fieldRef"`
						} `json:"valueFrom"`
					} `json:"env"`
					VolumeMounts []struct {
						Name      string `json:"name"`
						MountPath string `json:"mountPath"`
						ReadOnly  bool   `json:"readOnly"`
					} `json:"volumeMounts"`
					StartupProbe   hostPostureProbe `json:"startupProbe"`
					ReadinessProbe hostPostureProbe `json:"readinessProbe"`
					LivenessProbe  hostPostureProbe `json:"livenessProbe"`
					Resources      json.RawMessage  `json:"resources"`
				} `json:"containers"`
				Volumes []struct {
					Name     string `json:"name"`
					HostPath *struct {
						Path string `json:"path"`
						Type string `json:"type"`
					} `json:"hostPath"`
					Projected *struct {
						DefaultMode *int32 `json:"defaultMode"`
						Sources     []struct {
							ServiceAccountToken *struct {
								Path              string `json:"path"`
								ExpirationSeconds *int64 `json:"expirationSeconds"`
							} `json:"serviceAccountToken"`
							ConfigMap *struct {
								Name  string `json:"name"`
								Items []struct {
									Key  string `json:"key"`
									Path string `json:"path"`
								} `json:"items"`
							} `json:"configMap"`
						} `json:"sources"`
					} `json:"projected"`
				} `json:"volumes"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
	Status struct {
		ObservedGeneration     int64 `json:"observedGeneration"`
		DesiredNumberScheduled int32 `json:"desiredNumberScheduled"`
		CurrentNumberScheduled int32 `json:"currentNumberScheduled"`
		UpdatedNumberScheduled int32 `json:"updatedNumberScheduled"`
		NumberReady            int32 `json:"numberReady"`
		NumberUnavailable      int32 `json:"numberUnavailable"`
	} `json:"status"`
}

type hostPostureProbe struct {
	Exec *struct {
		Command []string `json:"command"`
	} `json:"exec"`
	InitialDelaySeconds int32 `json:"initialDelaySeconds"`
	PeriodSeconds       int32 `json:"periodSeconds"`
	TimeoutSeconds      int32 `json:"timeoutSeconds"`
	SuccessThreshold    int32 `json:"successThreshold"`
	FailureThreshold    int32 `json:"failureThreshold"`
}

type hostPostureServiceAccount struct {
	Metadata struct {
		Name            string            `json:"name"`
		Namespace       string            `json:"namespace"`
		UID             string            `json:"uid"`
		ResourceVersion string            `json:"resourceVersion"`
		Labels          map[string]string `json:"labels"`
		Annotations     map[string]string `json:"annotations"`
	} `json:"metadata"`
	AutomountServiceAccountToken *bool `json:"automountServiceAccountToken"`
}

type hostPostureClusterRole struct {
	Metadata struct {
		Name            string            `json:"name"`
		UID             string            `json:"uid"`
		ResourceVersion string            `json:"resourceVersion"`
		Labels          map[string]string `json:"labels"`
		Annotations     map[string]string `json:"annotations"`
	} `json:"metadata"`
	AggregationRule json.RawMessage `json:"aggregationRule"`
	Rules           []struct {
		APIGroups       []string `json:"apiGroups"`
		Resources       []string `json:"resources"`
		ResourceNames   []string `json:"resourceNames"`
		Verbs           []string `json:"verbs"`
		NonResourceURLs []string `json:"nonResourceURLs"`
	} `json:"rules"`
}

type hostPostureClusterRoleBinding struct {
	Metadata struct {
		Name            string            `json:"name"`
		UID             string            `json:"uid"`
		ResourceVersion string            `json:"resourceVersion"`
		Labels          map[string]string `json:"labels"`
		Annotations     map[string]string `json:"annotations"`
	} `json:"metadata"`
	RoleRef struct {
		APIGroup string `json:"apiGroup"`
		Kind     string `json:"kind"`
		Name     string `json:"name"`
	} `json:"roleRef"`
	Subjects []struct {
		APIGroup  string `json:"apiGroup"`
		Kind      string `json:"kind"`
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"subjects"`
}

type hostPostureState struct {
	present        bool
	release        helmReleaseSummary
	daemonSet      *hostPostureDaemonSet
	serviceAccount *hostPostureServiceAccount
	clusterRole    *hostPostureClusterRole
	roleBinding    *hostPostureClusterRoleBinding
}

func (s hostPostureState) fingerprint() string {
	parts := []string{strconv.FormatBool(s.present), s.release.Name, s.release.Namespace, s.release.Revision, s.release.Status, s.release.Chart, s.release.AppVersion}
	if s.daemonSet == nil {
		return strings.Join(append(parts, "absent"), "\x00")
	}
	ds := s.daemonSet
	spec, _ := json.Marshal(ds.Spec)
	serviceAccount, _ := json.Marshal(s.serviceAccount)
	clusterRole, _ := json.Marshal(s.clusterRole)
	roleBinding, _ := json.Marshal(s.roleBinding)
	parts = append(parts, ds.Metadata.Name, ds.Metadata.Namespace, ds.Metadata.UID, ds.Metadata.ResourceVersion, strconv.FormatInt(ds.Metadata.Generation, 10), ds.Metadata.Annotations[hostPostureContractKey],
		ds.Metadata.Annotations["meta.helm.sh/release-name"], ds.Metadata.Annotations["meta.helm.sh/release-namespace"], ds.Metadata.Labels["app.kubernetes.io/managed-by"],
		strconv.FormatInt(ds.Status.ObservedGeneration, 10), strconv.Itoa(int(ds.Status.DesiredNumberScheduled)), strconv.Itoa(int(ds.Status.CurrentNumberScheduled)),
		strconv.Itoa(int(ds.Status.UpdatedNumberScheduled)), strconv.Itoa(int(ds.Status.NumberReady)), strconv.Itoa(int(ds.Status.NumberUnavailable)), string(spec), string(serviceAccount), string(clusterRole), string(roleBinding))
	return strings.Join(parts, "\x00")
}

func discoverHostPostureState(ctx context.Context, runner k8sRunner, kubeContext string) (hostPostureState, error) {
	all, err := listAllHelmReleasesBounded(ctx, runner, kubeContext)
	if err != nil {
		return hostPostureState{}, err
	}
	candidates := make([]helmReleaseSummary, 0, 1)
	for _, release := range all {
		if release.Name == defaultHostPostureRelease || strings.HasPrefix(release.Chart, "tunnex-host-posture-") {
			candidates = append(candidates, release)
		}
	}
	if len(candidates) > 1 {
		return hostPostureState{}, fmt.Errorf("found %d cluster-wide host posture managers; refusing a second privileged singleton", len(candidates))
	}
	state := hostPostureState{}
	if len(candidates) == 1 {
		state.present, state.release = true, candidates[0]
		if state.release.Name != defaultHostPostureRelease || state.release.Namespace != defaultHostPostureNamespace || !strings.HasPrefix(state.release.Chart, "tunnex-host-posture-") {
			return hostPostureState{}, fmt.Errorf("host posture manager must be exact release %q in namespace %q; found %q in %q with chart %q", defaultHostPostureRelease, defaultHostPostureNamespace, state.release.Name, state.release.Namespace, state.release.Chart)
		}
	}
	dsResult, err := runChecked(ctx, runner, "read fixed host posture DaemonSet", k8sCommand{
		name: "kubectl", args: kubectlArgs(kubeContext, "get", "daemonset", hostPostureDaemonSetName, "--namespace", defaultHostPostureNamespace, "--ignore-not-found=true", "--output", "json"),
	})
	if err != nil {
		return hostPostureState{}, err
	}
	if strings.TrimSpace(string(dsResult.stdout)) != "" {
		var ds hostPostureDaemonSet
		if err := json.Unmarshal(dsResult.stdout, &ds); err != nil {
			return hostPostureState{}, fmt.Errorf("decode host posture DaemonSet: %w", err)
		}
		state.daemonSet = &ds
	}
	if present, err := readOptionalHostPostureObject(ctx, runner, kubeContext, "ServiceAccount", []string{"get", "sa", hostPostureDaemonSetName, "--namespace", defaultHostPostureNamespace, "--ignore-not-found=true", "--output", "json"}, &state.serviceAccount); err != nil {
		return hostPostureState{}, err
	} else if !present {
		state.serviceAccount = nil
	}
	if present, err := readOptionalHostPostureObject(ctx, runner, kubeContext, "ClusterRole", []string{"get", "clusterrole", hostPostureRBACName, "--ignore-not-found=true", "--output", "json"}, &state.clusterRole); err != nil {
		return hostPostureState{}, err
	} else if !present {
		state.clusterRole = nil
	}
	if present, err := readOptionalHostPostureObject(ctx, runner, kubeContext, "ClusterRoleBinding", []string{"get", "clusterrolebinding", hostPostureRBACName, "--ignore-not-found=true", "--output", "json"}, &state.roleBinding); err != nil {
		return hostPostureState{}, err
	} else if !present {
		state.roleBinding = nil
	}
	if !state.present && (state.daemonSet != nil || state.serviceAccount != nil || state.clusterRole != nil || state.roleBinding != nil) {
		return hostPostureState{}, errors.New("fixed host posture objects exist without their exact Helm release; refusing orphan adoption")
	}
	if state.present {
		if state.daemonSet == nil || state.serviceAccount == nil || state.clusterRole == nil || state.roleBinding == nil {
			return hostPostureState{}, errors.New("host posture Helm release is missing its fixed DaemonSet, ServiceAccount, ClusterRole, or ClusterRoleBinding; refusing implicit migration or adoption")
		}
		if err := verifyHostPostureOwnership(state.daemonSet); err != nil {
			return hostPostureState{}, err
		}
		if err := verifyHostPostureFixedShape(state.daemonSet); err != nil {
			return hostPostureState{}, err
		}
		if err := verifyHostPostureAccessObjects(state.serviceAccount, state.clusterRole, state.roleBinding); err != nil {
			return hostPostureState{}, err
		}
		revision, parseErr := strconv.Atoi(state.release.Revision)
		if parseErr != nil || revision <= 0 {
			return hostPostureState{}, fmt.Errorf("host posture Helm revision %q is invalid", state.release.Revision)
		}
		if err := requireZeroTouchRevision(ctx, runner, releaseOptions{release: defaultHostPostureRelease, namespace: defaultHostPostureNamespace, kubeContext: kubeContext, timeout: defaultK8sTimeout}, revision); err != nil {
			return hostPostureState{}, fmt.Errorf("host posture Helm provenance is not zero-touch: %w", err)
		}
	}
	return state, nil
}

func listAllHelmReleasesBounded(ctx context.Context, runner k8sRunner, kubeContext string) ([]helmReleaseSummary, error) {
	all := make([]helmReleaseSummary, 0, hostPostureHelmPageSize)
	seen := make(map[string]struct{})
	for offset := 0; ; offset += hostPostureHelmPageSize {
		if offset >= hostPostureHelmMaxItems {
			return nil, fmt.Errorf("cluster-wide Helm release inventory reached the fail-closed limit of %d; no privileged singleton mutation is safe", hostPostureHelmMaxItems)
		}
		args := []string{"list", "--all-namespaces", "--all", "--output", "json", "--max", strconv.Itoa(hostPostureHelmPageSize), "--offset", strconv.Itoa(offset)}
		result, err := runChecked(ctx, runner, "discover cluster-wide host posture managers page", k8sCommand{name: "helm", args: appendHelmContext(args, kubeContext)})
		if err != nil {
			return nil, err
		}
		var page []helmReleaseSummary
		if err := json.Unmarshal(result.stdout, &page); err != nil {
			return nil, fmt.Errorf("decode cluster-wide Helm releases at offset %d: %w", offset, err)
		}
		if len(page) > hostPostureHelmPageSize {
			return nil, fmt.Errorf("Helm returned %d releases for bounded page size %d", len(page), hostPostureHelmPageSize)
		}
		for _, release := range page {
			identity := release.Namespace + "\x00" + release.Name
			if _, duplicate := seen[identity]; duplicate {
				return nil, fmt.Errorf("cluster-wide Helm inventory repeated release %q in namespace %q across pages", release.Name, release.Namespace)
			}
			seen[identity] = struct{}{}
			all = append(all, release)
		}
		if len(page) < hostPostureHelmPageSize {
			return all, nil
		}
	}
}

func readOptionalHostPostureObject(ctx context.Context, runner k8sRunner, kubeContext, kind string, args []string, target any) (bool, error) {
	result, err := runChecked(ctx, runner, "read fixed host posture "+kind, k8sCommand{name: "kubectl", args: kubectlArgs(kubeContext, args...)})
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(string(result.stdout)) == "" {
		return false, nil
	}
	if err := json.Unmarshal(result.stdout, target); err != nil {
		return false, fmt.Errorf("decode host posture %s: %w", kind, err)
	}
	return true, nil
}

func verifyHostPostureOwnership(ds *hostPostureDaemonSet) error {
	if ds.Metadata.Name != hostPostureDaemonSetName || ds.Metadata.Namespace != defaultHostPostureNamespace ||
		ds.Metadata.Annotations[hostPostureContractKey] != hostPostureContractValue ||
		ds.Metadata.Annotations["meta.helm.sh/release-name"] != defaultHostPostureRelease ||
		ds.Metadata.Annotations["meta.helm.sh/release-namespace"] != defaultHostPostureNamespace ||
		ds.Metadata.Labels["app.kubernetes.io/name"] != "tunnex-host-posture" ||
		ds.Metadata.Labels["app.kubernetes.io/instance"] != defaultHostPostureRelease ||
		ds.Metadata.Labels["app.kubernetes.io/managed-by"] != "Helm" ||
		ds.Metadata.Labels["app.kubernetes.io/component"] != "host-posture" {
		return errors.New("host posture DaemonSet lacks exact fixed Helm ownership and lifecycle contract; refusing implicit migration or adoption")
	}
	if len(ds.Spec.Template.Spec.Containers) != 1 || ds.Spec.Template.Spec.Containers[0].Name != "host-posture-manager" {
		return errors.New("host posture DaemonSet shape is not the fixed singleton manager; refusing implicit upgrade")
	}
	return nil
}

func verifyHostPostureAccessObjects(sa *hostPostureServiceAccount, role *hostPostureClusterRole, binding *hostPostureClusterRoleBinding) error {
	if sa == nil || role == nil || binding == nil {
		return errors.New("host posture access objects are incomplete")
	}
	if sa.Metadata.Name != hostPostureDaemonSetName || sa.Metadata.Namespace != defaultHostPostureNamespace ||
		!hostPostureHelmMetadata(sa.Metadata.Labels, sa.Metadata.Annotations) || sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
		return errors.New("host posture ServiceAccount identity, Helm ownership, or automount=false contract is not exact")
	}
	if role.Metadata.Name != hostPostureRBACName || !hostPostureHelmMetadata(role.Metadata.Labels, role.Metadata.Annotations) ||
		(len(bytesTrimSpace(role.AggregationRule)) != 0 && string(bytesTrimSpace(role.AggregationRule)) != "null") || len(role.Rules) != 1 {
		return errors.New("host posture ClusterRole identity, ownership, aggregation, or rule count is not exact")
	}
	rule := role.Rules[0]
	if !equalStrings(rule.APIGroups, []string{""}) || !equalStrings(rule.Resources, []string{"pods"}) || !equalStrings(rule.Verbs, []string{"get", "list"}) || len(rule.ResourceNames) != 0 || len(rule.NonResourceURLs) != 0 {
		return errors.New("host posture ClusterRole must grant only pods get/list with no resource-name or non-resource expansion")
	}
	if binding.Metadata.Name != hostPostureRBACName || !hostPostureHelmMetadata(binding.Metadata.Labels, binding.Metadata.Annotations) ||
		binding.RoleRef.APIGroup != "rbac.authorization.k8s.io" || binding.RoleRef.Kind != "ClusterRole" || binding.RoleRef.Name != hostPostureRBACName || len(binding.Subjects) != 1 {
		return errors.New("host posture ClusterRoleBinding identity, ownership, roleRef, or subject count is not exact")
	}
	subject := binding.Subjects[0]
	if subject.APIGroup != "" || subject.Kind != "ServiceAccount" || subject.Name != hostPostureDaemonSetName || subject.Namespace != defaultHostPostureNamespace {
		return errors.New("host posture ClusterRoleBinding must bind only the fixed tunnex-system ServiceAccount")
	}
	return nil
}

func hostPostureHelmMetadata(labels, annotations map[string]string) bool {
	return labels["app.kubernetes.io/name"] == "tunnex-host-posture" &&
		labels["app.kubernetes.io/instance"] == defaultHostPostureRelease &&
		labels["app.kubernetes.io/managed-by"] == "Helm" &&
		labels["app.kubernetes.io/component"] == "host-posture" &&
		annotations["meta.helm.sh/release-name"] == defaultHostPostureRelease &&
		annotations["meta.helm.sh/release-namespace"] == defaultHostPostureNamespace
}

func bytesTrimSpace(value []byte) []byte {
	return []byte(strings.TrimSpace(string(value)))
}

func verifyHostPostureFixedShape(ds *hostPostureDaemonSet) error {
	wantSelector := map[string]string{
		"app.kubernetes.io/name":      "tunnex-host-posture",
		"app.kubernetes.io/instance":  defaultHostPostureRelease,
		"app.kubernetes.io/component": "host-posture",
	}
	if !equalStringMap(ds.Spec.Selector.MatchLabels, wantSelector) || !equalStringMap(ds.Spec.Template.Metadata.Labels, wantSelector) ||
		ds.Spec.Template.Metadata.Annotations[hostPostureContractKey] != hostPostureContractValue ||
		strings.TrimSpace(ds.Spec.Template.Metadata.Annotations["tunnex.io/rollout-revision"]) == "" {
		return errors.New("host posture DaemonSet selector or Pod template is not the fixed lifecycle contract; refusing implicit repair")
	}
	if ds.Spec.UpdateStrategy.Type != "RollingUpdate" || !rawIntOrStringEquals(ds.Spec.UpdateStrategy.RollingUpdate.MaxUnavailable, 1) || !rawIntOrStringEquals(ds.Spec.UpdateStrategy.RollingUpdate.MaxSurge, 0) {
		return errors.New("host posture DaemonSet update strategy is not fixed RollingUpdate maxUnavailable=1 maxSurge=0")
	}
	pod := ds.Spec.Template.Spec
	if pod.ServiceAccountName != hostPostureDaemonSetName || pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken ||
		!pod.HostNetwork || pod.DNSPolicy != "ClusterFirstWithHostNet" || pod.TerminationGracePeriod == nil || *pod.TerminationGracePeriod != 10 ||
		!equalStringMap(pod.NodeSelector, map[string]string{"kubernetes.io/os": "linux"}) || len(pod.Tolerations) != 1 ||
		pod.Tolerations[0].Key != "" || pod.Tolerations[0].Operator != "Exists" || pod.Tolerations[0].Value != "" || pod.Tolerations[0].Effect != "" || pod.Tolerations[0].TolerationSeconds != nil {
		return errors.New("host posture DaemonSet Pod identity/network contract is not exact (fixed ServiceAccount, automount=false, hostNetwork, Linux placement)")
	}
	affinity := strings.TrimSpace(string(pod.Affinity))
	if affinity != "" && affinity != "null" && affinity != "{}" {
		return errors.New("host posture DaemonSet affinity must be empty so every Linux node remains eligible")
	}
	if len(pod.Containers) != 1 {
		return errors.New("host posture DaemonSet must contain exactly one manager container")
	}
	container := pod.Containers[0]
	wantCommand := []string{"/usr/local/bin/tunnex-node", "k8s-host-posture-manager", "--run"}
	security := container.SecurityContext
	if container.Name != "host-posture-manager" || container.ImagePullPolicy != defaultNodeImagePullPolicy || !equalStrings(container.Command, wantCommand) || security.Privileged == nil || !*security.Privileged ||
		security.RunAsUser == nil || *security.RunAsUser != 0 || security.RunAsNonRoot == nil || *security.RunAsNonRoot ||
		security.AllowPrivilegeEscalation == nil || !*security.AllowPrivilegeEscalation || security.ReadOnlyRootFilesystem == nil || !*security.ReadOnlyRootFilesystem ||
		security.SeccompProfile.Type != "RuntimeDefault" {
		return errors.New("host posture manager command or privileged-root security contract is not exact; refusing implicit repair")
	}
	if err := verifyHostPostureEnvironment(container.Env); err != nil {
		return err
	}
	if !hostPostureProbeEquals(container.StartupProbe, "k8s-host-posture-check", "--ready", 2, 2, 45) ||
		!hostPostureProbeEquals(container.ReadinessProbe, "k8s-host-posture-check", "--ready", 2, 2, 3) ||
		!hostPostureProbeEquals(container.LivenessProbe, "k8s-host-posture-check", "--live", 10, 2, 3) {
		return errors.New("host posture manager startup/readiness/liveness probes are not the exact executable health contract")
	}
	wantMounts := map[string]struct {
		path     string
		readOnly bool
	}{
		"host-posture-state": {path: "/var/lib/tunnex/host-posture/v1"},
		"host-proc-sys":      {path: "/host/proc/sys"},
		"k8s-api-token":      {path: "/var/run/secrets/kubernetes.io/serviceaccount", readOnly: true},
	}
	if len(container.VolumeMounts) != len(wantMounts) {
		return errors.New("host posture manager must mount exactly its state, host proc/sys, and projected API token")
	}
	for _, mount := range container.VolumeMounts {
		want, ok := wantMounts[mount.Name]
		if !ok || mount.MountPath != want.path || mount.ReadOnly != want.readOnly {
			return fmt.Errorf("host posture manager volume mount %q does not match the fixed host contract", mount.Name)
		}
		delete(wantMounts, mount.Name)
	}
	if len(wantMounts) != 0 {
		return errors.New("host posture manager is missing a fixed volume mount")
	}
	if err := verifyHostPostureVolumes(pod.Volumes); err != nil {
		return err
	}
	return nil
}

func hostPostureProbeEquals(probe hostPostureProbe, verb, mode string, period, timeout, failures int32) bool {
	return probe.Exec != nil && equalStrings(probe.Exec.Command, []string{"/usr/local/bin/tunnex-node", verb, mode}) &&
		probe.InitialDelaySeconds == 0 && probe.PeriodSeconds == period && probe.TimeoutSeconds == timeout &&
		(probe.SuccessThreshold == 0 || probe.SuccessThreshold == 1) && probe.FailureThreshold == failures
}

func verifyHostPostureEnvironment(env []struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	ValueFrom struct {
		FieldRef struct {
			FieldPath string `json:"fieldPath"`
		} `json:"fieldRef"`
	} `json:"valueFrom"`
}) error {
	values := make(map[string]string, len(env))
	fields := make(map[string]string, len(env))
	for _, item := range env {
		if _, exists := values[item.Name]; exists {
			return fmt.Errorf("host posture manager environment contains duplicate %q", item.Name)
		}
		values[item.Name] = item.Value
		fields[item.Name] = item.ValueFrom.FieldRef.FieldPath
	}
	if len(values) != 7 || fields["TUNNEX_HOST_POSTURE_NODE_NAME"] != "spec.nodeName" || fields["TUNNEX_HOST_POSTURE_MANAGER_UID"] != "metadata.uid" ||
		values["TUNNEX_HOST_POSTURE_STATE_DIR"] != "/var/lib/tunnex/host-posture/v1" || values["TUNNEX_HOST_POSTURE_PROC_SYS"] != "/host/proc/sys" ||
		strings.TrimSpace(values["TUNNEX_HOST_POSTURE_RECONCILE_INTERVAL"]) == "" || strings.TrimSpace(values["TUNNEX_HOST_POSTURE_API_TIMEOUT"]) == "" || strings.TrimSpace(values["TUNNEX_HOST_POSTURE_MAX_OWNERS"]) == "" {
		return errors.New("host posture manager environment is not the fixed field/path contract")
	}
	return nil
}

func verifyHostPostureVolumes(volumes []struct {
	Name     string `json:"name"`
	HostPath *struct {
		Path string `json:"path"`
		Type string `json:"type"`
	} `json:"hostPath"`
	Projected *struct {
		DefaultMode *int32 `json:"defaultMode"`
		Sources     []struct {
			ServiceAccountToken *struct {
				Path              string `json:"path"`
				ExpirationSeconds *int64 `json:"expirationSeconds"`
			} `json:"serviceAccountToken"`
			ConfigMap *struct {
				Name  string `json:"name"`
				Items []struct {
					Key  string `json:"key"`
					Path string `json:"path"`
				} `json:"items"`
			} `json:"configMap"`
		} `json:"sources"`
	} `json:"projected"`
}) error {
	if len(volumes) != 3 {
		return errors.New("host posture DaemonSet must define exactly three fixed volumes")
	}
	foundState, foundProc, foundToken := false, false, false
	for _, volume := range volumes {
		switch volume.Name {
		case "host-posture-state":
			foundState = volume.HostPath != nil && volume.HostPath.Path == "/var/lib/tunnex/host-posture/v1" && volume.HostPath.Type == "DirectoryOrCreate" && volume.Projected == nil
		case "host-proc-sys":
			foundProc = volume.HostPath != nil && volume.HostPath.Path == "/proc/sys" && volume.HostPath.Type == "Directory" && volume.Projected == nil
		case "k8s-api-token":
			foundToken = verifyHostPostureProjectedToken(volume.Projected) && volume.HostPath == nil
		default:
			return fmt.Errorf("host posture DaemonSet has unexpected volume %q", volume.Name)
		}
	}
	if !foundState || !foundProc || !foundToken {
		return errors.New("host posture DaemonSet hostPath or projected-token volumes are not exact")
	}
	return nil
}

func verifyHostPostureProjectedToken(projected *struct {
	DefaultMode *int32 `json:"defaultMode"`
	Sources     []struct {
		ServiceAccountToken *struct {
			Path              string `json:"path"`
			ExpirationSeconds *int64 `json:"expirationSeconds"`
		} `json:"serviceAccountToken"`
		ConfigMap *struct {
			Name  string `json:"name"`
			Items []struct {
				Key  string `json:"key"`
				Path string `json:"path"`
			} `json:"items"`
		} `json:"configMap"`
	} `json:"sources"`
}) bool {
	if projected == nil || projected.DefaultMode == nil || *projected.DefaultMode != 420 || len(projected.Sources) != 2 {
		return false
	}
	foundToken, foundCA := false, false
	for _, source := range projected.Sources {
		if token := source.ServiceAccountToken; token != nil && source.ConfigMap == nil && token.Path == "token" && token.ExpirationSeconds != nil && *token.ExpirationSeconds == 3600 {
			foundToken = true
			continue
		}
		if cm := source.ConfigMap; cm != nil && source.ServiceAccountToken == nil && cm.Name == "kube-root-ca.crt" && len(cm.Items) == 1 && cm.Items[0].Key == "ca.crt" && cm.Items[0].Path == "ca.crt" {
			foundCA = true
			continue
		}
		return false
	}
	return foundToken && foundCA
}

func equalStringMap(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for key, value := range want {
		if got[key] != value {
			return false
		}
	}
	return true
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func rawIntOrStringEquals(raw json.RawMessage, want int) bool {
	var number int
	if json.Unmarshal(raw, &number) == nil {
		return number == want
	}
	var text string
	return json.Unmarshal(raw, &text) == nil && text == strconv.Itoa(want)
}

func verifyHostPostureDaemonSet(ds *hostPostureDaemonSet, expectedImage string, expectedPullSecrets []string) error {
	if err := verifyHostPostureDaemonSetHealth(ds); err != nil {
		return err
	}
	if expectedImage != "" && expectedImage != "chart-default" && ds.Spec.Template.Spec.Containers[0].Image != expectedImage {
		return fmt.Errorf("host posture manager image is %q, expected approved %q", ds.Spec.Template.Spec.Containers[0].Image, expectedImage)
	}
	actualSecrets := hostPostureImagePullSecrets(ds)
	expectedSecrets := append([]string(nil), expectedPullSecrets...)
	sort.Strings(expectedSecrets)
	if strings.Join(actualSecrets, "\x00") != strings.Join(expectedSecrets, "\x00") {
		return fmt.Errorf("host posture imagePullSecrets are %v, expected approved %v", actualSecrets, expectedSecrets)
	}
	return nil
}

func verifyHostPostureDaemonSetHealth(ds *hostPostureDaemonSet) error {
	if ds == nil {
		return errors.New("host posture DaemonSet is absent")
	}
	if err := verifyHostPostureOwnership(ds); err != nil {
		return err
	}
	if err := verifyHostPostureFixedShape(ds); err != nil {
		return err
	}
	if ds.Status.DesiredNumberScheduled <= 0 || ds.Status.ObservedGeneration < ds.Metadata.Generation || ds.Status.CurrentNumberScheduled != ds.Status.DesiredNumberScheduled || ds.Status.UpdatedNumberScheduled != ds.Status.DesiredNumberScheduled || ds.Status.NumberReady != ds.Status.DesiredNumberScheduled || ds.Status.NumberUnavailable != 0 {
		return fmt.Errorf("host posture DaemonSet is not converged (desired=%d current=%d updated=%d ready=%d unavailable=%d)", ds.Status.DesiredNumberScheduled, ds.Status.CurrentNumberScheduled, ds.Status.UpdatedNumberScheduled, ds.Status.NumberReady, ds.Status.NumberUnavailable)
	}
	if len(ds.Spec.Template.Spec.Containers) != 1 || ds.Spec.Template.Spec.Containers[0].Name != "host-posture-manager" || strings.TrimSpace(ds.Spec.Template.Spec.Containers[0].Image) == "" {
		return errors.New("host posture DaemonSet must contain exactly the fixed manager container")
	}
	seenSecrets := make(map[string]struct{})
	for _, secret := range ds.Spec.Template.Spec.ImagePullSecrets {
		if strings.TrimSpace(secret.Name) == "" {
			return errors.New("host posture DaemonSet has an empty imagePullSecret name")
		}
		if _, duplicate := seenSecrets[secret.Name]; duplicate {
			return fmt.Errorf("host posture DaemonSet repeats imagePullSecret %q", secret.Name)
		}
		seenSecrets[secret.Name] = struct{}{}
	}
	return nil
}

func hostPostureImagePullSecrets(ds *hostPostureDaemonSet) []string {
	actualSecrets := make([]string, 0, len(ds.Spec.Template.Spec.ImagePullSecrets))
	for _, secret := range ds.Spec.Template.Spec.ImagePullSecrets {
		actualSecrets = append(actualSecrets, secret.Name)
	}
	sort.Strings(actualSecrets)
	return actualSecrets
}

func planHostPosture(o installOptions, state hostPostureState, image imageValues, metadata chartMetadata, artifactSHA256 string) (lifecycleHostPosture, error) {
	action := "install"
	desiredImage := resolvedImageReference(image, metadata.AppVersion)
	if desiredImage == "" {
		desiredImage = image.reference
	}
	if state.present {
		if o.hostPostureVersion == "" {
			return lifecycleHostPosture{}, errors.New("an existing cluster-wide host posture manager cannot be safely compared with an unversioned local chart; pass --host-posture-chart-version explicitly")
		}
		existingVersion := strings.TrimPrefix(state.release.Chart, "tunnex-host-posture-")
		order, err := compareReleaseVersions(existingVersion, o.hostPostureVersion)
		if err != nil {
			return lifecycleHostPosture{}, fmt.Errorf("compare existing host posture chart %q with approved version %q: %w", existingVersion, o.hostPostureVersion, err)
		}
		if order > 0 {
			return lifecycleHostPosture{}, fmt.Errorf("cluster-wide host posture manager version %q is newer than this CLI's approved version %q; refusing a shared-manager downgrade", existingVersion, o.hostPostureVersion)
		}
		action = "upgrade"
		desiredChart := "tunnex-host-posture-" + o.hostPostureVersion
		if state.release.Status == "deployed" && (o.hostPostureVersion == "" || state.release.Chart == desiredChart) && verifyHostPostureDaemonSet(state.daemonSet, desiredImage, o.imagePullSecrets) == nil {
			action = "reuse"
		}
	}
	return lifecycleHostPosture{
		Action: action, Release: defaultHostPostureRelease, Namespace: defaultHostPostureNamespace, DaemonSet: hostPostureDaemonSetName,
		Chart: o.hostPostureChart, ChartName: metadata.Name, Version: metadata.Version, AppVersion: metadata.AppVersion, ArtifactSHA256: artifactSHA256, Contract: hostPostureContractValue, Image: desiredImage,
		ImagePullSecrets: append([]string(nil), o.imagePullSecrets...),
	}, nil
}

func planExistingHostPostureCleanup(state hostPostureState) (lifecycleHostPosture, chartMetadata, error) {
	if !state.present || state.daemonSet == nil {
		return lifecycleHostPosture{}, chartMetadata{}, errors.New("cluster-wide host posture manager is absent; refusing enrollment cleanup without its exact live manager state")
	}
	if state.release.Status != "deployed" {
		return lifecycleHostPosture{}, chartMetadata{}, fmt.Errorf("host posture Helm release status is %q, expected deployed", state.release.Status)
	}
	if err := verifyHostPostureDaemonSetHealth(state.daemonSet); err != nil {
		return lifecycleHostPosture{}, chartMetadata{}, err
	}
	version := strings.TrimPrefix(state.release.Chart, "tunnex-host-posture-")
	if version == "" || version == state.release.Chart || !versionRE.MatchString(version) || strings.TrimSpace(state.release.AppVersion) == "" {
		return lifecycleHostPosture{}, chartMetadata{}, fmt.Errorf("live host posture chart identity %q appVersion %q is not exact", state.release.Chart, state.release.AppVersion)
	}
	container := state.daemonSet.Spec.Template.Spec.Containers[0]
	metadata := chartMetadata{Reference: state.release.Chart, Name: "tunnex-host-posture", Version: version, AppVersion: state.release.AppVersion}
	return lifecycleHostPosture{
		Action: "reuse", Release: defaultHostPostureRelease, Namespace: defaultHostPostureNamespace, DaemonSet: hostPostureDaemonSetName,
		Chart: state.release.Chart, ChartName: metadata.Name, Version: metadata.Version, AppVersion: metadata.AppVersion,
		Contract: state.daemonSet.Metadata.Annotations[hostPostureContractKey], Image: container.Image,
		ImagePullSecrets: hostPostureImagePullSecrets(state.daemonSet),
	}, metadata, nil
}

func compareReleaseVersions(existing, desired string) (int, error) {
	parse := func(value string) ([3]int, string, error) {
		var core [3]int
		value = strings.TrimPrefix(strings.TrimSpace(value), "v")
		withoutBuild := strings.SplitN(value, "+", 2)[0]
		parts := strings.SplitN(withoutBuild, "-", 2)
		numbers := strings.Split(parts[0], ".")
		if len(numbers) != 3 {
			return core, "", fmt.Errorf("%q is not a three-component semantic version", value)
		}
		for i, part := range numbers {
			if part == "" || (len(part) > 1 && part[0] == '0') {
				return core, "", fmt.Errorf("%q is not a canonical semantic version", value)
			}
			n, err := strconv.Atoi(part)
			if err != nil || n < 0 {
				return core, "", fmt.Errorf("%q is not a canonical semantic version", value)
			}
			core[i] = n
		}
		pre := ""
		if len(parts) == 2 {
			pre = parts[1]
			if pre == "" {
				return core, "", fmt.Errorf("%q has an empty prerelease", value)
			}
		}
		return core, pre, nil
	}
	existingCore, existingPre, err := parse(existing)
	if err != nil {
		return 0, err
	}
	desiredCore, desiredPre, err := parse(desired)
	if err != nil {
		return 0, err
	}
	for i := range existingCore {
		if existingCore[i] < desiredCore[i] {
			return -1, nil
		}
		if existingCore[i] > desiredCore[i] {
			return 1, nil
		}
	}
	return comparePrerelease(existingPre, desiredPre), nil
}

func comparePrerelease(existing, desired string) int {
	if existing == desired {
		return 0
	}
	if existing == "" {
		return 1
	}
	if desired == "" {
		return -1
	}
	existingParts, desiredParts := strings.Split(existing, "."), strings.Split(desired, ".")
	limit := len(existingParts)
	if len(desiredParts) < limit {
		limit = len(desiredParts)
	}
	for i := 0; i < limit; i++ {
		eNum, eErr := strconv.Atoi(existingParts[i])
		dNum, dErr := strconv.Atoi(desiredParts[i])
		switch {
		case eErr == nil && dErr == nil && eNum < dNum:
			return -1
		case eErr == nil && dErr == nil && eNum > dNum:
			return 1
		case eErr == nil && dErr != nil:
			return -1
		case eErr != nil && dErr == nil:
			return 1
		case eErr != nil && dErr != nil && existingParts[i] < desiredParts[i]:
			return -1
		case eErr != nil && dErr != nil && existingParts[i] > desiredParts[i]:
			return 1
		}
	}
	if len(existingParts) < len(desiredParts) {
		return -1
	}
	return 1
}

func hostPostureHelmCommand(prepared preparedInstall) (k8sCommand, error) {
	o := prepared.options
	args := []string{"upgrade", "--install", defaultHostPostureRelease, prepared.hostPostureArtifact.Path, "--namespace", defaultHostPostureNamespace, "--description", zeroTouchContract, "--atomic", "--wait", "--timeout", o.timeout, "--values", "-"}
	if prepared.plan.HostPosture.Action == "upgrade" {
		args = append(args, "--reset-then-reuse-values")
	}
	args = appendHelmContext(args, o.kubeContext)
	values := map[string]any{
		"acknowledgePrivileged": true,
		"rolloutRevision":       rolloutRevision(prepared.digest),
		"nodeSelector":          map[string]string{"kubernetes.io/os": "linux"},
		"tolerations":           []map[string]string{{"operator": "Exists"}},
		"affinity":              map[string]any{},
	}
	pullSecrets := make([]map[string]string, 0, len(o.imagePullSecrets))
	for _, name := range o.imagePullSecrets {
		pullSecrets = append(pullSecrets, map[string]string{"name": name})
	}
	values["image"] = map[string]any{"pullSecrets": pullSecrets}
	appendImageValues(values, prepared.image)
	encoded, err := json.Marshal(values)
	if err != nil {
		return k8sCommand{}, err
	}
	return k8sCommand{name: "helm", args: args, stdin: encoded}, nil
}

func ensureHostPostureManager(ctx context.Context, deps k8sDeps, prepared preparedInstall, onHelmMutation func()) error {
	current, err := discoverHostPostureState(ctx, deps.runner, prepared.options.kubeContext)
	if err != nil {
		return err
	}
	if current.fingerprint() != prepared.hostPosture.fingerprint() {
		return errors.New("cluster-wide host posture manager changed after plan approval; no gateway token was minted")
	}
	if prepared.plan.HostPosture.Action != "reuse" {
		if prepared.plan.HostPosture.Action == "upgrade" {
			help, err := runChecked(ctx, deps.runner, "verify Helm safe host-manager value-merge support", k8sCommand{name: "helm", args: []string{"upgrade", "--help"}})
			if err != nil {
				return err
			}
			if !strings.Contains(string(help.stdout), "--reset-then-reuse-values") {
				return errors.New("this Helm client lacks --reset-then-reuse-values; upgrade it before changing the shared host manager so customer placement and resource values are retained")
			}
		}
		if err := applyNamespace(ctx, deps.runner, prepared.options.kubeContext, defaultHostPostureNamespace); err != nil {
			return err
		}
		command, err := hostPostureHelmCommand(prepared)
		if err != nil {
			return err
		}
		if _, err := runChecked(ctx, deps.runner, "install or upgrade cluster-wide host posture manager", command); err != nil {
			return err
		}
		if onHelmMutation != nil {
			onHelmMutation()
		}
	}
	after, err := discoverHostPostureState(ctx, deps.runner, prepared.options.kubeContext)
	if err != nil {
		return err
	}
	if !after.present || after.release.Status != "deployed" {
		return errors.New("host posture Helm release is not deployed")
	}
	if prepared.options.hostPostureVersion != "" && after.release.Chart != "tunnex-host-posture-"+prepared.options.hostPostureVersion {
		return fmt.Errorf("host posture Helm release chart is %q after apply, expected approved %q", after.release.Chart, "tunnex-host-posture-"+prepared.options.hostPostureVersion)
	}
	if after.release.AppVersion != prepared.hostPostureChart.AppVersion {
		return fmt.Errorf("host posture Helm release appVersion is %q after apply, expected approved %q", after.release.AppVersion, prepared.hostPostureChart.AppVersion)
	}
	if err := verifyHostPostureDaemonSet(after.daemonSet, prepared.plan.HostPosture.Image, prepared.options.imagePullSecrets); err != nil {
		return err
	}
	return nil
}

type hostPostureStatusOutput struct {
	Release          string   `json:"release"`
	Namespace        string   `json:"namespace"`
	Revision         string   `json:"revision"`
	Chart            string   `json:"chart"`
	DaemonSet        string   `json:"daemon_set"`
	Contract         string   `json:"contract"`
	Image            string   `json:"image"`
	ImagePullSecrets []string `json:"image_pull_secrets,omitempty"`
	Desired          int32    `json:"desired"`
	Ready            int32    `json:"ready"`
	Unavailable      int32    `json:"unavailable"`
}

func collectHostPostureStatus(ctx context.Context, runner k8sRunner, kubeContext string) (hostPostureState, hostPostureStatusOutput, error) {
	state, err := discoverHostPostureState(ctx, runner, kubeContext)
	if err != nil {
		return hostPostureState{}, hostPostureStatusOutput{}, err
	}
	if !state.present || state.daemonSet == nil {
		return state, hostPostureStatusOutput{}, errors.New("cluster-wide host posture manager is absent")
	}
	ds := state.daemonSet
	status := hostPostureStatusOutput{
		Release: defaultHostPostureRelease, Namespace: defaultHostPostureNamespace, Revision: state.release.Revision, Chart: state.release.Chart,
		DaemonSet: ds.Metadata.Name, Contract: ds.Metadata.Annotations[hostPostureContractKey], Image: ds.Spec.Template.Spec.Containers[0].Image,
		ImagePullSecrets: hostPostureImagePullSecrets(ds), Desired: ds.Status.DesiredNumberScheduled, Ready: ds.Status.NumberReady, Unavailable: ds.Status.NumberUnavailable,
	}
	if state.release.Status != "deployed" {
		return state, status, fmt.Errorf("host posture Helm release status is %q, expected deployed", state.release.Status)
	}
	if err := verifyHostPostureDaemonSetHealth(ds); err != nil {
		return state, status, err
	}
	return state, status, nil
}

func recheckHealthyHostPosture(ctx context.Context, runner k8sRunner, kubeContext string, approved hostPostureState) error {
	current, _, err := collectHostPostureStatus(ctx, runner, kubeContext)
	if err != nil {
		return err
	}
	if current.fingerprint() != approved.fingerprint() {
		return errors.New("cluster-wide host posture manager changed after lifecycle plan approval")
	}
	return nil
}
