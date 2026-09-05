package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

const (
	preflightHookType                   = "pre-install,pre-upgrade"
	preflightHookWeight                 = "-5"
	preflightHookDeletePolicyOld        = "before-hook-creation,hook-succeeded"
	preflightHookDeletePolicyLive       = "before-hook-creation,hook-succeeded,hook-failed"
	preflightHookInstallProofAnnotation = "tunnex.io/lifecycle-install-proof"
)

type canonicalLifecycleInstallHookProof struct {
	SchemaVersion            int    `json:"schema_version"`
	AnchorUID                string `json:"anchor_uid"`
	OrganizationID           string `json:"organization_id"`
	LifecycleClaim           string `json:"lifecycle_claim"`
	LifecycleGeneration      int    `json:"lifecycle_generation"`
	LifecycleRequestID       string `json:"lifecycle_request_id"`
	InstallOperationID       string `json:"install_operation_id"`
	InstallHolderEpoch       int64  `json:"install_holder_epoch"`
	RequestedDurationSeconds int    `json:"requested_duration_seconds"`
	InstallOperationNotAfter string `json:"install_operation_not_after"`
	InstallIntentDigest      string `json:"install_intent_digest"`
	ReleaseNamespace         string `json:"release_namespace"`
	ReleaseName              string `json:"release_name"`
}

func lifecycleInstallHookProof(anchor lifecycleAnchorMetadata, namespace, release string, holderEpoch int64) (string, error) {
	if err := validateOwnedLifecycleAnchor(anchor, release+"-lifecycle", release); err != nil {
		return "", err
	}
	if !validCanonicalOperationID(anchor.orgID) || !validCanonicalOperationID(anchor.lifecycleClaim) ||
		!validCanonicalOperationID(anchor.requestID) || !validCanonicalOperationID(anchor.installOperationID) {
		return "", errors.New("lifecycle install hook proof requires canonical organization, claim, request, and operation UUIDs")
	}
	if anchor.generation <= 0 || holderEpoch <= 0 || anchor.installOperationDurationSeconds <= 0 || anchor.installOperationDurationSeconds > 900 ||
		anchor.installOperationNotAfter.IsZero() || !validCanonicalSHA256Digest(anchor.installIntentDigest) {
		return "", errors.New("lifecycle install hook proof requires a positive generation, holder epoch, bounded duration, deadline, and canonical install intent")
	}
	if err := validateDNSLabel("release namespace", namespace, 63); err != nil {
		return "", err
	}
	if err := validateRelease(release); err != nil {
		return "", err
	}
	if anchor.releaseNamespace != namespace || anchor.releaseName != release {
		return "", errors.New("lifecycle install hook proof release scope differs from the exact lifecycle anchor")
	}
	_, digest, err := canonicalPlan(canonicalLifecycleInstallHookProof{
		SchemaVersion: 1, AnchorUID: anchor.uid, OrganizationID: anchor.orgID,
		LifecycleClaim: anchor.lifecycleClaim, LifecycleGeneration: anchor.generation, LifecycleRequestID: anchor.requestID,
		InstallOperationID: anchor.installOperationID, InstallHolderEpoch: holderEpoch,
		RequestedDurationSeconds: anchor.installOperationDurationSeconds,
		InstallOperationNotAfter: anchor.installOperationNotAfter.UTC().Format(time.RFC3339Nano),
		InstallIntentDigest:      anchor.installIntentDigest, ReleaseNamespace: namespace, ReleaseName: release,
	})
	return digest, err
}

func lifecycleInstallHookProofForInstallingAnchor(anchor lifecycleAnchorMetadata, namespace, release string) (string, error) {
	if anchor.state != "installing" {
		return "", fmt.Errorf("lifecycle install hook proof requires an installing anchor, got %q", anchor.state)
	}
	return lifecycleInstallHookProof(anchor, namespace, release, anchor.installOperationEpoch)
}

func validateLifecycleAbortHookBinding(anchor lifecycleAnchorMetadata, takeover lifecycleInstallOperationStatus, namespace, release string) (string, error) {
	if anchor.state != "aborting" {
		return "", fmt.Errorf("failed preflight hook cleanup requires an aborting lifecycle anchor, got %q", anchor.state)
	}
	begin, err := lifecycleInstallBeginFromAnchor(anchor)
	if err != nil {
		return "", err
	}
	if err := validateLifecycleInstallOperationStatus(takeover, begin); err != nil {
		return "", err
	}
	if err := validateLifecycleInstallState(takeover, lifecycleInstallAborting); err != nil {
		return "", err
	}
	if takeover.epoch != anchor.installOperationEpoch || !takeover.notAfter.Equal(anchor.installOperationNotAfter) {
		return "", errors.New("failed preflight hook cleanup takeover epoch/deadline differs from the exact lifecycle anchor")
	}
	if takeover.epoch <= 1 {
		return "", errors.New("failed preflight hook cleanup takeover does not have one prior holder epoch")
	}
	return lifecycleInstallHookProof(anchor, namespace, release, takeover.epoch-1)
}

type preflightHookOwnerReference struct {
	APIVersion         string `json:"apiVersion"`
	Kind               string `json:"kind"`
	Name               string `json:"name"`
	UID                string `json:"uid"`
	Controller         *bool  `json:"controller,omitempty"`
	BlockOwnerDeletion *bool  `json:"blockOwnerDeletion,omitempty"`
}

type preflightHookMetadata struct {
	Name              string                        `json:"name"`
	GenerateName      string                        `json:"generateName,omitempty"`
	Namespace         string                        `json:"namespace"`
	UID               string                        `json:"uid"`
	ResourceVersion   string                        `json:"resourceVersion"`
	DeletionTimestamp string                        `json:"deletionTimestamp,omitempty"`
	Labels            map[string]string             `json:"labels"`
	Annotations       map[string]string             `json:"annotations"`
	OwnerReferences   []preflightHookOwnerReference `json:"ownerReferences,omitempty"`
	Finalizers        []string                      `json:"finalizers,omitempty"`
}

type preflightHookJob struct {
	APIVersion string                `json:"apiVersion"`
	Kind       string                `json:"kind"`
	Metadata   preflightHookMetadata `json:"metadata"`
}

type preflightHookPod struct {
	APIVersion string                `json:"apiVersion"`
	Kind       string                `json:"kind"`
	Metadata   preflightHookMetadata `json:"metadata"`
}

type preflightHookPodList struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Items      []preflightHookPod `json:"items"`
}

func canonicalPreflightHookName(release string) string {
	return gatewayFullname(release) + "-preflight"
}

func hasCanonicalPreflightLabels(labels map[string]string, release string) bool {
	return labels["app.kubernetes.io/name"] == "tunnex-gateway" &&
		labels["app.kubernetes.io/instance"] == release &&
		labels["app.kubernetes.io/component"] == "preflight" &&
		labels["app.kubernetes.io/managed-by"] == "Helm"
}

func hasReleaseGatewayLabels(labels map[string]string, release string) bool {
	return labels["app.kubernetes.io/name"] == "tunnex-gateway" &&
		labels["app.kubernetes.io/instance"] == release
}

func isCanonicalPreflightDeletePolicy(value string) bool {
	return value == preflightHookDeletePolicyOld || value == preflightHookDeletePolicyLive
}

func validateCanonicalPreflightHookJob(job preflightHookJob, release, namespace, expectedInstallProof string) error {
	name := canonicalPreflightHookName(release)
	if job.APIVersion != "batch/v1" || job.Kind != "Job" ||
		job.Metadata.Name != name || job.Metadata.GenerateName != "" || job.Metadata.Namespace != namespace ||
		job.Metadata.UID == "" || job.Metadata.ResourceVersion == "" {
		return fmt.Errorf("preflight hook Job %q has malformed or unstable object identity", name)
	}
	if job.Metadata.DeletionTimestamp != "" {
		if _, err := time.Parse(time.RFC3339Nano, job.Metadata.DeletionTimestamp); err != nil {
			return fmt.Errorf("preflight hook Job %q has malformed deletion timestamp", name)
		}
	}
	if len(job.Metadata.OwnerReferences) != 0 {
		return fmt.Errorf("preflight hook Job %q has unexpected owner references", name)
	}
	if len(job.Metadata.Finalizers) != 0 {
		if len(job.Metadata.Finalizers) != 1 || job.Metadata.Finalizers[0] != "foregroundDeletion" || job.Metadata.DeletionTimestamp == "" {
			return fmt.Errorf("preflight hook Job %q has unexpected finalizers", name)
		}
	}
	if !hasCanonicalPreflightLabels(job.Metadata.Labels, release) {
		return fmt.Errorf("preflight hook Job %q has foreign release, component, or manager labels", name)
	}
	annotations := job.Metadata.Annotations
	if annotations["helm.sh/hook"] != preflightHookType ||
		annotations["helm.sh/hook-weight"] != preflightHookWeight ||
		!isCanonicalPreflightDeletePolicy(annotations["helm.sh/hook-delete-policy"]) {
		return fmt.Errorf("preflight hook Job %q has foreign or malformed Helm hook provenance", name)
	}
	if !validCanonicalSHA256Digest(expectedInstallProof) || annotations[preflightHookInstallProofAnnotation] != expectedInstallProof {
		return fmt.Errorf("preflight hook Job %q lacks the exact lifecycle install proof", name)
	}
	return nil
}

func readCanonicalPreflightHookJob(ctx context.Context, runner k8sRunner, kubeContext, namespace, release, expectedInstallProof string) (*preflightHookJob, error) {
	name := canonicalPreflightHookName(release)
	result, err := runChecked(ctx, runner, "read exact failed preflight hook Job", k8sCommand{
		name: "kubectl", args: kubectlArgs(kubeContext, "get", "job", name, "--namespace", namespace, "--ignore-not-found=true", "--output", "json"),
	})
	if err != nil {
		return nil, err
	}
	if len(result.stdout) == 0 {
		return nil, nil
	}
	var job preflightHookJob
	if err := json.Unmarshal(result.stdout, &job); err != nil {
		return nil, fmt.Errorf("decode exact failed preflight hook Job: %w", err)
	}
	if err := validateCanonicalPreflightHookJob(job, release, namespace, expectedInstallProof); err != nil {
		return nil, err
	}
	return &job, nil
}

func preflightPodReferencesJob(pod preflightHookPod, job preflightHookJob) bool {
	for _, owner := range pod.Metadata.OwnerReferences {
		if owner.UID == job.Metadata.UID || (owner.Kind == "Job" && owner.Name == job.Metadata.Name) {
			return true
		}
	}
	return false
}

func validateCanonicalPreflightHookPod(pod preflightHookPod, job preflightHookJob, release, namespace string) error {
	if pod.APIVersion != "v1" || pod.Kind != "Pod" || pod.Metadata.Name == "" ||
		pod.Metadata.Namespace != namespace || pod.Metadata.UID == "" || pod.Metadata.ResourceVersion == "" {
		return errors.New("preflight hook controller Pod has malformed or unstable object identity")
	}
	if !hasCanonicalPreflightLabels(pod.Metadata.Labels, release) {
		return fmt.Errorf("preflight hook controller Pod %q has foreign release, component, or manager labels", pod.Metadata.Name)
	}
	if len(pod.Metadata.OwnerReferences) != 1 {
		return fmt.Errorf("preflight hook controller Pod %q does not have one exact Job owner", pod.Metadata.Name)
	}
	owner := pod.Metadata.OwnerReferences[0]
	if owner.APIVersion != "batch/v1" || owner.Kind != "Job" || owner.Name != job.Metadata.Name || owner.UID != job.Metadata.UID ||
		owner.Controller == nil || !*owner.Controller || owner.BlockOwnerDeletion == nil || !*owner.BlockOwnerDeletion {
		return fmt.Errorf("preflight hook controller Pod %q has foreign or malformed Job ownership", pod.Metadata.Name)
	}
	return nil
}

func readPreflightHookControllerPods(ctx context.Context, runner k8sRunner, kubeContext, namespace, release string, job preflightHookJob) ([]preflightHookPod, error) {
	result, err := runChecked(ctx, runner, "read failed preflight hook controller Pods", k8sCommand{
		name: "kubectl", args: kubectlArgs(kubeContext, "get", "pods", "--namespace", namespace, "--output", "json"),
	})
	if err != nil {
		return nil, err
	}
	var pods preflightHookPodList
	if err := json.Unmarshal(result.stdout, &pods); err != nil {
		return nil, fmt.Errorf("decode failed preflight hook controller Pods: %w", err)
	}
	if pods.APIVersion != "v1" || pods.Kind != "PodList" {
		return nil, errors.New("preflight hook Pod list response was malformed")
	}
	matched := make([]preflightHookPod, 0)
	for _, pod := range pods.Items {
		referencesJob := preflightPodReferencesJob(pod, job)
		if !referencesJob && !hasReleaseGatewayLabels(pod.Metadata.Labels, release) {
			continue
		}
		if err := validateCanonicalPreflightHookPod(pod, job, release, namespace); err != nil {
			return nil, err
		}
		matched = append(matched, pod)
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].Metadata.Name < matched[j].Metadata.Name })
	return matched, nil
}

func provePreflightHookControllerPodsAbsent(ctx context.Context, runner k8sRunner, kubeContext, namespace, release string, job preflightHookJob) error {
	result, err := runChecked(ctx, runner, "prove failed preflight hook controller Pods absent", k8sCommand{
		name: "kubectl", args: kubectlArgs(kubeContext, "get", "pods", "--namespace", namespace, "--output", "json"),
	})
	if err != nil {
		return err
	}
	var pods preflightHookPodList
	if err := json.Unmarshal(result.stdout, &pods); err != nil {
		return fmt.Errorf("decode failed preflight hook controller Pod absence: %w", err)
	}
	if pods.APIVersion != "v1" || pods.Kind != "PodList" {
		return errors.New("preflight hook Pod absence response was malformed")
	}
	for _, pod := range pods.Items {
		if preflightPodReferencesJob(pod, job) || hasReleaseGatewayLabels(pod.Metadata.Labels, release) {
			return fmt.Errorf("preflight hook Job %q still has a controller-owned or same-release Pod %q", job.Metadata.Name, pod.Metadata.Name)
		}
	}
	return nil
}

func cleanupCanonicalFailedPreflightHook(ctx context.Context, runner k8sRunner, kubeContext, namespace, release, timeout string, expectedAnchor lifecycleAnchorMetadata, takeover lifecycleInstallOperationStatus) error {
	expectedInstallProof, err := validateLifecycleAbortHookBinding(expectedAnchor, takeover, namespace, release)
	if err != nil {
		return err
	}
	job, err := readCanonicalPreflightHookJob(ctx, runner, kubeContext, namespace, release, expectedInstallProof)
	if err != nil || job == nil {
		return err
	}
	pods, err := readPreflightHookControllerPods(ctx, runner, kubeContext, namespace, release, *job)
	if err != nil {
		return err
	}
	actualAnchor, err := getLifecycleAnchorMetadata(ctx, runner, kubeContext, namespace, expectedAnchor.name)
	if err != nil {
		return fmt.Errorf("re-read lifecycle anchor immediately before failed preflight hook cleanup: %w", err)
	}
	if actualAnchor == nil || actualAnchor.uid != expectedAnchor.uid || actualAnchor.resourceVersion != expectedAnchor.resourceVersion {
		return errors.New("lifecycle anchor disappeared or changed immediately before failed preflight hook cleanup")
	}
	if err := validateExactLifecycleAnchorReadback(expectedAnchor, *actualAnchor, release, false); err != nil {
		return fmt.Errorf("re-prove lifecycle anchor immediately before failed preflight hook cleanup: %w", err)
	}
	actualProof, err := validateLifecycleAbortHookBinding(*actualAnchor, takeover, namespace, release)
	if err != nil {
		return err
	}
	if actualProof != expectedInstallProof || job.Metadata.Annotations[preflightHookInstallProofAnnotation] != actualProof {
		return errors.New("lifecycle install proof changed immediately before failed preflight hook cleanup")
	}
	deleteOptions, err := json.Marshal(map[string]any{
		"apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": "Foreground",
		"preconditions": map[string]string{"uid": job.Metadata.UID, "resourceVersion": job.Metadata.ResourceVersion},
	})
	if err != nil {
		return err
	}
	rawPath := "/apis/batch/v1/namespaces/" + namespace + "/jobs/" + job.Metadata.Name
	if _, err := runChecked(ctx, runner, "delete exact failed preflight hook Job with UID/resourceVersion preconditions", k8sCommand{
		name: "kubectl", args: kubectlArgs(kubeContext, "delete", "--raw="+rawPath, "-f", "-"), stdin: deleteOptions,
	}); err != nil {
		return err
	}
	for _, pod := range pods {
		if _, err := runChecked(ctx, runner, "wait for exact failed preflight hook controller Pod deletion", k8sCommand{
			name: "kubectl", args: kubectlArgs(kubeContext, "wait", "--for=delete", "pod/"+pod.Metadata.Name, "--namespace", namespace, "--timeout", timeout),
		}); err != nil {
			return err
		}
	}
	if _, err := runChecked(ctx, runner, "wait for exact failed preflight hook Job deletion", k8sCommand{
		name: "kubectl", args: kubectlArgs(kubeContext, "wait", "--for=delete", "job/"+job.Metadata.Name, "--namespace", namespace, "--timeout", timeout),
	}); err != nil {
		return err
	}
	return provePreflightHookControllerPodsAbsent(ctx, runner, kubeContext, namespace, release, *job)
}
