package cli

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	zeroTouchContract               = "tunnex-zero-touch/v1"
	zeroTouchContractAnnotationKey  = "tunnex.io/zero-touch-contract"
	lifecycleOrganizationAnnotation = "tunnex.io/organization-id"
	lifecycleClaimAnnotation        = "tunnex.io/lifecycle-claim"
	maxZeroTouchHistoryDepth        = 256
)

var helmRollbackDescriptionRE = regexp.MustCompile(`^Rollback to ([1-9][0-9]*)$`)

type releaseOptions struct {
	release     string
	namespace   string
	kubeContext string
	timeout     string
}

func addReleaseFlags(fs *flag.FlagSet, o *releaseOptions) {
	fs.StringVar(&o.release, "release", defaultK8sRelease, "Helm release")
	fs.StringVar(&o.namespace, "namespace", defaultK8sNamespace, "Kubernetes namespace")
	fs.StringVar(&o.kubeContext, "context", "", "kube context")
	fs.StringVar(&o.timeout, "timeout", defaultK8sTimeout, "wait timeout")
}

func validateReleaseOptions(o *releaseOptions) error {
	o.release = strings.TrimSpace(o.release)
	o.namespace = strings.TrimSpace(o.namespace)
	o.kubeContext = strings.TrimSpace(o.kubeContext)
	if err := validateRelease(o.release); err != nil {
		return err
	}
	if err := validateDNSLabel("namespace", o.namespace, 63); err != nil {
		return err
	}
	duration, err := time.ParseDuration(o.timeout)
	if err != nil {
		return fmt.Errorf("invalid --timeout: %w", err)
	}
	if duration <= 0 {
		return errors.New("--timeout must be greater than zero")
	}
	return nil
}

type helmReleaseSummary struct {
	Name       string `json:"name"`
	Namespace  string `json:"namespace"`
	Revision   string `json:"revision"`
	Updated    string `json:"updated,omitempty"`
	Status     string `json:"status"`
	Chart      string `json:"chart"`
	AppVersion string `json:"app_version,omitempty"`
}

func listHelmReleases(ctx context.Context, runner k8sRunner, kubeContext, namespace, release string) ([]helmReleaseSummary, error) {
	args := []string{"list", "--all", "--namespace", namespace, "--filter", "^" + regexp.QuoteMeta(release) + "$", "--output", "json"}
	args = appendHelmContext(args, kubeContext)
	result, err := runChecked(ctx, runner, "read Helm release", k8sCommand{name: "helm", args: args})
	if err != nil {
		return nil, err
	}
	var releases []helmReleaseSummary
	if err := json.Unmarshal(result.stdout, &releases); err != nil {
		return nil, fmt.Errorf("decode Helm release summary: %w", err)
	}
	filtered := releases[:0]
	for _, candidate := range releases {
		if candidate.Name == release && candidate.Namespace == namespace {
			filtered = append(filtered, candidate)
		}
	}
	return filtered, nil
}

func requireHelmRelease(ctx context.Context, runner k8sRunner, kubeContext, namespace, release string) (helmReleaseSummary, error) {
	releases, err := listHelmReleases(ctx, runner, kubeContext, namespace, release)
	if err != nil {
		return helmReleaseSummary{}, err
	}
	if len(releases) == 0 {
		return helmReleaseSummary{}, fmt.Errorf("Helm release %q is absent from namespace %q", release, namespace)
	}
	if len(releases) != 1 {
		return helmReleaseSummary{}, fmt.Errorf("Helm returned %d exact matches for release %q", len(releases), release)
	}
	return releases[0], nil
}

type deploymentView struct {
	Metadata struct {
		Name            string            `json:"name"`
		UID             string            `json:"uid"`
		ResourceVersion string            `json:"resourceVersion"`
		Generation      int64             `json:"generation"`
		Annotations     map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		Replicas *int32 `json:"replicas"`
		Template struct {
			Metadata struct {
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
			Spec struct {
				NodeSelector map[string]string `json:"nodeSelector"`
				Tolerations  []struct {
					Key               string `json:"key"`
					Operator          string `json:"operator"`
					Value             string `json:"value"`
					Effect            string `json:"effect"`
					TolerationSeconds *int64 `json:"tolerationSeconds"`
				} `json:"tolerations"`
				ImagePullSecrets []struct {
					Name string `json:"name"`
				} `json:"imagePullSecrets"`
				Containers []struct {
					Name            string `json:"name"`
					Image           string `json:"image"`
					ImagePullPolicy string `json:"imagePullPolicy"`
				} `json:"containers"`
				Volumes []struct {
					Name                  string `json:"name"`
					PersistentVolumeClaim *struct {
						ClaimName string `json:"claimName"`
					} `json:"persistentVolumeClaim,omitempty"`
				} `json:"volumes"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
	Status struct {
		ObservedGeneration int64 `json:"observedGeneration"`
		ReadyReplicas      int32 `json:"readyReplicas"`
		AvailableReplicas  int32 `json:"availableReplicas"`
		UpdatedReplicas    int32 `json:"updatedReplicas"`
	} `json:"status"`
}

type servicePortView struct {
	Name     string `json:"name"`
	Port     int32  `json:"port"`
	NodePort int32  `json:"nodePort"`
	Protocol string `json:"protocol"`
}

type serviceView struct {
	Metadata struct {
		Name        string            `json:"name"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		Type           string            `json:"type"`
		LoadBalancerIP string            `json:"loadBalancerIP"`
		Ports          []servicePortView `json:"ports"`
	} `json:"spec"`
	Status struct {
		LoadBalancer struct {
			Ingress []struct {
				IP       string `json:"ip"`
				Hostname string `json:"hostname"`
			} `json:"ingress"`
		} `json:"loadBalancer"`
	} `json:"status"`
}

type pvcView struct {
	Metadata struct {
		Name              string            `json:"name"`
		Namespace         string            `json:"namespace"`
		UID               string            `json:"uid"`
		ResourceVersion   string            `json:"resourceVersion"`
		DeletionTimestamp string            `json:"deletionTimestamp"`
		Labels            map[string]string `json:"labels"`
		Annotations       map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		StorageClassName *string `json:"storageClassName"`
		VolumeName       string  `json:"volumeName"`
	} `json:"spec"`
	Status struct {
		Phase string `json:"phase"`
	} `json:"status"`
}

type gatewayMutationSnapshot struct {
	release            helmReleaseSummary
	deploymentUID      string
	deploymentVersion  string
	claim              string
	pvcUID             string
	volumeName         string
	pvcResourceVersion string
	zeroTouchContract  string
	runtime            lifecycleGatewayRuntime
}

type lifecycleGatewayRuntime struct {
	Image            string              `json:"image"`
	ImagePullPolicy  string              `json:"image_pull_policy"`
	ImagePullSecrets []string            `json:"image_pull_secrets"`
	NodeSelector     map[string]string   `json:"node_selector"`
	Tolerations      []gatewayToleration `json:"tolerations"`
}

func ptrGatewayRuntime(value lifecycleGatewayRuntime) *lifecycleGatewayRuntime {
	copy := cloneGatewayRuntime(value)
	return &copy
}

func cloneGatewayRuntime(value lifecycleGatewayRuntime) lifecycleGatewayRuntime {
	cloned := lifecycleGatewayRuntime{
		Image:            value.Image,
		ImagePullPolicy:  value.ImagePullPolicy,
		ImagePullSecrets: make([]string, len(value.ImagePullSecrets)),
		NodeSelector:     make(map[string]string, len(value.NodeSelector)),
		Tolerations:      make([]gatewayToleration, len(value.Tolerations)),
	}
	copy(cloned.ImagePullSecrets, value.ImagePullSecrets)
	copy(cloned.Tolerations, value.Tolerations)
	for key, item := range value.NodeSelector {
		cloned.NodeSelector[key] = item
	}
	return cloned
}

func runtimeFingerprint(value lifecycleGatewayRuntime) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func (s gatewayMutationSnapshot) planView() lifecycleStateSnapshot {
	return lifecycleStateSnapshot{
		Claim:           s.claim,
		PVCUID:          s.pvcUID,
		VolumeName:      s.volumeName,
		ResourceVersion: s.pvcResourceVersion,
	}
}

func (s gatewayMutationSnapshot) sameIdentity(other gatewayMutationSnapshot) bool {
	return s.claim == other.claim && s.pvcUID == other.pvcUID && s.volumeName == other.volumeName
}

func (s gatewayMutationSnapshot) fingerprint() string {
	runtime, _ := json.Marshal(s.runtime)
	return strings.Join([]string{
		s.release.Name, s.release.Namespace, s.release.Revision, s.release.Updated, s.release.Status, s.release.Chart, s.release.AppVersion,
		s.deploymentUID, s.deploymentVersion, s.claim, s.pvcUID, s.volumeName, s.pvcResourceVersion, s.zeroTouchContract, string(runtime),
	}, "\x00")
}

func captureGatewayMutationSnapshot(ctx context.Context, runner k8sRunner, o releaseOptions) (gatewayMutationSnapshot, error) {
	release, err := requireHelmRelease(ctx, runner, o.kubeContext, o.namespace, o.release)
	if err != nil {
		return gatewayMutationSnapshot{}, err
	}
	deployment, err := getDeployment(ctx, runner, o.kubeContext, o.namespace, o.release)
	if err != nil {
		return gatewayMutationSnapshot{}, err
	}
	claim, err := deploymentClaim(deployment)
	if err != nil {
		return gatewayMutationSnapshot{}, err
	}
	pvc, err := getPVC(ctx, runner, o.kubeContext, o.namespace, claim)
	if err != nil {
		return gatewayMutationSnapshot{}, err
	}
	if err := validateGatewayIdentityPVC(pvc, claim, o.release); err != nil {
		return gatewayMutationSnapshot{}, err
	}
	runtime, err := gatewayRuntimeFromDeployment(deployment)
	if err != nil {
		return gatewayMutationSnapshot{}, err
	}
	if deployment.Metadata.UID == "" || deployment.Metadata.ResourceVersion == "" {
		return gatewayMutationSnapshot{}, errors.New("gateway Deployment lacks UID/resourceVersion required for lifecycle plan readback")
	}
	return gatewayMutationSnapshot{
		release:            release,
		deploymentUID:      deployment.Metadata.UID,
		deploymentVersion:  deployment.Metadata.ResourceVersion,
		claim:              claim,
		pvcUID:             pvc.Metadata.UID,
		volumeName:         pvc.Spec.VolumeName,
		pvcResourceVersion: pvc.Metadata.ResourceVersion,
		zeroTouchContract:  deployment.Metadata.Annotations[zeroTouchContractAnnotationKey],
		runtime:            runtime,
	}, nil
}

func gatewayRuntimeFromDeployment(deployment deploymentView) (lifecycleGatewayRuntime, error) {
	if err := verifyGatewayContainerImage(deployment, ""); err != nil {
		return lifecycleGatewayRuntime{}, err
	}
	runtime := lifecycleGatewayRuntime{
		Image:           deployment.Spec.Template.Spec.Containers[0].Image,
		ImagePullPolicy: deployment.Spec.Template.Spec.Containers[0].ImagePullPolicy,
		NodeSelector:    make(map[string]string, len(deployment.Spec.Template.Spec.NodeSelector)),
	}
	if runtime.ImagePullPolicy != "Always" && runtime.ImagePullPolicy != defaultNodeImagePullPolicy && runtime.ImagePullPolicy != "Never" {
		return lifecycleGatewayRuntime{}, fmt.Errorf("gateway Deployment imagePullPolicy %q is not a Kubernetes pull policy", runtime.ImagePullPolicy)
	}
	for key, value := range deployment.Spec.Template.Spec.NodeSelector {
		runtime.NodeSelector[key] = value
	}
	for _, secret := range deployment.Spec.Template.Spec.ImagePullSecrets {
		if strings.TrimSpace(secret.Name) == "" {
			return lifecycleGatewayRuntime{}, errors.New("gateway Deployment has an empty imagePullSecret name")
		}
		runtime.ImagePullSecrets = append(runtime.ImagePullSecrets, secret.Name)
	}
	sort.Strings(runtime.ImagePullSecrets)
	for i := 1; i < len(runtime.ImagePullSecrets); i++ {
		if runtime.ImagePullSecrets[i] == runtime.ImagePullSecrets[i-1] {
			return lifecycleGatewayRuntime{}, fmt.Errorf("gateway Deployment repeats imagePullSecret %q", runtime.ImagePullSecrets[i])
		}
	}
	for _, item := range deployment.Spec.Template.Spec.Tolerations {
		if item.TolerationSeconds != nil {
			return lifecycleGatewayRuntime{}, fmt.Errorf("gateway Deployment toleration %q has unsupported tolerationSeconds", item.Key)
		}
		runtime.Tolerations = append(runtime.Tolerations, gatewayToleration{Key: item.Key, Operator: item.Operator, Value: item.Value, Effect: item.Effect})
	}
	sort.Slice(runtime.Tolerations, func(i, j int) bool {
		return gatewayTolerationKey(runtime.Tolerations[i]) < gatewayTolerationKey(runtime.Tolerations[j])
	})
	if runtime.ImagePullSecrets == nil {
		runtime.ImagePullSecrets = []string{}
	}
	if runtime.NodeSelector == nil {
		runtime.NodeSelector = map[string]string{}
	}
	if runtime.Tolerations == nil {
		runtime.Tolerations = []gatewayToleration{}
	}
	return runtime, nil
}

func validateGatewayIdentityPVC(pvc pvcView, claim, release string) error {
	if pvc.Metadata.Name != claim ||
		pvc.Metadata.Labels["app.kubernetes.io/name"] != "tunnex-gateway" ||
		pvc.Metadata.Labels["app.kubernetes.io/instance"] != release ||
		pvc.Metadata.Annotations["helm.sh/resource-policy"] != "keep" {
		return fmt.Errorf("state claim %q is not the retained Tunnex identity claim for release %q", claim, release)
	}
	if pvc.Status.Phase != "Bound" || pvc.Metadata.UID == "" || pvc.Metadata.ResourceVersion == "" || pvc.Spec.VolumeName == "" {
		return fmt.Errorf("state claim %q lacks a stable Bound UID/volume/resourceVersion identity", claim)
	}
	return nil
}

func verifyPVCStorageClass(pvc pvcView, expected string) error {
	actual := ""
	if pvc.Spec.StorageClassName != nil {
		actual = *pvc.Spec.StorageClassName
	}
	if actual != expected {
		return fmt.Errorf("gateway state claim %q uses StorageClass %q, expected approved StorageClass %q", pvc.Metadata.Name, actual, expected)
	}
	return nil
}

func recheckGatewayMutationSnapshot(ctx context.Context, runner k8sRunner, o releaseOptions, before gatewayMutationSnapshot) error {
	after, err := captureGatewayMutationSnapshot(ctx, runner, o)
	if err != nil {
		return err
	}
	if after.fingerprint() != before.fingerprint() {
		return errors.New("Helm release or gateway state changed while awaiting approval; no lifecycle mutation was applied — review and approve a fresh plan")
	}
	return nil
}

func verifyGatewayIdentityPreserved(ctx context.Context, runner k8sRunner, o releaseOptions, before gatewayMutationSnapshot) error {
	after, err := captureGatewayMutationSnapshot(ctx, runner, o)
	if err != nil {
		return err
	}
	if err := requireLiveZeroTouchContract(after.zeroTouchContract); err != nil {
		return err
	}
	if !before.sameIdentity(after) {
		return fmt.Errorf("gateway became ready but its state identity changed (claim/UID/volume); expected retained claim %q UID %q volume %q", before.claim, before.pvcUID, before.volumeName)
	}
	return nil
}

func requireLiveZeroTouchContract(actual string) error {
	if actual != zeroTouchContract {
		return fmt.Errorf("gateway Deployment annotation %q is %q, expected exact lifecycle contract %q", zeroTouchContractAnnotationKey, actual, zeroTouchContract)
	}
	return nil
}

type bootstrapSecretMetadata struct {
	name            string
	uid             string
	resourceVersion string
	appName         string
	instance        string
	managedBy       string
	immutable       bool
	lifecycleClaim  string
	requestID       string
	generation      int
	expiresAt       time.Time
	ownerAPIVersion string
	ownerKind       string
	ownerName       string
	ownerUID        string
}

type installState struct {
	resumeCleanup                         bool
	completedReplay                       bool
	resumeRelease                         helmReleaseSummary
	retrySecret                           bool
	secretUID                             string
	secretResourceVersion                 string
	secretLifecycleClaim                  string
	secretRequestID                       string
	secretGeneration                      int
	secretExpiresAt                       time.Time
	secretOwnerAPIVersion                 string
	secretOwnerKind                       string
	secretOwnerName                       string
	secretOwnerUID                        string
	anchorExists                          bool
	anchorName                            string
	anchorUID                             string
	anchorResourceVersion                 string
	anchorOrgID                           string
	anchorNodeName                        string
	anchorLifecycleClaim                  string
	anchorRequestID                       string
	anchorExpectedGen                     int
	anchorGeneration                      int
	anchorState                           string
	anchorExpiresAt                       time.Time
	anchorInstallOperationID              string
	anchorInstallOperationEpoch           int64
	anchorInstallOperationDurationSeconds int
	anchorInstallOperationNotAfter        time.Time
	anchorInstallIntentDigest             string
	anchorReleaseNamespace                string
	anchorReleaseName                     string
	pvcExists                             bool
	pvcName                               string
	pvcUID                                string
	pvcResourceVersion                    string
	pvcVolumeName                         string
	pvcPhase                              string
	pvcStorageClass                       string
	pvcOrganizationID                     string
	pvcLifecycleClaim                     string
}

func (s installState) fingerprint() string {
	encoded := strings.Join([]string{
		strconv.FormatBool(s.resumeCleanup), strconv.FormatBool(s.completedReplay), s.resumeRelease.Name, s.resumeRelease.Namespace,
		s.resumeRelease.Revision, s.resumeRelease.Updated, s.resumeRelease.Status, s.resumeRelease.Chart, s.resumeRelease.AppVersion,
		strconv.FormatBool(s.retrySecret), s.secretUID, s.secretResourceVersion,
		s.secretLifecycleClaim, s.secretRequestID, strconv.Itoa(s.secretGeneration), s.secretExpiresAt.UTC().Format(time.RFC3339Nano),
		s.secretOwnerAPIVersion, s.secretOwnerKind, s.secretOwnerName, s.secretOwnerUID,
		strconv.FormatBool(s.anchorExists), s.anchorName, s.anchorUID, s.anchorResourceVersion, s.anchorOrgID, s.anchorNodeName,
		s.anchorLifecycleClaim, s.anchorRequestID, strconv.Itoa(s.anchorExpectedGen), strconv.Itoa(s.anchorGeneration), s.anchorState, s.anchorExpiresAt.UTC().Format(time.RFC3339Nano),
		s.anchorInstallOperationID, strconv.FormatInt(s.anchorInstallOperationEpoch, 10), strconv.Itoa(s.anchorInstallOperationDurationSeconds), s.anchorInstallOperationNotAfter.UTC().Format(time.RFC3339Nano),
		s.anchorInstallIntentDigest, s.anchorReleaseNamespace, s.anchorReleaseName,
		strconv.FormatBool(s.pvcExists), s.pvcName, s.pvcUID, s.pvcResourceVersion, s.pvcVolumeName,
		s.pvcPhase, s.pvcStorageClass, s.pvcOrganizationID, s.pvcLifecycleClaim,
	}, "\x00")
	sum := sha256.Sum256([]byte(encoded))
	return hex.EncodeToString(sum[:])
}

func discoverInstallState(ctx context.Context, runner k8sRunner, o installOptions) (installState, error) {
	releases, err := listHelmReleases(ctx, runner, o.kubeContext, o.namespace, o.release)
	if err != nil {
		return installState{}, err
	}
	if len(releases) > 1 {
		return installState{}, fmt.Errorf("Helm returned %d exact matches for release %q", len(releases), o.release)
	}
	state := installState{}
	if o.mode == "reuse" {
		if len(releases) != 0 {
			return installState{}, fmt.Errorf("Helm release %q already exists with status %q; run 'tunnex k8s status --release %s' and use 'tunnex k8s upgrade' instead of installing over it", o.release, releases[0].Status, o.release)
		}
		pvc, err := getPVC(ctx, runner, o.kubeContext, o.namespace, o.existingClaim)
		if err != nil {
			return installState{}, err
		}
		if pvc.Metadata.Name != o.existingClaim ||
			pvc.Metadata.Labels["app.kubernetes.io/name"] != "tunnex-gateway" ||
			pvc.Metadata.Labels["app.kubernetes.io/instance"] != o.release ||
			pvc.Metadata.Annotations["helm.sh/resource-policy"] != "keep" {
			return installState{}, fmt.Errorf("retained claim %q is not owned by Tunnex release %q; refusing cross-release identity reuse", o.existingClaim, o.release)
		}
		if pvc.Status.Phase != "Bound" {
			return installState{}, fmt.Errorf("retained claim %q is %q, not Bound", o.existingClaim, pvc.Status.Phase)
		}
		if pvc.Metadata.DeletionTimestamp != "" {
			return installState{}, fmt.Errorf("retained claim %q is terminating; refusing identity reuse", o.existingClaim)
		}
		if pvc.Metadata.UID == "" || pvc.Metadata.ResourceVersion == "" || pvc.Spec.VolumeName == "" {
			return installState{}, fmt.Errorf("retained claim %q lacks a stable Bound UID/volume/resourceVersion identity", o.existingClaim)
		}
		if mountedBy, err := claimMountedByLivePod(ctx, runner, o.kubeContext, o.namespace, o.existingClaim); err != nil {
			return installState{}, err
		} else if mountedBy != "" {
			return installState{}, fmt.Errorf("retained claim %q is still mounted by %s; refusing to mount one identity/fence store twice", o.existingClaim, mountedBy)
		}
		state.pvcExists = true
		state.pvcName = pvc.Metadata.Name
		state.pvcUID = pvc.Metadata.UID
		state.pvcResourceVersion = pvc.Metadata.ResourceVersion
		state.pvcVolumeName = pvc.Spec.VolumeName
		state.pvcPhase = pvc.Status.Phase
		if pvc.Spec.StorageClassName != nil {
			state.pvcStorageClass = *pvc.Spec.StorageClassName
		}
		return state, nil
	}
	secretName := o.release + "-bootstrap"
	anchorName := o.release + "-lifecycle"
	anchor, err := getLifecycleAnchorMetadata(ctx, runner, o.kubeContext, o.namespace, anchorName)
	if err != nil {
		return installState{}, err
	}
	if anchor != nil {
		if err := validateOwnedLifecycleAnchor(*anchor, anchorName, o.release); err != nil {
			return installState{}, err
		}
		state.anchorExists = true
		state.anchorName = anchor.name
		state.anchorUID = anchor.uid
		state.anchorResourceVersion = anchor.resourceVersion
		state.anchorOrgID = anchor.orgID
		state.anchorNodeName = anchor.nodeName
		state.anchorLifecycleClaim = anchor.lifecycleClaim
		state.anchorRequestID = anchor.requestID
		state.anchorExpectedGen = anchor.expectedGeneration
		state.anchorGeneration = anchor.generation
		state.anchorState = anchor.state
		state.anchorExpiresAt = anchor.expiresAt
		state.anchorInstallOperationID = anchor.installOperationID
		state.anchorInstallOperationEpoch = anchor.installOperationEpoch
		state.anchorInstallOperationDurationSeconds = anchor.installOperationDurationSeconds
		state.anchorInstallOperationNotAfter = anchor.installOperationNotAfter
		state.anchorInstallIntentDigest = anchor.installIntentDigest
		state.anchorReleaseNamespace = anchor.releaseNamespace
		state.anchorReleaseName = anchor.releaseName
	}
	secret, err := getBootstrapSecretMetadata(ctx, runner, o.kubeContext, o.namespace, secretName)
	if err != nil {
		return installState{}, err
	}
	if secret != nil {
		if secret.name != secretName || secret.appName != "tunnex-gateway-bootstrap" || secret.instance != o.release || secret.managedBy != "tunnex-lifecycle" {
			return installState{}, fmt.Errorf("bootstrap Secret %q already exists but is not owned by this Tunnex release; refusing to read or overwrite it", secretName)
		}
		if secret.uid == "" || secret.resourceVersion == "" {
			return installState{}, fmt.Errorf("bootstrap Secret %q lacks UID/resourceVersion metadata required for safe retry cleanup; its value was not read", secretName)
		}
		if !secret.immutable {
			return installState{}, fmt.Errorf("bootstrap Secret %q is mutable; refusing retry because its one-time token could change after approval", secretName)
		}
		if anchor == nil {
			return installState{}, fmt.Errorf("bootstrap Secret %q exists without its owned token-blind lifecycle anchor %q; refusing manual adoption", secretName, anchorName)
		}
		if err := validateBootstrapSecretAnchor(*secret, *anchor); err != nil {
			return installState{}, err
		}
		exactCurrent := secret.lifecycleClaim == anchor.lifecycleClaim && secret.requestID == anchor.requestID && secret.generation == anchor.generation && secret.expiresAt.Equal(anchor.expiresAt) && (anchor.state == "issued" || anchor.state == "acknowledged" || anchor.state == "installing")
		pendingExpiredRotation := secret.lifecycleClaim == anchor.lifecycleClaim && anchor.state == "pending" && anchor.expectedGeneration == secret.generation && anchor.generation == secret.generation && anchor.requestID != secret.requestID && !secret.expiresAt.After(time.Now())
		if !exactCurrent && !pendingExpiredRotation {
			return installState{}, fmt.Errorf("bootstrap Secret %q lifecycle metadata does not match anchor %q; refusing ambiguous recovery", secretName, anchorName)
		}
		state.retrySecret = true
		state.secretUID = secret.uid
		state.secretResourceVersion = secret.resourceVersion
		state.secretLifecycleClaim = secret.lifecycleClaim
		state.secretRequestID = secret.requestID
		state.secretGeneration = secret.generation
		state.secretExpiresAt = secret.expiresAt
		state.secretOwnerAPIVersion = secret.ownerAPIVersion
		state.secretOwnerKind = secret.ownerKind
		state.secretOwnerName = secret.ownerName
		state.secretOwnerUID = secret.ownerUID
	}
	expectedClaim := gatewayFullname(o.release) + "-state"
	pvc, err := findPVC(ctx, runner, o.kubeContext, o.namespace, expectedClaim)
	if err != nil {
		return installState{}, err
	}
	if pvc != nil {
		state.pvcExists = true
		state.pvcName = pvc.Metadata.Name
		state.pvcUID = pvc.Metadata.UID
		state.pvcResourceVersion = pvc.Metadata.ResourceVersion
		state.pvcVolumeName = pvc.Spec.VolumeName
		state.pvcPhase = pvc.Status.Phase
		if pvc.Spec.StorageClassName != nil {
			state.pvcStorageClass = *pvc.Spec.StorageClassName
		}
		if pvc.Metadata.Name != expectedClaim || pvc.Metadata.Labels["app.kubernetes.io/name"] != "tunnex-gateway" || pvc.Metadata.Labels["app.kubernetes.io/instance"] != o.release || pvc.Metadata.Annotations["helm.sh/resource-policy"] != "keep" {
			return installState{}, fmt.Errorf("state claim %q exists but is not the retained Tunnex claim for release %q", expectedClaim, o.release)
		}
		if pvc.Status.Phase != "Pending" && pvc.Status.Phase != "Bound" {
			return installState{}, fmt.Errorf("retained retry claim %q is %q, expected Pending or Bound", expectedClaim, pvc.Status.Phase)
		}
		if len(releases) == 0 {
			if mountedBy, err := claimMountedByLivePod(ctx, runner, o.kubeContext, o.namespace, expectedClaim); err != nil {
				return installState{}, err
			} else if mountedBy != "" {
				return installState{}, fmt.Errorf("retained retry claim %q is still mounted by %s; refusing concurrent identity use", expectedClaim, mountedBy)
			}
		}
		if !state.retrySecret && !state.anchorExists && len(releases) == 0 {
			return installState{}, fmt.Errorf("state claim %q exists without retry Secret %q; refusing a fresh enrollment over orphan state. If it contains an enrolled identity, use --mode reuse --existing-claim %s", expectedClaim, secretName, expectedClaim)
		}
	}
	if len(releases) != 0 {
		if !state.anchorExists {
			if !state.pvcExists {
				return installState{}, fmt.Errorf("Helm release %q exists without its lifecycle anchor or exact retained identity claim %q; anchorless completion replay is unsafe", o.release, expectedClaim)
			}
			if err := validateRetainedPVCMetadata(*pvc, expectedClaim, o.release, o.namespace); err != nil {
				return installState{}, err
			}
			organizationID, lifecycleClaim, present, provenanceErr := exactLifecycleProvenance(*pvc)
			if provenanceErr != nil {
				return installState{}, fmt.Errorf("anchorless completion replay PVC provenance is invalid: %w", provenanceErr)
			}
			if !present {
				return installState{}, errors.New("anchorless completion replay requires canonical organization and lifecycle-claim PVC provenance")
			}
			if pvc.Status.Phase != "Bound" || pvc.Metadata.UID == "" || pvc.Metadata.ResourceVersion == "" || pvc.Spec.VolumeName == "" {
				return installState{}, errors.New("anchorless completion replay requires one stable Bound retained PVC identity")
			}
			state.completedReplay = true
			state.resumeRelease = releases[0]
			state.pvcOrganizationID = organizationID
			state.pvcLifecycleClaim = lifecycleClaim
			return state, nil
		}
		if !state.pvcExists {
			return installState{}, fmt.Errorf("Helm release %q and owned bootstrap Secret %q exist but the expected identity claim %q is absent; the one-time token may already be consumed and automatic cleanup is unsafe", o.release, secretName, expectedClaim)
		}
		state.resumeCleanup = true
		state.resumeRelease = releases[0]
	}
	return state, nil
}

func claimMountedByLivePod(ctx context.Context, runner k8sRunner, kubeContext, namespace, claim string) (string, error) {
	result, err := runChecked(ctx, runner, "check live state claim mounts", k8sCommand{name: "kubectl", args: kubectlArgs(kubeContext, "get", "pods", "--namespace", namespace, "--output", "json")})
	if err != nil {
		return "", err
	}
	var pods podList
	if err := json.Unmarshal(result.stdout, &pods); err != nil {
		return "", fmt.Errorf("decode Pod claim references: %w", err)
	}
	for _, pod := range pods.Items {
		// Completed workload pods no longer have running containers capable of
		// using the identity store. Every other phase, including empty/Unknown
		// and a terminating Running pod, remains an authoritative live mount.
		if pod.Status.Phase == "Succeeded" || pod.Status.Phase == "Failed" {
			continue
		}
		for _, volume := range pod.Spec.Volumes {
			if volume.PersistentVolumeClaim == nil || volume.PersistentVolumeClaim.ClaimName != claim {
				continue
			}
			owner := "standalone"
			if len(pod.Metadata.OwnerReferences) != 0 {
				owner = pod.Metadata.OwnerReferences[0].Kind + "/" + pod.Metadata.OwnerReferences[0].Name
			}
			state := pod.Status.Phase
			if state == "" {
				state = "Unknown"
			}
			if pod.Metadata.DeletionTimestamp != "" {
				state += ", terminating"
			}
			return fmt.Sprintf("Pod %q (%s, owner %s)", pod.Metadata.Name, state, owner), nil
		}
	}
	return "", nil
}

const bootstrapSecretMetadataJSONPath = `{.metadata.name}{"\t"}{.metadata.uid}{"\t"}{.metadata.resourceVersion}{"\t"}{.metadata.labels.app\.kubernetes\.io/name}{"\t"}{.metadata.labels.app\.kubernetes\.io/instance}{"\t"}{.metadata.labels.app\.kubernetes\.io/managed-by}{"\t"}{.immutable}{"\t"}{.metadata.annotations.tunnex\.io/lifecycle-claim}{"\t"}{.metadata.annotations.tunnex\.io/lifecycle-request-id}{"\t"}{.metadata.annotations.tunnex\.io/lifecycle-generation}{"\t"}{.metadata.annotations.tunnex\.io/lifecycle-expires-at}{"\t"}{range .metadata.ownerReferences[*]}{.apiVersion}{"|"}{.kind}{"|"}{.name}{"|"}{.uid}{";"}{end}{"\n"}`

func getBootstrapSecretMetadata(ctx context.Context, runner k8sRunner, kubeContext, namespace, name string) (*bootstrapSecretMetadata, error) {
	result, err := runChecked(ctx, runner, "read bootstrap Secret metadata", k8sCommand{name: "kubectl", args: kubectlArgs(kubeContext, "get", "secret", name, "--namespace", namespace, "--ignore-not-found=true", "--output", "jsonpath="+bootstrapSecretMetadataJSONPath)})
	if err != nil {
		return nil, err
	}
	line := strings.TrimSuffix(string(result.stdout), "\n")
	if strings.TrimSpace(line) == "" {
		return nil, nil
	}
	return parseBootstrapSecretMetadata(line)
}

func parseBootstrapSecretMetadata(line string) (*bootstrapSecretMetadata, error) {
	line = strings.TrimSuffix(line, "\n")
	if strings.TrimSpace(line) == "" {
		return nil, nil
	}
	fields := strings.Split(line, "\t")
	if len(fields) != 12 || (fields[6] != "true" && fields[6] != "false") {
		return nil, errors.New("bootstrap Secret metadata response was malformed; its value was not read")
	}
	generation, err := strconv.Atoi(fields[9])
	if err != nil || generation <= 0 {
		return nil, errors.New("bootstrap Secret lifecycle generation metadata was malformed; its value was not read")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, fields[10])
	if err != nil {
		return nil, errors.New("bootstrap Secret lifecycle expiry metadata was malformed; its value was not read")
	}
	if _, err := uuid.Parse(fields[7]); err != nil {
		return nil, errors.New("bootstrap Secret lifecycle claim metadata was malformed; its value was not read")
	}
	if _, err := uuid.Parse(fields[8]); err != nil {
		return nil, errors.New("bootstrap Secret lifecycle request metadata was malformed; its value was not read")
	}
	owners := strings.Split(fields[11], ";")
	if len(owners) != 2 || owners[1] != "" {
		return nil, errors.New("bootstrap Secret must carry exactly one lifecycle anchor owner reference; its value was not read")
	}
	owner := strings.Split(owners[0], "|")
	if len(owner) != 4 || owner[0] == "" || owner[1] == "" || owner[2] == "" || owner[3] == "" {
		return nil, errors.New("bootstrap Secret lifecycle anchor owner reference was malformed; its value was not read")
	}
	return &bootstrapSecretMetadata{
		name: fields[0], uid: fields[1], resourceVersion: fields[2], appName: fields[3], instance: fields[4], managedBy: fields[5], immutable: fields[6] == "true",
		lifecycleClaim: fields[7], requestID: fields[8], generation: generation, expiresAt: expiresAt,
		ownerAPIVersion: owner[0], ownerKind: owner[1], ownerName: owner[2], ownerUID: owner[3],
	}, nil
}

func findPVC(ctx context.Context, runner k8sRunner, kubeContext, namespace, claim string) (*pvcView, error) {
	result, err := runChecked(ctx, runner, "detect gateway state claim", k8sCommand{name: "kubectl", args: kubectlArgs(kubeContext, "get", "pvc", claim, "--namespace", namespace, "--ignore-not-found=true", "--output", "json")})
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(result.stdout)) == "" {
		return nil, nil
	}
	var pvc pvcView
	if err := json.Unmarshal(result.stdout, &pvc); err != nil {
		return nil, fmt.Errorf("decode gateway state claim metadata: %w", err)
	}
	return &pvc, nil
}

func getDeployment(ctx context.Context, runner k8sRunner, kubeContext, namespace, release string) (deploymentView, error) {
	name := gatewayFullname(release)
	result, err := runChecked(ctx, runner, "read gateway Deployment", k8sCommand{name: "kubectl", args: kubectlArgs(kubeContext, "get", "deployment", name, "--namespace", namespace, "--output", "json")})
	if err != nil {
		return deploymentView{}, err
	}
	var deployment deploymentView
	if err := json.Unmarshal(result.stdout, &deployment); err != nil {
		return deploymentView{}, fmt.Errorf("decode gateway Deployment: %w", err)
	}
	return deployment, nil
}

func getService(ctx context.Context, runner k8sRunner, kubeContext, namespace, release string) (serviceView, error) {
	name := gatewayFullname(release) + "-wg"
	result, err := runChecked(ctx, runner, "read gateway Service", k8sCommand{name: "kubectl", args: kubectlArgs(kubeContext, "get", "service", name, "--namespace", namespace, "--output", "json")})
	if err != nil {
		return serviceView{}, err
	}
	var service serviceView
	if err := json.Unmarshal(result.stdout, &service); err != nil {
		return serviceView{}, fmt.Errorf("decode gateway Service: %w", err)
	}
	return service, nil
}

func getPVC(ctx context.Context, runner k8sRunner, kubeContext, namespace, claim string) (pvcView, error) {
	result, err := runChecked(ctx, runner, "read gateway state claim", k8sCommand{name: "kubectl", args: kubectlArgs(kubeContext, "get", "pvc", claim, "--namespace", namespace, "--output", "json")})
	if err != nil {
		return pvcView{}, err
	}
	var pvc pvcView
	if err := json.Unmarshal(result.stdout, &pvc); err != nil {
		return pvcView{}, fmt.Errorf("decode gateway state claim: %w", err)
	}
	return pvc, nil
}

func deploymentClaim(deployment deploymentView) (string, error) {
	var claims []string
	for _, volume := range deployment.Spec.Template.Spec.Volumes {
		if volume.PersistentVolumeClaim != nil && strings.TrimSpace(volume.PersistentVolumeClaim.ClaimName) != "" {
			claims = append(claims, volume.PersistentVolumeClaim.ClaimName)
		}
	}
	sort.Strings(claims)
	if len(claims) != 1 {
		return "", fmt.Errorf("gateway Deployment must reference exactly one persistent state claim, found %d", len(claims))
	}
	return claims[0], nil
}

func serviceEndpoint(service serviceView) (string, error) {
	port, err := serviceWireguardPort(service)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(port.Protocol, "UDP") {
		return "", errors.New("gateway Service wireguard port is not UDP")
	}
	if port.Port != defaultK8sWireGuardPort {
		return "", fmt.Errorf("gateway Service wireguard port is %d, expected approved port %d", port.Port, defaultK8sWireGuardPort)
	}
	switch service.Spec.Type {
	case "LoadBalancer":
		for _, ingress := range service.Status.LoadBalancer.Ingress {
			host := strings.TrimSpace(ingress.IP)
			if host == "" {
				host = strings.TrimSpace(ingress.Hostname)
			}
			if host != "" {
				if ip := net.ParseIP(host); ip != nil {
					host = ip.String()
				}
				return net.JoinHostPort(host, strconv.Itoa(int(port.Port))), nil
			}
		}
		return "", errors.New("LoadBalancer Service has no status.loadBalancer.ingress endpoint")
	case "NodePort":
		if port.NodePort <= 0 {
			return "", errors.New("NodePort Service has no allocated nodePort")
		}
		return fmt.Sprintf("explicit-node-address:%d", port.NodePort), nil
	default:
		return "", fmt.Errorf("unsupported gateway Service type %q", service.Spec.Type)
	}
}

func serviceWireguardPort(service serviceView) (servicePortView, error) {
	if len(service.Spec.Ports) == 0 {
		return servicePortView{}, errors.New("gateway Service has no ports")
	}
	port := service.Spec.Ports[0]
	for _, candidate := range service.Spec.Ports {
		if candidate.Name == "wireguard" {
			port = candidate
			break
		}
	}
	return port, nil
}

func verifyGateway(ctx context.Context, runner k8sRunner, kubeContext, namespace, release, expectedServiceType, expectedEndpoint string, expectedNodePort int, timeout string) error {
	name := gatewayFullname(release)
	if _, err := runChecked(ctx, runner, "verify gateway Deployment readiness", k8sCommand{name: "kubectl", args: kubectlArgs(kubeContext, "rollout", "status", "deployment/"+name, "--namespace", namespace, "--timeout", timeout)}); err != nil {
		return err
	}
	deployment, err := getDeployment(ctx, runner, kubeContext, namespace, release)
	if err != nil {
		return err
	}
	desired := int32(1)
	if deployment.Spec.Replicas != nil {
		desired = *deployment.Spec.Replicas
	}
	if desired != 1 {
		return fmt.Errorf("gateway Deployment must run exactly one replica for one persistent connector identity, found %d", desired)
	}
	if deployment.Status.ObservedGeneration < deployment.Metadata.Generation || deployment.Status.ReadyReplicas != desired || deployment.Status.AvailableReplicas != desired || deployment.Status.UpdatedReplicas != desired {
		return fmt.Errorf("gateway Deployment is not fully converged (desired=%d ready=%d available=%d updated=%d)", desired, deployment.Status.ReadyReplicas, deployment.Status.AvailableReplicas, deployment.Status.UpdatedReplicas)
	}
	service, err := getService(ctx, runner, kubeContext, namespace, release)
	if err != nil {
		return err
	}
	if expectedServiceType != "" && service.Spec.Type != expectedServiceType {
		return fmt.Errorf("gateway Service type is %q, expected %q", service.Spec.Type, expectedServiceType)
	}
	port, portErr := serviceWireguardPort(service)
	if portErr != nil {
		return portErr
	}
	if !strings.EqualFold(port.Protocol, "UDP") {
		return errors.New("gateway Service wireguard port is not UDP")
	}
	if port.Port != defaultK8sWireGuardPort {
		return fmt.Errorf("gateway Service wireguard port is %d, expected approved port %d", port.Port, defaultK8sWireGuardPort)
	}
	if expectedEndpoint == "" {
		if _, err := serviceEndpoint(service); err != nil {
			return fmt.Errorf("gateway endpoint is not ready: %w", err)
		}
	}
	if expectedEndpoint != "" {
		_, rawExpectedPort, _ := net.SplitHostPort(expectedEndpoint)
		expectedPort, _ := strconv.Atoi(rawExpectedPort)
		actualPort := int(port.Port)
		if service.Spec.Type == "NodePort" {
			if port.NodePort <= 0 {
				return errors.New("NodePort Service has no allocated nodePort")
			}
			actualPort = int(port.NodePort)
			if expectedNodePort == 0 {
				return errors.New("NodePort verification requires the selected nodePort")
			}
			if int(port.NodePort) != expectedNodePort {
				return fmt.Errorf("gateway Service allocated nodePort %d, expected selected nodePort %d", port.NodePort, expectedNodePort)
			}
		}
		if actualPort != expectedPort {
			return fmt.Errorf("gateway Service exposes port %d but explicit endpoint uses %d", actualPort, expectedPort)
		}
	}
	return nil
}

func verifyInstalledGatewayState(ctx context.Context, runner k8sRunner, prepared preparedInstall) error {
	o := prepared.options
	expectedClaim := prepared.plan.Storage.Claim
	deployment, err := getDeployment(ctx, runner, o.kubeContext, o.namespace, o.release)
	if err != nil {
		return err
	}
	if err := requireLiveZeroTouchContract(deployment.Metadata.Annotations[zeroTouchContractAnnotationKey]); err != nil {
		return err
	}
	service, err := getService(ctx, runner, o.kubeContext, o.namespace, o.release)
	if err != nil {
		return err
	}
	if err := verifyPlannedGatewayInputs(deployment, service, o, resolvedImageReference(prepared.image, prepared.gatewayChart.AppVersion)); err != nil {
		return err
	}
	claim, err := deploymentClaim(deployment)
	if err != nil {
		return err
	}
	if claim != expectedClaim {
		return fmt.Errorf("gateway Deployment mounts state claim %q, expected approved claim %q", claim, expectedClaim)
	}
	pvc, err := getPVC(ctx, runner, o.kubeContext, o.namespace, claim)
	if err != nil {
		return err
	}
	if err := validateGatewayIdentityPVC(pvc, claim, o.release); err != nil {
		return err
	}
	if err := verifyPVCStorageClass(pvc, prepared.plan.Storage.Class); err != nil {
		return err
	}
	if prepared.state.pvcExists {
		if pvc.Metadata.UID != prepared.state.pvcUID {
			return fmt.Errorf("gateway state claim %q UID changed during install", claim)
		}
		if prepared.state.pvcVolumeName != "" && pvc.Spec.VolumeName != prepared.state.pvcVolumeName {
			return fmt.Errorf("gateway state claim %q bound volume changed during install", claim)
		}
	}
	if o.mode == "enroll" {
		if err := validatePVCLifecycleProvenance(pvc, prepared.anchor); err != nil {
			return err
		}
	}
	return nil
}

func verifyPlannedGatewayInputs(deployment deploymentView, service serviceView, o installOptions, expectedImage string) error {
	if service.Spec.LoadBalancerIP != o.loadBalancerIP {
		return fmt.Errorf("gateway Service loadBalancerIP is %q, expected approved %q", service.Spec.LoadBalancerIP, o.loadBalancerIP)
	}
	for key, expected := range serviceAnnotationMap(o.serviceAnnotations) {
		if actual, ok := service.Metadata.Annotations[key]; !ok || actual != expected {
			return fmt.Errorf("gateway Service annotation %q is %q, expected approved %q", key, actual, expected)
		}
	}
	actualPullSecrets := make([]string, 0, len(deployment.Spec.Template.Spec.ImagePullSecrets))
	for _, secret := range deployment.Spec.Template.Spec.ImagePullSecrets {
		actualPullSecrets = append(actualPullSecrets, secret.Name)
	}
	sort.Strings(actualPullSecrets)
	expectedPullSecrets := append([]string(nil), o.imagePullSecrets...)
	sort.Strings(expectedPullSecrets)
	if strings.Join(actualPullSecrets, "\x00") != strings.Join(expectedPullSecrets, "\x00") {
		return fmt.Errorf("gateway Deployment imagePullSecrets are %v, expected approved %v", actualPullSecrets, expectedPullSecrets)
	}
	expectedSelector := gatewaySelectorMap(o.gatewaySelectors)
	if !equalStringMap(deployment.Spec.Template.Spec.NodeSelector, expectedSelector) {
		return fmt.Errorf("gateway Deployment nodeSelector is %v, expected approved %v", deployment.Spec.Template.Spec.NodeSelector, expectedSelector)
	}
	actualTolerations := make([]gatewayToleration, 0, len(deployment.Spec.Template.Spec.Tolerations))
	for _, item := range deployment.Spec.Template.Spec.Tolerations {
		if item.TolerationSeconds != nil {
			return fmt.Errorf("gateway Deployment toleration %q has unapproved tolerationSeconds", item.Key)
		}
		actualTolerations = append(actualTolerations, gatewayToleration{Key: item.Key, Operator: item.Operator, Value: item.Value, Effect: item.Effect})
	}
	sort.Slice(actualTolerations, func(i, j int) bool {
		return gatewayTolerationKey(actualTolerations[i]) < gatewayTolerationKey(actualTolerations[j])
	})
	expectedTolerations := append([]gatewayToleration(nil), o.gatewayTolerations...)
	sort.Slice(expectedTolerations, func(i, j int) bool {
		return gatewayTolerationKey(expectedTolerations[i]) < gatewayTolerationKey(expectedTolerations[j])
	})
	if !equalGatewayTolerations(actualTolerations, expectedTolerations) {
		return fmt.Errorf("gateway Deployment tolerations are %v, expected approved %v", actualTolerations, expectedTolerations)
	}
	if err := verifyGatewayContainerImage(deployment, expectedImage); err != nil {
		return err
	}
	if deployment.Spec.Template.Spec.Containers[0].ImagePullPolicy != defaultNodeImagePullPolicy {
		return fmt.Errorf("gateway Deployment imagePullPolicy is %q, expected approved %q", deployment.Spec.Template.Spec.Containers[0].ImagePullPolicy, defaultNodeImagePullPolicy)
	}
	return nil
}

func verifyGatewayContainerImage(deployment deploymentView, expectedImage string) error {
	if len(deployment.Spec.Template.Spec.Containers) != 1 || deployment.Spec.Template.Spec.Containers[0].Name != "gateway" || strings.TrimSpace(deployment.Spec.Template.Spec.Containers[0].Image) == "" {
		return errors.New("gateway Deployment must contain exactly one non-empty gateway container image")
	}
	if expectedImage != "" && deployment.Spec.Template.Spec.Containers[0].Image != expectedImage {
		return fmt.Errorf("gateway Deployment image is %q, expected approved %q", deployment.Spec.Template.Spec.Containers[0].Image, expectedImage)
	}
	return nil
}

func equalGatewayTolerations(actual, expected []gatewayToleration) bool {
	if len(actual) != len(expected) {
		return false
	}
	for i := range expected {
		if actual[i] != expected[i] {
			return false
		}
	}
	return true
}

func gatewayTolerationKey(item gatewayToleration) string {
	return item.Key + "\x00" + item.Operator + "\x00" + item.Value + "\x00" + item.Effect
}

type statusOutput struct {
	SchemaVersion int                     `json:"schema_version"`
	Context       string                  `json:"context"`
	HostPosture   hostPostureStatusOutput `json:"host_posture"`
	Release       helmReleaseSummary      `json:"release"`
	Deployment    struct {
		Name               string `json:"name"`
		Desired            int32  `json:"desired"`
		Ready              int32  `json:"ready"`
		Available          int32  `json:"available"`
		Updated            int32  `json:"updated"`
		ObservedGeneration int64  `json:"observed_generation"`
	} `json:"deployment"`
	Service struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Endpoint string `json:"endpoint"`
	} `json:"service"`
	StateClaim string `json:"state_claim"`
}

func collectStatus(ctx context.Context, runner k8sRunner, o releaseOptions) (statusOutput, error) {
	_, hostPosture, err := collectHostPostureStatus(ctx, runner, o.kubeContext)
	if err != nil {
		return statusOutput{}, fmt.Errorf("shared host posture manager is not healthy: %w", err)
	}
	release, err := requireHelmRelease(ctx, runner, o.kubeContext, o.namespace, o.release)
	if err != nil {
		return statusOutput{}, err
	}
	deployment, err := getDeployment(ctx, runner, o.kubeContext, o.namespace, o.release)
	if err != nil {
		return statusOutput{}, err
	}
	service, err := getService(ctx, runner, o.kubeContext, o.namespace, o.release)
	if err != nil {
		return statusOutput{}, err
	}
	endpoint, endpointErr := serviceEndpoint(service)
	if endpointErr != nil {
		endpoint = "not ready: " + endpointErr.Error()
	}
	claim, claimErr := deploymentClaim(deployment)
	if claimErr != nil {
		claim = "not available: " + claimErr.Error()
	}
	desired := int32(1)
	if deployment.Spec.Replicas != nil {
		desired = *deployment.Spec.Replicas
	}
	result := statusOutput{SchemaVersion: 1, Context: o.kubeContext, HostPosture: hostPosture, Release: release, StateClaim: claim}
	result.Deployment.Name = deployment.Metadata.Name
	result.Deployment.Desired = desired
	result.Deployment.Ready = deployment.Status.ReadyReplicas
	result.Deployment.Available = deployment.Status.AvailableReplicas
	result.Deployment.Updated = deployment.Status.UpdatedReplicas
	result.Deployment.ObservedGeneration = deployment.Status.ObservedGeneration
	result.Service.Name = service.Metadata.Name
	result.Service.Type = service.Spec.Type
	result.Service.Endpoint = endpoint
	return result, nil
}

func runK8sStatus(ctx context.Context, args []string, deps k8sDeps) error {
	o := releaseOptions{}
	fs := flag.NewFlagSet("k8s status", flag.ContinueOnError)
	fs.SetOutput(deps.errOut)
	addReleaseFlags(fs, &o)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if err := validateReleaseOptions(&o); err != nil {
		return err
	}
	contextName, err := runToolContextPreflight(ctx, deps, o.kubeContext)
	if err != nil {
		return err
	}
	o.kubeContext = contextName
	status, err := collectStatus(ctx, deps.runner, o)
	if err != nil {
		return err
	}
	return writeJSON(deps.out, status)
}

type upgradeOptions struct {
	releaseOptions
	chart        string
	chartVersion string
	image        string
	yes          bool
}

type mutationPlan struct {
	SchemaVersion  int                      `json:"schema_version"`
	Action         string                   `json:"action"`
	Kubernetes     lifecycleKubernetes      `json:"kubernetes"`
	HostPosture    *hostPostureStatusOutput `json:"host_posture,omitempty"`
	Current        helmReleaseSummary       `json:"current_release,omitempty"`
	CurrentRuntime *lifecycleGatewayRuntime `json:"current_runtime,omitempty"`
	TargetRuntime  *lifecycleGatewayRuntime `json:"target_runtime,omitempty"`
	Chart          lifecycleChart           `json:"chart,omitempty"`
	Image          string                   `json:"image,omitempty"`
	TargetRevision int                      `json:"target_revision,omitempty"`
	StateClaim     string                   `json:"state_claim,omitempty"`
	StatePolicy    string                   `json:"state_policy,omitempty"`
	StateSnapshot  *lifecycleStateSnapshot  `json:"state_snapshot,omitempty"`
	Operations     []string                 `json:"operations"`
}

type lifecycleStateSnapshot struct {
	Claim           string `json:"claim"`
	PVCUID          string `json:"pvc_uid"`
	VolumeName      string `json:"volume_name"`
	ResourceVersion string `json:"resource_version"`
}

func ptrLifecycleStateSnapshot(value lifecycleStateSnapshot) *lifecycleStateSnapshot {
	return &value
}

func parseUpgradeOptions(args []string, deps k8sDeps) (upgradeOptions, error) {
	o := upgradeOptions{}
	fs := flag.NewFlagSet("k8s upgrade", flag.ContinueOnError)
	fs.SetOutput(deps.errOut)
	addReleaseFlags(fs, &o.releaseOptions)
	fs.StringVar(&o.chart, "chart", deps.defaultChart, "gateway chart OCI reference or local path")
	fs.StringVar(&o.chartVersion, "chart-version", "", "gateway chart version")
	fs.StringVar(&o.image, "image", "", "node-agent image override")
	fs.BoolVar(&o.yes, "yes", false, "approve the printed plan")
	if err := fs.Parse(args); err != nil {
		return upgradeOptions{}, err
	}
	if fs.NArg() != 0 {
		return upgradeOptions{}, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if err := validateReleaseOptions(&o.releaseOptions); err != nil {
		return upgradeOptions{}, err
	}
	o.chart = strings.TrimSpace(o.chart)
	o.chartVersion = strings.TrimPrefix(strings.TrimSpace(o.chartVersion), "v")
	o.image = strings.TrimSpace(o.image)
	if err := validateChartReference(o.chart); err != nil {
		return upgradeOptions{}, err
	}
	if strings.HasPrefix(o.chart, "oci://") && o.chartVersion == "" {
		v := strings.TrimPrefix(strings.TrimSpace(deps.buildVersion), "v")
		if v == "" || v == "dev" || v == "devel" || v == "unknown" {
			return upgradeOptions{}, errors.New("a dev/source CLI cannot guess an OCI chart version: pass --chart with a local path or --chart-version explicitly")
		}
		o.chartVersion = v
	}
	if o.chartVersion != "" && !versionRE.MatchString(o.chartVersion) {
		return upgradeOptions{}, errors.New("--chart-version contains unsupported characters")
	}
	if o.image != "" {
		if _, err := parseImageRef(o.image); err != nil {
			return upgradeOptions{}, fmt.Errorf("invalid --image: %w", err)
		}
	}
	return o, nil
}

func runK8sUpgrade(ctx context.Context, args []string, deps k8sDeps) (retErr error) {
	o, err := parseUpgradeOptions(args, deps)
	if err != nil {
		return err
	}
	contextName, err := runToolContextPreflight(ctx, deps, o.kubeContext)
	if err != nil {
		return err
	}
	o.kubeContext = contextName
	artifact, artifactRoot, err := materializeUpgradeChartWithCleanup(ctx, deps.runner, o.kubeContext, o.chart, o.chartVersion, deps.cleanupChartRoot)
	if err != nil {
		return err
	}
	helmMutationConfirmed := false
	defer func() {
		retErr = errors.Join(retErr, finalizeChartCleanup(artifactRoot, deps.cleanupChartRoot, helmMutationConfirmed, deps.errOut))
	}()
	chart := artifact.Metadata
	o.chartVersion = chart.Version
	hostPostureBefore, hostPostureStatus, err := collectHostPostureStatus(ctx, deps.runner, o.kubeContext)
	if err != nil {
		return fmt.Errorf("shared host posture manager is not healthy: %w", err)
	}
	upgradeHelp, err := runChecked(ctx, deps.runner, "verify Helm safe value-merge support", k8sCommand{name: "helm", args: []string{"upgrade", "--help"}})
	if err != nil {
		return err
	}
	if !strings.Contains(string(upgradeHelp.stdout), "--reset-then-reuse-values") {
		return errors.New("this Helm client lacks --reset-then-reuse-values; upgrade it before changing a gateway release so new chart defaults and retained non-secret settings merge safely")
	}
	stateBefore, err := captureGatewayMutationSnapshot(ctx, deps.runner, o.releaseOptions)
	if err != nil {
		return err
	}
	if err := requireCurrentZeroTouchProvenance(ctx, deps.runner, o.releaseOptions, stateBefore); err != nil {
		return err
	}
	imageRef := o.image
	if imageRef == "" {
		cred, loadErr := deps.loadCredential()
		if loadErr != nil {
			return loadErr
		}
		cp, cpErr := deps.newControlPlane(cred)
		if cpErr != nil {
			return cpErr
		}
		meta, metaErr := cp.GetMeta(ctx)
		if metaErr != nil {
			return metaErr
		}
		imageRef = implicitPinnedImage(meta.nodeAgentImage)
	}
	image := imageValues{}
	if imageRef != "" {
		image, err = parseImageRef(imageRef)
		if err != nil {
			return fmt.Errorf("node-agent image is invalid: %w", err)
		}
	}
	targetImage := resolvedImageReference(image, chart.AppVersion)
	if targetImage == "" {
		return errors.New("upgrade cannot prove the target gateway image from an unversioned local chart; pass --image or --chart-version")
	}
	targetRuntime := cloneGatewayRuntime(stateBefore.runtime)
	targetRuntime.Image = targetImage
	targetRuntime.ImagePullPolicy = defaultNodeImagePullPolicy
	plan := mutationPlan{
		SchemaVersion:  1,
		Action:         "upgrade",
		Kubernetes:     lifecycleKubernetes{Context: o.kubeContext, Namespace: o.namespace, Release: o.release},
		HostPosture:    &hostPostureStatus,
		Current:        stateBefore.release,
		CurrentRuntime: ptrGatewayRuntime(stateBefore.runtime),
		TargetRuntime:  &targetRuntime,
		Chart:          lifecycleChart{Name: chart.Name, Reference: o.chart, Version: chart.Version, AppVersion: chart.AppVersion, ArtifactSHA256: artifact.SHA256, RolloutRevision: "derived from approved plan digest"},
		Image:          targetImage,
		StateClaim:     stateBefore.claim,
		StateSnapshot:  ptrLifecycleStateSnapshot(stateBefore.planView()),
		Operations:     []string{"recheck exact shared host posture manager health", "Helm atomic upgrade", "verify Deployment readiness", "verify Service endpoint", "preserve state claim"},
	}
	canonical, digest, err := canonicalPlan(plan)
	if err != nil {
		return err
	}
	if err := printPlan(deps.out, canonical, digest); err != nil {
		return err
	}
	if err := requireApproval(deps.in, deps.out, digest, o.yes); err != nil {
		return err
	}
	if err := verifyChartArtifact(artifact, "gateway"); err != nil {
		return err
	}
	if err := recheckHealthyHostPosture(ctx, deps.runner, o.kubeContext, hostPostureBefore); err != nil {
		return err
	}
	if err := recheckGatewayMutationSnapshot(ctx, deps.runner, o.releaseOptions, stateBefore); err != nil {
		return err
	}
	if err := requireCurrentZeroTouchProvenance(ctx, deps.runner, o.releaseOptions, stateBefore); err != nil {
		return err
	}
	helmArgs := []string{"upgrade", o.release, artifact.Path, "--namespace", o.namespace, "--description", zeroTouchContract, "--reset-then-reuse-values", "--atomic", "--wait", "--timeout", o.timeout, "--values", "-"}
	helmArgs = appendHelmContext(helmArgs, o.kubeContext)
	pullSecrets := make([]map[string]string, 0, len(targetRuntime.ImagePullSecrets))
	for _, name := range targetRuntime.ImagePullSecrets {
		pullSecrets = append(pullSecrets, map[string]string{"name": name})
	}
	values := map[string]any{
		"rolloutRevision": rolloutRevision(digest),
		"nodeSelector":    targetRuntime.NodeSelector,
		"tolerations":     targetRuntime.Tolerations,
		"image":           map[string]any{"pullSecrets": pullSecrets},
	}
	appendGatewayImageValues(values, image)
	valuesJSON, err := json.Marshal(values)
	if err != nil {
		return err
	}
	if _, err := runChecked(ctx, deps.runner, "upgrade gateway release", k8sCommand{name: "helm", args: helmArgs, stdin: valuesJSON}); err != nil {
		return err
	}
	helmMutationConfirmed = true
	if err := verifyGateway(ctx, deps.runner, o.kubeContext, o.namespace, o.release, "", "", 0, o.timeout); err != nil {
		return err
	}
	deploymentAfter, err := getDeployment(ctx, deps.runner, o.kubeContext, o.namespace, o.release)
	if err != nil {
		return err
	}
	actualRuntime, err := gatewayRuntimeFromDeployment(deploymentAfter)
	if err != nil {
		return err
	}
	if runtimeFingerprint(actualRuntime) != runtimeFingerprint(targetRuntime) {
		return fmt.Errorf("gateway Deployment runtime after upgrade is %s, expected approved %s", runtimeFingerprint(actualRuntime), runtimeFingerprint(targetRuntime))
	}
	if err := verifyGatewayContainerImage(deploymentAfter, targetImage); err != nil {
		return err
	}
	if err := verifyGatewayIdentityPreserved(ctx, deps.runner, o.releaseOptions, stateBefore); err != nil {
		return err
	}
	if _, _, err := collectHostPostureStatus(ctx, deps.runner, o.kubeContext); err != nil {
		return fmt.Errorf("gateway upgraded but shared host posture manager is not healthy: %w", err)
	}
	_, err = fmt.Fprintf(deps.out, "Gateway %q upgraded and verified; its state claim was preserved.\n", o.release)
	return err
}

type rollbackOptions struct {
	releaseOptions
	revision int
	yes      bool
}

func runK8sRollback(ctx context.Context, args []string, deps k8sDeps) error {
	o := rollbackOptions{}
	fs := flag.NewFlagSet("k8s rollback", flag.ContinueOnError)
	fs.SetOutput(deps.errOut)
	addReleaseFlags(fs, &o.releaseOptions)
	fs.IntVar(&o.revision, "revision", 0, "target Helm revision")
	fs.BoolVar(&o.yes, "yes", false, "approve the printed plan")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if err := validateReleaseOptions(&o.releaseOptions); err != nil {
		return err
	}
	if o.revision <= 0 {
		return errors.New("--revision must be a positive Helm revision")
	}
	contextName, err := runToolContextPreflight(ctx, deps, o.kubeContext)
	if err != nil {
		return err
	}
	o.kubeContext = contextName
	hostPostureBefore, hostPostureStatus, err := collectHostPostureStatus(ctx, deps.runner, o.kubeContext)
	if err != nil {
		return fmt.Errorf("shared host posture manager is not healthy: %w", err)
	}
	stateBefore, err := captureGatewayMutationSnapshot(ctx, deps.runner, o.releaseOptions)
	if err != nil {
		return err
	}
	if err := requireZeroTouchRevision(ctx, deps.runner, o.releaseOptions, o.revision); err != nil {
		return err
	}
	plan := mutationPlan{
		SchemaVersion:  1,
		Action:         "rollback",
		Kubernetes:     lifecycleKubernetes{Context: o.kubeContext, Namespace: o.namespace, Release: o.release},
		HostPosture:    &hostPostureStatus,
		Current:        stateBefore.release,
		TargetRevision: o.revision,
		StateClaim:     stateBefore.claim,
		StateSnapshot:  ptrLifecycleStateSnapshot(stateBefore.planView()),
		Operations:     []string{"recheck exact shared host posture manager health", "Helm rollback with cleanup-on-fail", "verify Deployment readiness", "verify Service endpoint", "preserve state claim"},
	}
	canonical, digest, err := canonicalPlan(plan)
	if err != nil {
		return err
	}
	if err := printPlan(deps.out, canonical, digest); err != nil {
		return err
	}
	if err := requireApproval(deps.in, deps.out, digest, o.yes); err != nil {
		return err
	}
	if err := recheckHealthyHostPosture(ctx, deps.runner, o.kubeContext, hostPostureBefore); err != nil {
		return err
	}
	if err := recheckGatewayMutationSnapshot(ctx, deps.runner, o.releaseOptions, stateBefore); err != nil {
		return err
	}
	if err := requireZeroTouchRevision(ctx, deps.runner, o.releaseOptions, o.revision); err != nil {
		return err
	}
	helmArgs := []string{"rollback", o.release, strconv.Itoa(o.revision), "--namespace", o.namespace, "--wait", "--cleanup-on-fail", "--timeout", o.timeout}
	helmArgs = appendHelmContext(helmArgs, o.kubeContext)
	if _, err := runChecked(ctx, deps.runner, "rollback gateway release", k8sCommand{name: "helm", args: helmArgs}); err != nil {
		return err
	}
	if err := verifyGateway(ctx, deps.runner, o.kubeContext, o.namespace, o.release, "", "", 0, o.timeout); err != nil {
		return err
	}
	if err := verifyGatewayIdentityPreserved(ctx, deps.runner, o.releaseOptions, stateBefore); err != nil {
		return err
	}
	if _, _, err := collectHostPostureStatus(ctx, deps.runner, o.kubeContext); err != nil {
		return fmt.Errorf("gateway rolled back but shared host posture manager is not healthy: %w", err)
	}
	_, err = fmt.Fprintf(deps.out, "Gateway %q rolled back to revision %d and verified.\n", o.release, o.revision)
	return err
}

type historyEntry struct {
	Revision    int    `json:"revision"`
	Updated     string `json:"updated"`
	Status      string `json:"status"`
	Chart       string `json:"chart"`
	AppVersion  string `json:"app_version"`
	Description string `json:"description"`
}

func readHelmHistory(ctx context.Context, runner k8sRunner, o releaseOptions) ([]historyEntry, error) {
	args := []string{"history", o.release, "--namespace", o.namespace, "--output", "json", "--max", strconv.Itoa(maxZeroTouchHistoryDepth)}
	args = appendHelmContext(args, o.kubeContext)
	result, err := runChecked(ctx, runner, "read token-blind Helm revision history", k8sCommand{name: "helm", args: args})
	if err != nil {
		return nil, err
	}
	var history []historyEntry
	if err := json.Unmarshal(result.stdout, &history); err != nil {
		return nil, fmt.Errorf("decode token-blind Helm revision history: %w", err)
	}
	return history, nil
}

func proveZeroTouchRevision(history []historyEntry, target int) error {
	if target <= 0 {
		return fmt.Errorf("Helm revision %d is invalid", target)
	}
	byRevision := make(map[int]historyEntry, len(history))
	for _, entry := range history {
		if entry.Revision <= 0 {
			return fmt.Errorf("Helm history contains invalid revision %d", entry.Revision)
		}
		if _, duplicate := byRevision[entry.Revision]; duplicate {
			return fmt.Errorf("Helm history contains duplicate revision %d", entry.Revision)
		}
		byRevision[entry.Revision] = entry
	}
	revision := target
	visited := make(map[int]struct{})
	for depth := 0; depth < maxZeroTouchHistoryDepth; depth++ {
		if _, cycle := visited[revision]; cycle {
			return fmt.Errorf("Helm rollback provenance contains a cycle at revision %d", revision)
		}
		visited[revision] = struct{}{}
		entry, ok := byRevision[revision]
		if !ok {
			return fmt.Errorf("Helm revision %d is missing from bounded token-blind history", revision)
		}
		if entry.Description == zeroTouchContract {
			return nil
		}
		match := helmRollbackDescriptionRE.FindStringSubmatch(entry.Description)
		if len(match) != 2 {
			return fmt.Errorf("Helm revision %d has unproven lifecycle description %q", revision, entry.Description)
		}
		ancestor, err := strconv.Atoi(match[1])
		if err != nil || ancestor <= 0 {
			return fmt.Errorf("Helm revision %d has malformed rollback ancestor %q", revision, match[1])
		}
		if _, cycle := visited[ancestor]; cycle {
			return fmt.Errorf("Helm rollback provenance contains a cycle from revision %d to revision %d", revision, ancestor)
		}
		if ancestor > revision {
			return fmt.Errorf("Helm revision %d has unsafe forward rollback edge to revision %d", revision, ancestor)
		}
		revision = ancestor
	}
	return fmt.Errorf("Helm revision %d provenance exceeded the bounded history depth %d", target, maxZeroTouchHistoryDepth)
}

func requireZeroTouchRevision(ctx context.Context, runner k8sRunner, o releaseOptions, revision int) error {
	history, err := readHelmHistory(ctx, runner, o)
	if err != nil {
		return err
	}
	if err := proveZeroTouchRevision(history, revision); err != nil {
		return fmt.Errorf("refusing unproven Kubernetes gateway lifecycle: %w", err)
	}
	return nil
}

func requireCurrentZeroTouchProvenance(ctx context.Context, runner k8sRunner, o releaseOptions, state gatewayMutationSnapshot) error {
	if err := requireLiveZeroTouchContract(state.zeroTouchContract); err != nil {
		return err
	}
	revision, err := strconv.Atoi(state.release.Revision)
	if err != nil || revision <= 0 {
		return fmt.Errorf("current Helm revision %q is invalid", state.release.Revision)
	}
	return requireZeroTouchRevision(ctx, runner, o, revision)
}

type podList struct {
	Items []struct {
		Metadata struct {
			Name              string `json:"name"`
			DeletionTimestamp string `json:"deletionTimestamp"`
			OwnerReferences   []struct {
				Kind string `json:"kind"`
				Name string `json:"name"`
			} `json:"ownerReferences"`
		} `json:"metadata"`
		Spec struct {
			NodeName string `json:"nodeName"`
			Volumes  []struct {
				PersistentVolumeClaim *struct {
					ClaimName string `json:"claimName"`
				} `json:"persistentVolumeClaim,omitempty"`
			} `json:"volumes"`
		} `json:"spec"`
		Status struct {
			Phase             string `json:"phase"`
			ContainerStatuses []struct {
				Name         string `json:"name"`
				Ready        bool   `json:"ready"`
				RestartCount int32  `json:"restartCount"`
			} `json:"containerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

type eventList struct {
	Items []struct {
		Type    string `json:"type"`
		Reason  string `json:"reason"`
		Message string `json:"message"`
		Count   int32  `json:"count"`
	} `json:"items"`
}

type diagnosticPod struct {
	Name     string `json:"name"`
	Node     string `json:"node"`
	Phase    string `json:"phase"`
	Ready    bool   `json:"ready"`
	Restarts int32  `json:"restarts"`
}

type diagnosticEvent struct {
	Type    string `json:"type"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
	Count   int32  `json:"count"`
}

type diagnosticsOutput struct {
	SchemaVersion    int                      `json:"schema_version"`
	Context          string                   `json:"context"`
	Namespace        string                   `json:"namespace"`
	Release          string                   `json:"release"`
	HostPosture      *hostPostureStatusOutput `json:"host_posture,omitempty"`
	HostPostureError string                   `json:"host_posture_error,omitempty"`
	Status           *statusOutput            `json:"status,omitempty"`
	StatusError      string                   `json:"status_error,omitempty"`
	History          []historyEntry           `json:"history"`
	HistoryError     string                   `json:"history_error,omitempty"`
	Pods             []diagnosticPod          `json:"pods"`
	PodsError        string                   `json:"pods_error,omitempty"`
	Events           []diagnosticEvent        `json:"events"`
	EventsError      string                   `json:"events_error,omitempty"`
}

func runK8sDiagnostics(ctx context.Context, args []string, deps k8sDeps) error {
	o := releaseOptions{}
	fs := flag.NewFlagSet("k8s diagnostics", flag.ContinueOnError)
	fs.SetOutput(deps.errOut)
	addReleaseFlags(fs, &o)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if err := validateReleaseOptions(&o); err != nil {
		return err
	}
	contextName, err := runToolContextPreflight(ctx, deps, o.kubeContext)
	if err != nil {
		return err
	}
	o.kubeContext = contextName
	bundle := diagnosticsOutput{SchemaVersion: 1, Context: contextName, Namespace: o.namespace, Release: o.release, History: []historyEntry{}, Pods: []diagnosticPod{}, Events: []diagnosticEvent{}}
	if _, hostPosture, hostErr := collectHostPostureStatus(ctx, deps.runner, o.kubeContext); hostErr != nil {
		bundle.HostPostureError = redactText(hostErr.Error())
		if hostPosture.Release != "" {
			bundle.HostPosture = &hostPosture
		}
	} else {
		bundle.HostPosture = &hostPosture
	}
	if status, statusErr := collectStatus(ctx, deps.runner, o); statusErr != nil {
		bundle.StatusError = redactText(statusErr.Error())
	} else {
		bundle.Status = &status
	}
	historyArgs := []string{"history", o.release, "--namespace", o.namespace, "--output", "json", "--max", "20"}
	historyArgs = appendHelmContext(historyArgs, o.kubeContext)
	if result, historyErr := runChecked(ctx, deps.runner, "read Helm history", k8sCommand{name: "helm", args: historyArgs}); historyErr != nil {
		bundle.HistoryError = redactText(historyErr.Error())
	} else if decodeErr := json.Unmarshal(result.stdout, &bundle.History); decodeErr != nil {
		bundle.HistoryError = "decode Helm history: " + decodeErr.Error()
	} else {
		for i := range bundle.History {
			bundle.History[i].Description = redactText(bundle.History[i].Description)
		}
	}
	selector := "app.kubernetes.io/instance=" + o.release + ",app.kubernetes.io/component=gateway"
	if result, podsErr := runChecked(ctx, deps.runner, "read gateway pods", k8sCommand{name: "kubectl", args: kubectlArgs(o.kubeContext, "get", "pods", "--namespace", o.namespace, "--selector", selector, "--output", "json")}); podsErr != nil {
		bundle.PodsError = redactText(podsErr.Error())
	} else {
		var pods podList
		if decodeErr := json.Unmarshal(result.stdout, &pods); decodeErr != nil {
			bundle.PodsError = "decode gateway pods: " + decodeErr.Error()
		} else {
			for _, pod := range pods.Items {
				view := diagnosticPod{Name: pod.Metadata.Name, Node: pod.Spec.NodeName, Phase: pod.Status.Phase}
				for _, container := range pod.Status.ContainerStatuses {
					if container.Name == "gateway" {
						view.Ready = container.Ready
						view.Restarts = container.RestartCount
					}
				}
				bundle.Pods = append(bundle.Pods, view)
			}
		}
	}
	if result, eventsErr := runChecked(ctx, deps.runner, "read gateway events", k8sCommand{name: "kubectl", args: kubectlArgs(o.kubeContext, "get", "events", "--namespace", o.namespace, "--field-selector", "involvedObject.name="+gatewayFullname(o.release), "--output", "json")}); eventsErr != nil {
		bundle.EventsError = redactText(eventsErr.Error())
	} else {
		var events eventList
		if decodeErr := json.Unmarshal(result.stdout, &events); decodeErr != nil {
			bundle.EventsError = "decode gateway events: " + decodeErr.Error()
		} else {
			for _, event := range events.Items {
				bundle.Events = append(bundle.Events, diagnosticEvent{Type: event.Type, Reason: event.Reason, Message: redactText(event.Message), Count: event.Count})
			}
		}
	}
	return writeJSON(deps.out, bundle)
}

type uninstallOptions struct {
	releaseOptions
	yes bool
}

func runK8sUninstall(ctx context.Context, args []string, deps k8sDeps) error {
	o := uninstallOptions{}
	fs := flag.NewFlagSet("k8s uninstall", flag.ContinueOnError)
	fs.SetOutput(deps.errOut)
	addReleaseFlags(fs, &o.releaseOptions)
	fs.BoolVar(&o.yes, "yes", false, "approve the printed plan")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if err := validateReleaseOptions(&o.releaseOptions); err != nil {
		return err
	}
	contextName, err := runToolContextPreflight(ctx, deps, o.kubeContext)
	if err != nil {
		return err
	}
	o.kubeContext = contextName
	hostPostureBefore, hostPostureStatus, err := collectHostPostureStatus(ctx, deps.runner, o.kubeContext)
	if err != nil {
		return fmt.Errorf("shared host posture manager is not healthy: %w", err)
	}
	stateBefore, err := captureGatewayMutationSnapshot(ctx, deps.runner, o.releaseOptions)
	if err != nil {
		return err
	}
	plan := mutationPlan{
		SchemaVersion: 1,
		Action:        "uninstall",
		Kubernetes:    lifecycleKubernetes{Context: o.kubeContext, Namespace: o.namespace, Release: o.release},
		HostPosture:   &hostPostureStatus,
		Current:       stateBefore.release,
		StateClaim:    stateBefore.claim,
		StatePolicy:   "retain; deletion requires separate purge-state typed confirmation",
		StateSnapshot: ptrLifecycleStateSnapshot(stateBefore.planView()),
		Operations:    []string{"recheck and retain exact shared host posture manager", "Helm uninstall gateway release only", "verify gateway release absence", "verify state claim remains"},
	}
	canonical, digest, err := canonicalPlan(plan)
	if err != nil {
		return err
	}
	if err := printPlan(deps.out, canonical, digest); err != nil {
		return err
	}
	if err := requireApproval(deps.in, deps.out, digest, o.yes); err != nil {
		return err
	}
	if err := recheckHealthyHostPosture(ctx, deps.runner, o.kubeContext, hostPostureBefore); err != nil {
		return err
	}
	if err := recheckGatewayMutationSnapshot(ctx, deps.runner, o.releaseOptions, stateBefore); err != nil {
		return err
	}
	helmArgs := []string{"uninstall", o.release, "--namespace", o.namespace, "--wait", "--timeout", o.timeout}
	helmArgs = appendHelmContext(helmArgs, o.kubeContext)
	if _, err := runChecked(ctx, deps.runner, "uninstall gateway release", k8sCommand{name: "helm", args: helmArgs}); err != nil {
		return err
	}
	if releases, err := listHelmReleases(ctx, deps.runner, o.kubeContext, o.namespace, o.release); err != nil {
		return err
	} else if len(releases) != 0 {
		return fmt.Errorf("Helm release %q still exists after uninstall", o.release)
	}
	pvcAfter, err := getPVC(ctx, deps.runner, o.kubeContext, o.namespace, stateBefore.claim)
	if err != nil {
		return fmt.Errorf("state claim %q was not retained after uninstall: %w", stateBefore.claim, err)
	}
	if err := validateGatewayIdentityPVC(pvcAfter, stateBefore.claim, o.release); err != nil {
		return err
	}
	if pvcAfter.Metadata.UID != stateBefore.pvcUID || pvcAfter.Spec.VolumeName != stateBefore.volumeName {
		return fmt.Errorf("release was removed but retained state identity changed; expected claim %q UID %q volume %q", stateBefore.claim, stateBefore.pvcUID, stateBefore.volumeName)
	}
	if _, _, err := collectHostPostureStatus(ctx, deps.runner, o.kubeContext); err != nil {
		return fmt.Errorf("gateway was removed but shared host posture manager is not healthy: %w", err)
	}
	_, err = fmt.Fprintf(deps.out, "Gateway release %q was removed. State claim %q remains for recovery.\n", o.release, stateBefore.claim)
	return err
}

type purgeOptions struct {
	release                     string
	namespace                   string
	kubeContext                 string
	claim                       string
	confirmation                string
	legacyWithoutLifecycleProof bool
}

type purgeSnapshot struct {
	uid                     string
	resourceVersion         string
	legacy                  bool
	organizationID          string
	lifecycleClaim          string
	controlPlaneFingerprint string
}

func validateRetainedPVCMetadata(pvc pvcView, claim, release, namespace string) error {
	if pvc.Metadata.Name != claim || pvc.Metadata.Namespace != namespace ||
		pvc.Metadata.Labels["app.kubernetes.io/name"] != "tunnex-gateway" ||
		pvc.Metadata.Labels["app.kubernetes.io/instance"] != release ||
		pvc.Metadata.Labels["app.kubernetes.io/managed-by"] != "Helm" ||
		pvc.Metadata.Annotations["helm.sh/resource-policy"] != "keep" ||
		pvc.Metadata.Annotations["meta.helm.sh/release-name"] != release ||
		pvc.Metadata.Annotations["meta.helm.sh/release-namespace"] != namespace {
		return fmt.Errorf("claim %q is not the exact retained Helm-owned Tunnex state claim for release %q in namespace %q", claim, release, namespace)
	}
	if pvc.Metadata.DeletionTimestamp != "" {
		return fmt.Errorf("claim %q is already terminating; refusing a second lifecycle mutation", claim)
	}
	return nil
}

func exactLifecycleProvenance(pvc pvcView) (organizationID, lifecycleClaim string, present bool, err error) {
	organizationID, organizationPresent := pvc.Metadata.Annotations[lifecycleOrganizationAnnotation]
	lifecycleClaim, claimPresent := pvc.Metadata.Annotations[lifecycleClaimAnnotation]
	if !organizationPresent && !claimPresent {
		return "", "", false, nil
	}
	if organizationPresent != claimPresent || strings.TrimSpace(organizationID) != organizationID || strings.TrimSpace(lifecycleClaim) != lifecycleClaim || organizationID == "" || lifecycleClaim == "" {
		return "", "", false, errors.New("state claim has partial or malformed lifecycle provenance; refusing deletion")
	}
	parsedOrg, orgErr := uuid.Parse(organizationID)
	parsedClaim, claimErr := uuid.Parse(lifecycleClaim)
	if orgErr != nil || claimErr != nil || parsedOrg == uuid.Nil || parsedClaim == uuid.Nil || parsedOrg.String() != organizationID || parsedClaim.String() != lifecycleClaim {
		return "", "", false, errors.New("state claim lifecycle provenance is not two canonical UUIDs; refusing deletion")
	}
	return organizationID, lifecycleClaim, true, nil
}

func validatePVCLifecycleProvenance(pvc pvcView, anchor lifecycleAnchorMetadata) error {
	organizationID, lifecycleClaim, present, err := exactLifecycleProvenance(pvc)
	if err != nil {
		return fmt.Errorf("gateway state claim lifecycle provenance is invalid: %w", err)
	}
	if !present || organizationID != anchor.orgID || lifecycleClaim != anchor.lifecycleClaim {
		return fmt.Errorf("gateway state claim lifecycle provenance does not match the approved organization %s and claim %s", anchor.orgID, anchor.lifecycleClaim)
	}
	return nil
}

func validatePurgeLifecycleStatus(status k8sLifecycleClaimStatus, expectedClaim string) error {
	if status.claim != expectedClaim || status.nodeName == "" || status.requestID == "" || status.generation < 0 {
		return errors.New("control-plane lifecycle claim does not match the exact PVC provenance")
	}
	switch status.state {
	case "consumed":
		if status.consumedAt == nil || status.consumedAt.IsZero() || status.nodeID == "" {
			return errors.New("control-plane lifecycle claim is not an exact consumed identity")
		}
	case "aborted":
		if err := validateAlreadyAbortedLifecycleStatus(status, expectedClaim); err != nil {
			return fmt.Errorf("control-plane lifecycle claim is not an exact aborted identity: %w", err)
		}
	default:
		return fmt.Errorf("control-plane lifecycle claim is %q, not consumed or aborted; resume abort-install or lifecycle recovery before purging state", status.state)
	}
	return nil
}

func inspectPurgeState(ctx context.Context, deps k8sDeps, o purgeOptions) (purgeSnapshot, error) {
	releases, err := listHelmReleases(ctx, deps.runner, o.kubeContext, o.namespace, o.release)
	if err != nil {
		return purgeSnapshot{}, err
	}
	if len(releases) != 0 {
		return purgeSnapshot{}, fmt.Errorf("release %q is still present; uninstall it before purging state", o.release)
	}
	anchorName := o.release + "-lifecycle"
	anchor, err := getLifecycleAnchorMetadata(ctx, deps.runner, o.kubeContext, o.namespace, anchorName)
	if err != nil {
		return purgeSnapshot{}, err
	}
	if anchor != nil {
		if err := validateOwnedLifecycleAnchor(*anchor, anchorName, o.release); err != nil {
			return purgeSnapshot{}, err
		}
		return purgeSnapshot{}, fmt.Errorf("owned lifecycle anchor %q remains; resume abort-install or normal lifecycle cleanup before purging state", anchorName)
	}
	secretName := o.release + "-bootstrap"
	secret, err := getBootstrapSecretMetadata(ctx, deps.runner, o.kubeContext, o.namespace, secretName)
	if err != nil {
		return purgeSnapshot{}, err
	}
	if secret != nil {
		if err := validateOwnedBootstrapSecret(*secret, secretName, o.release); err != nil {
			return purgeSnapshot{}, err
		}
		return purgeSnapshot{}, fmt.Errorf("owned bootstrap Secret %q remains; resume abort-install or normal lifecycle cleanup before purging state", secretName)
	}
	pvc, err := getPVC(ctx, deps.runner, o.kubeContext, o.namespace, o.claim)
	if err != nil {
		return purgeSnapshot{}, err
	}
	if err := validateRetainedPVCMetadata(pvc, o.claim, o.release, o.namespace); err != nil {
		return purgeSnapshot{}, err
	}
	if pvc.Metadata.UID == "" || pvc.Metadata.ResourceVersion == "" {
		return purgeSnapshot{}, fmt.Errorf("claim %q lacks Kubernetes UID/resourceVersion preconditions; refusing deletion", o.claim)
	}
	if mountedBy, err := claimMountedByLivePod(ctx, deps.runner, o.kubeContext, o.namespace, o.claim); err != nil {
		return purgeSnapshot{}, err
	} else if mountedBy != "" {
		return purgeSnapshot{}, fmt.Errorf("claim %q is still mounted by %s; refusing permanent identity deletion", o.claim, mountedBy)
	}
	organizationID, lifecycleClaim, hasProvenance, err := exactLifecycleProvenance(pvc)
	if err != nil {
		return purgeSnapshot{}, err
	}
	if !hasProvenance {
		if !o.legacyWithoutLifecycleProof {
			return purgeSnapshot{}, fmt.Errorf("claim %q has no lifecycle provenance; rerun only for a verified legacy claim with --legacy-without-lifecycle-proof", o.claim)
		}
		return purgeSnapshot{uid: pvc.Metadata.UID, resourceVersion: pvc.Metadata.ResourceVersion, legacy: true}, nil
	}
	if o.legacyWithoutLifecycleProof {
		return purgeSnapshot{}, errors.New("--legacy-without-lifecycle-proof is only valid when both lifecycle provenance annotations are absent")
	}
	credential, err := deps.loadCredential()
	if err != nil {
		return purgeSnapshot{}, fmt.Errorf("load control-plane credential for lifecycle purge proof: %w", err)
	}
	cp, err := deps.newControlPlane(credential)
	if err != nil {
		return purgeSnapshot{}, fmt.Errorf("create control-plane client for lifecycle purge proof: %w", err)
	}
	organizations, err := cp.ListOrganizations(ctx)
	if err != nil {
		return purgeSnapshot{}, fmt.Errorf("list organizations for lifecycle purge proof: %w", err)
	}
	organization, err := resolveOrganization(organizations, organizationID)
	if err != nil || organization.id != organizationID {
		if err == nil {
			err = errors.New("resolved organization differs from PVC provenance")
		}
		return purgeSnapshot{}, fmt.Errorf("resolve exact lifecycle provenance organization: %w", err)
	}
	status, err := cp.GetLifecycleClaimStatus(ctx, organization.id, lifecycleClaim)
	if err != nil {
		return purgeSnapshot{}, fmt.Errorf("prove terminal control-plane lifecycle claim before purging state: %w", err)
	}
	if err := validatePurgeLifecycleStatus(status, lifecycleClaim); err != nil {
		return purgeSnapshot{}, err
	}
	return purgeSnapshot{
		uid: pvc.Metadata.UID, resourceVersion: pvc.Metadata.ResourceVersion,
		organizationID: organizationID, lifecycleClaim: lifecycleClaim,
		controlPlaneFingerprint: lifecycleClaimStatusFingerprint(status),
	}, nil
}

func runK8sPurgeState(ctx context.Context, args []string, deps k8sDeps) (retErr error) {
	o := purgeOptions{}
	fs := flag.NewFlagSet("k8s purge-state", flag.ContinueOnError)
	fs.SetOutput(deps.errOut)
	fs.StringVar(&o.release, "release", "", "absent Helm release that owned the claim")
	fs.StringVar(&o.namespace, "namespace", defaultK8sNamespace, "Kubernetes namespace")
	fs.StringVar(&o.kubeContext, "context", "", "kube context")
	fs.StringVar(&o.claim, "claim", "", "exact retained state claim")
	fs.StringVar(&o.confirmation, "confirm", "", "exact typed confirmation: DELETE <claim>")
	fs.BoolVar(&o.legacyWithoutLifecycleProof, "legacy-without-lifecycle-proof", false, "acknowledge a pre-provenance retained claim; requires DELETE LEGACY <claim>")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	o.release = strings.TrimSpace(o.release)
	o.namespace = strings.TrimSpace(o.namespace)
	o.kubeContext = strings.TrimSpace(o.kubeContext)
	o.claim = strings.TrimSpace(o.claim)
	if o.release == "" {
		return errors.New("purge-state requires an explicit --release")
	}
	if err := validateRelease(o.release); err != nil {
		return err
	}
	if err := validateDNSLabel("namespace", o.namespace, 63); err != nil {
		return err
	}
	if err := validateDNSSubdomain("claim", o.claim, 253); err != nil {
		return err
	}
	contextName, err := runToolContextPreflight(ctx, deps, o.kubeContext)
	if err != nil {
		return err
	}
	o.kubeContext = contextName
	before, err := inspectPurgeState(ctx, deps, o)
	if err != nil {
		return err
	}
	want := "DELETE " + o.claim
	if before.legacy {
		want = "DELETE LEGACY " + o.claim
	}
	if strings.TrimSpace(o.confirmation) == "" {
		if _, err := fmt.Fprintf(deps.out, "WARNING: deleting %q permanently destroys this gateway identity and HA state.\nType %q to continue: ", o.claim, want); err != nil {
			return err
		}
		line, readErr := bufio.NewReader(deps.in).ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		o.confirmation = strings.TrimSpace(line)
	}
	if o.confirmation != want {
		return fmt.Errorf("confirmation did not match exactly %q; state was not deleted", want)
	}
	binding := retainedStateFenceBinding{
		kubeContext: o.kubeContext, namespace: o.namespace, release: o.release,
		claim: o.claim, pvcUID: before.uid,
	}
	fence, err := acquireRetainedStateFence(ctx, deps, binding, retainedStateFenceOperationPurge, func(reproofCtx context.Context) error {
		current, reproofErr := inspectPurgeState(reproofCtx, deps, o)
		if reproofErr != nil {
			return reproofErr
		}
		if current != before {
			return fmt.Errorf("claim %q changed before expired Lease takeover", o.claim)
		}
		return nil
	})
	if err != nil {
		return err
	}
	renewal := startRetainedStateFenceRenewal(ctx, deps, fence)
	fencedCtx := renewal.ctx
	deleteAttempted := false
	deleteConfirmed := false
	defer func() {
		renewErr := renewal.stop()
		if renewErr != nil && !deleteConfirmed {
			retErr = errors.Join(retErr, renewErr)
			return
		}
		if deleteAttempted && !deleteConfirmed {
			return
		}
		cleanupCtx, cancel := retainedStateFenceCleanupContext()
		defer cancel()
		retErr = errors.Join(retErr, fence.release(cleanupCtx))
	}()
	after, err := inspectPurgeState(fencedCtx, deps, o)
	if err != nil {
		return err
	}
	if after != before {
		return fmt.Errorf("claim %q changed while awaiting confirmation; re-run purge-state against the current object", o.claim)
	}
	deleteOptions, err := json.Marshal(map[string]any{
		"apiVersion": "v1",
		"kind":       "DeleteOptions",
		"preconditions": map[string]string{
			"uid":             after.uid,
			"resourceVersion": after.resourceVersion,
		},
	})
	if err != nil {
		return fmt.Errorf("encode preconditioned state deletion: %w", err)
	}
	rawPath := "/api/v1/namespaces/" + o.namespace + "/persistentvolumeclaims/" + o.claim
	deleteAttempted = true
	if _, err := runChecked(fencedCtx, deps.runner, "delete gateway state claim with UID/resourceVersion preconditions", k8sCommand{
		name: "kubectl", args: kubectlArgs(o.kubeContext, "delete", "--raw="+rawPath, "-f", "-"), stdin: deleteOptions,
	}); err != nil {
		return err
	}
	// The Lease is owned by this exact PVC UID and may be garbage-collected as
	// soon as deletion begins. Stop renewal before waiting for final absence;
	// reuse refuses the terminating PVC and cannot recreate the same name until
	// Kubernetes has completed deletion.
	_ = renewal.stop()
	if _, err := runChecked(ctx, deps.runner, "wait for gateway state claim deletion", k8sCommand{
		name: "kubectl", args: kubectlArgs(o.kubeContext, "wait", "--for=delete", "pvc/"+o.claim, "--namespace", o.namespace, "--timeout=5m"),
	}); err != nil {
		return err
	}
	deleteConfirmed = true
	_, err = fmt.Fprintf(deps.out, "State claim %q was deleted permanently and cannot be recovered.\n", o.claim)
	return err
}

func writeJSON(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
