package cli

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	maxLifecycleInstallLease          = 15 * time.Minute
	lifecycleInstallCompletionMargin  = time.Minute
	minLifecycleInstallFinishMargin   = 30 * time.Second
	lifecycleInstallHeartbeatInterval = 15 * time.Second
	lifecycleInstallAbsentAfterExpiry = "lifecycle_install_operation_absent_after_expiry"
)

var errLifecycleInstallOperationAbsentAfterExpiry = errors.New(lifecycleInstallAbsentAfterExpiry)

type lifecycleInstallOperationState string

const (
	lifecycleInstallActive         lifecycleInstallOperationState = "active"
	lifecycleInstallAbortRequested lifecycleInstallOperationState = "abort_requested"
	lifecycleInstallExpired        lifecycleInstallOperationState = "expired"
	lifecycleInstallReleased       lifecycleInstallOperationState = "released"
	lifecycleInstallAborting       lifecycleInstallOperationState = "aborting"
	lifecycleInstallCompleted      lifecycleInstallOperationState = "completed"
	lifecycleInstallAborted        lifecycleInstallOperationState = "aborted"
)

type lifecycleInstallOperationStatus struct {
	claim                    string
	generation               int
	requestID                string
	operationID              string
	epoch                    int64
	state                    lifecycleInstallOperationState
	releaseNamespace         string
	releaseName              string
	installIntentDigest      string
	requestedDurationSeconds int
	notAfter                 time.Time
	serverTime               time.Time
	heartbeatAt              time.Time
	abortRequestedAt         *time.Time
	releasedAt               *time.Time
	completedAt              *time.Time
	takenOverAt              *time.Time
	abortedAt                *time.Time
}

type lifecycleInstallBeginRequest struct {
	claim                    string
	expectedGeneration       int
	requestID                string
	operationID              string
	releaseNamespace         string
	releaseName              string
	installIntentDigest      string
	requestedDurationSeconds int
}

type lifecycleInstallCASRequest struct {
	claim              string
	expectedGeneration int
	requestID          string
	operationID        string
	expectedEpoch      int64
}

type lifecycleInstallAbortResult struct {
	claimStatus     *k8sLifecycleClaimStatus
	operationStatus *lifecycleInstallOperationStatus
	pending         bool
}

// lifecycleInstallControlPlane is deliberately separate from k8sControlPlane:
// reuse and older test fakes do not acquire D13h install authority. Enroll must
// require this exact extension before it can begin any Helm mutation.
type lifecycleInstallControlPlane interface {
	GetLatestLifecycleInstall(context.Context, string, string) (lifecycleInstallOperationStatus, error)
	BeginLifecycleInstall(context.Context, string, lifecycleInstallBeginRequest) (lifecycleInstallOperationStatus, error)
	HeartbeatLifecycleInstall(context.Context, string, lifecycleInstallCASRequest) (lifecycleInstallOperationStatus, error)
	ReleaseLifecycleInstall(context.Context, string, lifecycleInstallCASRequest) (lifecycleInstallOperationStatus, error)
	CompleteLifecycleInstall(context.Context, string, lifecycleInstallCASRequest) (lifecycleInstallOperationStatus, error)
	CoordinateLifecycleInstallAbort(context.Context, string, lifecycleInstallCASRequest) (lifecycleInstallAbortResult, error)
	FinalizeLifecycleInstallAbort(context.Context, string, lifecycleInstallCASRequest) (k8sLifecycleClaimStatus, error)
}

func lifecycleInstallBudget(timeout string) (time.Duration, int, error) {
	helmTimeout, err := time.ParseDuration(timeout)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid --timeout: %w", err)
	}
	if helmTimeout <= 0 {
		return 0, 0, errors.New("--timeout must be greater than zero")
	}
	maxHelmTimeout := maxLifecycleInstallLease - lifecycleInstallCompletionMargin
	if helmTimeout > maxHelmTimeout {
		return 0, 0, fmt.Errorf("--timeout %s exceeds the lifecycle install maximum %s; choose %s or less so verification and completion retain a %s safety margin", helmTimeout, maxHelmTimeout, maxHelmTimeout, lifecycleInstallCompletionMargin)
	}
	requested := helmTimeout + lifecycleInstallCompletionMargin
	requestedSeconds := int((requested + time.Second - 1) / time.Second)
	if requestedSeconds <= 0 || time.Duration(requestedSeconds)*time.Second > maxLifecycleInstallLease {
		return 0, 0, errors.New("lifecycle install duration is outside the control-plane 1..900 second authority window")
	}
	return helmTimeout, requestedSeconds, nil
}

type lifecycleInstallDeadlines struct {
	hard time.Time
	helm time.Time
}

type canonicalLifecycleInstallIntent struct {
	SchemaVersion             int                 `json:"schema_version"`
	OrganizationID            string              `json:"organization_id"`
	LifecycleClaim            string              `json:"lifecycle_claim"`
	LifecycleGeneration       int                 `json:"lifecycle_generation"`
	LifecycleRequestID        string              `json:"lifecycle_request_id"`
	Kubernetes                lifecycleKubernetes `json:"kubernetes"`
	GatewayChartName          string              `json:"gateway_chart_name"`
	GatewayChartVersion       string              `json:"gateway_chart_version"`
	GatewayChartAppVersion    string              `json:"gateway_chart_app_version"`
	GatewayChartArtifactSHA   string              `json:"gateway_chart_artifact_sha256"`
	HelmTimeoutNanoseconds    int64               `json:"helm_timeout_nanoseconds"`
	RolloutRevisionDerivation string              `json:"rollout_revision_derivation"`
	HelmValues                map[string]any      `json:"helm_values_without_rollout_revision"`
}

func lifecycleInstallIntentGeneration(anchor lifecycleAnchorMetadata) (int, error) {
	switch anchor.state {
	case "pending":
		if anchor.expectedGeneration < 0 || anchor.expectedGeneration == int(^uint(0)>>1) {
			return 0, errors.New("pending lifecycle anchor has an invalid expected generation")
		}
		return anchor.expectedGeneration + 1, nil
	case "issued", "acknowledged", "installing":
		if anchor.generation <= 0 {
			return 0, fmt.Errorf("%s lifecycle anchor has no positive generation", anchor.state)
		}
		return anchor.generation, nil
	default:
		return 0, fmt.Errorf("lifecycle anchor state %q cannot authorize an install intent", anchor.state)
	}
}

func describeFencedLifecycleInstallOperations(operations []string) []string {
	result := make([]string, 0, len(operations)+5)
	for _, operation := range operations {
		if operation != "Helm atomic install" {
			result = append(result, operation)
			continue
		}
		result = append(result,
			"persist stable install intent and opaque operation UUID in the lifecycle anchor",
			"Begin exact control-plane install operation before gateway Helm mutation",
			"CAS-mirror installing epoch and server-bounded hard deadline in the lifecycle anchor",
			"run Helm atomic install under the approved timeout with bounded control-plane heartbeats",
			"cancel Helm on abort, lost epoch, or hard deadline",
			"verify exact consumed claim, release/workload readiness, and persistent provenance",
			"Complete exact install epoch before deleting bootstrap recovery metadata",
		)
	}
	return result
}

// gatewayInstallValues is shared by stable intent hashing and the actual Helm
// command. The rollout revision is omitted while hashing because it is derived
// from that hash; production supplies rolloutRevision(installIntentDigest).
func gatewayInstallValues(prepared preparedInstall, rollout string) (map[string]any, error) {
	o := prepared.options
	if prepared.plan.ControlPlane == nil {
		return nil, errors.New("install plan has no control-plane endpoints")
	}
	controlPlane := *prepared.plan.ControlPlane
	serviceValues := map[string]any{"type": o.serviceType}
	if o.serviceType == "NodePort" {
		serviceValues["nodePort"] = o.nodePort
	}
	if o.loadBalancerIP != "" {
		serviceValues["loadBalancerIP"] = o.loadBalancerIP
	}
	if len(o.serviceAnnotations) != 0 {
		serviceValues["annotations"] = serviceAnnotationMap(o.serviceAnnotations)
	}
	values := map[string]any{
		"acknowledgePrivileged": true,
		"controlPlane": map[string]any{
			"apiURL":     controlPlane.APIURL,
			"agentURL":   controlPlane.AgentURL,
			"serverName": controlPlane.ServerName,
		},
		"endpoint": o.endpoint,
		"enrollment": map[string]any{
			"mode": o.mode,
		},
		"nodeName":     o.nodeName,
		"nodeSelector": gatewaySelectorMap(o.gatewaySelectors),
		"persistence": map[string]any{
			"storageClass": prepared.plan.Storage.Class,
		},
		"service": serviceValues,
		"wireguard": map[string]any{
			"port": defaultK8sWireGuardPort,
		},
	}
	tolerations := append([]gatewayToleration(nil), o.gatewayTolerations...)
	sort.Slice(tolerations, func(i, j int) bool {
		a := tolerations[i].Key + "\x00" + tolerations[i].Operator + "\x00" + tolerations[i].Value + "\x00" + tolerations[i].Effect
		b := tolerations[j].Key + "\x00" + tolerations[j].Operator + "\x00" + tolerations[j].Value + "\x00" + tolerations[j].Effect
		return a < b
	})
	values["tolerations"] = tolerations
	if rollout != "" {
		values["rolloutRevision"] = rollout
	}
	if len(o.imagePullSecrets) != 0 {
		secretNames := append([]string(nil), o.imagePullSecrets...)
		sort.Strings(secretNames)
		pullSecrets := make([]map[string]string, 0, len(secretNames))
		for _, name := range secretNames {
			pullSecrets = append(pullSecrets, map[string]string{"name": name})
		}
		values["image"] = map[string]any{"pullSecrets": pullSecrets}
	}
	if o.mode == "enroll" {
		if prepared.anchor.orgID == "" || prepared.anchor.orgID != prepared.org.id || prepared.anchor.lifecycleClaim == "" {
			return nil, errors.New("enroll chart values require the exact approved organization and lifecycle claim")
		}
		orgID, orgErr := uuid.Parse(prepared.anchor.orgID)
		claimID, claimErr := uuid.Parse(prepared.anchor.lifecycleClaim)
		if orgErr != nil || claimErr != nil || orgID == uuid.Nil || claimID == uuid.Nil || orgID.String() != prepared.anchor.orgID || claimID.String() != prepared.anchor.lifecycleClaim {
			return nil, errors.New("enroll chart values require canonical organization and lifecycle claim UUIDs")
		}
		values["enrollment"] = map[string]any{
			"mode":           o.mode,
			"existingSecret": prepared.plan.Gateway.BootstrapSecret,
			"secretOptional": true,
		}
		values["persistence"] = map[string]any{
			"storageClass": prepared.plan.Storage.Class,
			"provenance": map[string]any{
				"organizationID": prepared.anchor.orgID,
				"lifecycleClaim": prepared.anchor.lifecycleClaim,
			},
		}
	} else {
		values["persistence"] = map[string]any{
			"existingClaim": o.existingClaim,
		}
	}
	appendGatewayImageValues(values, prepared.image)
	return values, nil
}

func computeLifecycleInstallIntent(prepared preparedInstall) ([]byte, string, error) {
	if prepared.options.mode != "enroll" {
		return nil, "", errors.New("only zero-touch enroll has a control-plane lifecycle install intent")
	}
	orgID, orgErr := uuid.Parse(prepared.org.id)
	claimID, claimErr := uuid.Parse(prepared.anchor.lifecycleClaim)
	requestID, requestErr := uuid.Parse(prepared.anchor.requestID)
	if orgErr != nil || claimErr != nil || requestErr != nil || orgID == uuid.Nil || claimID == uuid.Nil || requestID == uuid.Nil ||
		orgID.String() != prepared.org.id || claimID.String() != prepared.anchor.lifecycleClaim || requestID.String() != prepared.anchor.requestID {
		return nil, "", errors.New("install intent requires canonical organization, claim, and request UUIDs")
	}
	generation, err := lifecycleInstallIntentGeneration(prepared.anchor)
	if err != nil {
		return nil, "", err
	}
	helmTimeout, _, err := lifecycleInstallBudget(prepared.options.timeout)
	if err != nil {
		return nil, "", err
	}
	artifactSHA := strings.ToLower(strings.TrimSpace(prepared.gatewayArtifact.SHA256))
	artifactHex := strings.TrimPrefix(artifactSHA, "sha256:")
	if !strings.HasPrefix(artifactSHA, "sha256:") || len(artifactHex) != 64 || !hexRE.MatchString(artifactHex) {
		return nil, "", errors.New("install intent requires the exact materialized gateway chart SHA-256")
	}
	values, err := gatewayInstallValues(prepared, "")
	if err != nil {
		return nil, "", err
	}
	intent := canonicalLifecycleInstallIntent{
		SchemaVersion:  1,
		OrganizationID: orgID.String(), LifecycleClaim: claimID.String(), LifecycleGeneration: generation, LifecycleRequestID: requestID.String(),
		Kubernetes:       prepared.plan.Kubernetes,
		GatewayChartName: prepared.gatewayChart.Name, GatewayChartVersion: prepared.gatewayChart.Version, GatewayChartAppVersion: prepared.gatewayChart.AppVersion,
		GatewayChartArtifactSHA:   artifactSHA,
		HelmTimeoutNanoseconds:    int64(helmTimeout),
		RolloutRevisionDerivation: "plan-<first-16-hex-of-install-intent-digest>",
		HelmValues:                values,
	}
	return canonicalPlan(intent)
}

// deriveLifecycleInstallDeadlines converts a DB-clock response into local
// monotonic deadlines. requestStart is captured immediately before the CP
// request and retains Go's monotonic component. No local wall-clock comparison
// is made: transit or skew can only shorten the resulting authority window.
func deriveLifecycleInstallDeadlines(requestStart time.Time, status lifecycleInstallOperationStatus, helmTimeout time.Duration) (lifecycleInstallDeadlines, error) {
	if requestStart.IsZero() || status.serverTime.IsZero() || status.notAfter.IsZero() {
		return lifecycleInstallDeadlines{}, errors.New("lifecycle install operation lacks a request-start, server time, or hard deadline")
	}
	if helmTimeout <= 0 || helmTimeout > maxLifecycleInstallLease-lifecycleInstallCompletionMargin {
		return lifecycleInstallDeadlines{}, errors.New("lifecycle install Helm timeout is outside the authority window")
	}
	remaining := status.notAfter.Sub(status.serverTime)
	approvedAuthority := time.Duration(status.requestedDurationSeconds) * time.Second
	if status.requestedDurationSeconds <= 0 || approvedAuthority > maxLifecycleInstallLease || remaining > approvedAuthority {
		return lifecycleInstallDeadlines{}, fmt.Errorf("control-plane lifecycle authority %s exceeds the approved %s operation budget", remaining, approvedAuthority)
	}
	required := helmTimeout + minLifecycleInstallFinishMargin
	if remaining < required {
		return lifecycleInstallDeadlines{}, fmt.Errorf("control-plane lifecycle authority has only %s remaining; the approved Helm timeout plus minimum completion margin requires %s", remaining, required)
	}
	hard := requestStart.Add(remaining)
	helm := requestStart.Add(helmTimeout)
	return lifecycleInstallDeadlines{hard: hard, helm: helm}, nil
}

func lifecycleInstallCASFromStatus(status lifecycleInstallOperationStatus) lifecycleInstallCASRequest {
	return lifecycleInstallCASRequest{
		claim: status.claim, expectedGeneration: status.generation, requestID: status.requestID,
		operationID: status.operationID, expectedEpoch: status.epoch,
	}
}

func validateLifecycleInstallOperationStatus(status lifecycleInstallOperationStatus, request lifecycleInstallBeginRequest) error {
	if !validCanonicalSHA256Digest(request.installIntentDigest) {
		return errors.New("lifecycle install operation request lacks a canonical install intent SHA-256")
	}
	if status.claim != request.claim || status.generation != request.expectedGeneration || status.requestID != request.requestID ||
		status.operationID != request.operationID || status.releaseNamespace != request.releaseNamespace || status.releaseName != request.releaseName ||
		status.installIntentDigest != request.installIntentDigest || status.requestedDurationSeconds != request.requestedDurationSeconds {
		return errors.New("control-plane lifecycle install operation does not match the exact approved claim, request, release, duration, and intent")
	}
	if status.epoch <= 0 || status.notAfter.IsZero() || status.serverTime.IsZero() || status.heartbeatAt.IsZero() {
		return errors.New("control-plane lifecycle install operation lacks a positive epoch or server-clock timestamps")
	}
	return nil
}

// validateLifecycleInstallOperationContinuation binds every mutating response
// to the exact immutable authority returned by Begin. The generic tuple check
// is not enough for continuation calls: a different epoch or deadline is a
// fencing event, not a refreshed grant.
func validateLifecycleInstallOperationContinuation(status lifecycleInstallOperationStatus, request lifecycleInstallBeginRequest, expected lifecycleInstallOperationStatus) error {
	if err := validateLifecycleInstallOperationStatus(status, request); err != nil {
		return err
	}
	if status.epoch != expected.epoch || !status.notAfter.Equal(expected.notAfter) {
		return errors.New("control-plane lifecycle install continuation changed the exact epoch or immutable deadline")
	}
	if status.heartbeatAt.Before(expected.heartbeatAt) {
		return errors.New("control-plane lifecycle install continuation moved heartbeat_at backwards")
	}
	if status.state == lifecycleInstallActive && !status.serverTime.Before(status.notAfter) {
		return errors.New("control-plane lifecycle install continuation reports active authority at or after its hard deadline")
	}
	if status.state == lifecycleInstallCompleted && status.completedAt != nil && status.completedAt.After(status.notAfter) {
		return errors.New("control-plane lifecycle install completion occurred after its hard deadline")
	}
	return nil
}

func validateLifecycleInstallState(status lifecycleInstallOperationStatus, expected lifecycleInstallOperationState) error {
	if status.state != expected {
		return fmt.Errorf("lifecycle install operation is %q, expected %q", status.state, expected)
	}
	switch expected {
	case lifecycleInstallActive:
		if status.abortRequestedAt != nil || status.releasedAt != nil || status.completedAt != nil || status.takenOverAt != nil || status.abortedAt != nil {
			return errors.New("active lifecycle install operation contains terminal or abort metadata")
		}
	case lifecycleInstallReleased:
		if status.releasedAt == nil || status.releasedAt.IsZero() {
			return errors.New("released lifecycle install operation lacks released_at")
		}
	case lifecycleInstallCompleted:
		if status.completedAt == nil || status.completedAt.IsZero() {
			return errors.New("completed lifecycle install operation lacks completed_at")
		}
	case lifecycleInstallAborting:
		if status.abortRequestedAt == nil || status.abortRequestedAt.IsZero() || status.takenOverAt == nil || status.takenOverAt.IsZero() {
			return errors.New("aborting lifecycle install operation lacks abort request or takeover timestamps")
		}
	case lifecycleInstallAborted:
		if status.abortedAt == nil || status.abortedAt.IsZero() {
			return errors.New("aborted lifecycle install operation lacks aborted_at")
		}
	}
	return nil
}

type lifecycleInstallAuthority struct {
	cp               lifecycleInstallControlPlane
	orgID            string
	begin            lifecycleInstallBeginRequest
	cas              lifecycleInstallCASRequest
	status           lifecycleInstallOperationStatus
	anchor           lifecycleAnchorMetadata
	deadlines        lifecycleInstallDeadlines
	helmTimeout      time.Duration
	requestedSeconds int
}

func validCanonicalOperationID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

func validCanonicalSHA256Digest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	return value == strings.ToLower(value) && hexRE.MatchString(strings.TrimPrefix(value, "sha256:"))
}

func proveExactGatewayObjectsAbsent(ctx context.Context, deps k8sDeps, o installOptions, pvcClaim string) error {
	releases, err := listHelmReleases(ctx, deps.runner, o.kubeContext, o.namespace, o.release)
	if err != nil {
		return err
	}
	if len(releases) != 0 {
		return fmt.Errorf("gateway release %q still exists", o.release)
	}
	selector := "app.kubernetes.io/name=tunnex-gateway,app.kubernetes.io/instance=" + o.release
	workloads, err := runChecked(ctx, deps.runner, "prove exact gateway workloads absent", k8sCommand{
		name: "kubectl", args: kubectlArgs(o.kubeContext, "get", "deployments,statefulsets,daemonsets,jobs,pods,services", "--namespace", o.namespace, "--selector", selector, "--ignore-not-found=true", "--output", "name"),
	})
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(workloads.stdout)) != "" {
		return fmt.Errorf("gateway release %q still has exact labeled workloads", o.release)
	}
	if pvcClaim != "" {
		mountedBy, mountErr := claimMountedByLivePod(ctx, deps.runner, o.kubeContext, o.namespace, pvcClaim)
		if mountErr != nil {
			return mountErr
		}
		if mountedBy != "" {
			return fmt.Errorf("gateway state claim %q is still mounted by %s", pvcClaim, mountedBy)
		}
	}
	return nil
}

func proveGatewayReleaseAndWorkloadsAbsent(ctx context.Context, deps k8sDeps, o installOptions, expectedAnchor lifecycleAnchorMetadata, pvcClaim string) error {
	if err := proveExactGatewayObjectsAbsent(ctx, deps, o, pvcClaim); err != nil {
		return err
	}
	actual, err := getLifecycleAnchorMetadata(ctx, deps.runner, o.kubeContext, o.namespace, expectedAnchor.name)
	if err != nil {
		return err
	}
	if actual == nil || actual.uid != expectedAnchor.uid || actual.resourceVersion != expectedAnchor.resourceVersion {
		return errors.New("lifecycle anchor changed during release/workload absence proof")
	}
	return validateExactLifecycleAnchorReadback(expectedAnchor, *actual, o.release, false)
}

func reconcileLifecycleAbortRelease(ctx context.Context, deps k8sDeps, o abortInstallOptions, anchor lifecycleAnchorMetadata, release *helmReleaseSummary, pvcClaim string) error {
	install := installOptions{release: o.release, namespace: o.namespace, kubeContext: o.kubeContext}
	if release != nil {
		revision, err := strconv.Atoi(release.Revision)
		if err != nil || revision <= 0 {
			return fmt.Errorf("current Helm revision %q is invalid", release.Revision)
		}
		if err := requireAbortableZeroTouchRevision(ctx, deps.runner, releaseOptions{release: o.release, namespace: o.namespace, kubeContext: o.kubeContext, timeout: o.timeout}, *release, revision); err != nil {
			return err
		}
		helmArgs := []string{"uninstall", o.release, "--namespace", o.namespace, "--wait", "--timeout", o.timeout}
		helmArgs = appendHelmContext(helmArgs, o.kubeContext)
		if _, err := runChecked(ctx, deps.runner, "reconcile exact gateway release during lifecycle abort takeover", k8sCommand{name: "helm", args: helmArgs}); err != nil {
			return err
		}
	}
	return proveGatewayReleaseAndWorkloadsAbsent(ctx, deps, install, anchor, pvcClaim)
}

func proveAbsentExpiredLifecycleOperationRecovery(ctx context.Context, deps k8sDeps, prepared preparedInstall, persisted lifecycleAnchorMetadata) error {
	if !prepared.state.retrySecret {
		return errors.New("typed absent-after-expiry recovery requires the exact owner-bound expired bootstrap Secret")
	}
	secretName := prepared.options.release + "-bootstrap"
	secret, err := getBootstrapSecretMetadata(ctx, deps.runner, prepared.options.kubeContext, prepared.options.namespace, secretName)
	if err != nil {
		return err
	}
	if secret == nil {
		return errors.New("typed absent-after-expiry recovery bootstrap Secret disappeared")
	}
	if err := validateBootstrapSecretAnchor(*secret, persisted); err != nil {
		return err
	}
	state := prepared.state
	if secret.uid != state.secretUID || secret.resourceVersion != state.secretResourceVersion ||
		secret.lifecycleClaim != state.secretLifecycleClaim || secret.requestID != state.secretRequestID ||
		secret.generation != state.secretGeneration || !secret.expiresAt.Equal(state.secretExpiresAt) ||
		secret.ownerAPIVersion != state.secretOwnerAPIVersion || secret.ownerKind != state.secretOwnerKind ||
		secret.ownerName != state.secretOwnerName || secret.ownerUID != state.secretOwnerUID ||
		secret.lifecycleClaim != persisted.lifecycleClaim || secret.requestID != persisted.requestID ||
		secret.generation != persisted.generation || !secret.expiresAt.Equal(persisted.expiresAt) {
		return errors.New("typed absent-after-expiry recovery bootstrap Secret changed after approval")
	}

	claim := prepared.plan.Storage.Claim
	pvc, err := findPVC(ctx, deps.runner, prepared.options.kubeContext, prepared.options.namespace, claim)
	if err != nil {
		return err
	}
	if !state.pvcExists {
		if pvc != nil {
			return errors.New("typed absent-after-expiry recovery found a retained PVC that was absent at approval")
		}
	} else {
		if pvc == nil {
			return errors.New("typed absent-after-expiry recovery retained PVC disappeared")
		}
		if err := validateRetainedPVCMetadata(*pvc, claim, prepared.options.release, prepared.options.namespace); err != nil {
			return err
		}
		organizationID, lifecycleClaim, present, provenanceErr := exactLifecycleProvenance(*pvc)
		if provenanceErr != nil {
			return provenanceErr
		}
		if !present || organizationID != persisted.orgID || lifecycleClaim != persisted.lifecycleClaim {
			return errors.New("typed absent-after-expiry recovery PVC provenance differs from the persisted lifecycle anchor")
		}
		storageClass := ""
		if pvc.Spec.StorageClassName != nil {
			storageClass = *pvc.Spec.StorageClassName
		}
		if pvc.Metadata.UID != state.pvcUID || pvc.Metadata.ResourceVersion != state.pvcResourceVersion ||
			pvc.Spec.VolumeName != state.pvcVolumeName || pvc.Status.Phase != state.pvcPhase || storageClass != state.pvcStorageClass {
			return errors.New("typed absent-after-expiry recovery retained PVC identity changed after approval")
		}
	}
	return proveGatewayReleaseAndWorkloadsAbsent(ctx, deps, prepared.options, persisted, claim)
}

func reconcileExpiredLifecycleInstallBeforeRemint(ctx context.Context, deps k8sDeps, prepared preparedInstall, persisted lifecycleAnchorMetadata) error {
	cp, ok := prepared.cp.(lifecycleInstallControlPlane)
	if !ok {
		return errors.New("control-plane client does not support expired lifecycle install reconciliation")
	}
	begin, err := lifecycleInstallBeginFromAnchor(persisted)
	if err != nil {
		return err
	}
	status, err := cp.BeginLifecycleInstall(ctx, prepared.org.id, begin)
	if err != nil {
		if errors.Is(err, errLifecycleInstallOperationAbsentAfterExpiry) {
			return proveAbsentExpiredLifecycleOperationRecovery(ctx, deps, prepared, persisted)
		}
		return fmt.Errorf("refresh expired lifecycle install operation before remint: %w", err)
	}
	if err := validateLifecycleInstallOperationStatus(status, begin); err != nil {
		return err
	}
	if persisted.installOperationEpoch > 0 && (status.epoch != persisted.installOperationEpoch || !status.notAfter.Equal(persisted.installOperationNotAfter)) {
		return errors.New("expired lifecycle install operation epoch/deadline differs from the persisted anchor")
	}
	switch status.state {
	case lifecycleInstallExpired:
		released, releaseErr := cp.ReleaseLifecycleInstall(ctx, prepared.org.id, lifecycleInstallCASFromStatus(status))
		if releaseErr != nil {
			return fmt.Errorf("release expired lifecycle install operation before remint: %w", releaseErr)
		}
		if err := validateLifecycleInstallOperationContinuation(released, begin, status); err != nil {
			return err
		}
		if err := validateLifecycleInstallState(released, lifecycleInstallReleased); err != nil {
			return err
		}
		status = released
	case lifecycleInstallReleased:
		if err := validateLifecycleInstallState(status, lifecycleInstallReleased); err != nil {
			return err
		}
	case lifecycleInstallActive:
		return errors.New("expired bootstrap credential still has an active lifecycle install holder; no remint was attempted")
	case lifecycleInstallAbortRequested, lifecycleInstallAborting, lifecycleInstallAborted:
		return errors.New("expired bootstrap credential has a durable lifecycle install abort; resume abort-install instead of reminting")
	case lifecycleInstallCompleted:
		return errors.New("expired bootstrap credential belongs to a completed lifecycle install; resume exact post-install cleanup instead of reminting")
	default:
		return fmt.Errorf("expired bootstrap credential has unrecoverable lifecycle install operation state %q", status.state)
	}
	if status.abortRequestedAt != nil {
		return errors.New("released lifecycle install operation has a durable abort request; resume abort-install instead of reminting")
	}
	return proveGatewayReleaseAndWorkloadsAbsent(ctx, deps, prepared.options, persisted, prepared.plan.Storage.Claim)
}

func prepareLifecycleInstallAuthority(ctx context.Context, deps k8sDeps, prepared preparedInstall, anchor lifecycleAnchorMetadata) (lifecycleInstallAuthority, error) {
	cp, ok := prepared.cp.(lifecycleInstallControlPlane)
	if !ok {
		return lifecycleInstallAuthority{}, errors.New("control-plane client does not support fenced lifecycle install operations")
	}
	helmTimeout, requestedSeconds, err := lifecycleInstallBudget(prepared.options.timeout)
	if err != nil {
		return lifecycleInstallAuthority{}, err
	}
	intentPrepared := prepared
	intentPrepared.anchor = anchor
	_, intentDigest, err := computeLifecycleInstallIntent(intentPrepared)
	if err != nil {
		return lifecycleInstallAuthority{}, fmt.Errorf("recompute exact lifecycle install intent: %w", err)
	}
	if prepared.installIntentDigest == "" || prepared.plan.InstallIntentDigest != prepared.installIntentDigest || intentDigest != prepared.installIntentDigest {
		return lifecycleInstallAuthority{}, errors.New("lifecycle install intent changed after approval; no Helm mutation was authorized")
	}
	if anchor.state != "acknowledged" && anchor.state != "installing" {
		return lifecycleInstallAuthority{}, fmt.Errorf("lifecycle anchor is %q, expected acknowledged or installing", anchor.state)
	}
	resumingInstalling := anchor.state == "installing"
	if anchor.installOperationID == "" {
		if anchor.state != "acknowledged" || anchor.installOperationEpoch != 0 || anchor.installOperationDurationSeconds != 0 || !anchor.installOperationNotAfter.IsZero() ||
			anchor.installIntentDigest != "" || anchor.releaseNamespace != "" || anchor.releaseName != "" {
			return lifecycleInstallAuthority{}, errors.New("lifecycle anchor contains partial install-operation metadata")
		}
		operationID := deps.newOperationID()
		if !validCanonicalOperationID(operationID) || operationID == anchor.lifecycleClaim || operationID == anchor.requestID {
			return lifecycleInstallAuthority{}, errors.New("could not allocate a fresh canonical lifecycle install operation UUID")
		}
		anchor.installOperationID = operationID
		anchor.installOperationDurationSeconds = requestedSeconds
		anchor.installIntentDigest = intentDigest
		anchor.releaseNamespace = prepared.options.namespace
		anchor.releaseName = prepared.options.release
		anchor, err = updateLifecycleAnchor(ctx, deps, prepared.options, anchor)
		if err != nil {
			return lifecycleInstallAuthority{}, fmt.Errorf("persist lifecycle install operation identity before Begin: %w", err)
		}
	} else {
		if !validCanonicalOperationID(anchor.installOperationID) || anchor.installIntentDigest != intentDigest ||
			anchor.installOperationDurationSeconds != requestedSeconds || anchor.releaseNamespace != prepared.options.namespace || anchor.releaseName != prepared.options.release {
			return lifecycleInstallAuthority{}, errors.New("persisted lifecycle install operation is bound to different approved inputs")
		}
		if anchor.state == "acknowledged" && (anchor.installOperationEpoch != 0 || !anchor.installOperationNotAfter.IsZero()) {
			return lifecycleInstallAuthority{}, errors.New("pre-Begin lifecycle anchor contains an epoch or deadline")
		}
		if anchor.state == "installing" && (anchor.installOperationEpoch <= 0 || anchor.installOperationNotAfter.IsZero()) {
			return lifecycleInstallAuthority{}, errors.New("installing lifecycle anchor lacks its exact epoch or deadline")
		}
	}
	begin := lifecycleInstallBeginRequest{
		claim: anchor.lifecycleClaim, expectedGeneration: anchor.generation, requestID: anchor.requestID,
		operationID: anchor.installOperationID, releaseNamespace: prepared.options.namespace, releaseName: prepared.options.release,
		installIntentDigest: intentDigest, requestedDurationSeconds: requestedSeconds,
	}
	requestStart := deps.now()
	status, err := cp.BeginLifecycleInstall(ctx, prepared.org.id, begin)
	if err != nil {
		return lifecycleInstallAuthority{}, fmt.Errorf("begin or resume lifecycle install operation: %w", err)
	}
	if err := validateLifecycleInstallOperationStatus(status, begin); err != nil {
		return lifecycleInstallAuthority{}, err
	}
	cas := lifecycleInstallCASFromStatus(status)
	releaseExact := func() (lifecycleInstallOperationStatus, error) {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		released, releaseErr := cp.ReleaseLifecycleInstall(cleanupCtx, prepared.org.id, cas)
		if releaseErr == nil {
			releaseErr = validateLifecycleInstallOperationContinuation(released, begin, status)
		}
		if releaseErr == nil {
			releaseErr = validateLifecycleInstallState(released, lifecycleInstallReleased)
		}
		return released, releaseErr
	}
	releaseOnFailure := func(cause error) (lifecycleInstallAuthority, error) {
		_, releaseErr := releaseExact()
		return lifecycleInstallAuthority{}, errors.Join(cause, releaseErr)
	}
	if status.state == lifecycleInstallExpired {
		status, err = releaseExact()
		if err != nil {
			return lifecycleInstallAuthority{}, fmt.Errorf("release expired lifecycle install operation before recovery: %w", err)
		}
	}
	if status.state == lifecycleInstallReleased {
		if status.abortRequestedAt != nil {
			return lifecycleInstallAuthority{}, errors.New("released lifecycle install operation has a durable abort request; resume abort-install")
		}
		if err := proveGatewayReleaseAndWorkloadsAbsent(ctx, deps, prepared.options, anchor, prepared.plan.Storage.Claim); err != nil {
			return lifecycleInstallAuthority{}, fmt.Errorf("re-prove exact release/workload absence before rotating released install operation: %w", err)
		}
		operationID := deps.newOperationID()
		if !validCanonicalOperationID(operationID) || operationID == anchor.installOperationID || operationID == anchor.lifecycleClaim || operationID == anchor.requestID {
			return lifecycleInstallAuthority{}, errors.New("could not allocate a distinct lifecycle install operation UUID for released-operation recovery")
		}
		anchor.state = "acknowledged"
		anchor.installOperationID = operationID
		anchor.installOperationEpoch = 0
		anchor.installOperationDurationSeconds = requestedSeconds
		anchor.installOperationNotAfter = time.Time{}
		anchor.installIntentDigest = intentDigest
		anchor.releaseNamespace = prepared.options.namespace
		anchor.releaseName = prepared.options.release
		anchor, err = updateLifecycleAnchor(ctx, deps, prepared.options, anchor)
		if err != nil {
			return lifecycleInstallAuthority{}, fmt.Errorf("CAS-rotate released lifecycle install operation: %w", err)
		}
		begin.operationID = operationID
		resumingInstalling = false
		requestStart = deps.now()
		status, err = cp.BeginLifecycleInstall(ctx, prepared.org.id, begin)
		if err != nil {
			return lifecycleInstallAuthority{}, fmt.Errorf("begin rotated lifecycle install operation: %w", err)
		}
		if err := validateLifecycleInstallOperationStatus(status, begin); err != nil {
			return lifecycleInstallAuthority{}, err
		}
		cas = lifecycleInstallCASFromStatus(status)
	}
	if status.state != lifecycleInstallActive {
		if status.state == lifecycleInstallAbortRequested {
			return lifecycleInstallAuthority{}, errors.New("lifecycle install abort was requested before Helm; the active holder must release and abort-install must resume")
		}
		return lifecycleInstallAuthority{}, fmt.Errorf("lifecycle install operation cannot mutate Helm from state %q", status.state)
	}
	if err := validateLifecycleInstallState(status, lifecycleInstallActive); err != nil {
		return lifecycleInstallAuthority{}, err
	}
	deadlines, err := deriveLifecycleInstallDeadlines(requestStart, status, helmTimeout)
	if err != nil {
		return lifecycleInstallAuthority{}, err
	}
	if resumingInstalling {
		return lifecycleInstallAuthority{}, fmt.Errorf("lifecycle install operation %s is already held by the invocation that CAS-mirrored epoch %d; this invocation will not rerun or release its Helm authority", anchor.installOperationID, anchor.installOperationEpoch)
	}
	desired := anchor
	desired.state = "installing"
	desired.installOperationEpoch = status.epoch
	desired.installOperationNotAfter = status.notAfter
	desired.installIntentDigest = intentDigest
	desired.releaseNamespace = status.releaseNamespace
	desired.releaseName = status.releaseName
	if anchor.state == "acknowledged" {
		updated, updateErr := updateLifecycleAnchor(ctx, deps, prepared.options, desired)
		if updateErr != nil {
			actual, readErr := getLifecycleAnchorMetadata(ctx, deps.runner, prepared.options.kubeContext, prepared.options.namespace, desired.name)
			var winnerReadbackErr error
			if readErr == nil && actual != nil && actual.uid == desired.uid {
				winner := desired
				winner.resourceVersion = actual.resourceVersion
				winnerReadbackErr = validateExactLifecycleAnchorReadback(winner, *actual, prepared.options.release, false)
				if winnerReadbackErr == nil {
					return lifecycleInstallAuthority{}, errors.New("another invocation won the lifecycle anchor CAS and owns this Helm authority; this invocation did not release or mutate it")
				}
			} else if readErr == nil {
				winnerReadbackErr = errors.New("lifecycle anchor CAS failure readback was absent or changed UID")
			}
			return lifecycleInstallAuthority{}, errors.Join(fmt.Errorf("CAS-mirror lifecycle install authority before Helm: %w", updateErr), readErr, winnerReadbackErr)
		}
		desired = updated
	} else if anchor.installOperationEpoch != status.epoch || !anchor.installOperationNotAfter.Equal(status.notAfter) {
		return releaseOnFailure(errors.New("installing lifecycle anchor does not mirror the exact control-plane epoch and deadline"))
	}
	actual, err := getLifecycleAnchorMetadata(ctx, deps.runner, prepared.options.kubeContext, prepared.options.namespace, desired.name)
	if err != nil {
		return releaseOnFailure(fmt.Errorf("read lifecycle install anchor before Helm: %w", err))
	}
	if actual == nil || actual.uid != desired.uid || actual.resourceVersion != desired.resourceVersion {
		return releaseOnFailure(errors.New("lifecycle install anchor disappeared or changed before Helm"))
	}
	if err := validateExactLifecycleAnchorReadback(desired, *actual, prepared.options.release, false); err != nil {
		return releaseOnFailure(fmt.Errorf("prove exact lifecycle install anchor before Helm: %w", err))
	}
	return lifecycleInstallAuthority{
		cp: cp, orgID: prepared.org.id, begin: begin, cas: cas, status: status, anchor: desired,
		deadlines: deadlines, helmTimeout: helmTimeout, requestedSeconds: requestedSeconds,
	}, nil
}

func (a lifecycleInstallAuthority) release(ctx context.Context) error {
	released, err := a.cp.ReleaseLifecycleInstall(ctx, a.orgID, a.cas)
	if err != nil {
		return err
	}
	if err := validateLifecycleInstallOperationContinuation(released, a.begin, a.status); err != nil {
		return err
	}
	return validateLifecycleInstallState(released, lifecycleInstallReleased)
}

func (a lifecycleInstallAuthority) complete(ctx context.Context) error {
	completed, err := a.cp.CompleteLifecycleInstall(ctx, a.orgID, a.cas)
	if err != nil {
		return err
	}
	if err := validateLifecycleInstallOperationContinuation(completed, a.begin, a.status); err != nil {
		return err
	}
	return validateLifecycleInstallState(completed, lifecycleInstallCompleted)
}

// reconcileLifecycleInstallCompleteError resolves the ambiguous window after a
// Complete request begins. A lost durable 200 is treated as success. Any exact
// nonterminal authority is promptly released so a recorded abort need not wait
// for the hard deadline. An unreadable, foreign, or taken-over operation is
// left untouched with the Kubernetes recovery metadata intact.
func reconcileLifecycleInstallCompleteError(ctx context.Context, authority lifecycleInstallAuthority) (bool, error) {
	status, err := authority.cp.BeginLifecycleInstall(ctx, authority.orgID, authority.begin)
	if err != nil {
		return false, fmt.Errorf("refresh lifecycle install operation after ambiguous Complete: %w", err)
	}
	if err := validateLifecycleInstallOperationStatus(status, authority.begin); err != nil {
		return false, err
	}
	if status.epoch != authority.status.epoch || !status.notAfter.Equal(authority.status.notAfter) {
		return false, errors.New("lifecycle install operation changed epoch or deadline after ambiguous Complete; recovery metadata was retained")
	}
	if status.state == lifecycleInstallCompleted {
		if err := validateLifecycleInstallOperationContinuation(status, authority.begin, authority.status); err != nil {
			return false, err
		}
		return true, validateLifecycleInstallState(status, lifecycleInstallCompleted)
	}
	if status.state == lifecycleInstallReleased {
		if err := validateLifecycleInstallOperationContinuation(status, authority.begin, authority.status); err != nil {
			return false, err
		}
		return false, validateLifecycleInstallState(status, lifecycleInstallReleased)
	}
	if status.state != lifecycleInstallActive && status.state != lifecycleInstallAbortRequested && status.state != lifecycleInstallExpired {
		return false, fmt.Errorf("lifecycle install operation is %q after ambiguous Complete; it was not released", status.state)
	}
	released, err := authority.cp.ReleaseLifecycleInstall(ctx, authority.orgID, lifecycleInstallCASFromStatus(status))
	if err != nil {
		return false, fmt.Errorf("release exact lifecycle install authority after refused Complete: %w", err)
	}
	if err := validateLifecycleInstallOperationContinuation(released, authority.begin, status); err != nil {
		return false, err
	}
	return false, validateLifecycleInstallState(released, lifecycleInstallReleased)
}

// reconcileLifecycleInstallFailure releases authority only after this holder
// has stopped all Helm mutation. Before Helm starts, or after an abort/hard
// deadline has stopped the holder, Release is safe immediately. Every other
// post-Helm error is ambiguous: exact release/workload/mount absence must be
// proven first, otherwise the bounded CP authority and Kubernetes recovery
// metadata are deliberately retained for resume/abort reconciliation.
func reconcileLifecycleInstallFailure(ctx context.Context, deps k8sDeps, authority lifecycleInstallAuthority, prepared preparedInstall, helmStarted, holderStopped bool) error {
	if helmStarted && !holderStopped {
		recoveryPrepared := prepared
		recoveryPrepared.anchor = authority.anchor
		readyErr := verifyGateway(ctx, deps.runner, prepared.options.kubeContext, prepared.options.namespace, prepared.options.release,
			prepared.options.serviceType, prepared.options.endpoint, prepared.options.nodePort, prepared.options.timeout)
		if readyErr == nil {
			readyErr = verifyInstalledGatewayState(ctx, deps.runner, recoveryPrepared)
		}
		if readyErr == nil {
			readyErr = verifyLifecycleConsumed(ctx, recoveryPrepared, authority.anchor)
		}
		if readyErr == nil {
			readyErr = completeRecoveredLifecycleInstall(ctx, deps, recoveryPrepared, authority)
			if readyErr != nil {
				completed, reconcileErr := reconcileLifecycleInstallCompleteError(ctx, authority)
				if completed {
					return nil
				}
				readyErr = errors.Join(readyErr, reconcileErr)
			} else {
				return nil
			}
		}
		if err := proveGatewayReleaseAndWorkloadsAbsent(ctx, deps, prepared.options, authority.anchor, prepared.plan.Storage.Claim); err != nil {
			return fmt.Errorf("lifecycle install authority was retained because Helm had started, exact ready/consumed completion failed (%v), and exact release/workload absence was not proven: %w", readyErr, err)
		}
	}
	if err := authority.release(ctx); err != nil {
		return fmt.Errorf("release exact lifecycle install authority after stopped holder: %w", err)
	}
	return nil
}

func (a lifecycleInstallAuthority) proveAnchor(ctx context.Context, deps k8sDeps, prepared preparedInstall) error {
	intentPrepared := prepared
	intentPrepared.anchor = a.anchor
	_, digest, err := computeLifecycleInstallIntent(intentPrepared)
	if err != nil {
		return err
	}
	if digest != a.begin.installIntentDigest || digest != a.anchor.installIntentDigest {
		return errors.New("lifecycle install intent changed immediately before Helm")
	}
	actual, err := getLifecycleAnchorMetadata(ctx, deps.runner, prepared.options.kubeContext, prepared.options.namespace, a.anchor.name)
	if err != nil {
		return err
	}
	if actual == nil || actual.uid != a.anchor.uid || actual.resourceVersion != a.anchor.resourceVersion {
		return errors.New("lifecycle install anchor disappeared or changed immediately before Helm")
	}
	return validateExactLifecycleAnchorReadback(a.anchor, *actual, prepared.options.release, false)
}

// refreshRecoveredLifecycleInstallAuthority refreshes the exact persisted
// operation before recovery reads any live release or identity state. Active
// recovery uses the control-plane DB clock to derive a local monotonic hard
// deadline; a terminal Completed operation needs no renewed mutation lease.
func refreshRecoveredLifecycleInstallAuthority(ctx context.Context, deps k8sDeps, prepared preparedInstall) (lifecycleInstallAuthority, bool, error) {
	anchor := prepared.anchor
	if anchor.state != "installing" || !validCanonicalOperationID(anchor.installOperationID) || anchor.installOperationEpoch <= 0 ||
		anchor.installOperationDurationSeconds <= 0 || anchor.installOperationDurationSeconds > 900 || anchor.installOperationNotAfter.IsZero() ||
		!validCanonicalSHA256Digest(anchor.installIntentDigest) || anchor.releaseNamespace != prepared.options.namespace || anchor.releaseName != prepared.options.release {
		return lifecycleInstallAuthority{}, false, errors.New("ready gateway recovery lacks an exact persisted lifecycle install operation")
	}
	cp, ok := prepared.cp.(lifecycleInstallControlPlane)
	if !ok {
		return lifecycleInstallAuthority{}, false, errors.New("control-plane client does not support lifecycle install completion recovery")
	}
	begin := lifecycleInstallBeginRequest{
		claim: anchor.lifecycleClaim, expectedGeneration: anchor.generation, requestID: anchor.requestID,
		operationID: anchor.installOperationID, releaseNamespace: anchor.releaseNamespace, releaseName: anchor.releaseName,
		installIntentDigest: anchor.installIntentDigest, requestedDurationSeconds: anchor.installOperationDurationSeconds,
	}
	requestStart := deps.now()
	status, err := cp.BeginLifecycleInstall(ctx, prepared.org.id, begin)
	if err != nil {
		return lifecycleInstallAuthority{}, false, fmt.Errorf("refresh lifecycle install operation before cleanup: %w", err)
	}
	if err := validateLifecycleInstallOperationStatus(status, begin); err != nil {
		return lifecycleInstallAuthority{}, false, err
	}
	if status.epoch != anchor.installOperationEpoch || !status.notAfter.Equal(anchor.installOperationNotAfter) {
		return lifecycleInstallAuthority{}, false, errors.New("ready gateway recovery operation epoch/deadline differs from the exact lifecycle anchor")
	}
	if err := validateLifecycleInstallOperationContinuation(status, begin, status); err != nil {
		return lifecycleInstallAuthority{}, false, err
	}
	if status.state == lifecycleInstallCompleted {
		if err := validateLifecycleInstallState(status, lifecycleInstallCompleted); err != nil {
			return lifecycleInstallAuthority{}, false, err
		}
		return lifecycleInstallAuthority{
			cp: cp, orgID: prepared.org.id, begin: begin, cas: lifecycleInstallCASFromStatus(status), status: status,
			anchor: anchor, requestedSeconds: anchor.installOperationDurationSeconds,
		}, true, nil
	}
	if status.state != lifecycleInstallActive {
		return lifecycleInstallAuthority{}, false, fmt.Errorf("ready gateway lifecycle install operation is %q; recovery metadata was retained and abort-install must reconcile it", status.state)
	}
	if err := validateLifecycleInstallState(status, lifecycleInstallActive); err != nil {
		return lifecycleInstallAuthority{}, false, err
	}
	remaining := status.notAfter.Sub(status.serverTime)
	if remaining <= 0 {
		return lifecycleInstallAuthority{}, false, errors.New("ready gateway lifecycle install authority has expired; recovery metadata was retained")
	}
	approved := time.Duration(anchor.installOperationDurationSeconds) * time.Second
	if remaining > approved {
		return lifecycleInstallAuthority{}, false, fmt.Errorf("ready gateway lifecycle install authority %s exceeds its exact approved %s duration", remaining, approved)
	}
	authority := lifecycleInstallAuthority{
		cp: cp, orgID: prepared.org.id, begin: begin, cas: lifecycleInstallCASFromStatus(status), status: status,
		anchor: anchor, deadlines: lifecycleInstallDeadlines{hard: requestStart.Add(remaining)}, requestedSeconds: anchor.installOperationDurationSeconds,
	}
	return authority, false, nil
}

// completeRecoveredLifecycleInstall performs the final Kubernetes anchor
// re-proof and exact CP Complete while the caller's recovered hard-deadline
// context remains authoritative.
func completeRecoveredLifecycleInstall(ctx context.Context, deps k8sDeps, prepared preparedInstall, authority lifecycleInstallAuthority) error {
	anchor := authority.anchor
	actual, err := getLifecycleAnchorMetadata(ctx, deps.runner, prepared.options.kubeContext, prepared.options.namespace, anchor.name)
	if err != nil {
		return err
	}
	if actual == nil || actual.uid != anchor.uid || actual.resourceVersion != anchor.resourceVersion {
		return errors.New("lifecycle install anchor changed before recovered completion")
	}
	if err := validateExactLifecycleAnchorReadback(anchor, *actual, prepared.options.release, false); err != nil {
		return err
	}
	completed, err := authority.cp.CompleteLifecycleInstall(ctx, authority.orgID, authority.cas)
	if err != nil {
		return fmt.Errorf("complete recovered lifecycle install operation (result may be durable; rerun safely): %w", err)
	}
	if err := validateLifecycleInstallOperationContinuation(completed, authority.begin, authority.status); err != nil {
		return err
	}
	return validateLifecycleInstallState(completed, lifecycleInstallCompleted)
}

var (
	errLifecycleInstallDeadline       = errors.New("control-plane lifecycle install authority reached its hard deadline")
	errLifecycleInstallHelmDeadline   = errors.New("Helm reached its approved lifecycle timeout")
	errLifecycleInstallAbortRequested = errors.New("control-plane requested lifecycle install abort")
)

type lifecycleInstallMonitor struct {
	mutationCtx context.Context
	cancelPoll  context.CancelFunc
	done        <-chan error
	ticker      k8sTicker
}

func startLifecycleInstallMonitor(parent context.Context, deps k8sDeps, authority lifecycleInstallAuthority) (*lifecycleInstallMonitor, context.CancelFunc) {
	hardCtx, cancelHard := context.WithDeadlineCause(parent, authority.deadlines.hard, errLifecycleInstallDeadline)
	mutationCtx, cancelMutation := context.WithCancelCause(hardCtx)
	pollCtx, cancelPoll := context.WithCancel(hardCtx)
	ticker := deps.newTicker(lifecycleInstallHeartbeatInterval)
	done := make(chan error, 1)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-pollCtx.Done():
				if cause := context.Cause(hardCtx); cause != nil {
					cancelMutation(cause)
					done <- cause
					return
				}
				done <- nil
				return
			case <-ticker.C():
				status, err := authority.cp.HeartbeatLifecycleInstall(pollCtx, authority.orgID, authority.cas)
				if err != nil && pollCtx.Err() != nil && context.Cause(hardCtx) == nil {
					done <- nil
					return
				}
				if err == nil {
					err = validateLifecycleInstallOperationContinuation(status, authority.begin, authority.status)
				}
				if err == nil && status.state == lifecycleInstallActive {
					err = validateLifecycleInstallState(status, lifecycleInstallActive)
				}
				if err == nil && status.state == lifecycleInstallAbortRequested {
					err = errLifecycleInstallAbortRequested
				}
				if err == nil && status.state != lifecycleInstallActive {
					err = fmt.Errorf("lifecycle install authority changed to %q", status.state)
				}
				if err != nil {
					cancelMutation(err)
					done <- err
					return
				}
			}
		}
	}()
	return &lifecycleInstallMonitor{mutationCtx: mutationCtx, cancelPoll: cancelPoll, done: done, ticker: ticker}, cancelHard
}

func (m *lifecycleInstallMonitor) stop() error {
	if m == nil {
		return nil
	}
	m.cancelPoll()
	return <-m.done
}
