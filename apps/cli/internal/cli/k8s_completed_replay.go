package cli

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

type completedInstallReplay struct {
	operation lifecycleInstallOperationStatus
	claim     k8sLifecycleClaimStatus
}

func canonicalNonNilUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validateCompletedInstallReplay(replay completedInstallReplay, org k8sOrganization, o installOptions, state installState) error {
	operation := replay.operation
	claim := replay.claim
	if !canonicalNonNilUUID(org.id) || org.id != state.pvcOrganizationID || !canonicalNonNilUUID(state.pvcLifecycleClaim) {
		return errors.New("completed-install replay organization or PVC claim provenance is not one exact canonical identity")
	}
	if operation.claim != state.pvcLifecycleClaim || !canonicalNonNilUUID(operation.claim) || operation.generation <= 0 ||
		!canonicalNonNilUUID(operation.requestID) || !canonicalNonNilUUID(operation.operationID) || operation.epoch <= 0 ||
		operation.releaseNamespace != o.namespace || operation.releaseName != o.release || !validCanonicalSHA256Digest(operation.installIntentDigest) ||
		operation.requestedDurationSeconds <= 0 || operation.requestedDurationSeconds > int(maxLifecycleInstallLease/time.Second) ||
		operation.notAfter.IsZero() || operation.serverTime.IsZero() || operation.heartbeatAt.IsZero() {
		return errors.New("latest lifecycle install operation does not match the exact completed replay scope")
	}
	if operation.state != lifecycleInstallCompleted || operation.completedAt == nil || operation.completedAt.IsZero() || operation.completedAt.After(operation.notAfter) ||
		operation.abortRequestedAt != nil || operation.releasedAt != nil || operation.takenOverAt != nil || operation.abortedAt != nil {
		return errors.New("latest lifecycle install operation is not an exact unambiguous completed terminal operation")
	}
	if claim.claim != operation.claim || claim.state != "consumed" || claim.nodeName != o.nodeName || !canonicalNonNilUUID(claim.nodeID) ||
		claim.generation != operation.generation || claim.requestID != operation.requestID || !canonicalNonNilUUID(claim.requestID) ||
		claim.expiresAt.IsZero() || claim.consumedAt == nil || claim.consumedAt.IsZero() || claim.abortedAt != nil {
		return errors.New("control-plane lifecycle claim is not the exact consumed node identity bound to the completed operation")
	}
	return nil
}

func completedInstallReplayFingerprint(replay completedInstallReplay) string {
	operation := replay.operation
	claim := replay.claim
	timestamp := func(value *time.Time) string {
		if value == nil {
			return ""
		}
		return value.UTC().Format(time.RFC3339Nano)
	}
	return strings.Join([]string{
		operation.claim, strconv.Itoa(operation.generation), operation.requestID, operation.operationID,
		strconv.FormatInt(operation.epoch, 10), string(operation.state), operation.releaseNamespace, operation.releaseName,
		operation.installIntentDigest, strconv.Itoa(operation.requestedDurationSeconds), operation.notAfter.UTC().Format(time.RFC3339Nano),
		operation.heartbeatAt.UTC().Format(time.RFC3339Nano), timestamp(operation.abortRequestedAt), timestamp(operation.releasedAt),
		timestamp(operation.completedAt), timestamp(operation.takenOverAt), timestamp(operation.abortedAt),
		claim.claim, claim.state, claim.nodeName, strconv.Itoa(claim.generation), claim.requestID, claim.expiresAt.UTC().Format(time.RFC3339Nano),
		timestamp(claim.acknowledgedAt), timestamp(claim.consumedAt), timestamp(claim.abortedAt), claim.nodeID,
	}, "\x00")
}

func loadCompletedInstallReplay(ctx context.Context, cp k8sControlPlane, org k8sOrganization, o installOptions, state installState) (completedInstallReplay, error) {
	installCP, ok := cp.(lifecycleInstallControlPlane)
	if !ok {
		return completedInstallReplay{}, errors.New("control-plane client does not support token-blind completed-install replay")
	}
	operation, err := installCP.GetLatestLifecycleInstall(ctx, org.id, state.pvcLifecycleClaim)
	if err != nil {
		return completedInstallReplay{}, fmt.Errorf("read latest lifecycle install operation for anchorless replay: %w", err)
	}
	claim, err := cp.GetLifecycleClaimStatus(ctx, org.id, state.pvcLifecycleClaim)
	if err != nil {
		return completedInstallReplay{}, fmt.Errorf("read consumed lifecycle claim for anchorless replay: %w", err)
	}
	replay := completedInstallReplay{operation: operation, claim: claim}
	if err := validateCompletedInstallReplay(replay, org, o, state); err != nil {
		return completedInstallReplay{}, err
	}
	return replay, nil
}

func sameHelmRelease(actual, expected helmReleaseSummary) bool {
	return actual.Name == expected.Name && actual.Namespace == expected.Namespace && actual.Revision == expected.Revision &&
		actual.Updated == expected.Updated && actual.Status == expected.Status && actual.Chart == expected.Chart && actual.AppVersion == expected.AppVersion
}

func validateCompletedReplayPVC(pvc pvcView, prepared preparedInstall) error {
	state := prepared.state
	o := prepared.options
	if err := validateRetainedPVCMetadata(pvc, state.pvcName, o.release, o.namespace); err != nil {
		return err
	}
	if pvc.Status.Phase != "Bound" || pvc.Metadata.UID != state.pvcUID || pvc.Metadata.ResourceVersion != state.pvcResourceVersion || pvc.Spec.VolumeName != state.pvcVolumeName {
		return errors.New("completed-install replay retained PVC identity changed after approval")
	}
	organizationID, lifecycleClaim, present, err := exactLifecycleProvenance(pvc)
	if err != nil {
		return err
	}
	if !present || organizationID != state.pvcOrganizationID || lifecycleClaim != state.pvcLifecycleClaim {
		return errors.New("completed-install replay retained PVC provenance changed after approval")
	}
	if err := verifyPVCStorageClass(pvc, prepared.plan.Storage.Class); err != nil {
		return err
	}
	return nil
}

type completedReplayKubernetesProof struct {
	release            helmReleaseSummary
	deploymentUID      string
	deploymentVersion  string
	pvcUID             string
	pvcResourceVersion string
	volumeName         string
}

func proveCompletedReplayKubernetes(ctx context.Context, deps k8sDeps, prepared preparedInstall) (completedReplayKubernetesProof, error) {
	o := prepared.options
	state := prepared.state
	if state.resumeRelease.Status != "deployed" {
		return completedReplayKubernetesProof{}, fmt.Errorf("completed-install replay Helm status is %q, not deployed", state.resumeRelease.Status)
	}
	releases, err := listHelmReleases(ctx, deps.runner, o.kubeContext, o.namespace, o.release)
	if err != nil {
		return completedReplayKubernetesProof{}, err
	}
	if len(releases) != 1 || !sameHelmRelease(releases[0], state.resumeRelease) {
		return completedReplayKubernetesProof{}, errors.New("completed-install replay Helm release identity changed after approval")
	}
	if err := verifyGateway(ctx, deps.runner, o.kubeContext, o.namespace, o.release, o.serviceType, o.endpoint, o.nodePort, o.timeout); err != nil {
		return completedReplayKubernetesProof{}, err
	}
	deployment, err := getDeployment(ctx, deps.runner, o.kubeContext, o.namespace, o.release)
	if err != nil {
		return completedReplayKubernetesProof{}, err
	}
	if err := requireLiveZeroTouchContract(deployment.Metadata.Annotations[zeroTouchContractAnnotationKey]); err != nil {
		return completedReplayKubernetesProof{}, err
	}
	service, err := getService(ctx, deps.runner, o.kubeContext, o.namespace, o.release)
	if err != nil {
		return completedReplayKubernetesProof{}, err
	}
	if err := verifyPlannedGatewayInputs(deployment, service, o, ""); err != nil {
		return completedReplayKubernetesProof{}, err
	}
	revision, err := strconv.Atoi(state.resumeRelease.Revision)
	if err != nil || revision <= 0 {
		return completedReplayKubernetesProof{}, fmt.Errorf("completed-install replay Helm revision %q is invalid", state.resumeRelease.Revision)
	}
	if err := requireZeroTouchRevision(ctx, deps.runner, releaseOptions{release: o.release, namespace: o.namespace, kubeContext: o.kubeContext, timeout: o.timeout}, revision); err != nil {
		return completedReplayKubernetesProof{}, err
	}
	claim, err := deploymentClaim(deployment)
	if err != nil {
		return completedReplayKubernetesProof{}, err
	}
	if claim != state.pvcName {
		return completedReplayKubernetesProof{}, fmt.Errorf("completed-install replay Deployment mounts %q, expected exact retained claim %q", claim, state.pvcName)
	}
	pvc, err := getPVC(ctx, deps.runner, o.kubeContext, o.namespace, claim)
	if err != nil {
		return completedReplayKubernetesProof{}, err
	}
	if err := validateCompletedReplayPVC(pvc, prepared); err != nil {
		return completedReplayKubernetesProof{}, err
	}
	expectedRollout := rolloutRevision(prepared.completedReplay.operation.installIntentDigest)
	if deployment.Spec.Template.Metadata.Annotations["tunnex.io/rollout-revision"] != expectedRollout {
		return completedReplayKubernetesProof{}, fmt.Errorf("completed-install replay workload rollout revision does not derive from exact install intent %s", prepared.completedReplay.operation.installIntentDigest)
	}
	return completedReplayKubernetesProof{
		release: releases[0], deploymentUID: deployment.Metadata.UID, deploymentVersion: deployment.Metadata.ResourceVersion,
		pvcUID: pvc.Metadata.UID, pvcResourceVersion: pvc.Metadata.ResourceVersion, volumeName: pvc.Spec.VolumeName,
	}, nil
}

func runCompletedInstallReplay(ctx context.Context, deps k8sDeps, prepared preparedInstall) error {
	if prepared.completedReplay == nil || !prepared.state.completedReplay {
		return errors.New("completed-install replay plan lacks its exact terminal control-plane proof")
	}
	replay, err := loadCompletedInstallReplay(ctx, prepared.cp, prepared.org, prepared.options, prepared.state)
	if err != nil {
		return err
	}
	if completedInstallReplayFingerprint(replay) != completedInstallReplayFingerprint(*prepared.completedReplay) {
		return errors.New("completed lifecycle install operation or consumed claim changed after approval")
	}
	proof, err := proveCompletedReplayKubernetes(ctx, deps, prepared)
	if err != nil {
		return err
	}

	// Final read-only reproof closes the approval/readiness window. Nothing in
	// this path creates, replaces, deletes, remints, acknowledges, or Completes.
	finalReplay, err := loadCompletedInstallReplay(ctx, prepared.cp, prepared.org, prepared.options, prepared.state)
	if err != nil {
		return err
	}
	if completedInstallReplayFingerprint(finalReplay) != completedInstallReplayFingerprint(replay) {
		return errors.New("completed lifecycle install proof changed during final replay verification")
	}
	releases, err := listHelmReleases(ctx, deps.runner, prepared.options.kubeContext, prepared.options.namespace, prepared.options.release)
	if err != nil {
		return err
	}
	if len(releases) != 1 || !sameHelmRelease(releases[0], proof.release) {
		return errors.New("completed-install replay Helm release changed during final verification")
	}
	deployment, err := getDeployment(ctx, deps.runner, prepared.options.kubeContext, prepared.options.namespace, prepared.options.release)
	if err != nil {
		return err
	}
	if deployment.Metadata.UID != proof.deploymentUID || deployment.Metadata.ResourceVersion != proof.deploymentVersion ||
		deployment.Spec.Template.Metadata.Annotations["tunnex.io/rollout-revision"] != rolloutRevision(replay.operation.installIntentDigest) {
		return errors.New("completed-install replay Deployment changed during final verification")
	}
	pvc, err := getPVC(ctx, deps.runner, prepared.options.kubeContext, prepared.options.namespace, prepared.state.pvcName)
	if err != nil {
		return err
	}
	if err := validateCompletedReplayPVC(pvc, prepared); err != nil {
		return err
	}
	if pvc.Metadata.UID != proof.pvcUID || pvc.Metadata.ResourceVersion != proof.pvcResourceVersion || pvc.Spec.VolumeName != proof.volumeName {
		return errors.New("completed-install replay PVC changed during final verification")
	}
	secret, err := getBootstrapSecretMetadata(ctx, deps.runner, prepared.options.kubeContext, prepared.options.namespace, prepared.options.release+"-bootstrap")
	if err != nil {
		return err
	}
	if secret != nil {
		return errors.New("completed-install replay found a bootstrap Secret during final verification")
	}
	anchor, err := getLifecycleAnchorMetadata(ctx, deps.runner, prepared.options.kubeContext, prepared.options.namespace, prepared.options.release+"-lifecycle")
	if err != nil {
		return err
	}
	if anchor != nil {
		return errors.New("completed-install replay found a lifecycle anchor during final verification")
	}
	_, err = fmt.Fprintf(deps.out, "Gateway %q is already ready from completed lifecycle operation %s. No token, Helm release, Kubernetes object, or control-plane state was mutated.\n", prepared.options.release, replay.operation.operationID)
	return err
}
