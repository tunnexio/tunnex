package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const lifecycleAnchorMetadataJSONPath = `{.metadata.name}{"\t"}{.metadata.uid}{"\t"}{.metadata.resourceVersion}{"\t"}{.metadata.labels.app\.kubernetes\.io/name}{"\t"}{.metadata.labels.app\.kubernetes\.io/instance}{"\t"}{.metadata.labels.app\.kubernetes\.io/managed-by}{"\t"}{.immutable}{"\t"}{.metadata.annotations.tunnex\.io/organization-id}{"\t"}{.metadata.annotations.tunnex\.io/node-name}{"\t"}{.metadata.annotations.tunnex\.io/lifecycle-claim}{"\t"}{.metadata.annotations.tunnex\.io/lifecycle-request-id}{"\t"}{.metadata.annotations.tunnex\.io/lifecycle-expected-generation}{"\t"}{.metadata.annotations.tunnex\.io/lifecycle-generation}{"\t"}{.metadata.annotations.tunnex\.io/lifecycle-state}{"\t"}{.metadata.annotations.tunnex\.io/lifecycle-expires-at}{"\t"}{.metadata.annotations.tunnex\.io/install-operation-id}{"\t"}{.metadata.annotations.tunnex\.io/install-operation-epoch}{"\t"}{.metadata.annotations.tunnex\.io/install-operation-duration-seconds}{"\t"}{.metadata.annotations.tunnex\.io/install-operation-not-after}{"\t"}{.metadata.annotations.tunnex\.io/install-intent-digest}{"\t"}{.metadata.annotations.tunnex\.io/release-namespace}{"\t"}{.metadata.annotations.tunnex\.io/release-name}{"\n"}`

type lifecycleAnchorMetadata struct {
	name                            string
	uid                             string
	resourceVersion                 string
	appName                         string
	instance                        string
	managedBy                       string
	immutable                       bool
	orgID                           string
	nodeName                        string
	lifecycleClaim                  string
	requestID                       string
	expectedGeneration              int
	generation                      int
	state                           string
	expiresAt                       time.Time
	installOperationID              string
	installOperationEpoch           int64
	installOperationDurationSeconds int
	installOperationNotAfter        time.Time
	installIntentDigest             string
	releaseNamespace                string
	releaseName                     string
}

func getLifecycleAnchorMetadata(ctx context.Context, runner k8sRunner, kubeContext, namespace, name string) (*lifecycleAnchorMetadata, error) {
	result, err := runChecked(ctx, runner, "read lifecycle anchor metadata", k8sCommand{
		name: "kubectl", args: kubectlArgs(kubeContext, "get", "configmap", name, "--namespace", namespace, "--ignore-not-found=true", "--output", "jsonpath="+lifecycleAnchorMetadataJSONPath),
	})
	if err != nil {
		return nil, err
	}
	return parseLifecycleAnchorMetadata(string(result.stdout))
}

func parseLifecycleAnchorMetadata(line string) (*lifecycleAnchorMetadata, error) {
	line = strings.TrimSuffix(line, "\n")
	if strings.TrimSpace(line) == "" {
		return nil, nil
	}
	fields := strings.Split(line, "\t")
	if len(fields) != 22 || (fields[6] != "true" && fields[6] != "false") {
		return nil, errors.New("lifecycle anchor metadata response was malformed")
	}
	claim, claimErr := uuid.Parse(fields[9])
	requestID, requestErr := uuid.Parse(fields[10])
	orgID, orgErr := uuid.Parse(fields[7])
	expectedGeneration, expectedErr := strconv.Atoi(fields[11])
	generation, generationErr := strconv.Atoi(fields[12])
	operationEpoch, operationEpochErr := strconv.ParseInt(fields[16], 10, 64)
	operationDuration, operationDurationErr := strconv.Atoi(fields[17])
	if claimErr != nil || requestErr != nil || orgErr != nil || expectedErr != nil || generationErr != nil || operationEpochErr != nil || operationDurationErr != nil || expectedGeneration < 0 || generation < 0 || expectedGeneration > generation || operationEpoch < 0 || operationDuration < 0 || operationDuration > 900 {
		return nil, errors.New("lifecycle anchor identity or generation metadata was malformed")
	}
	expiresAt := time.Time{}
	if fields[14] != "" {
		var expiryErr error
		expiresAt, expiryErr = time.Parse(time.RFC3339Nano, fields[14])
		if expiryErr != nil {
			return nil, errors.New("lifecycle anchor expiry metadata was malformed")
		}
	}
	operationNotAfter := time.Time{}
	if fields[18] != "" {
		var deadlineErr error
		operationNotAfter, deadlineErr = time.Parse(time.RFC3339Nano, fields[18])
		if deadlineErr != nil {
			return nil, errors.New("lifecycle install operation deadline metadata was malformed")
		}
	}
	if fields[13] != "pending" && fields[13] != "issued" && fields[13] != "acknowledged" && fields[13] != "installing" && fields[13] != "aborting" {
		return nil, errors.New("lifecycle anchor state metadata was malformed")
	}
	return &lifecycleAnchorMetadata{
		name: fields[0], uid: fields[1], resourceVersion: fields[2], appName: fields[3], instance: fields[4], managedBy: fields[5], immutable: fields[6] == "true",
		orgID: orgID.String(), nodeName: fields[8], lifecycleClaim: claim.String(), requestID: requestID.String(), expectedGeneration: expectedGeneration,
		generation: generation, state: fields[13], expiresAt: expiresAt,
		installOperationID: fields[15], installOperationEpoch: operationEpoch, installOperationDurationSeconds: operationDuration, installOperationNotAfter: operationNotAfter,
		installIntentDigest: fields[19], releaseNamespace: fields[20], releaseName: fields[21],
	}, nil
}

func validateOwnedLifecycleAnchor(anchor lifecycleAnchorMetadata, expectedName, release string) error {
	if anchor.name != expectedName || anchor.appName != "tunnex-gateway-lifecycle" || anchor.instance != release || anchor.managedBy != "tunnex-lifecycle" {
		return fmt.Errorf("lifecycle anchor %q is not owned by Tunnex release %q", expectedName, release)
	}
	if anchor.uid == "" || anchor.resourceVersion == "" || !anchor.immutable {
		return fmt.Errorf("lifecycle anchor %q lacks immutable UID/resourceVersion ownership", expectedName)
	}
	return nil
}

func validateExactLifecycleAnchorReadback(desired, actual lifecycleAnchorMetadata, release string, replacing bool) error {
	if err := validateOwnedLifecycleAnchor(actual, desired.name, release); err != nil {
		return err
	}
	if replacing && (actual.uid != desired.uid || actual.resourceVersion == desired.resourceVersion) {
		return errors.New("lifecycle anchor UID changed or resourceVersion did not advance during CAS replacement")
	}
	if actual.name != desired.name || actual.appName != desired.appName || actual.instance != desired.instance || actual.managedBy != desired.managedBy || actual.immutable != desired.immutable ||
		actual.orgID != desired.orgID || actual.nodeName != desired.nodeName || actual.lifecycleClaim != desired.lifecycleClaim || actual.requestID != desired.requestID ||
		actual.expectedGeneration != desired.expectedGeneration || actual.generation != desired.generation || actual.state != desired.state || !actual.expiresAt.Equal(desired.expiresAt) ||
		actual.installOperationID != desired.installOperationID || actual.installOperationEpoch != desired.installOperationEpoch || actual.installOperationDurationSeconds != desired.installOperationDurationSeconds || !actual.installOperationNotAfter.Equal(desired.installOperationNotAfter) ||
		actual.installIntentDigest != desired.installIntentDigest || actual.releaseNamespace != desired.releaseNamespace || actual.releaseName != desired.releaseName {
		return errors.New("lifecycle anchor readback does not exactly match the approved claim/request/generation metadata")
	}
	return nil
}

func lifecycleAnchorManifest(namespace, name, release string, anchor lifecycleAnchorMetadata) ([]byte, error) {
	annotations := map[string]string{
		"tunnex.io/organization-id":                    anchor.orgID,
		"tunnex.io/node-name":                          anchor.nodeName,
		"tunnex.io/lifecycle-claim":                    anchor.lifecycleClaim,
		"tunnex.io/lifecycle-request-id":               anchor.requestID,
		"tunnex.io/lifecycle-expected-generation":      strconv.Itoa(anchor.expectedGeneration),
		"tunnex.io/lifecycle-generation":               strconv.Itoa(anchor.generation),
		"tunnex.io/lifecycle-state":                    anchor.state,
		"tunnex.io/lifecycle-expires-at":               "",
		"tunnex.io/install-operation-id":               anchor.installOperationID,
		"tunnex.io/install-operation-epoch":            strconv.FormatInt(anchor.installOperationEpoch, 10),
		"tunnex.io/install-operation-duration-seconds": strconv.Itoa(anchor.installOperationDurationSeconds),
		"tunnex.io/install-operation-not-after":        "",
		"tunnex.io/install-intent-digest":              anchor.installIntentDigest,
		"tunnex.io/release-namespace":                  anchor.releaseNamespace,
		"tunnex.io/release-name":                       anchor.releaseName,
	}
	if !anchor.expiresAt.IsZero() {
		annotations["tunnex.io/lifecycle-expires-at"] = anchor.expiresAt.UTC().Format(time.RFC3339Nano)
	}
	if !anchor.installOperationNotAfter.IsZero() {
		annotations["tunnex.io/install-operation-not-after"] = anchor.installOperationNotAfter.UTC().Format(time.RFC3339Nano)
	}
	metadata := map[string]any{
		"name": name, "namespace": namespace,
		"labels": map[string]string{
			"app.kubernetes.io/name": "tunnex-gateway-lifecycle", "app.kubernetes.io/instance": release, "app.kubernetes.io/managed-by": "tunnex-lifecycle",
		},
		"annotations": annotations,
	}
	if anchor.uid != "" {
		metadata["uid"] = anchor.uid
	}
	if anchor.resourceVersion != "" {
		metadata["resourceVersion"] = anchor.resourceVersion
	}
	return json.Marshal(map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "immutable": true, "metadata": metadata})
}

func createLifecycleAnchor(ctx context.Context, runner k8sRunner, kubeContext, namespace, release string, anchor lifecycleAnchorMetadata) (*lifecycleAnchorMetadata, error) {
	manifest, err := lifecycleAnchorManifest(namespace, anchor.name, release, anchor)
	if err != nil {
		return nil, err
	}
	result, err := runChecked(ctx, runner, "create token-blind lifecycle anchor", k8sCommand{
		name: "kubectl", args: kubectlArgs(kubeContext, "create", "-f", "-", "--output", "jsonpath="+lifecycleAnchorMetadataJSONPath), stdin: manifest,
	})
	if err != nil {
		return nil, err
	}
	created, err := parseLifecycleAnchorMetadata(string(result.stdout))
	if err != nil {
		return nil, err
	}
	if created == nil {
		return nil, errors.New("kubectl returned no lifecycle anchor metadata")
	}
	if err := validateExactLifecycleAnchorReadback(anchor, *created, release, false); err != nil {
		return nil, err
	}
	return created, nil
}

func replaceLifecycleAnchor(ctx context.Context, runner k8sRunner, kubeContext, namespace, release string, anchor lifecycleAnchorMetadata) (*lifecycleAnchorMetadata, error) {
	manifest, err := lifecycleAnchorManifest(namespace, anchor.name, release, anchor)
	if err != nil {
		return nil, err
	}
	rawPath := "/api/v1/namespaces/" + namespace + "/configmaps/" + anchor.name
	if _, err := runChecked(ctx, runner, "replace lifecycle anchor with UID/resourceVersion CAS", k8sCommand{
		name: "kubectl", args: kubectlArgs(kubeContext, "replace", "--raw="+rawPath, "-f", "-"), stdin: manifest,
	}); err != nil {
		return nil, err
	}
	readback, err := getLifecycleAnchorMetadata(ctx, runner, kubeContext, namespace, anchor.name)
	if err != nil {
		return nil, err
	}
	if readback == nil {
		return nil, errors.New("lifecycle anchor disappeared after CAS replacement")
	}
	if err := validateExactLifecycleAnchorReadback(anchor, *readback, release, true); err != nil {
		return nil, err
	}
	return readback, nil
}

func deleteOwnedLifecycleAnchor(ctx context.Context, runner k8sRunner, kubeContext, namespace, timeout, release string, anchor lifecycleAnchorMetadata) error {
	if err := validateOwnedLifecycleAnchor(anchor, anchor.name, release); err != nil {
		return err
	}
	deleteOptions, err := json.Marshal(map[string]any{
		"apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": "Background",
		"preconditions": map[string]string{"uid": anchor.uid, "resourceVersion": anchor.resourceVersion},
	})
	if err != nil {
		return err
	}
	rawPath := "/api/v1/namespaces/" + namespace + "/configmaps/" + anchor.name
	if _, err := runChecked(ctx, runner, "delete token-blind lifecycle anchor with UID/resourceVersion preconditions", k8sCommand{
		name: "kubectl", args: kubectlArgs(kubeContext, "delete", "--raw="+rawPath, "-f", "-"), stdin: deleteOptions,
	}); err != nil {
		return err
	}
	_, err = runChecked(ctx, runner, "wait for lifecycle anchor deletion", k8sCommand{
		name: "kubectl", args: kubectlArgs(kubeContext, "wait", "--for=delete", "configmap/"+anchor.name, "--namespace", namespace, "--timeout", timeout),
	})
	return err
}

func validateControlPlaneClaim(status k8sLifecycleClaimStatus, anchor lifecycleAnchorMetadata) error {
	if status.claim != anchor.lifecycleClaim || status.nodeName != anchor.nodeName || status.generation != anchor.generation || status.requestID != anchor.requestID {
		return errors.New("control-plane lifecycle claim identity/generation does not match the approved Kubernetes anchor")
	}
	if !status.expiresAt.Equal(anchor.expiresAt) {
		return errors.New("control-plane lifecycle claim expiry does not match the approved Kubernetes anchor")
	}
	if status.nodeID != "" && status.state != "consumed" && status.state != "aborted" {
		return errors.New("control-plane lifecycle claim reports an identity in a nonterminal state")
	}
	return nil
}

func createBootstrapSecret(ctx context.Context, runner k8sRunner, o installOptions, anchor lifecycleAnchorMetadata, token string) (*bootstrapSecretMetadata, error) {
	secretName := o.release + "-bootstrap"
	if err := proveBootstrapSecretAnchor(ctx, runner, o, anchor); err != nil {
		return nil, err
	}
	manifest, err := bootstrapSecretManifest(o.namespace, secretName, o.release, token, anchor)
	if err != nil {
		return nil, err
	}
	created, err := runCheckedSecrets(ctx, runner, "create bootstrap Secret", k8sCommand{
		name: "kubectl", args: kubectlArgs(o.kubeContext, "create", "-f", "-", "--output", "jsonpath="+bootstrapSecretMetadataJSONPath), stdin: manifest,
	}, token)
	if err != nil {
		return nil, fmt.Errorf("create-only bootstrap Secret failed; any concurrent existing Secret was not read or overwritten: %w", err)
	}
	secret, err := parseBootstrapSecretMetadata(string(created.stdout))
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, errors.New("kubectl returned no bootstrap Secret ownership metadata")
	}
	if err := validateOwnedBootstrapSecret(*secret, secretName, o.release); err != nil {
		return nil, err
	}
	if err := validateBootstrapSecretAnchor(*secret, anchor); err != nil {
		return nil, err
	}
	if secret.lifecycleClaim != anchor.lifecycleClaim || secret.requestID != anchor.requestID || secret.generation != anchor.generation || !secret.expiresAt.Equal(anchor.expiresAt) {
		return nil, errors.New("created bootstrap Secret did not read back the exact lifecycle response metadata")
	}
	return secret, nil
}

func proveBootstrapSecretAnchor(ctx context.Context, runner k8sRunner, o installOptions, expected lifecycleAnchorMetadata) error {
	actual, err := getLifecycleAnchorMetadata(ctx, runner, o.kubeContext, o.namespace, expected.name)
	if err != nil {
		return fmt.Errorf("prove lifecycle anchor immediately before bootstrap Secret creation: %w", err)
	}
	if actual == nil {
		return errors.New("lifecycle anchor disappeared immediately before bootstrap Secret creation")
	}
	if actual.uid != expected.uid || actual.resourceVersion != expected.resourceVersion {
		return errors.New("lifecycle anchor UID/resourceVersion changed immediately before bootstrap Secret creation")
	}
	if err := validateExactLifecycleAnchorReadback(expected, *actual, o.release, false); err != nil {
		return fmt.Errorf("lifecycle anchor changed immediately before bootstrap Secret creation: %w", err)
	}
	if actual.state == "aborting" {
		return fmt.Errorf("lifecycle claim %s was fenced as aborting before bootstrap Secret creation", actual.lifecycleClaim)
	}
	if actual.state != "issued" || actual.generation <= 0 || actual.requestID == "" || actual.expiresAt.IsZero() {
		return errors.New("lifecycle anchor is not an exact issued credential identity immediately before bootstrap Secret creation")
	}
	return nil
}

func updateLifecycleAnchor(ctx context.Context, deps k8sDeps, o installOptions, anchor lifecycleAnchorMetadata) (lifecycleAnchorMetadata, error) {
	updated, err := replaceLifecycleAnchor(ctx, deps.runner, o.kubeContext, o.namespace, o.release, anchor)
	if err != nil {
		return lifecycleAnchorMetadata{}, err
	}
	if updated == nil {
		return lifecycleAnchorMetadata{}, errors.New("lifecycle anchor disappeared during CAS replacement")
	}
	if err := validateOwnedLifecycleAnchor(*updated, anchor.name, o.release); err != nil {
		return lifecycleAnchorMetadata{}, err
	}
	return *updated, nil
}

// ensureLifecycleBootstrap is the only raw-token path in the Kubernetes CLI.
// The non-secret anchor is durable before every CP mint/remint; the Secret then
// mirrors the exact response and acknowledgement destroys server redelivery.
func ensureLifecycleBootstrap(ctx context.Context, deps k8sDeps, prepared preparedInstall) (*bootstrapSecretMetadata, lifecycleAnchorMetadata, string, error) {
	o := prepared.options
	anchor := prepared.anchor
	if prepared.cp == nil || prepared.org.id == "" {
		return nil, lifecycleAnchorMetadata{}, "", errors.New("lifecycle control-plane client or organization is unavailable")
	}
	if !prepared.state.anchorExists {
		created, err := createLifecycleAnchor(ctx, deps.runner, o.kubeContext, o.namespace, o.release, anchor)
		if err != nil {
			return nil, lifecycleAnchorMetadata{}, "", fmt.Errorf("create lifecycle anchor before token mint: %w", err)
		}
		if created == nil {
			return nil, lifecycleAnchorMetadata{}, "", errors.New("lifecycle anchor creation returned no ownership metadata")
		}
		anchor = *created
	} else {
		if prepared.priorInstallAnchor != nil {
			if err := reconcileExpiredLifecycleInstallBeforeRemint(ctx, deps, prepared, *prepared.priorInstallAnchor); err != nil {
				return nil, lifecycleAnchorMetadata{}, "", err
			}
		}
		if anchor.requestID != prepared.state.anchorRequestID || anchor.expectedGeneration != prepared.state.anchorExpectedGen || anchor.state != prepared.state.anchorState || prepared.priorInstallAnchor != nil {
			updated, err := updateLifecycleAnchor(ctx, deps, o, anchor)
			if err != nil {
				return nil, lifecycleAnchorMetadata{}, "", fmt.Errorf("persist remint request identity and retire prior install operation before control-plane call: %w", err)
			}
			anchor = updated
		}
	}

	if prepared.state.retrySecret && prepared.state.secretExpiresAt.After(time.Now()) {
		status, err := prepared.cp.GetLifecycleClaimStatus(ctx, prepared.org.id, anchor.lifecycleClaim)
		if err != nil {
			return nil, lifecycleAnchorMetadata{}, "", err
		}
		if err := validateControlPlaneClaim(status, anchor); err != nil {
			return nil, lifecycleAnchorMetadata{}, "", err
		}
		if status.state != "issued" && status.state != "acknowledged" {
			return nil, lifecycleAnchorMetadata{}, "", fmt.Errorf("control-plane lifecycle claim is %q, not retry-safe", status.state)
		}
		if anchor.state == "installing" {
			if status.state != "acknowledged" {
				return nil, lifecycleAnchorMetadata{}, "", fmt.Errorf("active lifecycle install operation requires an acknowledged claim, got %q", status.state)
			}
			secret := &bootstrapSecretMetadata{
				name: o.release + "-bootstrap", uid: prepared.state.secretUID, resourceVersion: prepared.state.secretResourceVersion,
				appName: "tunnex-gateway-bootstrap", instance: o.release, managedBy: "tunnex-lifecycle", immutable: true,
				lifecycleClaim: prepared.state.secretLifecycleClaim, requestID: prepared.state.secretRequestID,
				generation: prepared.state.secretGeneration, expiresAt: prepared.state.secretExpiresAt,
				ownerAPIVersion: prepared.state.secretOwnerAPIVersion, ownerKind: prepared.state.secretOwnerKind,
				ownerName: prepared.state.secretOwnerName, ownerUID: prepared.state.secretOwnerUID,
			}
			return secret, anchor, "", nil
		}
		if _, err := prepared.cp.AcknowledgeLifecycleClaim(ctx, prepared.org.id, anchor.lifecycleClaim, anchor.generation, anchor.requestID); err != nil {
			return nil, lifecycleAnchorMetadata{}, "", err
		}
		if anchor.state != "acknowledged" {
			anchor.state = "acknowledged"
			updated, updateErr := updateLifecycleAnchor(ctx, deps, o, anchor)
			if updateErr != nil {
				return nil, lifecycleAnchorMetadata{}, "", updateErr
			}
			anchor = updated
		}
		secret := &bootstrapSecretMetadata{
			name: o.release + "-bootstrap", uid: prepared.state.secretUID, resourceVersion: prepared.state.secretResourceVersion,
			appName: "tunnex-gateway-bootstrap", instance: o.release, managedBy: "tunnex-lifecycle", immutable: true,
			lifecycleClaim: prepared.state.secretLifecycleClaim, requestID: prepared.state.secretRequestID,
			generation: prepared.state.secretGeneration, expiresAt: prepared.state.secretExpiresAt,
			ownerAPIVersion: prepared.state.secretOwnerAPIVersion, ownerKind: prepared.state.secretOwnerKind,
			ownerName: prepared.state.secretOwnerName, ownerUID: prepared.state.secretOwnerUID,
		}
		return secret, anchor, "", nil
	}

	if prepared.state.retrySecret {
		status, err := prepared.cp.GetLifecycleClaimStatus(ctx, prepared.org.id, prepared.state.secretLifecycleClaim)
		if err != nil {
			return nil, lifecycleAnchorMetadata{}, "", err
		}
		oldAnchor := anchor
		oldAnchor.requestID = prepared.state.secretRequestID
		oldAnchor.expectedGeneration = prepared.state.secretGeneration - 1
		oldAnchor.generation = prepared.state.secretGeneration
		if err := validateControlPlaneClaim(status, oldAnchor); err != nil {
			return nil, lifecycleAnchorMetadata{}, "", err
		}
		if status.state != "expired" || status.nodeID != "" {
			return nil, lifecycleAnchorMetadata{}, "", fmt.Errorf("expired Secret cannot be reminted because the exact control-plane claim is %q or already has an identity", status.state)
		}
		if anchor.state != "pending" || anchor.expectedGeneration != prepared.state.secretGeneration || anchor.generation != prepared.state.secretGeneration || anchor.requestID == prepared.state.secretRequestID {
			return nil, lifecycleAnchorMetadata{}, "", errors.New("expired Secret remint lacks the exact persisted pending request transition")
		}
		oldSecret := bootstrapSecretMetadata{
			name: o.release + "-bootstrap", uid: prepared.state.secretUID, resourceVersion: prepared.state.secretResourceVersion,
			appName: "tunnex-gateway-bootstrap", instance: o.release, managedBy: "tunnex-lifecycle", immutable: true,
			lifecycleClaim: prepared.state.secretLifecycleClaim, requestID: prepared.state.secretRequestID,
			generation: prepared.state.secretGeneration, expiresAt: prepared.state.secretExpiresAt,
			ownerAPIVersion: prepared.state.secretOwnerAPIVersion, ownerKind: prepared.state.secretOwnerKind,
			ownerName: prepared.state.secretOwnerName, ownerUID: prepared.state.secretOwnerUID,
		}
		if err := deleteOwnedBootstrapSecret(ctx, deps.runner, o.kubeContext, o.namespace, o.timeout, oldSecret.name, o.release, anchor, oldSecret); err != nil {
			return nil, lifecycleAnchorMetadata{}, "", fmt.Errorf("CAS-delete expired bootstrap Secret before control-plane remint: %w", err)
		}
	}

	reminted, err := prepared.cp.RemintLifecycleClaim(ctx, prepared.org.id, anchor.lifecycleClaim, anchor.nodeName, anchor.expectedGeneration, anchor.requestID)
	if err != nil {
		return nil, lifecycleAnchorMetadata{}, "", err
	}
	if reminted.claim != anchor.lifecycleClaim || reminted.requestID != anchor.requestID || reminted.generation != anchor.expectedGeneration+1 || !reminted.expiresAt.After(time.Now()) || strings.TrimSpace(reminted.joinToken) == "" {
		return nil, lifecycleAnchorMetadata{}, "", errors.New("control-plane remint response did not match the persisted lifecycle request")
	}
	token := reminted.joinToken
	anchor.generation = reminted.generation
	anchor.expiresAt = reminted.expiresAt
	anchor.state = "issued"
	anchor, err = updateLifecycleAnchor(ctx, deps, o, anchor)
	if err != nil {
		return nil, lifecycleAnchorMetadata{}, "", fmt.Errorf("persist remint response metadata: %w", err)
	}
	secret, err := createBootstrapSecret(ctx, deps.runner, o, anchor, token)
	if err != nil {
		return nil, lifecycleAnchorMetadata{}, "", fmt.Errorf("create exact lifecycle bootstrap Secret; rerun with claim %s to recover the same sealed response: %w", anchor.lifecycleClaim, err)
	}
	if _, err := prepared.cp.AcknowledgeLifecycleClaim(ctx, prepared.org.id, anchor.lifecycleClaim, anchor.generation, anchor.requestID); err != nil {
		return nil, lifecycleAnchorMetadata{}, "", fmt.Errorf("bootstrap Secret is durable but control-plane acknowledgement failed; rerun with claim %s: %w", anchor.lifecycleClaim, err)
	}
	anchor.state = "acknowledged"
	anchor, err = updateLifecycleAnchor(ctx, deps, o, anchor)
	if err != nil {
		return nil, lifecycleAnchorMetadata{}, "", fmt.Errorf("control-plane acknowledged the Secret but lifecycle anchor state update failed; rerun with claim %s: %w", anchor.lifecycleClaim, err)
	}
	return secret, anchor, token, nil
}

func verifyLifecycleConsumed(ctx context.Context, prepared preparedInstall, anchor lifecycleAnchorMetadata) error {
	status, err := prepared.cp.GetLifecycleClaimStatus(ctx, prepared.org.id, anchor.lifecycleClaim)
	if err != nil {
		return err
	}
	if err := validateControlPlaneClaim(status, anchor); err != nil {
		return err
	}
	if status.state != "consumed" || status.nodeID == "" {
		return fmt.Errorf("gateway became ready but control-plane lifecycle claim is %q without an exact enrolled node", status.state)
	}
	return nil
}

type abortInstallOptions struct {
	org          string
	release      string
	namespace    string
	kubeContext  string
	claim        string
	confirmation string
	timeout      string
}

type abortInstallSnapshot struct {
	anchor      lifecycleAnchorMetadata
	secret      *bootstrapSecretMetadata
	status      k8sLifecycleClaimStatus
	claimAbsent bool
	pvc         *pvcView
	release     *helmReleaseSummary
}

func isGenerationZeroAbortAnchor(anchor lifecycleAnchorMetadata) bool {
	return (anchor.state == "pending" || anchor.state == "aborting") &&
		anchor.expectedGeneration == 0 && anchor.generation == 0 && anchor.expiresAt.IsZero()
}

func isAbortableLifecycleAnchor(anchor lifecycleAnchorMetadata) bool {
	if anchor.state != "pending" && anchor.state != "issued" && anchor.state != "acknowledged" && anchor.state != "installing" && anchor.state != "aborting" {
		return false
	}
	if isGenerationZeroAbortAnchor(anchor) {
		return true
	}
	return anchor.generation > 0 && anchor.expectedGeneration >= 0 && anchor.expectedGeneration <= anchor.generation && !anchor.expiresAt.IsZero()
}

func lifecycleInstallBeginFromAnchor(anchor lifecycleAnchorMetadata) (lifecycleInstallBeginRequest, error) {
	if !validCanonicalOperationID(anchor.installOperationID) || anchor.installOperationDurationSeconds <= 0 || anchor.installOperationDurationSeconds > 900 ||
		!validCanonicalSHA256Digest(anchor.installIntentDigest) || anchor.releaseNamespace == "" || anchor.releaseName == "" {
		return lifecycleInstallBeginRequest{}, errors.New("lifecycle anchor contains incomplete install-operation identity")
	}
	if anchor.state == "acknowledged" && (anchor.installOperationEpoch != 0 || !anchor.installOperationNotAfter.IsZero()) {
		return lifecycleInstallBeginRequest{}, errors.New("pre-mirror lifecycle install anchor contains an epoch or deadline")
	}
	if (anchor.state == "installing" || anchor.state == "aborting") && (anchor.installOperationEpoch <= 0 || anchor.installOperationNotAfter.IsZero()) {
		return lifecycleInstallBeginRequest{}, errors.New("mirrored lifecycle install anchor lacks its exact epoch or deadline")
	}
	return lifecycleInstallBeginRequest{
		claim: anchor.lifecycleClaim, expectedGeneration: anchor.generation, requestID: anchor.requestID,
		operationID: anchor.installOperationID, releaseNamespace: anchor.releaseNamespace, releaseName: anchor.releaseName,
		installIntentDigest: anchor.installIntentDigest, requestedDurationSeconds: anchor.installOperationDurationSeconds,
	}, nil
}

func abortSecretFingerprint(secret *bootstrapSecretMetadata) string {
	if secret == nil {
		return "absent"
	}
	return strings.Join([]string{
		secret.name, secret.uid, secret.resourceVersion, secret.lifecycleClaim, secret.requestID,
		strconv.Itoa(secret.generation), secret.expiresAt.UTC().Format(time.RFC3339Nano),
		secret.ownerAPIVersion, secret.ownerKind, secret.ownerName, secret.ownerUID,
	}, "\x00")
}

func abortPVCFingerprint(pvc *pvcView) string {
	if pvc == nil {
		return "absent"
	}
	storageClass := ""
	if pvc.Spec.StorageClassName != nil {
		storageClass = *pvc.Spec.StorageClassName
	}
	return strings.Join([]string{pvc.Metadata.Name, pvc.Metadata.UID, pvc.Metadata.ResourceVersion, pvc.Spec.VolumeName, storageClass, pvc.Status.Phase}, "\x00")
}

func abortReleaseFingerprint(release *helmReleaseSummary) string {
	if release == nil {
		return "absent"
	}
	return strings.Join([]string{release.Name, release.Namespace, release.Revision, release.Updated, release.Status, release.Chart, release.AppVersion}, "\x00")
}

func abortAnchorFingerprint(anchor lifecycleAnchorMetadata) string {
	return strings.Join([]string{
		anchor.name, anchor.uid, anchor.resourceVersion, anchor.appName, anchor.instance, anchor.managedBy,
		strconv.FormatBool(anchor.immutable), anchor.orgID, anchor.nodeName, anchor.lifecycleClaim, anchor.requestID,
		strconv.Itoa(anchor.expectedGeneration), strconv.Itoa(anchor.generation), anchor.state,
		anchor.expiresAt.UTC().Format(time.RFC3339Nano), anchor.installOperationID,
		strconv.FormatInt(anchor.installOperationEpoch, 10), strconv.Itoa(anchor.installOperationDurationSeconds),
		anchor.installOperationNotAfter.UTC().Format(time.RFC3339Nano), anchor.installIntentDigest,
		anchor.releaseNamespace, anchor.releaseName,
	}, "\x00")
}

func (s abortInstallSnapshot) fingerprint() string {
	secret := abortSecretFingerprint(s.secret)
	pvc := abortPVCFingerprint(s.pvc)
	release := abortReleaseFingerprint(s.release)
	return strings.Join([]string{
		s.anchor.name, s.anchor.uid, s.anchor.resourceVersion, s.anchor.orgID, s.anchor.nodeName, s.anchor.lifecycleClaim, s.anchor.requestID,
		strconv.Itoa(s.anchor.expectedGeneration), strconv.Itoa(s.anchor.generation), s.anchor.state, s.anchor.expiresAt.UTC().Format(time.RFC3339Nano), secret,
		s.status.claim, s.status.state, s.status.nodeName, strconv.Itoa(s.status.generation), s.status.requestID, s.status.expiresAt.UTC().Format(time.RFC3339Nano), s.status.nodeID,
		strconv.FormatBool(s.claimAbsent), pvc, release,
	}, "\x00")
}

func validateAbortRetainedPVC(pvc pvcView, claim, release, namespace string) error {
	if err := validateRetainedPVCMetadata(pvc, claim, release, namespace); err != nil {
		return err
	}
	if pvc.Metadata.UID == "" || pvc.Metadata.ResourceVersion == "" {
		return fmt.Errorf("retained partial-install PVC %q lacks UID/resourceVersion identity", claim)
	}
	switch pvc.Status.Phase {
	case "Pending":
		// Binding is not an atomic phase/volume update. A WaitForFirstConsumer
		// claim may briefly name a selected volume while status still reports
		// Pending; both fields are fingerprinted and the claim is retained.
	case "Bound":
		if pvc.Spec.VolumeName == "" {
			return fmt.Errorf("Bound retained partial-install PVC %q lacks its volume identity", claim)
		}
	default:
		return fmt.Errorf("retained partial-install PVC %q is %q, expected Pending or Bound", claim, pvc.Status.Phase)
	}
	return nil
}

func inspectAbortInstall(ctx context.Context, deps k8sDeps, cp k8sControlPlane, org k8sOrganization, o abortInstallOptions) (abortInstallSnapshot, error) {
	anchorName := o.release + "-lifecycle"
	anchor, err := getLifecycleAnchorMetadata(ctx, deps.runner, o.kubeContext, o.namespace, anchorName)
	if err != nil {
		return abortInstallSnapshot{}, err
	}
	if anchor == nil {
		return abortInstallSnapshot{}, fmt.Errorf("owned lifecycle anchor %q was not found", anchorName)
	}
	if err := validateOwnedLifecycleAnchor(*anchor, anchorName, o.release); err != nil {
		return abortInstallSnapshot{}, err
	}
	if anchor.lifecycleClaim != o.claim || anchor.orgID != org.id {
		return abortInstallSnapshot{}, errors.New("typed claim or organization does not match the owned lifecycle anchor")
	}
	if !isAbortableLifecycleAnchor(*anchor) {
		return abortInstallSnapshot{}, errors.New("lifecycle anchor is not in an exact abortable pending, issued, acknowledged, installing, or aborting state")
	}
	hasInstallOperation := anchor.installOperationID != ""
	if hasInstallOperation {
		if anchor.state != "acknowledged" && anchor.state != "installing" && anchor.state != "aborting" {
			return abortInstallSnapshot{}, errors.New("lifecycle install operation is attached to a non-installing anchor state")
		}
		begin, beginErr := lifecycleInstallBeginFromAnchor(*anchor)
		if beginErr != nil {
			return abortInstallSnapshot{}, beginErr
		}
		if begin.releaseNamespace != o.namespace || begin.releaseName != o.release {
			return abortInstallSnapshot{}, errors.New("lifecycle install operation release binding does not match the typed abort scope")
		}
	} else if anchor.installOperationEpoch != 0 || anchor.installOperationDurationSeconds != 0 || !anchor.installOperationNotAfter.IsZero() ||
		anchor.installIntentDigest != "" || anchor.releaseNamespace != "" || anchor.releaseName != "" {
		return abortInstallSnapshot{}, errors.New("lifecycle anchor contains partial install-operation metadata")
	}
	releases, err := listHelmReleases(ctx, deps.runner, o.kubeContext, o.namespace, o.release)
	if err != nil {
		return abortInstallSnapshot{}, err
	}
	if len(releases) > 1 {
		return abortInstallSnapshot{}, fmt.Errorf("Helm returned %d exact matches for release %q", len(releases), o.release)
	}
	var release *helmReleaseSummary
	if len(releases) == 1 {
		if !hasInstallOperation {
			return abortInstallSnapshot{}, fmt.Errorf("release %q still exists without a fenced lifecycle install operation; use uninstall instead of abort-install", o.release)
		}
		revision, revisionErr := strconv.Atoi(releases[0].Revision)
		if revisionErr != nil || revision <= 0 {
			return abortInstallSnapshot{}, fmt.Errorf("current Helm revision %q is invalid", releases[0].Revision)
		}
		if provenanceErr := requireZeroTouchRevision(ctx, deps.runner, releaseOptions{release: o.release, namespace: o.namespace, kubeContext: o.kubeContext, timeout: o.timeout}, revision); provenanceErr != nil {
			return abortInstallSnapshot{}, provenanceErr
		}
		release = &releases[0]
	}
	secretName := o.release + "-bootstrap"
	secret, err := getBootstrapSecretMetadata(ctx, deps.runner, o.kubeContext, o.namespace, secretName)
	if err != nil {
		return abortInstallSnapshot{}, err
	}
	if secret != nil {
		if err := validateOwnedBootstrapSecret(*secret, secretName, o.release); err != nil {
			return abortInstallSnapshot{}, err
		}
		if err := validateBootstrapSecretAnchor(*secret, *anchor); err != nil {
			return abortInstallSnapshot{}, err
		}
		if secret.lifecycleClaim != anchor.lifecycleClaim {
			return abortInstallSnapshot{}, errors.New("bootstrap Secret claim does not match the owned lifecycle anchor")
		}
		exactCurrent := secret.requestID == anchor.requestID && secret.generation == anchor.generation && secret.expiresAt.Equal(anchor.expiresAt)
		pendingPrevious := (anchor.state == "pending" || anchor.state == "aborting") && anchor.expectedGeneration == secret.generation && anchor.generation == secret.generation && anchor.requestID != secret.requestID && !secret.expiresAt.After(time.Now())
		if !exactCurrent && !pendingPrevious {
			return abortInstallSnapshot{}, errors.New("bootstrap Secret and lifecycle anchor are not an exact recoverable transition")
		}
	}
	expectedClaim := gatewayFullname(o.release) + "-state"
	pvc, err := findPVC(ctx, deps.runner, o.kubeContext, o.namespace, expectedClaim)
	if err != nil {
		return abortInstallSnapshot{}, err
	}
	if pvc != nil {
		if err := validateAbortRetainedPVC(*pvc, expectedClaim, o.release, o.namespace); err != nil {
			return abortInstallSnapshot{}, err
		}
		if mountedBy, mountErr := claimMountedByLivePod(ctx, deps.runner, o.kubeContext, o.namespace, expectedClaim); mountErr != nil {
			return abortInstallSnapshot{}, mountErr
		} else if mountedBy != "" && release == nil {
			return abortInstallSnapshot{}, fmt.Errorf("retained partial-install PVC is still mounted by %s; refusing abort cleanup", mountedBy)
		}
	}
	status, err := cp.GetLifecycleClaimStatus(ctx, org.id, anchor.lifecycleClaim)
	if errors.Is(err, errK8sLifecycleClaimNotFound) {
		if !isGenerationZeroAbortAnchor(*anchor) || secret != nil {
			return abortInstallSnapshot{}, errors.New("control-plane lifecycle claim is absent outside the exact Secret-free pre-mint abort state")
		}
		status = k8sLifecycleClaimStatus{
			claim: anchor.lifecycleClaim, state: "absent", nodeName: anchor.nodeName,
			generation: 0, requestID: anchor.requestID,
		}
		return abortInstallSnapshot{anchor: *anchor, secret: nil, status: status, claimAbsent: true, pvc: pvc, release: release}, nil
	}
	if err != nil {
		return abortInstallSnapshot{}, err
	}
	if status.claim != anchor.lifecycleClaim || status.nodeName != anchor.nodeName {
		return abortInstallSnapshot{}, errors.New("control-plane lifecycle identity does not match the owned anchor")
	}
	if isGenerationZeroAbortAnchor(*anchor) {
		if secret != nil || status.requestID != anchor.requestID {
			return abortInstallSnapshot{}, errors.New("pre-mint abort claim does not match the Secret-free anchored request identity")
		}
		switch status.generation {
		case 0:
			if status.state != "aborted" || status.abortedAt == nil || status.nodeID != "" || !status.expiresAt.Equal(time.Unix(0, 0).UTC()) {
				return abortInstallSnapshot{}, errors.New("generation-zero control-plane claim is not an exact credentialless aborted tombstone")
			}
		case 1:
			if status.state != "issued" && status.state != "acknowledged" && status.state != "expired" && status.state != "consumed" && status.state != "aborted" {
				return abortInstallSnapshot{}, errors.New("mint-race lifecycle successor is not in a recognized exact claim state")
			}
			if status.state == "aborted" {
				if err := validateAlreadyAbortedLifecycleStatus(status, anchor.lifecycleClaim); err != nil {
					return abortInstallSnapshot{}, fmt.Errorf("mint-race lifecycle successor is not an exact aborted identity: %w", err)
				}
			}
		default:
			return abortInstallSnapshot{}, errors.New("pre-mint abort found a lifecycle generation beyond the exact generation-one mint race")
		}
		return abortInstallSnapshot{anchor: *anchor, secret: nil, status: status, pvc: pvc, release: release}, nil
	}
	current := status.generation == anchor.generation && status.requestID == anchor.requestID
	pendingPrevious := (anchor.state == "pending" || anchor.state == "aborting") && status.generation == anchor.expectedGeneration && status.state == "expired"
	if pendingPrevious && secret != nil {
		pendingPrevious = status.requestID == secret.requestID
	}
	pendingNext := (anchor.state == "pending" || anchor.state == "aborting") && status.generation == anchor.expectedGeneration+1 && status.requestID == anchor.requestID
	if !current && !pendingPrevious && !pendingNext {
		return abortInstallSnapshot{}, errors.New("control-plane generation/request is outside the exact anchored abort transition")
	}
	return abortInstallSnapshot{anchor: *anchor, secret: secret, status: status, pvc: pvc, release: release}, nil
}

type generationZeroLifecycleAborter interface {
	AbortLifecycleClaimBeforeMint(context.Context, string, string, string, string) (k8sLifecycleClaimStatus, error)
}

func validateAlreadyAbortedLifecycleStatus(status k8sLifecycleClaimStatus, expectedClaim string) error {
	if status.claim != expectedClaim || status.state != "aborted" || status.abortedAt == nil || status.abortedAt.IsZero() || status.nodeName == "" || status.requestID == "" || status.generation < 0 {
		return errors.New("control-plane claim is not an exact aborted lifecycle identity")
	}
	if status.generation == 0 {
		if status.nodeID != "" || !status.expiresAt.Equal(time.Unix(0, 0).UTC()) {
			return errors.New("generation-zero aborted claim is not a credentialless tombstone")
		}
		return nil
	}
	if status.expiresAt.IsZero() || status.expiresAt.After(*status.abortedAt) {
		return errors.New("positive-generation aborted claim expiry is not canonically bounded by aborted_at")
	}
	return nil
}

func validateGenerationZeroAbortResponse(status, previous k8sLifecycleClaimStatus, anchor lifecycleAnchorMetadata) error {
	if status.claim != anchor.lifecycleClaim || status.nodeName != anchor.nodeName || status.requestID != anchor.requestID {
		return errors.New("control-plane pre-mint abort response does not match the exact anchored claim/request/node identity")
	}
	if err := validateAlreadyAbortedLifecycleStatus(status, anchor.lifecycleClaim); err != nil {
		return err
	}
	switch status.generation {
	case 0:
	case 1:
		// The only positive generation accepted here is the exact successor a
		// racing mint can create from this generation-zero request. Its expiry
		// must be the same canonical minimum enforced for every positive abort.
		if err := validatePositiveAbortResponse(status, previous, anchor); err != nil {
			return fmt.Errorf("generation-one mint-race abort is not canonical: %w", err)
		}
	default:
		return errors.New("control-plane pre-mint abort response is outside the exact generation-zero/generation-one race")
	}
	return nil
}

func validatePositiveAbortResponse(status, previous k8sLifecycleClaimStatus, anchor lifecycleAnchorMetadata) error {
	if status.claim != anchor.lifecycleClaim || status.nodeName != anchor.nodeName || status.generation != previous.generation || status.requestID != previous.requestID {
		return errors.New("control-plane abort response does not match the exact lifecycle claim identity/generation")
	}
	if status.state != "aborted" || status.abortedAt == nil || status.abortedAt.IsZero() {
		return errors.New("control-plane abort response is not aborted with a typed timestamp")
	}
	expectedExpiry := previous.expiresAt
	if status.abortedAt.Before(expectedExpiry) {
		expectedExpiry = *status.abortedAt
	}
	if !status.expiresAt.Equal(expectedExpiry) {
		return errors.New("control-plane abort response expiry is not the canonical minimum of the previous expiry and aborted_at")
	}
	return nil
}

func validateLifecycleInstallAbortStatus(status lifecycleInstallOperationStatus, begin lifecycleInstallBeginRequest, prior lifecycleInstallOperationStatus) error {
	if err := validateLifecycleInstallOperationStatus(status, begin); err != nil {
		return err
	}
	if !status.notAfter.Equal(prior.notAfter) || status.heartbeatAt.Before(prior.heartbeatAt) {
		return errors.New("lifecycle install abort coordination changed the immutable deadline or moved heartbeat_at backwards")
	}
	switch status.state {
	case lifecycleInstallAbortRequested:
		if status.epoch != prior.epoch || status.abortRequestedAt == nil || status.abortRequestedAt.IsZero() || !status.serverTime.Before(status.notAfter) {
			return errors.New("active lifecycle install abort request is not bound to the exact live epoch and deadline")
		}
	case lifecycleInstallAborting:
		if status.epoch != prior.epoch && status.epoch != prior.epoch+1 {
			return errors.New("lifecycle install abort takeover did not retain or increment the exact epoch")
		}
		if status.epoch == prior.epoch && prior.state != lifecycleInstallAborting {
			return errors.New("lifecycle install abort takeover did not fence the prior holder with a new epoch")
		}
		if err := validateLifecycleInstallState(status, lifecycleInstallAborting); err != nil {
			return err
		}
	default:
		return fmt.Errorf("lifecycle install abort coordination returned unexpected operation state %q", status.state)
	}
	return nil
}

func coordinateLifecycleInstallAbortUntilTakeover(ctx context.Context, deps k8sDeps, cp lifecycleInstallControlPlane, orgID string, begin lifecycleInstallBeginRequest, initial lifecycleInstallOperationStatus) (lifecycleInstallAbortResult, error) {
	prior := initial
	ticker := deps.newTicker(lifecycleInstallHeartbeatInterval)
	defer ticker.Stop()
	for {
		result, err := requestLifecycleInstallAbort(ctx, cp, orgID, begin, prior)
		if err != nil {
			return lifecycleInstallAbortResult{}, err
		}
		if result.claimStatus != nil {
			return result, nil
		}
		status := *result.operationStatus
		if status.state == lifecycleInstallAborting {
			return result, nil
		}
		prior = status
		select {
		case <-ctx.Done():
			return lifecycleInstallAbortResult{}, fmt.Errorf("lifecycle install abort request is durable, but the active holder has not released before cancellation: %w", ctx.Err())
		case <-ticker.C():
		}
	}
}

func requestLifecycleInstallAbort(ctx context.Context, cp lifecycleInstallControlPlane, orgID string, begin lifecycleInstallBeginRequest, prior lifecycleInstallOperationStatus) (lifecycleInstallAbortResult, error) {
	result, err := cp.CoordinateLifecycleInstallAbort(ctx, orgID, lifecycleInstallCASFromStatus(prior))
	if err != nil {
		return lifecycleInstallAbortResult{}, err
	}
	if result.claimStatus != nil {
		if result.operationStatus != nil || result.pending {
			return lifecycleInstallAbortResult{}, errors.New("control-plane returned both terminal claim and pending install-operation abort state")
		}
		return result, nil
	}
	if !result.pending || result.operationStatus == nil {
		return lifecycleInstallAbortResult{}, errors.New("control-plane lifecycle install abort response lacked terminal claim or pending operation status")
	}
	if err := validateLifecycleInstallAbortStatus(*result.operationStatus, begin, prior); err != nil {
		return lifecycleInstallAbortResult{}, err
	}
	return result, nil
}

func releaseLifecycleInstallBeforeAbort(ctx context.Context, cp lifecycleInstallControlPlane, orgID string, begin lifecycleInstallBeginRequest, prior lifecycleInstallOperationStatus) (lifecycleInstallOperationStatus, error) {
	released, err := cp.ReleaseLifecycleInstall(ctx, orgID, lifecycleInstallCASFromStatus(prior))
	if err != nil {
		return lifecycleInstallOperationStatus{}, err
	}
	if err := validateLifecycleInstallOperationContinuation(released, begin, prior); err != nil {
		return lifecycleInstallOperationStatus{}, err
	}
	if err := validateLifecycleInstallState(released, lifecycleInstallReleased); err != nil {
		return lifecycleInstallOperationStatus{}, err
	}
	return released, nil
}

func runK8sAbortInstall(ctx context.Context, args []string, deps k8sDeps) error {
	o := abortInstallOptions{}
	fs := flag.NewFlagSet("k8s abort-install", flag.ContinueOnError)
	fs.SetOutput(deps.errOut)
	fs.StringVar(&o.org, "org", "", "organization id, slug, or exact name (required for idempotent recovery when login has multiple organizations)")
	fs.StringVar(&o.release, "release", "", "exact partial Helm release")
	fs.StringVar(&o.namespace, "namespace", defaultK8sNamespace, "Kubernetes namespace")
	fs.StringVar(&o.kubeContext, "context", "", "kube context")
	fs.StringVar(&o.claim, "claim", "", "exact opaque lifecycle claim")
	fs.StringVar(&o.confirmation, "confirm", "", "exact typed confirmation: ABORT <claim>")
	fs.StringVar(&o.timeout, "timeout", defaultK8sTimeout, "Kubernetes deletion timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	o.org, o.release, o.namespace, o.kubeContext, o.claim = strings.TrimSpace(o.org), strings.TrimSpace(o.release), strings.TrimSpace(o.namespace), strings.TrimSpace(o.kubeContext), strings.TrimSpace(o.claim)
	if o.release == "" {
		return errors.New("abort-install requires an explicit --release")
	}
	if err := validateRelease(o.release); err != nil {
		return err
	}
	if err := validateDNSLabel("namespace", o.namespace, 63); err != nil {
		return err
	}
	if _, err := uuid.Parse(o.claim); err != nil {
		return errors.New("abort-install requires an exact UUID --claim")
	}
	contextName, err := runToolContextPreflight(ctx, deps, o.kubeContext)
	if err != nil {
		return err
	}
	o.kubeContext = contextName
	anchor, err := getLifecycleAnchorMetadata(ctx, deps.runner, o.kubeContext, o.namespace, o.release+"-lifecycle")
	if err != nil {
		return err
	}
	cred, err := deps.loadCredential()
	if err != nil {
		return err
	}
	cp, err := deps.newControlPlane(cred)
	if err != nil {
		return err
	}
	orgs, err := cp.ListOrganizations(ctx)
	if err != nil {
		return err
	}
	orgSelector := o.org
	if anchor != nil {
		if orgSelector == "" {
			orgSelector = anchor.orgID
		}
	}
	org, err := resolveOrganization(orgs, orgSelector)
	if err != nil {
		return err
	}
	if anchor == nil {
		return completeAlreadyAbortedInstall(ctx, deps, cp, org, o)
	}
	if anchor.orgID != org.id {
		return errors.New("selected organization does not match the owned lifecycle anchor")
	}
	before, err := inspectAbortInstall(ctx, deps, cp, org, o)
	if err != nil {
		return err
	}
	impactSteps := []string{"CAS-fence the exact lifecycle anchor as aborting before the control-plane transaction", "permanently invalidate the exact lifecycle join token", "revoke the exact claim-bound partial gateway identity if one exists", "CAS-delete owned bootstrap Secret metadata if present", "CAS-delete the owned lifecycle anchor", "retain any PVC for explicit purge-state recovery"}
	if before.anchor.installOperationID != "" {
		impactSteps = []string{"durably request abort on the exact control-plane install operation", "CAS-mirror the abort request and exact epoch in the lifecycle anchor", "retain recovery metadata while a holder is active and wait for release or hard-deadline epoch takeover", "reconcile the exact zero-touch Helm release and labeled workloads to absence", "finalize exact control-plane claim abort/revocation", "CAS-delete owner-bound bootstrap Secret and lifecycle anchor", "retain any PVC for explicit purge-state recovery"}
	}
	impact := map[string]any{
		"action": "abort-install", "context": o.kubeContext, "namespace": o.namespace, "release": o.release,
		"lifecycle_claim": o.claim, "generation": before.status.generation, "control_plane_state": before.status.state,
		"impact": impactSteps,
	}
	if err := writeJSON(deps.out, impact); err != nil {
		return err
	}
	want := "ABORT " + o.claim
	if strings.TrimSpace(o.confirmation) == "" {
		if _, err := fmt.Fprintf(deps.out, "Type %q to abort this exact context/namespace/release/claim: ", want); err != nil {
			return err
		}
		line, readErr := bufio.NewReader(deps.in).ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		o.confirmation = strings.TrimSpace(line)
	}
	if o.confirmation != want {
		return fmt.Errorf("confirmation did not match exactly %q; nothing was aborted", want)
	}
	after, err := inspectAbortInstall(ctx, deps, cp, org, o)
	if err != nil {
		return err
	}
	if after.fingerprint() != before.fingerprint() {
		return errors.New("lifecycle claim, Secret, or anchor changed while awaiting confirmation; rerun abort-install")
	}
	hasInstallOperation := after.anchor.installOperationID != ""
	var installCP lifecycleInstallControlPlane
	var installBegin lifecycleInstallBeginRequest
	var installStatus lifecycleInstallOperationStatus
	var installAbort lifecycleInstallAbortResult
	if hasInstallOperation {
		var ok bool
		installCP, ok = cp.(lifecycleInstallControlPlane)
		if !ok {
			return errors.New("control-plane client does not support fenced lifecycle install abort coordination")
		}
		installBegin, err = lifecycleInstallBeginFromAnchor(after.anchor)
		if err != nil {
			return err
		}
		installStatus, err = installCP.BeginLifecycleInstall(ctx, org.id, installBegin)
		if err != nil {
			return fmt.Errorf("refresh exact lifecycle install operation before abort fence: %w", err)
		}
		if err := validateLifecycleInstallOperationStatus(installStatus, installBegin); err != nil {
			return err
		}
		if installStatus.state == lifecycleInstallCompleted {
			return errors.New("lifecycle install operation is already completed; resume install cleanup or uninstall the ready gateway instead of aborting a partial install")
		}
		if after.anchor.installOperationEpoch > 0 {
			epochExact := installStatus.epoch == after.anchor.installOperationEpoch
			takeoverCrash := (after.anchor.state == "installing" || after.anchor.state == "aborting") && installStatus.state == lifecycleInstallAborting && installStatus.epoch == after.anchor.installOperationEpoch+1
			if (!epochExact && !takeoverCrash) || !installStatus.notAfter.Equal(after.anchor.installOperationNotAfter) {
				return errors.New("control-plane install operation epoch/deadline differs from the exact lifecycle anchor")
			}
		}
		mirrorAbortFence := func(operation lifecycleInstallOperationStatus) error {
			fencedAnchor := after.anchor
			fencedAnchor.state = "aborting"
			fencedAnchor.installOperationEpoch = operation.epoch
			fencedAnchor.installOperationNotAfter = operation.notAfter
			if abortAnchorFingerprint(fencedAnchor) == abortAnchorFingerprint(after.anchor) {
				return nil
			}
			fenced, fenceErr := updateLifecycleAnchor(ctx, deps, installOptions{release: o.release, namespace: o.namespace, kubeContext: o.kubeContext}, fencedAnchor)
			if fenceErr != nil {
				return fmt.Errorf("CAS-fence lifecycle anchor and exact install epoch before abort coordination: %w", fenceErr)
			}
			after.anchor = fenced
			return nil
		}
		preBeginNoHolder := after.anchor.state == "acknowledged" && after.anchor.installOperationEpoch == 0 && after.anchor.installOperationNotAfter.IsZero() &&
			(installStatus.state == lifecycleInstallActive || installStatus.state == lifecycleInstallAbortRequested || installStatus.state == lifecycleInstallExpired || installStatus.state == lifecycleInstallReleased)
		resumeNoHolderFence := after.anchor.state == "aborting" && installStatus.state == lifecycleInstallActive &&
			after.anchor.installOperationEpoch == installStatus.epoch && after.anchor.installOperationNotAfter.Equal(installStatus.notAfter)
		if preBeginNoHolder || resumeNoHolderFence {
			// No invocation can hold this authority unless it wins the same
			// acknowledged->installing anchor CAS. Win the aborting CAS first;
			// only then Release the newly-created/no-holder CP operation so abort
			// takeover is immediate. A CAS loser never releases a winner's grant.
			if err := mirrorAbortFence(installStatus); err != nil {
				return err
			}
			if installStatus.state != lifecycleInstallReleased {
				installStatus, err = releaseLifecycleInstallBeforeAbort(ctx, installCP, org.id, installBegin, installStatus)
				if err != nil {
					return fmt.Errorf("release fenced no-holder lifecycle install operation before abort takeover: %w", err)
				}
			}
			installAbort, err = requestLifecycleInstallAbort(ctx, installCP, org.id, installBegin, installStatus)
			if err != nil {
				return fmt.Errorf("coordinate no-holder lifecycle install abort takeover: %w", err)
			}
		} else {
			// Once a holder may exist, the control-plane request is the abort
			// linearization point. Its next heartbeat/Complete observes
			// abort_requested even if this process crashes before the K8s mirror.
			installAbort, err = requestLifecycleInstallAbort(ctx, installCP, org.id, installBegin, installStatus)
			if err != nil {
				return fmt.Errorf("durably request exact lifecycle install abort before Kubernetes fence: %w", err)
			}
			operationForFence := installStatus
			if installAbort.operationStatus != nil {
				operationForFence = *installAbort.operationStatus
			}
			if err := mirrorAbortFence(operationForFence); err != nil {
				return err
			}
		}
	} else if after.anchor.state != "aborting" {
		fencedAnchor := after.anchor
		fencedAnchor.state = "aborting"
		fenced, fenceErr := updateLifecycleAnchor(ctx, deps, installOptions{
			release: o.release, namespace: o.namespace, kubeContext: o.kubeContext,
		}, fencedAnchor)
		if fenceErr != nil {
			return fmt.Errorf("CAS-fence lifecycle anchor before control-plane abort: %w", fenceErr)
		}
		after.anchor = fenced
	}
	if after.anchor.state != "aborting" {
		return errors.New("lifecycle anchor is not durably fenced as aborting")
	}
	// Re-read every retained object and the CP claim after the fence. CP state
	// may advance under the exact request and a stale installer may create the
	// owner-bound Secret in the residual read/create window; both transitions
	// are closed by the same abort while anchor/PVC identity must not drift.
	fencedSnapshot, inspectErr := inspectAbortInstall(ctx, deps, cp, org, o)
	if inspectErr != nil {
		return inspectErr
	}
	if abortAnchorFingerprint(fencedSnapshot.anchor) != abortAnchorFingerprint(after.anchor) || abortPVCFingerprint(fencedSnapshot.pvc) != abortPVCFingerprint(after.pvc) {
		return errors.New("lifecycle anchor or retained PVC changed after the abort fence")
	}
	if after.secret != nil && abortSecretFingerprint(fencedSnapshot.secret) != abortSecretFingerprint(after.secret) {
		return errors.New("bootstrap Secret changed or disappeared after the abort fence")
	}
	after = fencedSnapshot

	var aborted k8sLifecycleClaimStatus
	if isGenerationZeroAbortAnchor(after.anchor) {
		aborter, ok := cp.(generationZeroLifecycleAborter)
		if !ok {
			return errors.New("control-plane client does not support atomic generation-zero lifecycle abort")
		}
		aborted, err = aborter.AbortLifecycleClaimBeforeMint(ctx, org.id, o.claim, after.anchor.nodeName, after.anchor.requestID)
		if err != nil {
			return err
		}
		if err := validateGenerationZeroAbortResponse(aborted, after.status, after.anchor); err != nil {
			return fmt.Errorf("Kubernetes recovery metadata was retained: %w", err)
		}
	} else if hasInstallOperation {
		coordination := installAbort
		if coordination.operationStatus != nil && coordination.operationStatus.state == lifecycleInstallAbortRequested {
			var coordinateErr error
			coordination, coordinateErr = coordinateLifecycleInstallAbortUntilTakeover(ctx, deps, installCP, org.id, installBegin, *coordination.operationStatus)
			if coordinateErr != nil {
				return fmt.Errorf("lifecycle install abort is not yet finalized; recovery metadata was retained: %w", coordinateErr)
			}
		}
		if coordination.claimStatus != nil {
			aborted = *coordination.claimStatus
			if err := validatePositiveAbortResponse(aborted, after.status, after.anchor); err != nil {
				return fmt.Errorf("terminal lifecycle install abort did not match the exact claim: %w", err)
			}
			claim := ""
			if after.pvc != nil {
				claim = after.pvc.Metadata.Name
			}
			if err := proveGatewayReleaseAndWorkloadsAbsent(ctx, deps, installOptions{release: o.release, namespace: o.namespace, kubeContext: o.kubeContext}, after.anchor, claim); err != nil {
				return fmt.Errorf("control-plane claim is aborted but exact release/workload absence is not proven; recovery metadata was retained: %w", err)
			}
		} else {
			takeover := *coordination.operationStatus
			if takeover.state != lifecycleInstallAborting {
				return errors.New("lifecycle install abort coordination did not return exact takeover authority")
			}
			if after.anchor.installOperationEpoch != takeover.epoch || !after.anchor.installOperationNotAfter.Equal(takeover.notAfter) {
				fencedAnchor := after.anchor
				fencedAnchor.installOperationEpoch = takeover.epoch
				fencedAnchor.installOperationNotAfter = takeover.notAfter
				fenced, fenceErr := updateLifecycleAnchor(ctx, deps, installOptions{release: o.release, namespace: o.namespace, kubeContext: o.kubeContext}, fencedAnchor)
				if fenceErr != nil {
					return fmt.Errorf("CAS-mirror lifecycle abort takeover epoch: %w", fenceErr)
				}
				after.anchor = fenced
			}
			latest, inspectErr := inspectAbortInstall(ctx, deps, cp, org, o)
			if inspectErr != nil {
				return inspectErr
			}
			if abortAnchorFingerprint(latest.anchor) != abortAnchorFingerprint(after.anchor) || abortPVCFingerprint(latest.pvc) != abortPVCFingerprint(after.pvc) {
				return errors.New("lifecycle anchor or retained PVC changed after install-operation takeover")
			}
			if after.secret != nil && abortSecretFingerprint(latest.secret) != abortSecretFingerprint(after.secret) {
				return errors.New("bootstrap Secret changed or disappeared after install-operation takeover")
			}
			after = latest
			claim := ""
			if after.pvc != nil {
				claim = after.pvc.Metadata.Name
			}
			if err := reconcileLifecycleAbortRelease(ctx, deps, o, after.anchor, after.release, claim); err != nil {
				return fmt.Errorf("install abort takeover retained recovery metadata because release/workload reconciliation failed: %w", err)
			}
			aborted, err = installCP.FinalizeLifecycleInstallAbort(ctx, org.id, lifecycleInstallCASFromStatus(takeover))
			if err != nil {
				return fmt.Errorf("finalize exact lifecycle install abort after release absence: %w", err)
			}
			if err := validatePositiveAbortResponse(aborted, after.status, after.anchor); err != nil {
				return fmt.Errorf("finalized lifecycle install abort did not match the exact claim: %w", err)
			}
		}
	} else {
		aborted, err = cp.AbortLifecycleClaim(ctx, org.id, o.claim, after.status.generation, after.status.requestID)
		if err != nil {
			return err
		}
		if err := validatePositiveAbortResponse(aborted, after.status, after.anchor); err != nil {
			return fmt.Errorf("control-plane abort response did not match the exact lifecycle claim; Kubernetes recovery metadata was retained: %w", err)
		}
	}
	if after.secret != nil {
		if err := deleteOwnedBootstrapSecret(ctx, deps.runner, o.kubeContext, o.namespace, o.timeout, after.secret.name, o.release, after.anchor, *after.secret); err != nil {
			return fmt.Errorf("control-plane claim was aborted, but bootstrap Secret cleanup failed; rerun abort-install with the same claim: %w", err)
		}
	}
	if err := deleteOwnedLifecycleAnchor(ctx, deps.runner, o.kubeContext, o.namespace, o.timeout, o.release, after.anchor); err != nil {
		return fmt.Errorf("control-plane claim was aborted, but lifecycle anchor cleanup failed; rerun abort-install with the same claim: %w", err)
	}
	_, err = fmt.Fprintf(deps.out, "Partial install %q was aborted for lifecycle claim %s. Any retained PVC was not deleted.\n", o.release, o.claim)
	return err
}

func requireAbortInstallConfirmation(deps k8sDeps, o *abortInstallOptions) error {
	want := "ABORT " + o.claim
	if strings.TrimSpace(o.confirmation) == "" {
		if _, err := fmt.Fprintf(deps.out, "Type %q to abort this exact context/namespace/release/claim: ", want); err != nil {
			return err
		}
		line, readErr := bufio.NewReader(deps.in).ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		o.confirmation = strings.TrimSpace(line)
	}
	if o.confirmation != want {
		return fmt.Errorf("confirmation did not match exactly %q; nothing was aborted", want)
	}
	return nil
}

func completeAlreadyAbortedInstall(ctx context.Context, deps k8sDeps, cp k8sControlPlane, org k8sOrganization, o abortInstallOptions) error {
	if err := proveExactGatewayObjectsAbsent(ctx, deps, installOptions{release: o.release, namespace: o.namespace, kubeContext: o.kubeContext}, ""); err != nil {
		return fmt.Errorf("owned lifecycle anchor is absent but exact release/workload absence is not proven: %w", err)
	}
	secret, err := getBootstrapSecretMetadata(ctx, deps.runner, o.kubeContext, o.namespace, o.release+"-bootstrap")
	if err != nil {
		return err
	}
	if secret != nil {
		return errors.New("owned lifecycle anchor is absent but bootstrap Secret metadata remains; refusing unbound cleanup")
	}
	status, err := cp.GetLifecycleClaimStatus(ctx, org.id, o.claim)
	if err != nil {
		return fmt.Errorf("owned lifecycle anchor is absent and exact control-plane abort completion could not be proven: %w", err)
	}
	if err := validateAlreadyAbortedLifecycleStatus(status, o.claim); err != nil {
		return fmt.Errorf("owned lifecycle anchor is absent and the exact control-plane claim is not an aborted lifecycle identity: %w", err)
	}
	impact := map[string]any{
		"action": "abort-install", "context": o.kubeContext, "namespace": o.namespace, "release": o.release,
		"organization_id": org.id, "lifecycle_claim": o.claim, "generation": status.generation, "control_plane_state": status.state,
		"impact": []string{"confirm the exact lifecycle claim is already permanently aborted", "confirm no Helm release, lifecycle anchor, or bootstrap Secret remains under the typed scope", "retain any PVC for explicit purge-state recovery"},
	}
	if err := writeJSON(deps.out, impact); err != nil {
		return err
	}
	if err := requireAbortInstallConfirmation(deps, &o); err != nil {
		return err
	}
	anchorAfter, err := getLifecycleAnchorMetadata(ctx, deps.runner, o.kubeContext, o.namespace, o.release+"-lifecycle")
	if err != nil {
		return err
	}
	secretAfter, err := getBootstrapSecretMetadata(ctx, deps.runner, o.kubeContext, o.namespace, o.release+"-bootstrap")
	if err != nil {
		return err
	}
	objectsAbsentErr := proveExactGatewayObjectsAbsent(ctx, deps, installOptions{release: o.release, namespace: o.namespace, kubeContext: o.kubeContext}, "")
	statusAfter, err := cp.GetLifecycleClaimStatus(ctx, org.id, o.claim)
	if err != nil {
		return err
	}
	if anchorAfter != nil || secretAfter != nil || objectsAbsentErr != nil || lifecycleClaimStatusFingerprint(statusAfter) != lifecycleClaimStatusFingerprint(status) {
		return errors.New("already-aborted claim or Kubernetes recovery scope changed while awaiting confirmation; rerun abort-install")
	}
	_, err = fmt.Fprintf(deps.out, "Lifecycle claim %s is already aborted and no release, bootstrap Secret, or lifecycle anchor remains under %s/%s. Any retained PVC was not deleted.\n", o.claim, o.namespace, o.release)
	return err
}

func lifecycleClaimStatusFingerprint(status k8sLifecycleClaimStatus) string {
	formatOptionalTime := func(value *time.Time) string {
		if value == nil {
			return ""
		}
		return value.UTC().Format(time.RFC3339Nano)
	}
	return strings.Join([]string{
		status.claim, status.state, status.nodeName, strconv.Itoa(status.generation), status.requestID,
		status.expiresAt.UTC().Format(time.RFC3339Nano), formatOptionalTime(status.acknowledgedAt),
		formatOptionalTime(status.consumedAt), formatOptionalTime(status.abortedAt), status.nodeID,
	}, "\x00")
}
