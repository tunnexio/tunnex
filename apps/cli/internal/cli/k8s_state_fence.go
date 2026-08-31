package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	retainedStateFenceContract       = "tunnex-retained-state-fence/v1"
	retainedStateFenceLeaseDuration  = 30 * time.Second
	retainedStateFenceRenewInterval  = 10 * time.Second
	retainedStateFenceCleanupTimeout = 10 * time.Second
	kubernetesMicroTimeLayout        = "2006-01-02T15:04:05.000000Z07:00"

	retainedStateFenceOperationReuse = "reuse"
	retainedStateFenceOperationPurge = "purge"
)

const (
	stateFenceContractAnnotation  = "tunnex.io/state-fence-contract"
	stateFenceReleaseAnnotation   = "tunnex.io/state-fence-release"
	stateFenceClaimAnnotation     = "tunnex.io/state-fence-claim"
	stateFencePVCUIDAnnotation    = "tunnex.io/state-fence-pvc-uid"
	stateFenceNamespaceAnnotation = "tunnex.io/state-fence-namespace"
	stateFenceOperationAnnotation = "tunnex.io/state-fence-operation"
)

// k8sTicker is shared by lifecycle protocols that must make wall-clock
// authority deterministic in tests. Callers read ticks through C rather than
// depending directly on time.Ticker.
type k8sTicker interface {
	C() <-chan time.Time
	Stop()
}

type realK8sTicker struct {
	ticker *time.Ticker
}

func (t realK8sTicker) C() <-chan time.Time { return t.ticker.C }
func (t realK8sTicker) Stop()               { t.ticker.Stop() }

func newRealK8sTicker(interval time.Duration) k8sTicker {
	return realK8sTicker{ticker: time.NewTicker(interval)}
}

type retainedStateFenceBinding struct {
	kubeContext string
	namespace   string
	release     string
	claim       string
	pvcUID      string
}

func (b retainedStateFenceBinding) validate() error {
	if err := validateRelease(b.release); err != nil {
		return err
	}
	if err := validateDNSLabel("namespace", b.namespace, 63); err != nil {
		return err
	}
	if err := validateDNSSubdomain("claim", b.claim, 253); err != nil {
		return err
	}
	if strings.TrimSpace(b.pvcUID) == "" || strings.TrimSpace(b.pvcUID) != b.pvcUID {
		return errors.New("retained state claim lacks an exact PVC UID for fencing")
	}
	return nil
}

func (b retainedStateFenceBinding) leaseName() string {
	// Release names are capped at 42 bytes, so this remains a DNS label.
	return b.release + "-state-fence"
}

type stateFenceOwnerReference struct {
	APIVersion         string `json:"apiVersion"`
	Kind               string `json:"kind"`
	Name               string `json:"name"`
	UID                string `json:"uid"`
	Controller         *bool  `json:"controller,omitempty"`
	BlockOwnerDeletion *bool  `json:"blockOwnerDeletion,omitempty"`
}

type stateFenceLease struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name              string                     `json:"name"`
		Namespace         string                     `json:"namespace"`
		UID               string                     `json:"uid,omitempty"`
		ResourceVersion   string                     `json:"resourceVersion,omitempty"`
		DeletionTimestamp string                     `json:"deletionTimestamp,omitempty"`
		Labels            map[string]string          `json:"labels"`
		Annotations       map[string]string          `json:"annotations"`
		OwnerReferences   []stateFenceOwnerReference `json:"ownerReferences"`
		Finalizers        []string                   `json:"finalizers,omitempty"`
	} `json:"metadata"`
	Spec struct {
		HolderIdentity       string `json:"holderIdentity"`
		LeaseDurationSeconds int32  `json:"leaseDurationSeconds"`
		AcquireTime          string `json:"acquireTime"`
		RenewTime            string `json:"renewTime"`
		LeaseTransitions     int32  `json:"leaseTransitions"`
		Strategy             string `json:"strategy,omitempty"`
		PreferredHolder      string `json:"preferredHolder,omitempty"`
	} `json:"spec"`
}

type validatedStateFenceLease struct {
	acquiredAt time.Time
	renewedAt  time.Time
	expiresAt  time.Time
}

func formatKubernetesMicroTime(value time.Time) string {
	return value.UTC().Truncate(time.Microsecond).Format(kubernetesMicroTimeLayout)
}

func newStateFenceLease(binding retainedStateFenceBinding, operation, operationID string, now time.Time) stateFenceLease {
	lease := stateFenceLease{APIVersion: "coordination.k8s.io/v1", Kind: "Lease"}
	lease.Metadata.Name = binding.leaseName()
	lease.Metadata.Namespace = binding.namespace
	lease.Metadata.Labels = map[string]string{
		"app.kubernetes.io/name":       "tunnex-retained-state-fence",
		"app.kubernetes.io/instance":   binding.release,
		"app.kubernetes.io/managed-by": "tunnex-lifecycle",
	}
	lease.Metadata.Annotations = map[string]string{
		stateFenceContractAnnotation:  retainedStateFenceContract,
		stateFenceReleaseAnnotation:   binding.release,
		stateFenceClaimAnnotation:     binding.claim,
		stateFencePVCUIDAnnotation:    binding.pvcUID,
		stateFenceNamespaceAnnotation: binding.namespace,
		stateFenceOperationAnnotation: operation,
	}
	lease.Metadata.OwnerReferences = []stateFenceOwnerReference{{
		APIVersion: "v1", Kind: "PersistentVolumeClaim", Name: binding.claim, UID: binding.pvcUID,
	}}
	lease.Spec.HolderIdentity = operationID
	lease.Spec.LeaseDurationSeconds = int32(retainedStateFenceLeaseDuration / time.Second)
	// coordination.k8s.io/v1 Lease uses metav1.MicroTime. The API server's
	// decoder requires exactly six fractional digits; RFC3339Nano may emit nine
	// and is rejected before the fence can be created.
	lease.Spec.AcquireTime = formatKubernetesMicroTime(now)
	lease.Spec.RenewTime = lease.Spec.AcquireTime
	return lease
}

func validateStateFenceOperation(operation string) error {
	if operation != retainedStateFenceOperationReuse && operation != retainedStateFenceOperationPurge {
		return fmt.Errorf("unsupported retained-state fence operation %q", operation)
	}
	return nil
}

func validateStateFenceOperationID(operationID string) error {
	parsed, err := uuid.Parse(operationID)
	if err != nil || parsed == uuid.Nil || parsed.String() != operationID {
		return errors.New("retained-state fence operation identity is not a canonical non-zero UUID")
	}
	return nil
}

func validateStateFenceLease(lease stateFenceLease, binding retainedStateFenceBinding, now time.Time) (validatedStateFenceLease, error) {
	name := binding.leaseName()
	if lease.APIVersion != "coordination.k8s.io/v1" || lease.Kind != "Lease" ||
		lease.Metadata.Name != name || lease.Metadata.Namespace != binding.namespace ||
		lease.Metadata.UID == "" || lease.Metadata.ResourceVersion == "" || lease.Metadata.DeletionTimestamp != "" {
		return validatedStateFenceLease{}, fmt.Errorf("retained-state Lease %q has malformed or unstable object identity", name)
	}
	if len(lease.Metadata.Finalizers) != 0 {
		return validatedStateFenceLease{}, fmt.Errorf("retained-state Lease %q has unexpected finalizers", name)
	}
	if lease.Metadata.Labels["app.kubernetes.io/name"] != "tunnex-retained-state-fence" ||
		lease.Metadata.Labels["app.kubernetes.io/instance"] != binding.release ||
		lease.Metadata.Labels["app.kubernetes.io/managed-by"] != "tunnex-lifecycle" ||
		lease.Metadata.Annotations[stateFenceContractAnnotation] != retainedStateFenceContract ||
		lease.Metadata.Annotations[stateFenceReleaseAnnotation] != binding.release ||
		lease.Metadata.Annotations[stateFenceClaimAnnotation] != binding.claim ||
		lease.Metadata.Annotations[stateFencePVCUIDAnnotation] != binding.pvcUID ||
		lease.Metadata.Annotations[stateFenceNamespaceAnnotation] != binding.namespace {
		return validatedStateFenceLease{}, fmt.Errorf("retained-state Lease %q is foreign or bound to different state", name)
	}
	if err := validateStateFenceOperation(lease.Metadata.Annotations[stateFenceOperationAnnotation]); err != nil {
		return validatedStateFenceLease{}, fmt.Errorf("retained-state Lease %q: %w", name, err)
	}
	if len(lease.Metadata.OwnerReferences) != 1 {
		return validatedStateFenceLease{}, fmt.Errorf("retained-state Lease %q does not have one exact PVC owner", name)
	}
	owner := lease.Metadata.OwnerReferences[0]
	if owner.APIVersion != "v1" || owner.Kind != "PersistentVolumeClaim" || owner.Name != binding.claim || owner.UID != binding.pvcUID ||
		(owner.Controller != nil && *owner.Controller) || (owner.BlockOwnerDeletion != nil && *owner.BlockOwnerDeletion) {
		return validatedStateFenceLease{}, fmt.Errorf("retained-state Lease %q PVC owner binding differs from the approved claim", name)
	}
	if lease.Spec.Strategy != "" || lease.Spec.PreferredHolder != "" {
		return validatedStateFenceLease{}, fmt.Errorf("retained-state Lease %q has foreign coordinated-election fields", name)
	}
	if err := validateStateFenceOperationID(lease.Spec.HolderIdentity); err != nil {
		return validatedStateFenceLease{}, fmt.Errorf("retained-state Lease %q: %w", name, err)
	}
	maxDurationSeconds := int32(retainedStateFenceLeaseDuration / time.Second)
	if lease.Spec.LeaseDurationSeconds <= 0 || lease.Spec.LeaseDurationSeconds > maxDurationSeconds {
		return validatedStateFenceLease{}, fmt.Errorf("retained-state Lease %q has an unbounded duration", name)
	}
	if lease.Spec.LeaseTransitions < 0 {
		return validatedStateFenceLease{}, fmt.Errorf("retained-state Lease %q has a negative transition count", name)
	}
	acquiredAt, err := time.Parse(time.RFC3339Nano, lease.Spec.AcquireTime)
	if err != nil {
		return validatedStateFenceLease{}, fmt.Errorf("retained-state Lease %q has malformed acquireTime", name)
	}
	renewedAt, err := time.Parse(time.RFC3339Nano, lease.Spec.RenewTime)
	if err != nil || renewedAt.Before(acquiredAt) {
		return validatedStateFenceLease{}, fmt.Errorf("retained-state Lease %q has malformed renewTime", name)
	}
	duration := time.Duration(lease.Spec.LeaseDurationSeconds) * time.Second
	// Refuse clocks far enough in the future to turn a bounded Lease into an
	// effectively unbounded foreign lock. One lease duration permits ordinary
	// client/API-server skew while keeping the upper bound finite.
	if renewedAt.After(now.UTC().Add(retainedStateFenceLeaseDuration)) {
		return validatedStateFenceLease{}, fmt.Errorf("retained-state Lease %q renewTime is implausibly in the future", name)
	}
	return validatedStateFenceLease{
		acquiredAt: acquiredAt.UTC(), renewedAt: renewedAt.UTC(), expiresAt: renewedAt.UTC().Add(duration),
	}, nil
}

func readStateFenceLease(ctx context.Context, runner k8sRunner, binding retainedStateFenceBinding) (*stateFenceLease, error) {
	result, err := runChecked(ctx, runner, "read retained-state Lease", k8sCommand{
		name: "kubectl",
		args: kubectlArgs(binding.kubeContext, "get", "lease", binding.leaseName(), "--namespace", binding.namespace, "--ignore-not-found=true", "--output", "json"),
	})
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(result.stdout)) == "" {
		return nil, nil
	}
	var lease stateFenceLease
	if err := json.Unmarshal(result.stdout, &lease); err != nil {
		return nil, fmt.Errorf("decode retained-state Lease: %w", err)
	}
	return &lease, nil
}

func createStateFenceLease(ctx context.Context, runner k8sRunner, binding retainedStateFenceBinding, lease stateFenceLease) error {
	manifest, err := json.Marshal(lease)
	if err != nil {
		return fmt.Errorf("encode retained-state Lease: %w", err)
	}
	_, err = runChecked(ctx, runner, "create retained-state Lease", k8sCommand{
		name: "kubectl", args: kubectlArgs(binding.kubeContext, "create", "-f", "-"), stdin: manifest,
	})
	return err
}

func replaceStateFenceLease(ctx context.Context, runner k8sRunner, binding retainedStateFenceBinding, lease stateFenceLease) error {
	manifest, err := json.Marshal(lease)
	if err != nil {
		return fmt.Errorf("encode retained-state Lease CAS: %w", err)
	}
	rawPath := "/apis/coordination.k8s.io/v1/namespaces/" + binding.namespace + "/leases/" + binding.leaseName()
	_, err = runChecked(ctx, runner, "replace retained-state Lease with UID/resourceVersion CAS", k8sCommand{
		name: "kubectl", args: kubectlArgs(binding.kubeContext, "replace", "--raw="+rawPath, "-f", "-"), stdin: manifest,
	})
	return err
}

type retainedStateFence struct {
	runner      k8sRunner
	binding     retainedStateFenceBinding
	operation   string
	operationID string
	now         func() time.Time

	mu              sync.Mutex
	uid             string
	resourceVersion string
}

func acquireRetainedStateFence(
	ctx context.Context,
	deps k8sDeps,
	binding retainedStateFenceBinding,
	operation string,
	reprove func(context.Context) error,
) (*retainedStateFence, error) {
	if err := binding.validate(); err != nil {
		return nil, err
	}
	if err := validateStateFenceOperation(operation); err != nil {
		return nil, err
	}
	operationID := deps.newOperationID()
	if err := validateStateFenceOperationID(operationID); err != nil {
		return nil, err
	}
	now := deps.now().UTC()
	existing, err := readStateFenceLease(ctx, deps.runner, binding)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		created := newStateFenceLease(binding, operation, operationID, now)
		createErr := createStateFenceLease(ctx, deps.runner, binding, created)
		readback, readErr := readStateFenceLease(ctx, deps.runner, binding)
		if readErr != nil {
			return nil, errors.Join(createErr, fmt.Errorf("read back retained-state Lease after create: %w", readErr))
		}
		if readback == nil {
			if createErr != nil {
				return nil, createErr
			}
			return nil, errors.New("retained-state Lease create succeeded without a live readback")
		}
		if createErr == nil {
			if _, err := validateStateFenceLease(*readback, binding, deps.now()); err != nil {
				return nil, err
			}
			if readback.Spec.HolderIdentity != operationID || readback.Metadata.Annotations[stateFenceOperationAnnotation] != operation {
				return nil, fmt.Errorf("retained-state Lease %q was replaced by another holder during create readback", binding.leaseName())
			}
			return &retainedStateFence{
				runner: deps.runner, binding: binding, operation: operation, operationID: operationID, now: deps.now,
				uid: readback.Metadata.UID, resourceVersion: readback.Metadata.ResourceVersion,
			}, nil
		}
		// The create response may have been lost after the API server persisted
		// the Lease. Classify the live object below; only this exact operation can
		// resume it, and even that path first re-proves the state.
		existing = readback
	}

	validated, err := validateStateFenceLease(*existing, binding, deps.now())
	if err != nil {
		return nil, err
	}
	if existing.Spec.HolderIdentity != operationID && deps.now().UTC().Before(validated.expiresAt) {
		return nil, fmt.Errorf("retained state claim %q is fenced by live %s operation %s until %s", binding.claim,
			existing.Metadata.Annotations[stateFenceOperationAnnotation], existing.Spec.HolderIdentity, validated.expiresAt.Format(time.RFC3339Nano))
	}
	if reprove == nil {
		return nil, errors.New("retained-state Lease resume/takeover requires an exact fresh reproof")
	}
	if err := reprove(ctx); err != nil {
		return nil, fmt.Errorf("re-prove retained state before Lease resume/takeover: %w", err)
	}

	next := newStateFenceLease(binding, operation, operationID, deps.now())
	next.Metadata.UID = existing.Metadata.UID
	next.Metadata.ResourceVersion = existing.Metadata.ResourceVersion
	if existing.Spec.HolderIdentity == operationID {
		next.Spec.AcquireTime = existing.Spec.AcquireTime
		next.Spec.LeaseTransitions = existing.Spec.LeaseTransitions
	} else {
		if existing.Spec.LeaseTransitions == math.MaxInt32 {
			return nil, errors.New("retained-state Lease transition counter is exhausted")
		}
		next.Spec.LeaseTransitions = existing.Spec.LeaseTransitions + 1
	}
	if err := replaceStateFenceLease(ctx, deps.runner, binding, next); err != nil {
		return nil, err
	}
	readback, err := readStateFenceLease(ctx, deps.runner, binding)
	if err != nil {
		return nil, fmt.Errorf("read back retained-state Lease after CAS: %w", err)
	}
	if readback == nil {
		return nil, errors.New("retained-state Lease disappeared after CAS")
	}
	if _, err := validateStateFenceLease(*readback, binding, deps.now()); err != nil {
		return nil, err
	}
	if readback.Metadata.UID != existing.Metadata.UID || readback.Spec.HolderIdentity != operationID ||
		readback.Metadata.Annotations[stateFenceOperationAnnotation] != operation {
		return nil, errors.New("retained-state Lease CAS readback is owned by another operation")
	}
	return &retainedStateFence{
		runner: deps.runner, binding: binding, operation: operation, operationID: operationID, now: deps.now,
		uid: readback.Metadata.UID, resourceVersion: readback.Metadata.ResourceVersion,
	}, nil
}

func (f *retainedStateFence) renew(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	current, err := readStateFenceLease(ctx, f.runner, f.binding)
	if err != nil {
		return err
	}
	if current == nil {
		return errors.New("retained-state Lease disappeared")
	}
	validated, err := validateStateFenceLease(*current, f.binding, f.now())
	if err != nil {
		return err
	}
	if current.Metadata.UID != f.uid || current.Spec.HolderIdentity != f.operationID ||
		current.Metadata.Annotations[stateFenceOperationAnnotation] != f.operation {
		return errors.New("retained-state Lease is no longer held by this operation")
	}
	if !f.now().UTC().Before(validated.expiresAt) {
		return errors.New("retained-state Lease expired before renewal")
	}
	next := newStateFenceLease(f.binding, f.operation, f.operationID, f.now())
	next.Metadata.UID = current.Metadata.UID
	next.Metadata.ResourceVersion = current.Metadata.ResourceVersion
	next.Spec.AcquireTime = current.Spec.AcquireTime
	next.Spec.LeaseTransitions = current.Spec.LeaseTransitions
	if err := replaceStateFenceLease(ctx, f.runner, f.binding, next); err != nil {
		return err
	}
	readback, err := readStateFenceLease(ctx, f.runner, f.binding)
	if err != nil {
		return fmt.Errorf("read back renewed retained-state Lease: %w", err)
	}
	if readback == nil {
		return errors.New("renewed retained-state Lease disappeared")
	}
	if _, err := validateStateFenceLease(*readback, f.binding, f.now()); err != nil {
		return err
	}
	if readback.Metadata.UID != f.uid || readback.Spec.HolderIdentity != f.operationID ||
		readback.Metadata.Annotations[stateFenceOperationAnnotation] != f.operation {
		return errors.New("renewed retained-state Lease readback is no longer held by this operation")
	}
	f.resourceVersion = readback.Metadata.ResourceVersion
	return nil
}

func (f *retainedStateFence) release(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	current, err := readStateFenceLease(ctx, f.runner, f.binding)
	if err != nil {
		return err
	}
	if current == nil {
		return nil
	}
	if _, err := validateStateFenceLease(*current, f.binding, f.now()); err != nil {
		return err
	}
	if current.Metadata.UID != f.uid || current.Spec.HolderIdentity != f.operationID ||
		current.Metadata.Annotations[stateFenceOperationAnnotation] != f.operation {
		return errors.New("retained-state Lease is held by another operation; refusing to delete it")
	}
	deleteOptions, err := json.Marshal(map[string]any{
		"apiVersion": "v1", "kind": "DeleteOptions",
		"preconditions": map[string]string{"uid": current.Metadata.UID, "resourceVersion": current.Metadata.ResourceVersion},
	})
	if err != nil {
		return fmt.Errorf("encode retained-state Lease deletion: %w", err)
	}
	rawPath := "/apis/coordination.k8s.io/v1/namespaces/" + f.binding.namespace + "/leases/" + f.binding.leaseName()
	_, deleteErr := runChecked(ctx, f.runner, "delete retained-state Lease with UID/resourceVersion preconditions", k8sCommand{
		name: "kubectl", args: kubectlArgs(f.binding.kubeContext, "delete", "--raw="+rawPath, "-f", "-"), stdin: deleteOptions,
	})
	readback, readErr := readStateFenceLease(ctx, f.runner, f.binding)
	if readErr != nil {
		return errors.Join(deleteErr, fmt.Errorf("read back retained-state Lease after release: %w", readErr))
	}
	if readback == nil {
		return nil
	}
	// A successor may create a new Lease after this operation's preconditioned
	// delete. Its UID/holder is foreign and must be left untouched.
	if readback.Metadata.UID != current.Metadata.UID || readback.Spec.HolderIdentity != f.operationID {
		return nil
	}
	if deleteErr != nil {
		return deleteErr
	}
	return errors.New("retained-state Lease remained after successful release request")
}

type retainedStateFenceRenewal struct {
	ctx      context.Context
	cancel   context.CancelCauseFunc
	ticker   k8sTicker
	stopCh   chan struct{}
	done     chan error
	stopOnce sync.Once
	stopErr  error
}

func startRetainedStateFenceRenewal(ctx context.Context, deps k8sDeps, fence *retainedStateFence) *retainedStateFenceRenewal {
	renewCtx, cancel := context.WithCancelCause(ctx)
	renewal := &retainedStateFenceRenewal{
		ctx: renewCtx, cancel: cancel, ticker: deps.newTicker(retainedStateFenceRenewInterval),
		stopCh: make(chan struct{}), done: make(chan error, 1),
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				renewal.done <- nil
				return
			case <-renewal.stopCh:
				renewal.done <- nil
				return
			case <-renewal.ticker.C():
				if err := fence.renew(renewCtx); err != nil {
					select {
					case <-renewal.stopCh:
						renewal.done <- nil
						return
					default:
					}
					if ctx.Err() != nil {
						renewal.done <- nil
						return
					}
					err = fmt.Errorf("retained-state Lease renewal failed: %w", err)
					cancel(err)
					renewal.done <- err
					return
				}
			}
		}
	}()
	return renewal
}

func (r *retainedStateFenceRenewal) stop() error {
	r.stopOnce.Do(func() {
		close(r.stopCh)
		r.ticker.Stop()
		r.cancel(context.Canceled)
		r.stopErr = <-r.done
	})
	return r.stopErr
}

func retainedStateFenceCleanupContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), retainedStateFenceCleanupTimeout)
}

func retainedStateFenceBindingForReuse(prepared preparedInstall) (retainedStateFenceBinding, error) {
	o := prepared.options
	binding := retainedStateFenceBinding{
		kubeContext: o.kubeContext, namespace: o.namespace, release: o.release,
		claim: o.existingClaim, pvcUID: prepared.state.pvcUID,
	}
	if o.mode != "reuse" || !prepared.state.pvcExists || prepared.state.pvcName != o.existingClaim {
		return retainedStateFenceBinding{}, errors.New("reuse plan lacks one exact retained PVC binding")
	}
	if err := binding.validate(); err != nil {
		return retainedStateFenceBinding{}, err
	}
	return binding, nil
}

func reproveReuseStateFence(ctx context.Context, deps k8sDeps, o installOptions, binding retainedStateFenceBinding, approvedFingerprint string) error {
	if approvedFingerprint == "" {
		if o.mode != "reuse" || o.kubeContext != binding.kubeContext || o.namespace != binding.namespace ||
			o.release != binding.release || o.existingClaim != binding.claim {
			return errors.New("reuse failure reproof does not match the retained-state fence binding")
		}
		releases, err := listHelmReleases(ctx, deps.runner, binding.kubeContext, binding.namespace, binding.release)
		if err != nil {
			return fmt.Errorf("prove exact Helm release absence before releasing retained-state fence: %w", err)
		}
		if len(releases) != 0 {
			return fmt.Errorf("Helm release %q exists after failed reuse; retained-state fence must remain until bounded expiry", binding.release)
		}
		selector := "app.kubernetes.io/name=tunnex-gateway,app.kubernetes.io/instance=" + binding.release
		workloads, err := runChecked(ctx, deps.runner, "prove failed reuse workloads absent", k8sCommand{
			name: "kubectl",
			args: kubectlArgs(binding.kubeContext, "get", "deployments,statefulsets,daemonsets,jobs,pods,services", "--namespace", binding.namespace, "--selector", selector, "--ignore-not-found=true", "--output", "name"),
		})
		if err != nil {
			return fmt.Errorf("prove exact gateway workload absence before releasing retained-state fence: %w", err)
		}
		if strings.TrimSpace(string(workloads.stdout)) != "" {
			return fmt.Errorf("gateway workloads remain after failed reuse; retained-state fence must remain until bounded expiry")
		}
		mountedBy, err := claimMountedByLivePod(ctx, deps.runner, binding.kubeContext, binding.namespace, binding.claim)
		if err != nil {
			return fmt.Errorf("prove retained claim mount absence before releasing retained-state fence: %w", err)
		}
		if mountedBy != "" {
			return fmt.Errorf("retained state claim %q is mounted by %s after failed reuse; retained-state fence must remain until bounded expiry", binding.claim, mountedBy)
		}
		pvc, err := getPVC(ctx, deps.runner, binding.kubeContext, binding.namespace, binding.claim)
		if err != nil {
			return err
		}
		if err := validateGatewayIdentityPVC(pvc, binding.claim, binding.release); err != nil {
			return err
		}
		if pvc.Metadata.DeletionTimestamp != "" || pvc.Metadata.UID != binding.pvcUID {
			return errors.New("retained state claim no longer has the approved non-terminating PVC UID binding")
		}
		return nil
	}
	state, err := discoverInstallState(ctx, deps.runner, o)
	if err != nil {
		return err
	}
	if approvedFingerprint != "" && state.fingerprint() != approvedFingerprint {
		return errors.New("Kubernetes release/claim state differs from the approved reuse plan")
	}
	if !state.pvcExists || state.pvcName != binding.claim || state.pvcUID != binding.pvcUID {
		return errors.New("retained state claim no longer has the approved PVC UID binding")
	}
	return nil
}
