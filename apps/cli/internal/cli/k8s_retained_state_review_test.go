package cli

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	retainedReviewOrganizationID = "11111111-1111-1111-1111-111111111111"
	retainedReviewForeignOrgID   = "22222222-2222-2222-2222-222222222222"
	retainedReviewForeignClaim   = "88888888-8888-8888-8888-888888888888"
	retainedReviewForeignNodeID  = "99999999-9999-9999-9999-999999999999"
)

var retainedReviewConsumedAt = time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

type retainedReviewClaimRead struct {
	organizationID string
	claim          string
}

type retainedReviewControlPlane struct {
	*fakeK8sControlPlane
	claimReads []retainedReviewClaimRead
}

func (c *retainedReviewControlPlane) GetLifecycleClaimStatus(ctx context.Context, organizationID, claim string) (k8sLifecycleClaimStatus, error) {
	c.claimReads = append(c.claimReads, retainedReviewClaimRead{organizationID: organizationID, claim: claim})
	return c.fakeK8sControlPlane.GetLifecycleClaimStatus(ctx, organizationID, claim)
}

// retainedReuseControlPlane is shared by pre-existing successful reuse tests.
// A deliberately unrelated historical node name proves that mutable display
// names are not used as the identity authority; the consumed claim's canonical
// node UUID is the immutable binding.
func retainedReuseControlPlane() *fakeK8sControlPlane {
	cp := baseK8sControlPlane()
	consumedAt := retainedReviewConsumedAt
	cp.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{
		claim: testLifecycleClaim, state: "consumed", nodeName: "historical-name-does-not-authorize-reuse",
		generation: 1, requestID: testLifecycleRequest, expiresAt: testLifecycleExpiry,
		consumedAt: &consumedAt, nodeID: testLifecycleNodeID,
	}
	return cp
}

func assertRetainedReviewNoClusterMutation(t *testing.T, runner *fakeK8sRunner, cp *fakeK8sControlPlane) {
	t.Helper()
	for _, command := range runner.commands {
		if command.name == "helm" && len(command.args) != 0 {
			switch command.args[0] {
			case "install", "uninstall", "rollback":
				t.Fatalf("unproven retained state reached Helm mutation: %+v", command)
			case "upgrade":
				if len(command.args) < 2 || command.args[1] != "--help" {
					t.Fatalf("unproven retained state reached Helm mutation: %+v", command)
				}
			}
		}
		if command.name == "kubectl" {
			joined := " " + strings.Join(command.args, " ") + " "
			for _, verb := range []string{" create ", " replace ", " delete ", " patch ", " apply ", " scale "} {
				if strings.Contains(joined, verb) {
					t.Fatalf("unproven retained state reached Kubernetes mutation: %+v", command)
				}
			}
		}
	}
	if cp.issueCount != 0 || cp.abortCount != 0 || cp.installBeginCount != 0 || cp.installHeartbeatCount != 0 ||
		cp.installReleaseCount != 0 || cp.installCompleteCount != 0 || cp.installAbortCount != 0 || cp.installFinalizeAbortCount != 0 {
		t.Fatalf("unproven retained state mutated control plane: issue=%d abort=%d begin=%d heartbeat=%d release=%d complete=%d coordinate=%d finalize=%d",
			cp.issueCount, cp.abortCount, cp.installBeginCount, cp.installHeartbeatCount, cp.installReleaseCount, cp.installCompleteCount, cp.installAbortCount, cp.installFinalizeAbortCount)
	}
}

func TestRetainedReviewReuseRequiresExactOrganizationAndConsumedNodeBinding(t *testing.T) {
	t.Run("same organization and immutable node UUID succeed despite mutable name difference", func(t *testing.T) {
		base := retainedReuseControlPlane()
		cp := &retainedReviewControlPlane{fakeK8sControlPlane: base}
		runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
			if command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "get deployment") {
				return stdout(readyDeploymentJSON("tunnex-gateway", "retained-state-a")), nil
			}
			return baseRunnerHandler(command)
		}}
		err := runK8s(context.Background(), []string{"install", "--node-name", "new-display-name", "--mode", "reuse", "--existing-claim", "retained-state-a", "--yes"}, baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}))
		if err != nil {
			t.Fatalf("exact retained reuse: %v", err)
		}
		if len(cp.claimReads) < 3 {
			t.Fatalf("lifecycle proof reads = %d, want prepare, post-approval, and post-Helm reads", len(cp.claimReads))
		}
		for _, read := range cp.claimReads {
			if read.organizationID != retainedReviewOrganizationID || read.claim != testLifecycleClaim {
				t.Fatalf("lifecycle proof read foreign identity: %+v", read)
			}
		}
		if base.issueCount != 0 {
			t.Fatalf("reuse minted %d tokens", base.issueCount)
		}
	})

	t.Run("cross organization refuses before host posture or mutation", func(t *testing.T) {
		base := retainedReuseControlPlane()
		base.orgs = append(base.orgs, k8sOrganization{id: retainedReviewForeignOrgID, name: "Foreign", slug: "foreign"})
		cp := &retainedReviewControlPlane{fakeK8sControlPlane: base}
		pvcBytes := readyPVCJSON("retained-state-a", "tunnex-gateway")
		runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
			if command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "get pvc retained-state-a") {
				return stdout(pvcBytes), nil
			}
			return baseRunnerHandler(command)
		}}
		err := runK8s(context.Background(), []string{"install", "--org", retainedReviewForeignOrgID, "--node-name", "same-name-cannot-authorize", "--mode", "reuse", "--existing-claim", "retained-state-a", "--yes"}, baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}))
		if err == nil || !strings.Contains(err.Error(), "pinned to a different organization") {
			t.Fatalf("cross-organization reuse error = %v", err)
		}
		if len(cp.claimReads) != 0 {
			t.Fatalf("foreign organization reached lifecycle status read: %+v", cp.claimReads)
		}
		for _, command := range runner.commands {
			if command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "get daemonset tunnex-host-posture") {
				t.Fatalf("foreign organization reached host-posture discovery: %+v", command)
			}
		}
		if pvcBytes != readyPVCJSON("retained-state-a", "tunnex-gateway") {
			t.Fatal("retained PVC fixture bytes changed")
		}
		assertRetainedReviewNoClusterMutation(t, runner, base)
	})
}

func TestRetainedReviewReuseRejectsMissingMalformedAndForeignLifecycleBinding(t *testing.T) {
	validPVC := readyPVCJSON("retained-state-a", "tunnex-gateway")
	tests := []struct {
		name      string
		pvc       string
		configure func(*fakeK8sControlPlane)
		want      string
	}{
		{name: "missing PVC provenance", pvc: readyLegacyPVCJSON("retained-state-a", "tunnex-gateway"), want: "has no lifecycle provenance"},
		{name: "partial PVC provenance", pvc: strings.Replace(validPVC, `,"tunnex.io/lifecycle-claim":"`+testLifecycleClaim+`"`, "", 1), want: "lifecycle provenance is invalid"},
		{name: "malformed PVC provenance", pvc: strings.Replace(validPVC, retainedReviewOrganizationID, "NOT-A-UUID", 1), want: "lifecycle provenance is invalid"},
		{name: "absent control-plane claim", pvc: validPVC, want: "lifecycle claim is absent"},
		{
			name: "foreign control-plane claim", pvc: validPVC, want: "does not match its immutable PVC provenance",
			configure: func(cp *fakeK8sControlPlane) {
				consumedAt := retainedReviewConsumedAt
				cp.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{
					claim: retainedReviewForeignClaim, state: "consumed", nodeName: "same-requested-name",
					generation: 1, requestID: testLifecycleRequest, consumedAt: &consumedAt, nodeID: retainedReviewForeignNodeID,
				}
			},
		},
		{
			name: "non-consumed control-plane claim", pvc: validPVC, want: "not one exact consumed canonical node identity",
			configure: func(cp *fakeK8sControlPlane) {
				cp.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{
					claim: testLifecycleClaim, state: "acknowledged", nodeName: "same-requested-name",
					generation: 1, requestID: testLifecycleRequest,
				}
			},
		},
		{
			name: "matching mutable name cannot rescue malformed node UUID", pvc: validPVC, want: "not one exact consumed canonical node identity",
			configure: func(cp *fakeK8sControlPlane) {
				consumedAt := retainedReviewConsumedAt
				cp.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{
					claim: testLifecycleClaim, state: "consumed", nodeName: "same-requested-name",
					generation: 1, requestID: testLifecycleRequest, consumedAt: &consumedAt, nodeID: "not-a-node-uuid",
				}
			},
		},
		{
			name: "missing consumption timestamp", pvc: validPVC, want: "not one exact consumed canonical node identity",
			configure: func(cp *fakeK8sControlPlane) {
				cp.claims[testLifecycleClaim] = k8sLifecycleClaimStatus{
					claim: testLifecycleClaim, state: "consumed", nodeName: "same-requested-name",
					generation: 1, requestID: testLifecycleRequest, nodeID: testLifecycleNodeID,
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cp := baseK8sControlPlane()
			if tc.configure != nil {
				tc.configure(cp)
			}
			pvcBytes := tc.pvc
			runner := &fakeK8sRunner{handler: func(command k8sCommand) (k8sCommandResult, error) {
				if command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "get pvc retained-state-a") {
					return stdout(pvcBytes), nil
				}
				return baseRunnerHandler(command)
			}}
			err := runK8s(context.Background(), []string{"install", "--node-name", "same-requested-name", "--mode", "reuse", "--existing-claim", "retained-state-a", "--yes"}, baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{}))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("reuse binding error = %v, want %q", err, tc.want)
			}
			if pvcBytes != tc.pvc {
				t.Fatal("retained PVC fixture bytes changed")
			}
			assertRetainedReviewNoClusterMutation(t, runner, cp)
		})
	}
}

func TestRetainedReviewReusePinsControlPlaneIdentityAcrossRechecks(t *testing.T) {
	cp := retainedReuseControlPlane()
	o := installOptions{mode: "reuse", existingClaim: "retained-state-a"}
	organization := cp.orgs[0]
	state := installState{
		pvcExists: true, pvcName: o.existingClaim,
		pvcOrganizationID: retainedReviewOrganizationID, pvcLifecycleClaim: testLifecycleClaim,
	}
	if err := validateRetainedPVCReuseControlPlane(context.Background(), cp, organization, o, &state); err != nil {
		t.Fatalf("initial lifecycle proof: %v", err)
	}
	status := cp.claims[testLifecycleClaim]
	status.nodeID = retainedReviewForeignNodeID
	cp.claims[testLifecycleClaim] = status
	if err := validateRetainedPVCReuseControlPlane(context.Background(), cp, organization, o, &state); err == nil || !strings.Contains(err.Error(), "changed after approval") {
		t.Fatalf("changed immutable node binding error = %v", err)
	}
}

func TestRetainedReviewExpiredLeaseTakeoverReprovesControlPlaneIdentity(t *testing.T) {
	base := retainedReuseControlPlane()
	cp := &retainedReviewControlPlane{fakeK8sControlPlane: base}
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	binding := retainedStateFenceBinding{
		kubeContext: "walk-context", namespace: defaultK8sNamespace, release: defaultK8sRelease,
		claim: "retained-state-a", pvcUID: "uid-retained-state-a",
	}
	expired := newStateFenceLease(binding, retainedStateFenceOperationReuse, retainedReviewForeignNodeID, now.Add(-retainedStateFenceLeaseDuration-time.Second))
	expired.Metadata.UID = "uid-expired-retained-state-fence"
	expired.Metadata.ResourceVersion = "7"
	expired.Spec.LeaseTransitions = 2
	runner := &fakeK8sRunner{
		leases: map[string]stateFenceLease{binding.leaseName(): expired},
		handler: func(command k8sCommand) (k8sCommandResult, error) {
			if command.name == "kubectl" && strings.Contains(strings.Join(command.args, " "), "get deployment") {
				return stdout(readyDeploymentJSON(defaultK8sRelease, binding.claim)), nil
			}
			return baseRunnerHandler(command)
		},
	}
	deps := baseK8sDeps(runner, cp, &bytes.Buffer{}, &bytes.Buffer{})
	deps.now = func() time.Time { return now }
	if err := runK8s(context.Background(), []string{"install", "--node-name", "display-name-is-not-authority", "--mode", "reuse", "--existing-claim", binding.claim, "--yes"}, deps); err != nil {
		t.Fatalf("expired retained-state Lease takeover: %v", err)
	}
	if len(cp.claimReads) < 4 {
		t.Fatalf("lifecycle proof reads = %d, want prepare, Lease takeover, post-approval, and post-Helm reads", len(cp.claimReads))
	}
	replacedBeforeHelm := false
	for index, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		if command.name != "kubectl" || !strings.Contains(joined, "replace --raw=") || !strings.Contains(joined, "/leases/") {
			continue
		}
		for _, later := range runner.commands[index+1:] {
			if later.name == "helm" && len(later.args) != 0 && later.args[0] == "install" {
				replacedBeforeHelm = true
				break
			}
		}
	}
	if !replacedBeforeHelm || len(runner.leases) != 0 {
		t.Fatalf("expired Lease was not safely taken over and released: replaced-before-Helm=%t remaining=%d", replacedBeforeHelm, len(runner.leases))
	}
}

func TestRetainedReviewEnrollRetryRequiresAnchorMatchedPVCProvenance(t *testing.T) {
	release := "tunnex-gateway"
	claim := gatewayFullname(release) + "-state"
	anchor := testLifecycleAnchor(release, "gateway-a", "issued")
	secretBytes := bootstrapSecretMetadataLine(release)
	validPVC := readyPVCJSON(claim, release)
	tests := []struct {
		name string
		pvc  string
		want string
	}{
		{name: "same organization and claim", pvc: validPVC},
		{name: "missing provenance", pvc: readyLegacyPVCJSON(claim, release), want: "does not match its owned lifecycle anchor"},
		{name: "foreign organization", pvc: strings.Replace(validPVC, retainedReviewOrganizationID, retainedReviewForeignOrgID, 1), want: "does not match its owned lifecycle anchor"},
		{name: "foreign lifecycle claim", pvc: strings.Replace(validPVC, testLifecycleClaim, retainedReviewForeignClaim, 1), want: "does not match its owned lifecycle anchor"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pvcBytes := tc.pvc
			runner := &fakeK8sRunner{anchors: map[string]lifecycleAnchorMetadata{anchor.name: anchor}}
			runner.handler = func(command k8sCommand) (k8sCommandResult, error) {
				joined := strings.Join(command.args, " ")
				switch {
				case command.name == "kubectl" && strings.Contains(joined, "get secret "+release+"-bootstrap"):
					return stdout(secretBytes), nil
				case command.name == "kubectl" && strings.Contains(joined, "get pvc "+claim):
					return stdout(pvcBytes), nil
				case command.name == "kubectl" && strings.Contains(joined, "get pods"):
					return stdout(`{"items":[]}`), nil
				default:
					return baseRunnerHandler(command)
				}
			}
			o := installOptions{release: release, namespace: defaultK8sNamespace, kubeContext: "walk-context", mode: "enroll"}
			state, err := discoverInstallState(context.Background(), runner, o)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("matching retained enroll retry: %v", err)
				}
				if !state.anchorExists || !state.retrySecret || state.pvcOrganizationID != anchor.orgID || state.pvcLifecycleClaim != anchor.lifecycleClaim {
					t.Fatalf("matching retained enroll state = %+v", state)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("retained enroll error = %v, want %q", err, tc.want)
			}
			if pvcBytes != tc.pvc || secretBytes != bootstrapSecretMetadataLine(release) || !reflect.DeepEqual(runner.anchors[anchor.name], anchor) {
				t.Fatal("retained PVC, Secret, or lifecycle anchor fixture changed")
			}
			assertRetainedReviewNoClusterMutation(t, runner, baseK8sControlPlane())
		})
	}
}
