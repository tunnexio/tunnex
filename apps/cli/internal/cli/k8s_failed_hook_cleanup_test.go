package cli

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type d13hHookCleanupRunner struct {
	job                *preflightHookJob
	pods               []preflightHookPod
	anchor             *lifecycleAnchorMetadata
	anchorReadMutation func(*lifecycleAnchorMetadata)
	deleted            bool
	retainAfterDelete  bool
	commands           []k8sCommand
	fallback           func(k8sCommand) (k8sCommandResult, error)
}

func (r *d13hHookCleanupRunner) LookPath(name string) (string, error) {
	return "/usr/bin/" + name, nil
}

func (r *d13hHookCleanupRunner) Run(_ context.Context, command k8sCommand) (k8sCommandResult, error) {
	r.commands = append(r.commands, k8sCommand{name: command.name, args: append([]string(nil), command.args...), stdin: append([]byte(nil), command.stdin...)})
	joined := strings.Join(command.args, " ")
	switch {
	case command.name == "kubectl" && strings.Contains(joined, "get job "):
		if r.job == nil || r.deleted {
			return stdout(""), nil
		}
		raw, err := json.Marshal(r.job)
		return k8sCommandResult{stdout: raw}, err
	case command.name == "kubectl" && strings.Contains(joined, "get pods "):
		pods := r.pods
		if r.deleted && !r.retainAfterDelete {
			pods = nil
		}
		raw, err := json.Marshal(preflightHookPodList{APIVersion: "v1", Kind: "PodList", Items: pods})
		return k8sCommandResult{stdout: raw}, err
	case command.name == "kubectl" && strings.Contains(joined, "get configmap ") && r.anchor != nil:
		if r.anchorReadMutation != nil {
			r.anchorReadMutation(r.anchor)
			r.anchorReadMutation = nil
		}
		return stdout(lifecycleAnchorMetadataLine(*r.anchor)), nil
	case command.name == "kubectl" && strings.Contains(joined, "delete --raw=/apis/batch/v1/namespaces/"):
		r.deleted = true
		return stdout(`{"kind":"Status","status":"Success"}`), nil
	case command.name == "kubectl" && strings.Contains(joined, "wait --for=delete "):
		return stdout("deleted\n"), nil
	default:
		if r.fallback != nil {
			return r.fallback(command)
		}
		return k8sCommandResult{}, errors.New("unexpected test command: " + command.name + " " + joined)
	}
}

func d13hAbortHookBinding(t *testing.T, release string) (lifecycleAnchorMetadata, lifecycleInstallOperationStatus, string) {
	t.Helper()
	anchor := testLifecycleAnchor(release, "aks-gateway-a", "aborting")
	now := time.Date(2099, 1, 2, 3, 4, 5, 0, time.UTC)
	abortRequestedAt := now.Add(-time.Minute)
	takenOverAt := now.Add(-30 * time.Second)
	anchor.installOperationID = testStateFenceOpID
	anchor.installOperationEpoch = 2
	anchor.installOperationDurationSeconds = 660
	anchor.installOperationNotAfter = now.Add(10 * time.Minute)
	anchor.installIntentDigest = "sha256:" + strings.Repeat("c", 64)
	anchor.releaseNamespace = defaultK8sNamespace
	anchor.releaseName = release
	takeover := lifecycleInstallOperationStatus{
		claim: anchor.lifecycleClaim, generation: anchor.generation, requestID: anchor.requestID,
		operationID: anchor.installOperationID, epoch: anchor.installOperationEpoch, state: lifecycleInstallAborting,
		releaseNamespace: anchor.releaseNamespace, releaseName: anchor.releaseName, installIntentDigest: anchor.installIntentDigest,
		requestedDurationSeconds: anchor.installOperationDurationSeconds, notAfter: anchor.installOperationNotAfter,
		serverTime: now, heartbeatAt: now.Add(-time.Minute), abortRequestedAt: &abortRequestedAt, takenOverAt: &takenOverAt,
	}
	proof, err := validateLifecycleAbortHookBinding(anchor, takeover, defaultK8sNamespace, release)
	if err != nil {
		t.Fatalf("derive abort hook binding: %v", err)
	}
	return anchor, takeover, proof
}

func d13hCanonicalHookJob(release, policy, installProof string) preflightHookJob {
	job := preflightHookJob{APIVersion: "batch/v1", Kind: "Job"}
	job.Metadata.Name = canonicalPreflightHookName(release)
	job.Metadata.Namespace = defaultK8sNamespace
	job.Metadata.UID = "hook-job-uid"
	job.Metadata.ResourceVersion = "17"
	job.Metadata.Labels = map[string]string{
		"app.kubernetes.io/name":       "tunnex-gateway",
		"app.kubernetes.io/instance":   release,
		"app.kubernetes.io/component":  "preflight",
		"app.kubernetes.io/managed-by": "Helm",
		"helm.sh/chart":                "tunnex-gateway-0.2.0",
	}
	job.Metadata.Annotations = map[string]string{
		"helm.sh/hook":                      preflightHookType,
		"helm.sh/hook-weight":               preflightHookWeight,
		"helm.sh/hook-delete-policy":        policy,
		preflightHookInstallProofAnnotation: installProof,
	}
	return job
}

func d13hCanonicalHookPod(job preflightHookJob, release string) preflightHookPod {
	truth := true
	pod := preflightHookPod{APIVersion: "v1", Kind: "Pod"}
	pod.Metadata.Name = job.Metadata.Name + "-fixture"
	pod.Metadata.Namespace = job.Metadata.Namespace
	pod.Metadata.UID = "hook-pod-uid"
	pod.Metadata.ResourceVersion = "19"
	pod.Metadata.Labels = map[string]string{
		"app.kubernetes.io/name":       "tunnex-gateway",
		"app.kubernetes.io/instance":   release,
		"app.kubernetes.io/component":  "preflight",
		"app.kubernetes.io/managed-by": "Helm",
		"job-name":                     job.Metadata.Name,
	}
	pod.Metadata.OwnerReferences = []preflightHookOwnerReference{{
		APIVersion: "batch/v1", Kind: "Job", Name: job.Metadata.Name, UID: job.Metadata.UID,
		Controller: &truth, BlockOwnerDeletion: &truth,
	}}
	return pod
}

func d13hHookDeleteCommand(t *testing.T, commands []k8sCommand) k8sCommand {
	t.Helper()
	for _, command := range commands {
		joined := strings.Join(command.args, " ")
		if command.name == "kubectl" && strings.Contains(joined, "delete --raw=/apis/batch/v1/namespaces/") {
			return command
		}
	}
	t.Fatal("exact raw hook Job delete command was not issued")
	return k8sCommand{}
}

func TestD13hAbortTakeoverRecomputesTheInstallHolderProof(t *testing.T) {
	anchor, takeover, abortProof := d13hAbortHookBinding(t, "gateway-a")
	holderAnchor := anchor
	holderAnchor.state = "installing"
	holderAnchor.installOperationEpoch = takeover.epoch - 1
	holderProof, err := lifecycleInstallHookProofForInstallingAnchor(holderAnchor, defaultK8sNamespace, "gateway-a")
	if err != nil {
		t.Fatalf("derive install-holder hook proof: %v", err)
	}
	if holderProof != abortProof {
		t.Fatalf("holder/takeover hook proofs differ: %s != %s", holderProof, abortProof)
	}
	if currentEpochProof, proofErr := lifecycleInstallHookProof(anchor, defaultK8sNamespace, "gateway-a", takeover.epoch); proofErr != nil || currentEpochProof == abortProof {
		t.Fatalf("takeover epoch proof=(%s,%v), want distinct from holder proof %s", currentEpochProof, proofErr, abortProof)
	}
}

func TestD13hAbortCleanupAcceptsPriorAndCurrentCanonicalHookPolicies(t *testing.T) {
	for _, policy := range []string{preflightHookDeletePolicyOld, preflightHookDeletePolicyLive} {
		t.Run(policy, func(t *testing.T) {
			release := "gateway-a"
			anchor, takeover, proof := d13hAbortHookBinding(t, release)
			job := d13hCanonicalHookJob(release, policy, proof)
			pod := d13hCanonicalHookPod(job, release)
			runner := &d13hHookCleanupRunner{job: &job, pods: []preflightHookPod{pod}, anchor: &anchor}
			if err := cleanupCanonicalFailedPreflightHook(context.Background(), runner, "aks-a", defaultK8sNamespace, release, "2m", anchor, takeover); err != nil {
				t.Fatalf("cleanup canonical hook: %v", err)
			}
			command := d13hHookDeleteCommand(t, runner.commands)
			wantPath := "delete --raw=/apis/batch/v1/namespaces/tunnex/jobs/" + canonicalPreflightHookName(release) + " -f -"
			if !strings.Contains(strings.Join(command.args, " "), wantPath) {
				t.Fatalf("raw hook deletion = %q, want exact path %q", strings.Join(command.args, " "), wantPath)
			}
			var options struct {
				PropagationPolicy string `json:"propagationPolicy"`
				Preconditions     struct {
					UID             string `json:"uid"`
					ResourceVersion string `json:"resourceVersion"`
				} `json:"preconditions"`
			}
			if err := json.Unmarshal(command.stdin, &options); err != nil {
				t.Fatalf("decode hook DeleteOptions: %v", err)
			}
			if options.PropagationPolicy != "Foreground" || options.Preconditions.UID != job.Metadata.UID || options.Preconditions.ResourceVersion != job.Metadata.ResourceVersion {
				t.Fatalf("hook DeleteOptions = %+v", options)
			}
			podWait, jobWait := false, false
			for _, command := range runner.commands {
				joined := strings.Join(command.args, " ")
				if strings.Contains(joined, "delete") && strings.Contains(joined, "--selector") {
					t.Fatalf("hook cleanup used selector-wide deletion: %+v", command)
				}
				podWait = podWait || strings.Contains(joined, "wait --for=delete pod/"+pod.Metadata.Name)
				jobWait = jobWait || strings.Contains(joined, "wait --for=delete job/"+job.Metadata.Name)
			}
			if !podWait || !jobWait {
				t.Fatalf("hook cleanup waits pod/job=%t/%t", podWait, jobWait)
			}
		})
	}
}

func TestD13hAbortCleanupRefusesMalformedOrForeignHookBeforeMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*preflightHookJob)
	}{
		{name: "missing UID", mutate: func(j *preflightHookJob) { j.Metadata.UID = "" }},
		{name: "missing resourceVersion", mutate: func(j *preflightHookJob) { j.Metadata.ResourceVersion = "" }},
		{name: "foreign release", mutate: func(j *preflightHookJob) { j.Metadata.Labels["app.kubernetes.io/instance"] = "gateway-b" }},
		{name: "foreign component", mutate: func(j *preflightHookJob) { j.Metadata.Labels["app.kubernetes.io/component"] = "gateway" }},
		{name: "foreign manager", mutate: func(j *preflightHookJob) { j.Metadata.Labels["app.kubernetes.io/managed-by"] = "manual" }},
		{name: "foreign hook", mutate: func(j *preflightHookJob) { j.Metadata.Annotations["helm.sh/hook"] = "post-delete" }},
		{name: "foreign hook weight", mutate: func(j *preflightHookJob) { j.Metadata.Annotations["helm.sh/hook-weight"] = "0" }},
		{name: "foreign hook policy", mutate: func(j *preflightHookJob) { j.Metadata.Annotations["helm.sh/hook-delete-policy"] = "hook-succeeded" }},
		{name: "missing lifecycle install proof", mutate: func(j *preflightHookJob) { delete(j.Metadata.Annotations, preflightHookInstallProofAnnotation) }},
		{name: "foreign lifecycle install proof", mutate: func(j *preflightHookJob) {
			j.Metadata.Annotations[preflightHookInstallProofAnnotation] = "sha256:" + strings.Repeat("f", 64)
		}},
		{name: "unexpected owner", mutate: func(j *preflightHookJob) {
			j.Metadata.OwnerReferences = []preflightHookOwnerReference{{Kind: "Deployment", Name: "foreign"}}
		}},
		{name: "unexpected finalizer", mutate: func(j *preflightHookJob) { j.Metadata.Finalizers = []string{"foreign.example/fence"} }},
		{name: "malformed deletion time", mutate: func(j *preflightHookJob) { j.Metadata.DeletionTimestamp = "not-a-time" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			anchor, takeover, proof := d13hAbortHookBinding(t, "gateway-a")
			job := d13hCanonicalHookJob("gateway-a", preflightHookDeletePolicyLive, proof)
			tc.mutate(&job)
			runner := &d13hHookCleanupRunner{job: &job, anchor: &anchor}
			err := cleanupCanonicalFailedPreflightHook(context.Background(), runner, "aks-a", defaultK8sNamespace, "gateway-a", "2m", anchor, takeover)
			if err == nil {
				t.Fatal("malformed/foreign hook was accepted")
			}
			if runner.deleted {
				t.Fatal("malformed/foreign hook was deleted")
			}
		})
	}
}

func TestD13hAbortCleanupBindsProofToExactAnchorAndTakeoverTuple(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*lifecycleAnchorMetadata, *lifecycleInstallOperationStatus)
	}{
		{name: "anchor UID", mutate: func(a *lifecycleAnchorMetadata, _ *lifecycleInstallOperationStatus) { a.uid = "different-anchor-uid" }},
		{name: "organization", mutate: func(a *lifecycleAnchorMetadata, _ *lifecycleInstallOperationStatus) {
			a.orgID = "22222222-2222-4222-8222-222222222222"
		}},
		{name: "claim", mutate: func(a *lifecycleAnchorMetadata, s *lifecycleInstallOperationStatus) {
			a.lifecycleClaim, s.claim = "22222222-2222-4222-8222-222222222222", "22222222-2222-4222-8222-222222222222"
		}},
		{name: "generation", mutate: func(a *lifecycleAnchorMetadata, s *lifecycleInstallOperationStatus) {
			a.generation, s.generation = 2, 2
		}},
		{name: "request", mutate: func(a *lifecycleAnchorMetadata, s *lifecycleInstallOperationStatus) {
			a.requestID, s.requestID = "33333333-3333-4333-8333-333333333333", "33333333-3333-4333-8333-333333333333"
		}},
		{name: "operation", mutate: func(a *lifecycleAnchorMetadata, s *lifecycleInstallOperationStatus) {
			a.installOperationID, s.operationID = "44444444-4444-4444-8444-444444444444", "44444444-4444-4444-8444-444444444444"
		}},
		{name: "holder epoch", mutate: func(a *lifecycleAnchorMetadata, s *lifecycleInstallOperationStatus) {
			a.installOperationEpoch, s.epoch = 3, 3
		}},
		{name: "duration", mutate: func(a *lifecycleAnchorMetadata, s *lifecycleInstallOperationStatus) {
			a.installOperationDurationSeconds, s.requestedDurationSeconds = 600, 600
		}},
		{name: "deadline", mutate: func(a *lifecycleAnchorMetadata, s *lifecycleInstallOperationStatus) {
			a.installOperationNotAfter = a.installOperationNotAfter.Add(time.Second)
			s.notAfter = a.installOperationNotAfter
		}},
		{name: "intent", mutate: func(a *lifecycleAnchorMetadata, s *lifecycleInstallOperationStatus) {
			a.installIntentDigest, s.installIntentDigest = "sha256:"+strings.Repeat("d", 64), "sha256:"+strings.Repeat("d", 64)
		}},
		{name: "takeover state", mutate: func(_ *lifecycleAnchorMetadata, s *lifecycleInstallOperationStatus) {
			s.state = lifecycleInstallAbortRequested
		}},
		{name: "takeover timestamp", mutate: func(_ *lifecycleAnchorMetadata, s *lifecycleInstallOperationStatus) { s.takenOverAt = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			originalAnchor, originalTakeover, proof := d13hAbortHookBinding(t, "gateway-a")
			job := d13hCanonicalHookJob("gateway-a", preflightHookDeletePolicyLive, proof)
			anchor, takeover := originalAnchor, originalTakeover
			tc.mutate(&anchor, &takeover)
			runner := &d13hHookCleanupRunner{job: &job, anchor: &anchor}
			err := cleanupCanonicalFailedPreflightHook(context.Background(), runner, "aks-a", defaultK8sNamespace, "gateway-a", "2m", anchor, takeover)
			if err == nil {
				t.Fatal("changed lifecycle hook binding was accepted")
			}
			if runner.deleted {
				t.Fatal("changed lifecycle hook binding deleted the Job")
			}
		})
	}
}

func TestD13hAbortCleanupRefusesAnchorDriftImmediatelyBeforeMutation(t *testing.T) {
	anchor, takeover, proof := d13hAbortHookBinding(t, "gateway-a")
	job := d13hCanonicalHookJob("gateway-a", preflightHookDeletePolicyLive, proof)
	runner := &d13hHookCleanupRunner{
		job: &job, anchor: &anchor,
		anchorReadMutation: func(actual *lifecycleAnchorMetadata) { actual.resourceVersion = "changed-after-job-read" },
	}
	err := cleanupCanonicalFailedPreflightHook(context.Background(), runner, "aks-a", defaultK8sNamespace, "gateway-a", "2m", anchor, takeover)
	if err == nil || !strings.Contains(err.Error(), "changed immediately before") {
		t.Fatalf("anchor drift error = %v", err)
	}
	if runner.deleted {
		t.Fatal("anchor drift deleted the proof-bound hook Job")
	}
}

func TestD13hAbortCleanupRefusesForeignControllerPodBeforeMutation(t *testing.T) {
	anchor, takeover, proof := d13hAbortHookBinding(t, "gateway-a")
	job := d13hCanonicalHookJob("gateway-a", preflightHookDeletePolicyLive, proof)
	pod := d13hCanonicalHookPod(job, "gateway-a")
	pod.Metadata.OwnerReferences[0].UID = "foreign-job-uid"
	runner := &d13hHookCleanupRunner{job: &job, pods: []preflightHookPod{pod}, anchor: &anchor}
	err := cleanupCanonicalFailedPreflightHook(context.Background(), runner, "aks-a", defaultK8sNamespace, "gateway-a", "2m", anchor, takeover)
	if err == nil || !strings.Contains(err.Error(), "foreign or malformed Job ownership") {
		t.Fatalf("foreign controller Pod error = %v", err)
	}
	if runner.deleted {
		t.Fatal("hook Job was deleted despite foreign controller Pod")
	}
}

func TestD13hAbortCleanupRefusesSuccessWhileControllerPodRemains(t *testing.T) {
	anchor, takeover, proof := d13hAbortHookBinding(t, "gateway-a")
	job := d13hCanonicalHookJob("gateway-a", preflightHookDeletePolicyLive, proof)
	pod := d13hCanonicalHookPod(job, "gateway-a")
	runner := &d13hHookCleanupRunner{job: &job, pods: []preflightHookPod{pod}, anchor: &anchor, retainAfterDelete: true}
	err := cleanupCanonicalFailedPreflightHook(context.Background(), runner, "aks-a", defaultK8sNamespace, "gateway-a", "2m", anchor, takeover)
	if err == nil || !strings.Contains(err.Error(), "still has a controller-owned") {
		t.Fatalf("retained controller Pod error = %v", err)
	}
	if !runner.deleted {
		t.Fatal("retained-controller proof did not run after the exact Job delete")
	}
}

func TestD13hAbortReconcileProvesRevisionUninstallsCleansHookThenReprovesAbsence(t *testing.T) {
	release := "gateway-a"
	anchor, takeover, proof := d13hAbortHookBinding(t, release)
	job := d13hCanonicalHookJob(release, preflightHookDeletePolicyOld, proof)
	pod := d13hCanonicalHookPod(job, release)
	releaseExists := true
	runner := &d13hHookCleanupRunner{job: &job, pods: []preflightHookPod{pod}, anchor: &anchor}
	runner.fallback = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		switch {
		case command.name == "helm" && strings.HasPrefix(joined, "history "):
			return stdout(`[{"revision":1,"updated":"now","status":"pending-install","chart":"tunnex-gateway-0.2.0","app_version":"v0.2.0","description":"Initial install underway"}]`), nil
		case command.name == "helm" && strings.HasPrefix(joined, "uninstall "):
			releaseExists = false
			return stdout("release uninstalled\n"), nil
		case command.name == "helm" && strings.HasPrefix(joined, "list --all "):
			if releaseExists {
				return stdout(`[{"name":"gateway-a","namespace":"tunnex","revision":"1","status":"pending-install","chart":"tunnex-gateway-0.2.0","app_version":"v0.2.0"}]`), nil
			}
			return stdout(`[]`), nil
		case command.name == "kubectl" && strings.Contains(joined, "get deployments,statefulsets,daemonsets,jobs,pods,services"):
			return stdout(""), nil
		case command.name == "kubectl" && strings.Contains(joined, "get configmap "+anchor.name):
			return stdout(lifecycleAnchorMetadataLine(anchor)), nil
		default:
			return k8sCommandResult{}, errors.New("unexpected reconciliation command: " + command.name + " " + joined)
		}
	}
	releaseSummary := &helmReleaseSummary{
		Name: release, Namespace: defaultK8sNamespace, Revision: "1", Status: "pending-install",
		Chart: "tunnex-gateway-0.2.0", AppVersion: "v0.2.0",
	}
	err := reconcileLifecycleAbortRelease(context.Background(), k8sDeps{runner: runner}, abortInstallOptions{
		release: release, namespace: defaultK8sNamespace, kubeContext: "aks-a", timeout: "2m",
	}, anchor, takeover, releaseSummary, "")
	if err != nil {
		t.Fatalf("reconcile failed preflight hook: %v", err)
	}
	if releaseExists || !runner.deleted {
		t.Fatalf("reconciliation retained release/hook=%t/%t", releaseExists, !runner.deleted)
	}
	indexes := func(needle string) []int {
		var found []int
		for i, command := range runner.commands {
			if strings.Contains(command.name+" "+strings.Join(command.args, " "), needle) {
				found = append(found, i)
			}
		}
		return found
	}
	history, uninstall := indexes("helm history"), indexes("helm uninstall")
	deleteHook := indexes("delete --raw=/apis/batch/v1/namespaces/tunnex/jobs/")
	releaseAbsence := indexes("helm list --all")
	workloadAbsence := indexes("get deployments,statefulsets,daemonsets,jobs,pods,services")
	anchorReproofs := indexes("get configmap " + anchor.name)
	if len(history) != 1 || len(uninstall) != 1 || len(deleteHook) != 1 || len(releaseAbsence) != 1 || len(workloadAbsence) != 1 || len(anchorReproofs) != 2 ||
		uninstall[0] <= history[0] || anchorReproofs[0] <= uninstall[0] || deleteHook[0] != anchorReproofs[0]+1 || releaseAbsence[0] <= deleteHook[0] || workloadAbsence[0] <= releaseAbsence[0] || anchorReproofs[1] <= workloadAbsence[0] {
		t.Fatalf("reconciliation order history/uninstall/pre-delete-anchor/hook/release/workloads/final-anchor=%v/%v/%v/%v/%v/%v/%v", history, uninstall, anchorReproofs, deleteHook, releaseAbsence, workloadAbsence, anchorReproofs)
	}
}

func TestD13hAbortReconcileRefusesForeignHookProofBeforeHelmUninstall(t *testing.T) {
	release := "gateway-a"
	anchor, takeover, proof := d13hAbortHookBinding(t, release)
	job := d13hCanonicalHookJob(release, preflightHookDeletePolicyLive, proof)
	job.Metadata.Annotations[preflightHookInstallProofAnnotation] = "sha256:" + strings.Repeat("f", 64)
	releaseExists := true
	runner := &d13hHookCleanupRunner{job: &job, anchor: &anchor}
	runner.fallback = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		switch {
		case command.name == "helm" && strings.HasPrefix(joined, "history "):
			return stdout(`[{"revision":1,"updated":"now","status":"pending-install","chart":"tunnex-gateway-0.2.0","app_version":"v0.2.0","description":"Initial install underway"}]`), nil
		case command.name == "helm" && strings.HasPrefix(joined, "uninstall "):
			releaseExists = false
			return stdout("release uninstalled\n"), nil
		default:
			return k8sCommandResult{}, errors.New("unexpected foreign-proof reconciliation command: " + command.name + " " + joined)
		}
	}
	releaseSummary := &helmReleaseSummary{
		Name: release, Namespace: defaultK8sNamespace, Revision: "1", Status: "pending-install",
		Chart: "tunnex-gateway-0.2.0", AppVersion: "v0.2.0",
	}
	err := reconcileLifecycleAbortRelease(context.Background(), k8sDeps{runner: runner}, abortInstallOptions{
		release: release, namespace: defaultK8sNamespace, kubeContext: "aks-a", timeout: "2m",
	}, anchor, takeover, releaseSummary, "")
	if err == nil || !strings.Contains(err.Error(), "lacks the exact lifecycle install proof") {
		t.Fatalf("foreign hook proof error = %v", err)
	}
	if !releaseExists || runner.deleted {
		t.Fatalf("foreign hook proof mutated release/deleted-hook=%t/%t", !releaseExists, runner.deleted)
	}
	for _, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		if command.name == "helm" && strings.HasPrefix(joined, "uninstall ") {
			t.Fatalf("foreign hook proof reached Helm uninstall: %s", joined)
		}
	}
}

func TestD13hAbortReconcileCleansProofBoundHookWhenReleaseJournalIsAbsent(t *testing.T) {
	release := "gateway-a"
	anchor, takeover, proof := d13hAbortHookBinding(t, release)
	job := d13hCanonicalHookJob(release, preflightHookDeletePolicyLive, proof)
	pod := d13hCanonicalHookPod(job, release)
	runner := &d13hHookCleanupRunner{job: &job, pods: []preflightHookPod{pod}, anchor: &anchor}
	runner.fallback = func(command k8sCommand) (k8sCommandResult, error) {
		joined := strings.Join(command.args, " ")
		switch {
		case command.name == "helm" && strings.HasPrefix(joined, "list --all "):
			return stdout(`[]`), nil
		case command.name == "kubectl" && strings.Contains(joined, "get deployments,statefulsets,daemonsets,jobs,pods,services"):
			return stdout(""), nil
		default:
			return k8sCommandResult{}, errors.New("unexpected release-absent reconciliation command: " + command.name + " " + joined)
		}
	}
	if err := reconcileLifecycleAbortRelease(context.Background(), k8sDeps{runner: runner}, abortInstallOptions{
		release: release, namespace: defaultK8sNamespace, kubeContext: "aks-a", timeout: "2m",
	}, anchor, takeover, nil, ""); err != nil {
		t.Fatalf("reconcile release-absent proof-bound hook: %v", err)
	}
	if !runner.deleted {
		t.Fatal("release-absent reconciliation retained the proof-bound hook")
	}
	for _, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		if command.name == "helm" && (strings.HasPrefix(joined, "history ") || strings.HasPrefix(joined, "uninstall ")) {
			t.Fatalf("release-absent reconciliation invoked Helm history/uninstall: %s", joined)
		}
	}
}
