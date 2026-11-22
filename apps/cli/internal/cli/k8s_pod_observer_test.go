package cli

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestPodProblemsNamesWhatBlocksReadiness(t *testing.T) {
	// Shapes taken from the 2026-11-22 walks: GKE nodes without registry access, and the k3s gateway
	// whose node check never passed.
	imagePull := `{"items":[
	 {"metadata":{"name":"tunnex-host-posture-a"},"status":{"phase":"Pending","containerStatuses":[{"name":"host-posture-manager","image":"example.dev/node-agent:k8l2","ready":false,"restartCount":0,"state":{"waiting":{"reason":"ImagePullBackOff","message":"Back-off pulling image \"example.dev/node-agent:k8l2\": 403 Forbidden"}}}]}},
	 {"metadata":{"name":"tunnex-host-posture-b"},"status":{"phase":"Pending","containerStatuses":[{"name":"host-posture-manager","image":"example.dev/node-agent:k8l2","ready":false,"restartCount":0,"state":{"waiting":{"reason":"ImagePullBackOff","message":"Back-off pulling image"}}}]}}]}`
	got := podProblems([]byte(imagePull))
	if len(got) != 1 || !strings.Contains(got[0].text, "cannot pull its image (ImagePullBackOff) example.dev/node-agent:k8l2") || !strings.Contains(got[0].text, "403 Forbidden") {
		t.Fatalf("image pull: %+v", got)
	}

	initFailing := `{"items":[{"metadata":{"name":"gw-a-1"},"status":{"phase":"Pending",
	 "initContainerStatuses":[{"name":"host-posture-check","ready":false,"restartCount":3,"state":{"running":{}},"lastState":{"terminated":{"exitCode":1,"reason":"Error"}}}],
	 "containerStatuses":[{"name":"gateway","ready":false,"restartCount":0,"state":{"waiting":{"reason":"PodInitializing"}}}]}}]}`
	got = podProblems([]byte(initFailing))
	if len(got) != 1 || got[0].container != "host-posture-check" || !got[0].wantLog || !got[0].previous || !strings.Contains(got[0].text, "keeps failing (exit 1, 3 restarts)") {
		t.Fatalf("failing init container: %+v", got)
	}

	unschedulable := `{"items":[{"metadata":{"name":"gw-a-1"},"status":{"phase":"Pending","conditions":[{"type":"PodScheduled","status":"False","reason":"Unschedulable","message":"0/2 nodes are available: 2 node(s) didn't match Pod's node affinity/selector."}]}}]}`
	got = podProblems([]byte(unschedulable))
	if len(got) != 1 || !strings.Contains(got[0].text, "could not be scheduled: 0/2 nodes are available") {
		t.Fatalf("unschedulable: %+v", got)
	}

	healthy := `{"items":[{"metadata":{"name":"gw-a-1"},"status":{"phase":"Running","containerStatuses":[{"name":"gateway","ready":true,"restartCount":0,"state":{"running":{}}}]}}]}`
	if got := podProblems([]byte(healthy)); len(got) != 0 {
		t.Fatalf("a ready pod reported a problem: %+v", got)
	}
	if got := podProblems([]byte("not json")); got != nil {
		t.Fatalf("unreadable input reported a problem: %+v", got)
	}
}

func TestLastLogLineIsBoundedAndCarriesNoKeyMaterial(t *testing.T) {
	line := lastLogLine("first\n{\"status\":\"blocked\",\"reason\":\"wait for live host-posture CNI ownership\",\"key\":\"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5QUJDRA==\"}\n", "s3cret")
	if !strings.Contains(line, "wait for live host-posture CNI ownership") || strings.Contains(line, "QUJDREVG") || !strings.Contains(line, "<redacted>") {
		t.Fatalf("line = %q", line)
	}
	if got := lastLogLine("token is s3cret here", "s3cret"); strings.Contains(got, "s3cret") {
		t.Fatalf("secret survived: %q", got)
	}
	if got := lastLogLine(strings.Repeat("x y ", 600)); len(got) > podObserverLogBytes+4 {
		t.Fatalf("log line is not bounded: %d bytes", len(got))
	}
}

type observedRunner struct {
	mu   sync.Mutex
	pods string
	logs string
}

func (r *observedRunner) concurrentSafe()                 {}
func (r *observedRunner) LookPath(string) (string, error) { return "", nil }
func (r *observedRunner) Run(_ context.Context, command k8sCommand) (k8sCommandResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	joined := strings.Join(command.args, " ")
	switch {
	case strings.Contains(joined, "get pods"):
		return k8sCommandResult{stdout: []byte(r.pods)}, nil
	case strings.Contains(joined, "logs "):
		return k8sCommandResult{stdout: []byte(r.logs)}, nil
	}
	return k8sCommandResult{}, errors.New("unexpected command")
}

func TestObservePodsAddsTheReasonTheContainerPrinted(t *testing.T) {
	runner := &observedRunner{
		pods: `{"items":[{"metadata":{"name":"gw-a-1"},"status":{"initContainerStatuses":[{"name":"host-posture-check","ready":false,"restartCount":2,"state":{"running":{}},"lastState":{"terminated":{"exitCode":1}}}]}}]}`,
		logs: `{"status":"blocked","reason":"wait for live host-posture CNI ownership: context deadline exceeded"}`,
	}
	got := observePods(t.Context(), runner, "", "tunnex", gatewayPodSelector("gw-a"))
	if !strings.Contains(got, "init container host-posture-check keeps failing") || !strings.Contains(got, "it reported: {\"status\":\"blocked\"") {
		t.Fatalf("summary = %q", got)
	}
}

func TestPodObserverExplainsOnlyAFailure(t *testing.T) {
	// A runner that is not marked concurrent-safe is never observed, and a nil observer is inert.
	if o := startPodObserver(t.Context(), &fakeK8sRunner{}, "", "tunnex", "x"); o != nil {
		t.Fatal("an unmarked runner was observed")
	}
	var none *podObserver
	failure := errors.New("install gateway release failed")
	if got := none.explain(failure); got != failure || none.stop() != "" {
		t.Fatalf("nil observer changed the error: %v", got)
	}
	o := &podObserver{cancel: func() {}, done: make(chan struct{}), last: "container gateway cannot pull its image"}
	close(o.done)
	if got := o.explain(failure); !errors.Is(got, failure) || !strings.Contains(got.Error(), "Last seen before the rollback: container gateway cannot pull its image") {
		t.Fatalf("explained error = %v", got)
	}
	o = &podObserver{cancel: func() {}, done: make(chan struct{}), last: "something"}
	close(o.done)
	if got := o.explain(nil); got != nil {
		t.Fatalf("a success was turned into an error: %v", got)
	}
}

// A refused retry must say what to run next. Both texts were dead ends on 2026-11-22.
func TestRetryRefusalsNameTheNextCommand(t *testing.T) {
	o := installOptions{}
	o.release, o.namespace, o.nodeName = "gw-a", "tunnex", "onprem-gw-a"
	consumed := lifecycleClaimNotRetrySafe("consumed", o, "gw-a-tunnex-gateway-state").Error()
	for _, want := range []string{`claim is "consumed", not retry-safe`, "--mode reuse --existing-claim gw-a-tunnex-gateway-state", "--node-name onprem-gw-a --release gw-a --namespace tunnex"} {
		if !strings.Contains(consumed, want) {
			t.Errorf("consumed refusal lacks %q:\n%s", want, consumed)
		}
	}
	if other := lifecycleClaimNotRetrySafe("aborted", o, "").Error(); !strings.Contains(other, "tunnex k8s abort-install --release gw-a --namespace tunnex") || strings.Contains(other, "--mode reuse") {
		t.Errorf("non-consumed refusal: %s", other)
	}
}
