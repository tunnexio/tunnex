package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// A failed Helm operation rolls its pods back, and the reason goes with them:
// the operator is left with "context deadline exceeded". The observer watches
// the release's pods while Helm waits and keeps the last thing that was wrong,
// so the failure can say "image could not be pulled" or "the node check
// reported: ..." instead.

const (
	podObserverInterval   = 5 * time.Second
	podObserverLogBytes   = 600
	podObserverSummaryMax = 900
)

// concurrentK8sRunner marks a runner that may be called from a second
// goroutine while another command is running. Only such runners are observed.
type concurrentK8sRunner interface {
	k8sRunner
	concurrentSafe()
}

func (osK8sRunner) concurrentSafe() {}

type podObserver struct {
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
	last   string
}

// startPodObserver begins sampling pods that match selector in namespace. It
// returns nil when the runner cannot be used concurrently; every method is
// safe on a nil observer.
func startPodObserver(ctx context.Context, runner k8sRunner, kubeContext, namespace, selector string, secrets ...string) *podObserver {
	safe, ok := runner.(concurrentK8sRunner)
	if !ok {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	o := &podObserver{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(o.done)
		ticker := time.NewTicker(podObserverInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if summary := observePods(ctx, safe, kubeContext, namespace, selector, secrets...); summary != "" {
					o.mu.Lock()
					o.last = summary
					o.mu.Unlock()
				}
			}
		}
	}()
	return o
}

// stop ends sampling and returns the last problem seen, or "".
func (o *podObserver) stop() string {
	if o == nil {
		return ""
	}
	o.cancel()
	<-o.done
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.last
}

// explain appends what the observer last saw to a failure. It always stops
// the observer.
func (o *podObserver) explain(err error) error {
	seen := o.stop()
	if err == nil || seen == "" {
		return err
	}
	return fmt.Errorf("%w\nLast seen before the rollback: %s", err, seen)
}

func observePods(ctx context.Context, runner k8sRunner, kubeContext, namespace, selector string, secrets ...string) string {
	callCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	result, err := runner.Run(callCtx, k8sCommand{name: "kubectl", args: kubectlArgs(kubeContext, "get", "pods", "--namespace", namespace, "--selector", selector, "--output", "json")})
	if err != nil {
		return ""
	}
	problems := podProblems(result.stdout)
	if len(problems) == 0 {
		return ""
	}
	// One log line turns "the check container keeps failing" into the reason it printed.
	first := problems[0]
	if first.wantLog {
		logCtx, cancelLog := context.WithTimeout(ctx, 4*time.Second)
		args := []string{"logs", first.pod, "--namespace", namespace, "--container", first.container, "--tail", "1"}
		if first.previous {
			args = append(args, "--previous")
		}
		logs, logErr := runner.Run(logCtx, k8sCommand{name: "kubectl", args: kubectlArgs(kubeContext, args...)})
		cancelLog()
		if line := lastLogLine(string(logs.stdout), secrets...); logErr == nil && line != "" {
			problems[0].text += "; it reported: " + line
		}
	}
	texts := make([]string, 0, len(problems))
	for _, problem := range problems {
		texts = append(texts, problem.text)
	}
	return boundText(strings.Join(texts, " | "), podObserverSummaryMax)
}

type podProblem struct {
	text      string
	pod       string
	container string
	wantLog   bool
	previous  bool
}

// podProblems reads `kubectl get pods -o json` and names what is keeping each
// pod from becoming ready. Identical problems on several pods are reported
// once. Pure, so it is tested directly.
func podProblems(raw []byte) []podProblem {
	var list struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Status struct {
				Phase      string `json:"phase"`
				Conditions []struct {
					Type    string `json:"type"`
					Status  string `json:"status"`
					Reason  string `json:"reason"`
					Message string `json:"message"`
				} `json:"conditions"`
				InitContainerStatuses []containerStatus `json:"initContainerStatuses"`
				ContainerStatuses     []containerStatus `json:"containerStatuses"`
			} `json:"status"`
		} `json:"items"`
	}
	if json.Unmarshal(raw, &list) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []podProblem
	add := func(problem podProblem, key string) {
		if !seen[key] {
			seen[key] = true
			out = append(out, problem)
		}
	}
	for _, pod := range list.Items {
		name := pod.Metadata.Name
		for _, condition := range pod.Status.Conditions {
			if condition.Type == "PodScheduled" && condition.Status == "False" {
				text := "pod could not be scheduled"
				if condition.Message != "" {
					text += ": " + condition.Message
				}
				add(podProblem{text: text, pod: name}, "sched:"+condition.Message)
			}
		}
		for _, group := range []struct {
			kind     string
			statuses []containerStatus
		}{{"init container", pod.Status.InitContainerStatuses}, {"container", pod.Status.ContainerStatuses}} {
			for _, status := range group.statuses {
				label := group.kind + " " + status.Name
				switch {
				case status.State.Waiting != nil && isImageProblem(status.State.Waiting.Reason):
					text := label + " cannot pull its image (" + status.State.Waiting.Reason + ")"
					if status.Image != "" {
						text += " " + status.Image
					}
					if message := firstSentence(status.State.Waiting.Message); message != "" {
						text += ": " + message
					}
					add(podProblem{text: text, pod: name, container: status.Name}, "image:"+status.Name+status.State.Waiting.Reason)
				case status.State.Waiting != nil && status.State.Waiting.Reason == "CrashLoopBackOff",
					status.LastState.Terminated != nil && status.LastState.Terminated.ExitCode != 0:
					text := label + " keeps failing"
					if status.LastState.Terminated != nil {
						text += fmt.Sprintf(" (exit %d, %d restarts)", status.LastState.Terminated.ExitCode, status.RestartCount)
					}
					add(podProblem{text: text, pod: name, container: status.Name, wantLog: true, previous: status.LastState.Terminated != nil}, "crash:"+status.Name)
				case status.State.Waiting != nil && status.State.Waiting.Reason == "CreateContainerConfigError":
					add(podProblem{text: label + " could not be created: " + firstSentence(status.State.Waiting.Message), pod: name, container: status.Name}, "config:"+status.Name)
				case group.kind == "container" && status.State.Running != nil && !status.Ready:
					add(podProblem{text: label + " is running but not ready", pod: name, container: status.Name, wantLog: true}, "notready:"+status.Name)
				case group.kind == "init container" && status.State.Running != nil:
					add(podProblem{text: label + " has not finished", pod: name, container: status.Name, wantLog: true}, "initrun:"+status.Name)
				}
			}
		}
	}
	// The most actionable first: scheduling and image problems before "not ready yet".
	rank := func(text string) int {
		switch {
		case strings.Contains(text, "could not be scheduled"):
			return 0
		case strings.Contains(text, "cannot pull its image"), strings.Contains(text, "could not be created"):
			return 1
		case strings.Contains(text, "keeps failing"):
			return 2
		case strings.Contains(text, "has not finished"):
			return 3
		}
		return 4
	}
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i].text) < rank(out[j].text) })
	return out
}

type containerStatus struct {
	Name         string `json:"name"`
	Image        string `json:"image"`
	Ready        bool   `json:"ready"`
	RestartCount int    `json:"restartCount"`
	State        struct {
		Waiting *struct {
			Reason  string `json:"reason"`
			Message string `json:"message"`
		} `json:"waiting"`
		Running *struct{} `json:"running"`
	} `json:"state"`
	LastState struct {
		Terminated *struct {
			ExitCode int    `json:"exitCode"`
			Reason   string `json:"reason"`
		} `json:"terminated"`
	} `json:"lastState"`
}

func isImageProblem(reason string) bool {
	return reason == "ImagePullBackOff" || reason == "ErrImagePull" || reason == "InvalidImageName" || reason == "ErrImageNeverPull"
}

func firstSentence(text string) string {
	text = strings.TrimSpace(strings.ReplaceAll(text, "\n", " "))
	return boundText(text, 240)
}

var longTokenRE = regexp.MustCompile(`[A-Za-z0-9+/=_-]{40,}`)

// lastLogLine returns the final non-empty log line, bounded and with anything
// that looks like key material removed.
func lastLogLine(logs string, secrets ...string) string {
	lines := strings.Split(strings.TrimSpace(logs), "\n")
	line := strings.TrimSpace(lines[len(lines)-1])
	if line == "" {
		return ""
	}
	line = longTokenRE.ReplaceAllString(redactText(line, secrets...), "<redacted>")
	return boundText(line, podObserverLogBytes)
}

func boundText(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit] + "…"
}
