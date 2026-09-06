package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	k8sLifecycleRouteRetryMaxAttempts = 5
	k8sLifecycleRouteRetryWindow      = 5 * time.Second
	k8sLifecycleRouteMissingCode      = "validation_failed"
	k8sLifecycleRouteMissingMessage   = "no matching operation was found"
	k8sControlPlaneRolloutIncomplete  = "control_plane_rollout_incomplete"
)

var errK8sControlPlaneRolloutIncomplete = errors.New("control-plane rollout is incomplete")

type k8sControlPlaneRolloutIncompleteError struct {
	attempts int
}

func (e *k8sControlPlaneRolloutIncompleteError) Error() string {
	return fmt.Sprintf("control-plane rollout is incomplete after %d fresh-connection attempts; retry the same command (%s)", e.attempts, k8sControlPlaneRolloutIncomplete)
}

func (e *k8sControlPlaneRolloutIncompleteError) Unwrap() error {
	return errK8sControlPlaneRolloutIncomplete
}

func (e *k8sControlPlaneRolloutIncompleteError) Code() string {
	return k8sControlPlaneRolloutIncomplete
}

type lifecycleRouteRetryPolicy struct {
	maxAttempts int
	window      time.Duration
	backoff     func(int) time.Duration
	wait        func(context.Context, time.Duration) error
}

func defaultLifecycleRouteRetryPolicy() lifecycleRouteRetryPolicy {
	return lifecycleRouteRetryPolicy{
		maxAttempts: k8sLifecycleRouteRetryMaxAttempts,
		window:      k8sLifecycleRouteRetryWindow,
		backoff:     lifecycleRouteRetryBackoff,
		wait:        waitLifecycleRouteRetry,
	}
}

func (p lifecycleRouteRetryPolicy) normalized() lifecycleRouteRetryPolicy {
	defaults := defaultLifecycleRouteRetryPolicy()
	if p.maxAttempts <= 0 {
		p.maxAttempts = defaults.maxAttempts
	}
	if p.window <= 0 {
		p.window = defaults.window
	}
	if p.backoff == nil {
		p.backoff = defaults.backoff
	}
	if p.wait == nil {
		p.wait = defaults.wait
	}
	return p
}

func lifecycleRouteRetryBackoff(completedAttempt int) time.Duration {
	switch completedAttempt {
	case 1:
		return 100 * time.Millisecond
	case 2:
		return 250 * time.Millisecond
	case 3:
		return 500 * time.Millisecond
	default:
		return time.Second
	}
}

func waitLifecycleRouteRetry(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func retryLifecycleRoute[T any](
	ctx context.Context,
	policy lifecycleRouteRetryPolicy,
	request func(context.Context) (T, error),
	response func(T) (int, []byte),
) (T, error) {
	// The helper deliberately knows no generated operation or URL. Current and
	// future lifecycle methods opt in by supplying one immutable request closure
	// and a response view; the helper owns only the exact route-miss policy.
	policy = policy.normalized()
	retryCtx, cancel := context.WithTimeout(ctx, policy.window)
	defer cancel()

	var zero T
	for attempt := 1; attempt <= policy.maxAttempts; attempt++ {
		attemptCtx := context.WithValue(retryCtx, lifecycleFreshConnectionContextKey{}, true)
		result, err := request(attemptCtx)
		if err != nil {
			// A transport or response-decoding ambiguity is not evidence that the
			// lifecycle handler did not run. Return it without an automatic replay.
			return zero, err
		}
		status, body := response(result)
		if !isExactLifecycleRouteMissing(status, body) {
			return result, nil
		}
		if attempt == policy.maxAttempts {
			return zero, &k8sControlPlaneRolloutIncompleteError{attempts: attempt}
		}
		if err := policy.wait(retryCtx, policy.backoff(attempt)); err != nil {
			if ctx.Err() != nil {
				return zero, ctx.Err()
			}
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(retryCtx.Err(), context.DeadlineExceeded) {
				return zero, &k8sControlPlaneRolloutIncompleteError{attempts: attempt}
			}
			return zero, err
		}
	}
	return zero, &k8sControlPlaneRolloutIncompleteError{attempts: policy.maxAttempts}
}

func isExactLifecycleRouteMissing(status int, body []byte) bool {
	if status != http.StatusNotFound {
		return false
	}
	var result envelope
	if err := json.Unmarshal(body, &result); err != nil {
		return false
	}
	return result.Error.Code == k8sLifecycleRouteMissingCode && result.Error.Message == k8sLifecycleRouteMissingMessage
}

type lifecycleFreshConnectionTransport struct {
	base         http.RoundTripper
	newAttemptRT func() http.RoundTripper
}

type lifecycleFreshConnectionContextKey struct{}

func newLifecycleFreshConnectionTransport() lifecycleFreshConnectionTransport {
	base := http.DefaultTransport
	if template, ok := http.DefaultTransport.(*http.Transport); ok {
		base = template.Clone()
	}
	return lifecycleFreshConnectionTransport{
		base: base,
		newAttemptRT: func() http.RoundTripper {
			if template, ok := http.DefaultTransport.(*http.Transport); ok {
				attempt := template.Clone()
				attempt.DisableKeepAlives = true
				return attempt
			}
			return http.DefaultTransport
		},
	}
}

func (t lifecycleFreshConnectionTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	if fresh, _ := request.Context().Value(lifecycleFreshConnectionContextKey{}).(bool); !fresh {
		return base.RoundTrip(request)
	}
	// Every generated lifecycle request is a single RoundTrip. Marking it closed
	// prevents a route-missing N-1 connection from being reused by the next
	// bounded attempt, while leaving every other CLI API operation unchanged.
	fresh := request.Clone(request.Context())
	fresh.Close = true
	if t.newAttemptRT != nil {
		base = t.newAttemptRT()
	}
	return base.RoundTrip(fresh)
}
