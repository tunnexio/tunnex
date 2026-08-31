package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const d13cTestOrgID = "11111111-1111-1111-1111-111111111111"

type d13cConnectionIDKey struct{}

type d13cObservedRequest struct {
	body          string
	connectionID  int64
	close         bool
	authorization string
}

func TestK8sLifecycleOperationsRetryExactRouteMissOnFreshConnections(t *testing.T) {
	t.Parallel()

	var nextConnectionID atomic.Int64
	var mu sync.Mutex
	requests := map[string][]d13cObservedRequest{}
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			return
		}
		key := request.Method + " " + request.URL.Path
		observed := d13cObservedRequest{
			body: string(body), connectionID: request.Context().Value(d13cConnectionIDKey{}).(int64),
			close: request.Close, authorization: request.Header.Get("Authorization"),
		}
		mu.Lock()
		requests[key] = append(requests[key], observed)
		attempt := len(requests[key])
		mu.Unlock()

		response.Header().Set("Content-Type", "application/json")
		if attempt == 1 {
			response.WriteHeader(http.StatusNotFound)
			_, _ = response.Write([]byte(d13cRouteMissingBody))
			return
		}
		writeD13cLifecycleSuccess(t, response, request.URL.Path)
	})
	server := httptest.NewUnstartedServer(handler)
	server.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		return context.WithValue(ctx, d13cConnectionIDKey{}, nextConnectionID.Add(1))
	}
	server.Start()
	defer server.Close()

	cp := newD13cTestControlPlane(t, server.URL)
	status, err := cp.GetLifecycleClaimStatus(context.Background(), d13cTestOrgID, testLifecycleClaim)
	if err != nil || status.claim != testLifecycleClaim {
		t.Fatalf("get lifecycle claim: status=%+v error=%v", status, err)
	}
	reminted, err := cp.RemintLifecycleClaim(context.Background(), d13cTestOrgID, testLifecycleClaim, "gateway-a", 3, testLifecycleRequest)
	if err != nil || reminted.claim != testLifecycleClaim || reminted.generation != 4 || reminted.requestID != testLifecycleRequest || reminted.joinToken == "" {
		t.Fatalf("remint lifecycle claim: result=%+v error=%v", reminted, err)
	}
	status, err = cp.AcknowledgeLifecycleClaim(context.Background(), d13cTestOrgID, testLifecycleClaim, 4, testLifecycleRequest)
	if err != nil || status.state != "acknowledged" {
		t.Fatalf("acknowledge lifecycle claim: status=%+v error=%v", status, err)
	}
	status, err = cp.AbortLifecycleClaim(context.Background(), d13cTestOrgID, testLifecycleClaim, 4, testLifecycleRequest)
	if err != nil || status.state != "aborted" {
		t.Fatalf("abort lifecycle claim: status=%+v error=%v", status, err)
	}

	basePath := "/api/v1/organizations/" + d13cTestOrgID + "/nodes/lifecycle-claims/" + testLifecycleClaim
	for _, key := range []string{
		http.MethodGet + " " + basePath,
		http.MethodPost + " " + basePath + "/remint",
		http.MethodPost + " " + basePath + "/ack",
		http.MethodPost + " " + basePath + "/abort",
	} {
		mu.Lock()
		attempts := append([]d13cObservedRequest(nil), requests[key]...)
		mu.Unlock()
		if len(attempts) != 2 {
			t.Fatalf("%s attempts=%d, want route miss then success", key, len(attempts))
		}
		if attempts[0].connectionID == attempts[1].connectionID {
			t.Fatalf("%s reused route-missing connection %d", key, attempts[0].connectionID)
		}
		if !attempts[0].close || !attempts[1].close {
			t.Fatalf("%s close flags=%t/%t, want fresh connection per attempt", key, attempts[0].close, attempts[1].close)
		}
		if attempts[0].authorization != "Bearer cli-secret" || attempts[1].authorization != attempts[0].authorization {
			t.Fatalf("%s authorization changed across retry", key)
		}
		if attempts[0].body != attempts[1].body {
			t.Fatalf("%s body changed across retry: %q != %q", key, attempts[0].body, attempts[1].body)
		}
	}

	mu.Lock()
	remintBody := requests[http.MethodPost+" "+basePath+"/remint"][0].body
	ackBody := requests[http.MethodPost+" "+basePath+"/ack"][0].body
	abortBody := requests[http.MethodPost+" "+basePath+"/abort"][0].body
	mu.Unlock()
	assertD13cCASBody(t, remintBody, 3, true)
	assertD13cCASBody(t, ackBody, 4, false)
	assertD13cCASBody(t, abortBody, 4, false)
}

func TestK8sLifecycleRouteRetryExhaustionIsTypedAndBounded(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	var connectionIDs sync.Map
	var nextConnectionID atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		connectionIDs.Store(request.Context().Value(d13cConnectionIDKey{}).(int64), true)
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusNotFound)
		_, _ = response.Write([]byte(d13cRouteMissingBody))
	}))
	server.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		return context.WithValue(ctx, d13cConnectionIDKey{}, nextConnectionID.Add(1))
	}
	server.Start()
	defer server.Close()

	cp := newD13cTestControlPlane(t, server.URL)
	_, err := cp.GetLifecycleClaimStatus(context.Background(), d13cTestOrgID, testLifecycleClaim)
	var incomplete *k8sControlPlaneRolloutIncompleteError
	if !errors.As(err, &incomplete) || !errors.Is(err, errK8sControlPlaneRolloutIncomplete) || incomplete.Code() != k8sControlPlaneRolloutIncomplete {
		t.Fatalf("exhaustion error=%T %v, want typed %s", err, err, k8sControlPlaneRolloutIncomplete)
	}
	if incomplete.attempts != k8sLifecycleRouteRetryMaxAttempts || calls.Load() != k8sLifecycleRouteRetryMaxAttempts {
		t.Fatalf("attempts error/server=%d/%d, want %d", incomplete.attempts, calls.Load(), k8sLifecycleRouteRetryMaxAttempts)
	}
	connections := 0
	connectionIDs.Range(func(_, _ any) bool {
		connections++
		return true
	})
	if connections != k8sLifecycleRouteRetryMaxAttempts {
		t.Fatalf("fresh connections=%d, want %d", connections, k8sLifecycleRouteRetryMaxAttempts)
	}
	policy := defaultLifecycleRouteRetryPolicy()
	if policy.maxAttempts != 5 || policy.window != 5*time.Second {
		t.Fatalf("default retry bound=%d/%s, want 5 attempts/5s", policy.maxAttempts, policy.window)
	}
	var totalBackoff time.Duration
	for attempt := 1; attempt < policy.maxAttempts; attempt++ {
		totalBackoff += policy.backoff(attempt)
	}
	if totalBackoff >= policy.window {
		t.Fatalf("bounded backoff=%s must stay inside retry window=%s", totalBackoff, policy.window)
	}
}

func TestK8sLifecycleRouteRetryRefusesNonRouteMissingResponses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		status       int
		body         string
		wantNotFound bool
	}{
		{name: "domain not found", status: http.StatusNotFound, body: d13cErrorBody("lifecycle_claim_not_found", "claim not found"), wantNotFound: true},
		{name: "authentication", status: http.StatusUnauthorized, body: d13cErrorBody("unauthorized", "unauthorized")},
		{name: "authorization", status: http.StatusForbidden, body: d13cErrorBody("forbidden", "forbidden")},
		{name: "CAS conflict", status: http.StatusConflict, body: d13cErrorBody("lifecycle_claim_conflict", "conflict")},
		{name: "other validation", status: http.StatusNotFound, body: d13cErrorBody(k8sLifecycleRouteMissingCode, "another validation failure")},
		{name: "wrong code", status: http.StatusNotFound, body: d13cErrorBody("other_not_found", k8sLifecycleRouteMissingMessage)},
		{name: "wrong status", status: http.StatusBadRequest, body: d13cRouteMissingBody},
		{name: "server failure", status: http.StatusInternalServerError, body: d13cErrorBody("internal_error", "failed")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				response.Header().Set("Content-Type", "application/json")
				response.WriteHeader(test.status)
				_, _ = response.Write([]byte(test.body))
			}))
			defer server.Close()

			cp := newD13cTestControlPlane(t, server.URL)
			_, err := cp.GetLifecycleClaimStatus(context.Background(), d13cTestOrgID, testLifecycleClaim)
			if err == nil || calls.Load() != 1 {
				t.Fatalf("error=%v calls=%d, want immediate non-retry failure", err, calls.Load())
			}
			if errors.Is(err, errK8sLifecycleClaimNotFound) != test.wantNotFound {
				t.Fatalf("domain not-found classification=%t, want %t: %v", errors.Is(err, errK8sLifecycleClaimNotFound), test.wantNotFound, err)
			}
			if errors.Is(err, errK8sControlPlaneRolloutIncomplete) {
				t.Fatalf("non-route-missing response became rollout exhaustion: %v", err)
			}
		})
	}
}

func TestK8sLifecycleRouteRetryStopsOnTransportAmbiguity(t *testing.T) {
	t.Parallel()

	transportFailure := errors.New("response lost after dispatch")
	calls := 0
	base := d13cRoundTripper(func(request *http.Request) (*http.Response, error) {
		calls++
		if !request.Close {
			t.Fatal("lifecycle helper did not request a fresh connection")
		}
		if calls == 1 {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Status:     http.StatusText(http.StatusNotFound),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(d13cRouteMissingBody)),
				Request:    request,
			}, nil
		}
		return nil, transportFailure
	})
	client, err := newAuthedClientWithTransport(Credential{Server: "http://127.0.0.1", Token: "cli-secret"}, lifecycleFreshConnectionTransport{base: base})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	cp := &apiK8sControlPlane{client: client, lifecycleRetry: d13cNoWaitRetryPolicy()}
	_, err = cp.GetLifecycleClaimStatus(context.Background(), d13cTestOrgID, testLifecycleClaim)
	if !errors.Is(err, transportFailure) || calls != 2 || errors.Is(err, errK8sControlPlaneRolloutIncomplete) {
		t.Fatalf("transport ambiguity error=%v calls=%d, want immediate stop after second attempt", err, calls)
	}
}

func TestRetryLifecycleRouteIsOperationAgnostic(t *testing.T) {
	t.Parallel()

	type futureLifecycleResponse struct {
		status int
		body   []byte
	}
	calls := 0
	result, err := retryLifecycleRoute(context.Background(), d13cNoWaitRetryPolicy(),
		func(ctx context.Context) (futureLifecycleResponse, error) {
			calls++
			if fresh, _ := ctx.Value(lifecycleFreshConnectionContextKey{}).(bool); !fresh {
				t.Fatal("generic lifecycle attempt lacks fresh-connection marker")
			}
			if calls == 1 {
				return futureLifecycleResponse{status: http.StatusNotFound, body: []byte(d13cRouteMissingBody)}, nil
			}
			return futureLifecycleResponse{status: http.StatusAccepted}, nil
		},
		func(response futureLifecycleResponse) (int, []byte) { return response.status, response.body },
	)
	if err != nil || calls != 2 || result.status != http.StatusAccepted {
		t.Fatalf("generic future lifecycle operation result=%+v calls=%d error=%v", result, calls, err)
	}
}

type d13cRoundTripper func(*http.Request) (*http.Response, error)

func (f d13cRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func newD13cTestControlPlane(t *testing.T, serverURL string) *apiK8sControlPlane {
	t.Helper()
	controlPlane, err := newAPIK8sControlPlane(Credential{Server: serverURL, Token: "cli-secret"})
	if err != nil {
		t.Fatalf("new control plane: %v", err)
	}
	cp, ok := controlPlane.(*apiK8sControlPlane)
	if !ok {
		t.Fatalf("control plane type=%T", controlPlane)
	}
	cp.lifecycleRetry = d13cNoWaitRetryPolicy()
	return cp
}

func d13cNoWaitRetryPolicy() lifecycleRouteRetryPolicy {
	return lifecycleRouteRetryPolicy{
		maxAttempts: k8sLifecycleRouteRetryMaxAttempts,
		window:      k8sLifecycleRouteRetryWindow,
		backoff:     func(int) time.Duration { return 0 },
		wait: func(ctx context.Context, _ time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return nil
			}
		},
	}
}

func writeD13cLifecycleSuccess(t *testing.T, response http.ResponseWriter, requestPath string) {
	t.Helper()
	if strings.HasSuffix(requestPath, "/remint") {
		_ = json.NewEncoder(response).Encode(map[string]any{
			"claim": testLifecycleClaim, "join_token": testJoinToken, "generation": 4,
			"request_id": testLifecycleRequest, "expires_at": testLifecycleExpiry,
		})
		return
	}
	state := "issued"
	if strings.HasSuffix(requestPath, "/ack") {
		state = "acknowledged"
	}
	if strings.HasSuffix(requestPath, "/abort") {
		state = "aborted"
	}
	_ = json.NewEncoder(response).Encode(map[string]any{
		"claim": testLifecycleClaim, "state": state, "node_name": "gateway-a", "generation": 4,
		"request_id": testLifecycleRequest, "expires_at": testLifecycleExpiry,
	})
}

func assertD13cCASBody(t *testing.T, body string, generation int, wantNodeName bool) {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("decode CAS body %q: %v", body, err)
	}
	if decoded["expected_generation"] != float64(generation) || decoded["request_id"] != testLifecycleRequest {
		t.Fatalf("CAS identity=%v, want generation=%d request=%s", decoded, generation, testLifecycleRequest)
	}
	_, hasNodeName := decoded["node_name"]
	if hasNodeName != wantNodeName {
		t.Fatalf("CAS body node_name presence=%t, want %t: %v", hasNodeName, wantNodeName, decoded)
	}
}

func d13cErrorBody(code, message string) string {
	body, _ := json.Marshal(map[string]any{"error": map[string]string{"code": code, "message": message}})
	return string(body)
}

var d13cRouteMissingBody = d13cErrorBody(k8sLifecycleRouteMissingCode, k8sLifecycleRouteMissingMessage)
