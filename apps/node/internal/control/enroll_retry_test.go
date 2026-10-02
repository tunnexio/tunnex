package control

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestInitialEnrollmentRetriesOnlyBeforeConnection(t *testing.T) {
	refused := &url.Error{Op: "Post", URL: "http://control/api/v1/agent/enroll", Err: &net.OpError{Op: "dial", Err: errors.New("connection refused")}}
	for _, tc := range []struct {
		name  string
		err   error
		calls int
	}{
		{"connection refused then succeeds", refused, 3},
		{"HTTP refusal", errors.New("enroll failed (503)"), 1},
		{"lost response after possible token consumption", io.EOF, 1},
		{"read timeout after possible token consumption", &net.OpError{Op: "read", Err: errors.New("timeout")}, 1},
		{"cancellation", &net.OpError{Op: "dial", Err: context.Canceled}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls, waits := 0, 0
			result, err := retryInitialEnrollment(t.Context(), func(context.Context) (EnrollResult, error) {
				calls++
				if calls < 3 {
					return EnrollResult{}, tc.err
				}
				return EnrollResult{NodeID: "same-identity"}, nil
			}, func(context.Context, time.Duration) error { waits++; return nil })
			if calls != tc.calls || waits != calls-1 {
				t.Fatalf("calls=%d waits=%d", calls, waits)
			}
			if tc.calls == 3 && (err != nil || result.NodeID != "same-identity") {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if tc.calls == 1 && err == nil {
				t.Fatal("ambiguous failure was retried")
			}
		})
	}
}

func TestInitialEnrollmentRetryIsBoundedAndCancellable(t *testing.T) {
	calls, waits := 0, 0
	_, err := retryInitialEnrollment(t.Context(), func(context.Context) (EnrollResult, error) {
		calls++
		return EnrollResult{}, &net.OpError{Op: "dial", Err: errors.New("unavailable")}
	}, func(_ context.Context, delay time.Duration) error {
		waits++
		if delay > 10*time.Second || delay < time.Second {
			t.Fatalf("unbounded delay: %v", delay)
		}
		return nil
	})
	if err == nil || calls != 12 || waits != 11 {
		t.Fatalf("calls=%d waits=%d error=%v", calls, waits, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = retryInitialEnrollment(ctx, func(context.Context) (EnrollResult, error) {
		t.Fatal("canceled enrollment attempted")
		return EnrollResult{}, nil
	}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestEnrollmentNeverRedirectsOrRetriesAfterHTTPResponse(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		// A redirected connection failure must not be interpreted as a failed
		// first dial and retry a token the first server may have consumed.
		w.Header().Set("Location", "http://127.0.0.1:1/other")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	_, err := EnrollWithRetry(t.Context(), server.URL, "test-only-token", []byte("test-csr"), "test-node", "test", 1)
	if err == nil || calls.Load() != 1 {
		t.Fatalf("calls=%d err=%v", calls.Load(), err)
	}
}
