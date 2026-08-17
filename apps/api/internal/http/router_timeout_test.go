package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRequestTimeoutLeavesOnlyBoundedRuntimePollToItsOwnDeadline(t *testing.T) {
	handler := requestTimeout(10*time.Millisecond, 45*time.Millisecond)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(30 * time.Millisecond):
			w.WriteHeader(http.StatusNoContent)
		case <-r.Context().Done():
			return
		}
	}))

	for _, tc := range []struct {
		name string
		path string
		want int
	}{
		{name: "runtime poll owns its OpenAPI-bounded wait", path: "/api/v1/agent/runtime/poll", want: http.StatusNoContent},
		{name: "ordinary API route keeps the global timeout", path: "/api/v1/organizations", want: http.StatusGatewayTimeout},
		{name: "runtime report keeps the global timeout", path: "/api/v1/agent/runtime/report", want: http.StatusGatewayTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if rec.Code != tc.want {
				t.Fatalf("status = %d; want %d", rec.Code, tc.want)
			}
		})
	}
}

func TestRequestTimeoutEventuallyCancelsRuntimePoll(t *testing.T) {
	handler := requestTimeout(10*time.Millisecond, 25*time.Millisecond)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	rec := httptest.NewRecorder()
	started := time.Now()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/agent/runtime/poll", nil))
	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d; want %d", rec.Code, http.StatusGatewayTimeout)
	}
	if elapsed := time.Since(started); elapsed < 20*time.Millisecond || elapsed > 100*time.Millisecond {
		t.Fatalf("runtime poll deadline elapsed = %s; want bounded route-specific timeout", elapsed)
	}
}
