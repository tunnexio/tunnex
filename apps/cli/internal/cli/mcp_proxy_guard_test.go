package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The loopback listener is reachable by every local process and by any web
// page open on the agent host. Only a same-host, non-browser JSON request may
// reach the tool gate.
func TestMCPLoopbackGuardRefusesBrowserAndRebindingRequests(t *testing.T) {
	reached := 0
	guard := mcpLoopbackGuard("127.0.0.1:17100", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached++
		w.WriteHeader(http.StatusNoContent)
	}))
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	cases := []struct {
		name        string
		host        string
		origin      string
		contentType string
		want        int
	}{
		{"loopback address", "127.0.0.1:17100", "", "application/json", http.StatusNoContent},
		{"localhost name", "localhost:17100", "", "application/json; charset=utf-8", http.StatusNoContent},
		{"rebinding host", "attacker.example:17100", "", "application/json", http.StatusForbidden},
		{"wrong port", "127.0.0.1:8080", "", "application/json", http.StatusForbidden},
		{"browser origin", "127.0.0.1:17100", "https://attacker.example", "application/json", http.StatusForbidden},
		{"null origin", "127.0.0.1:17100", "null", "application/json", http.StatusForbidden},
		{"simple cross-site form post", "127.0.0.1:17100", "", "text/plain", http.StatusForbidden},
		{"missing content type", "127.0.0.1:17100", "", "", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := reached
			request := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
			request.Host = tc.host
			if tc.origin != "" {
				request.Header.Set("Origin", tc.origin)
			}
			if tc.contentType != "" {
				request.Header.Set("Content-Type", tc.contentType)
			}
			recorder := httptest.NewRecorder()
			guard.ServeHTTP(recorder, request)
			if recorder.Code != tc.want {
				t.Fatalf("status = %d, want %d", recorder.Code, tc.want)
			}
			if allowed := tc.want == http.StatusNoContent; allowed != (reached == before+1) {
				t.Fatalf("handler reached = %v, want %v", reached == before+1, allowed)
			}
		})
	}
}
