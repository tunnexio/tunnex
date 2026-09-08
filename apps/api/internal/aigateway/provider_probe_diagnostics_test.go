package aigateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestProbeDiagnosticsAcrossPrivateBoundaries(t *testing.T) {
	for _, tc := range []struct{ name, status, failure, want string }{
		{"provider", "error", `{"kind":"http_error","source":"provider","http_status":403,"message":"PRIVATE-KEY"}`, `{"kind":"http_error","source":"provider","http_status":403}`},
		{"proxy", "error", `{"kind":"http_error","source":"proxy","http_status":502}`, `{"kind":"http_error","source":"proxy","http_status":502}`},
		{"network", "error", `{"kind":"network_error","source":"provider"}`, `{"kind":"network_error","source":"provider"}`},
		{"timeout", "error", `{"kind":"timeout","source":"gateway"}`, `{"kind":"timeout","source":"gateway"}`},
		{"old-engine", "error", `null`, `null`},
		{"invalid-source", "error", `{"kind":"network_error","source":"PRIVATE-KEY"}`, `null`},
		{"invalid-kind", "error", `{"kind":"PRIVATE-KEY","source":"provider"}`, `null`},
		{"invalid-code", "error", `{"kind":"http_error","source":"provider","http_status":200}`, `null`},
		{"missing-code", "error", `{"kind":"http_error","source":"provider"}`, `null`},
		{"fabricated-code", "error", `{"kind":"network_error","source":"provider","http_status":502}`, `null`},
		{"success-discards-failure", "success", `{"kind":"http_error","source":"provider","http_status":403}`, `null`},
	} {
		for _, saved := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/saved=%v", tc.name, saved), func(t *testing.T) {
				spec := ProviderKeySpec{Provider: "openai", ID: "tnx-managed-" + uuid.NewString(), Revision: 1, Models: []string{"openai/existing"}, Enabled: true}
				calls := 0
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if saved && r.Method == http.MethodGet {
						json.NewEncoder(w).Encode(fixtureProviderKey(spec))
						return
					}
					calls++
					fmt.Fprintf(w, `{"status":%q,"duration_ms":1,"failure":%s,"error":"PRIVATE-KEY"}`, tc.status, tc.failure)
				}))
				defer srv.Close()
				var out ProviderProbeResult
				var err error
				if saved {
					e, _ := NewEngine(srv.URL, "admin", "fixture")
					out, err = e.ProbeSavedProviderKey(context.Background(), spec, "openai", "openai/new", ModeChat)
				} else {
					s := &Policies{providerManagement: true}
					if err := s.ConfigureLiteLLMBridge(srv.URL, "fixture-admin-token"); err != nil {
						t.Fatal(err)
					}
					out, err = s.ProbeProvider(context.Background(), uuid.New(), uuid.New(), ProviderProbeInput{Provider: "openai", Model: "openai/new", Secret: "PRIVATE-KEY"})
				}
				if err != nil || out.Status != tc.status || calls != 1 {
					t.Fatal(out, err, calls)
				}
				failure, _ := json.Marshal(out.Failure)
				if string(failure) != tc.want {
					t.Fatalf("failure=%s want=%s", failure, tc.want)
				}
				encoded, _ := json.Marshal(out)
				if strings.Contains(string(encoded), "PRIVATE-KEY") {
					t.Fatal("raw diagnostic leaked")
				}
			})
		}
	}
}

func TestProbeOuterDeadlineDiagnostic(t *testing.T) {
	for _, saved := range []bool{false, true} {
		for _, partial := range []bool{false, true} {
			t.Run(fmt.Sprintf("saved=%v/partial=%v", saved, partial), func(t *testing.T) {
				spec := ProviderKeySpec{Provider: "openai", ID: "tnx-managed-" + uuid.NewString(), Revision: 1, Models: []string{"openai/existing"}, Enabled: true}
				calls := 0
				release := make(chan struct{})
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if saved && r.Method == http.MethodGet {
						json.NewEncoder(w).Encode(fixtureProviderKey(spec))
						return
					}
					calls++
					io.Copy(io.Discard, r.Body)
					if partial {
						w.Write([]byte(`{"status":`))
						w.(http.Flusher).Flush()
					}
					select {
					case <-r.Context().Done():
					case <-release:
					}
				}))
				defer srv.Close()
				defer close(release)
				ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
				defer cancel()
				var result ProviderProbeResult
				var err error
				if saved {
					e, _ := NewEngine(srv.URL, "admin", "fixture")
					result, err = e.ProbeSavedProviderKey(ctx, spec, "openai", "openai/new", ModeChat)
				} else {
					s := &Policies{providerManagement: true}
					if err := s.ConfigureLiteLLMBridge(srv.URL, "fixture-admin-token"); err != nil {
						t.Fatal(err)
					}
					s.bridge.client.Timeout = 100 * time.Millisecond
					result, err = s.ProbeProvider(ctx, uuid.New(), uuid.New(), ProviderProbeInput{Provider: "openai", Model: "openai/new", Secret: "PRIVATE-KEY"})
				}
				if err != nil || calls != 1 || result.Status != "error" || result.Failure == nil || result.Failure.Kind != "timeout" || result.Failure.Source != "gateway" || result.Failure.HTTPStatus != nil {
					t.Fatal(result, err, calls)
				}
			})
		}
	}
}
