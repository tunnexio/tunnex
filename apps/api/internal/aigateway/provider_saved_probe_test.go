package aigateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

type savedProbeFixture struct {
	*providerFixtureEngine
	calls int
	model string
}

func (e *savedProbeFixture) ProbeSavedProviderKey(_ context.Context, spec ProviderKeySpec, provider, model string, mode ModelMode) (ProviderProbeResult, error) {
	e.calls++
	e.model = model
	return ProviderProbeResult{Status: "success", DurationMS: 1}, nil
}

func TestAISavedProviderProbePostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newPolicyFixture(t, ctx, pool)
	e := &savedProbeFixture{providerFixtureEngine: newProviderFixtureEngine()}
	f.policies.engine = e
	f.policies.EnableProviderManagement(true)
	secret := "synthetic-saved-key"
	p, err := f.policies.CreateProvider(ctx, f.org, f.owner, ProviderInput{Provider: "openai", Name: "Saved", Models: []string{"openai/existing"}, Secret: &secret, Enabled: true})
	if err != nil || p.Status != "applied" {
		t.Fatal("fixture create", err)
	}
	in := ProviderProbeInput{Provider: "openai", Model: "openai/new-model", Mode: ModeChat, ConnectionID: &p.ID, ExpectedRevision: &p.Revision}
	for _, tc := range []struct {
		name   string
		org    uuid.UUID
		change func(*ProviderProbeInput)
		status int
	}{
		{"new-model", f.org, func(*ProviderProbeInput) {}, 0},
		{"existing-model", f.org, func(i *ProviderProbeInput) { i.Model = "openai/existing" }, 0},
		{"foreign-org", uuid.New(), func(*ProviderProbeInput) {}, 404},
		{"foreign-id", f.org, func(i *ProviderProbeInput) { id := uuid.New(); i.ConnectionID = &id }, 404},
		{"stale", f.org, func(i *ProviderProbeInput) { v := int64(9); i.ExpectedRevision = &v }, 409},
		{"provider-mismatch", f.org, func(i *ProviderProbeInput) { i.Provider = "anthropic" }, 400},
		{"model-provider-mismatch", f.org, func(i *ProviderProbeInput) { i.Model = "anthropic/new-model" }, 400},
		{"endpoint-override", f.org, func(i *ProviderProbeInput) { v := "https://other.invalid"; i.EndpointURL = &v }, 400},
		{"secret-override", f.org, func(i *ProviderProbeInput) { i.Secret = "override" }, 400},
		{"missing-revision", f.org, func(i *ProviderProbeInput) { i.ExpectedRevision = nil }, 400},
		{"wildcard", f.org, func(i *ProviderProbeInput) { i.Model = "openai/*" }, 400},
		{"invalid-mode", f.org, func(i *ProviderProbeInput) { i.Mode = "other" }, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := f.policies.ConfigureLiteLLMBridge("http://127.0.0.1:1", "fixture-probe-token"); err != nil {
				t.Fatal(err)
			}
			input := in
			tc.change(&input)
			before := e.calls
			out, err := f.policies.ProbeProvider(ctx, tc.org, f.owner, input)
			if tc.status == 0 {
				if err != nil || out.Status != "success" || e.calls != before+1 || e.model != input.Model {
					t.Fatal(out, err)
				}
			} else if usageStatus(err) != tc.status || e.calls != before {
				t.Fatalf("status=%d want=%d, engine calls=%d", usageStatus(err), tc.status, e.calls-before)
			}
		})
	}
	items, _, err := f.policies.ListProviders(ctx, f.org)
	if err != nil || len(items) != 1 || !reflect.DeepEqual(items[0], p) || !reflect.DeepEqual(e.values[p.KeyID], providerSpec(p)) {
		t.Fatal("probe changed saved credential/model scope")
	}
	update := ProviderInput{Provider: p.Provider, Name: p.Name, Models: p.Models, Enabled: false}
	p, err = f.policies.UpdateProvider(ctx, f.org, f.owner, p.ID, update, p.Revision)
	if err != nil {
		t.Fatal(err)
	}
	in.ExpectedRevision = &p.Revision
	if _, err = f.policies.ProbeProvider(ctx, f.org, f.owner, in); usageStatus(err) != 409 {
		t.Fatal("disabled key probed", err)
	}
}

func TestSavedProbeEngineBoundary(t *testing.T) {
	for _, response := range []string{`{"status":"success","duration_ms":1,"api_key":"never-expose"}`, `{"status":"error","duration_ms":1}`, `{"status":"unknown"}`, `{"status":"success","duration_ms":-1}`} {
		t.Run(response[:16], func(t *testing.T) {
			spec := ProviderKeySpec{Provider: "openai", ID: "tnx-managed-" + uuid.NewString(), Revision: 3, Models: []string{"openai/existing"}, Enabled: true}
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					json.NewEncoder(w).Encode(fixtureProviderKey(spec))
					return
				}
				calls++
				time.Sleep(60 * time.Millisecond)
				if r.URL.Path != "/api/providers/openai/keys/"+spec.ID+"/test-connection" {
					t.Error("wrong private path")
				}
				var in map[string]any
				json.NewDecoder(r.Body).Decode(&in)
				if len(in) != 4 || in["key_name"] != spec.ID+"-r3" || in["model"] != "openai/new-model" || in["provider"] != "openai" || in["mode"] != "chat" {
					t.Error("unexpected probe payload")
				}
				w.Write([]byte(response))
			}))
			defer srv.Close()
			e, _ := NewEngine(srv.URL, "admin", "fixture")
			// Metadata's short header deadline must not truncate a model probe.
			e.client.Transport.(*http.Transport).ResponseHeaderTimeout = 20 * time.Millisecond
			out, err := e.ProbeSavedProviderKey(context.Background(), spec, "openai", "openai/new-model", ModeChat)
			if calls != 1 {
				t.Fatal("probe absent")
			}
			if strings.Contains(response, "unknown") || strings.Contains(response, "-1") {
				if err == nil {
					t.Fatal("invalid response accepted")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(out)
			if strings.Contains(string(encoded), "never-expose") {
				t.Fatal("secret escaped")
			}
		})
	}
}
