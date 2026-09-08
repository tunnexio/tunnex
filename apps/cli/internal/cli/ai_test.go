package cli

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAIUsesLoginAndBoundedModelRequest(t *testing.T) {
	t.Setenv("TUNNEX_STATE_DIR", t.TempDir())
	org := "00000000-0000-4000-8000-000000000001"
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer fixture-cli-login" {
			t.Error("stored login not used")
		}
		if r.URL.Path != "/api/v1/organizations/"+org+"/ai-gateway/inference/v1/chat/completions" {
			t.Errorf("wrong endpoint %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"Hello"}}]}`))
	}))
	defer srv.Close()
	if err := SaveCredential(Credential{Server: srv.URL, Token: "fixture-cli-login", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := AI(context.Background(), []string{"chat", "--org", org, "--model", "openrouter/engineering", "--prompt", "Hello"}, &output); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !strings.Contains(output.String(), "Hello") || strings.Contains(output.String(), "fixture-cli-login") {
		t.Fatal("response or credential hygiene failed")
	}
	if err := AI(context.Background(), []string{"chat", "--org", org, "--model", "openrouter/engineering"}, &output); err == nil || calls != 1 {
		t.Fatal("invalid chat reached upstream")
	}
}
func TestAIDoesNotFollowRedirect(t *testing.T) {
	t.Setenv("TUNNEX_STATE_DIR", t.TempDir())
	arrivals := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { arrivals++ }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer srv.Close()
	if err := SaveCredential(Credential{Server: srv.URL, Token: "fixture-cli-login"}); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := AI(context.Background(), []string{"models", "--org", "00000000-0000-4000-8000-000000000001"}, &output); err == nil || arrivals != 0 {
		t.Fatal("redirected login credential")
	}
}
