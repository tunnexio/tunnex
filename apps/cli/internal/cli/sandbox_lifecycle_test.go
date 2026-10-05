package cli

import (
	"bytes"
	"context"
	"github.com/google/uuid"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type sandboxLifecycleTransport func(*http.Request) (*http.Response, error)

func (f sandboxLifecycleTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestSandboxLifecycleStableIntentAndNoHumanCredentials(t *testing.T) {
	org, id, template, terminal := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	t.Setenv("TUNNEX_SERVER", "https://fixture.invalid")
	t.Setenv("TUNNEX_MACHINE_TOKEN", "tnxm_fixture")
	input := filepath.Join(t.TempDir(), "request.json")
	if err := os.WriteFile(input, []byte(`{"template_id":"`+template.String()+`","terminal_device_id":"`+terminal.String()+`","name":"work","ttl_seconds":900,"ssh_public_keys":[],"requested_scope":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	before := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = before })
	calls := 0
	http.DefaultTransport = sandboxLifecycleTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Header.Get("Authorization") != "Bearer tnxm_fixture" || r.Header.Get("Cookie") != "" {
			t.Fatal("credential contract")
		}
		status := 202
		if calls == 1 {
			if r.Method != "POST" || r.Header.Get("Idempotency-Key") != "stable" {
				t.Fatal("retry intent lost")
			}
			raw, _ := io.ReadAll(r.Body)
			if !bytes.Contains(raw, []byte(`"terminal_device_id":"`+terminal.String()+`"`)) {
				t.Fatal("selected terminal intent lost from create JSON")
			}
		} else if calls == 2 {
			status = 200
			if r.Method != "GET" || !strings.HasSuffix(r.URL.Path, id.String()) {
				t.Fatal("read path")
			}
		} else {
			raw, _ := io.ReadAll(r.Body)
			if !bytes.Contains(raw, []byte(`"generation":7`)) || !bytes.Contains(raw, []byte(`"desired_state":"stopped"`)) {
				t.Fatal("generation intent lost")
			}
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"id":"` + id.String() + `","organization_id":"` + org.String() + `","generation":8}`)), Request: r}, nil
	})
	for _, args := range [][]string{{"create", "--org", org.String(), "--request", input, "--idempotency-key", "stable"}, {"get", "--org", org.String(), "--id", id.String()}, {"stop", "--org", org.String(), "--id", id.String(), "--generation", "7"}} {
		if err := SandboxLifecycle(context.Background(), args, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("TUNNEX_MACHINE_TOKEN", "tnx_human")
	if err := SandboxLifecycle(context.Background(), []string{"get", "--org", org.String(), "--id", id.String()}, io.Discard); err == nil || calls != 3 {
		t.Fatal("human credential accepted")
	}
}
