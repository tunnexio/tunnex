package cli

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"testing"
)

type shelvedOutput struct{}

func (shelvedOutput) Write([]byte) (int, error) { panic("shelved command wrote output") }

func TestShelvedSandboxLifecycleRefusesBeforeInputsAndIO(t *testing.T) {
	// Valid-looking credentials cannot activate the product. Invalid flags and
	// missing input must produce the same refusal, before their own validation.
	t.Setenv("TUNNEX_SERVER", "https://fixture.invalid")
	t.Setenv("TUNNEX_MACHINE_TOKEN", "tnxm_fixture")
	t.Setenv("TUNNEX_SANDBOX_ENABLED", "true")
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	calls := 0
	http.DefaultTransport = sandboxLifecycleTransport(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("unexpected request")
	})
	const org = "7f51971b-a172-4253-b3de-dc7734a864b1"
	const id = "715a3dc3-6d55-4844-b589-2bc3822ec275"
	missing := filepath.Join(t.TempDir(), "unread-create-request.json")
	inputs := [][]string{
		nil,
		{"create", "--not-a-flag"},
		{"create", "--org", org, "--request", missing, "--idempotency-key", "stable"},
	}
	for _, verb := range []string{"get", "start", "stop", "delete"} {
		inputs = append(inputs, []string{verb, "--org", org, "--id", id, "--generation", "1"})
	}
	for _, args := range inputs {
		if err := SandboxLifecycle(context.Background(), args, shelvedOutput{}); !errors.Is(err, ErrSandboxShelved) {
			t.Fatalf("args %v: got %v, want shelved refusal before input handling", args, err)
		}
	}
	if calls != 0 {
		t.Fatalf("shelved lifecycle made %d HTTP requests", calls)
	}
}
