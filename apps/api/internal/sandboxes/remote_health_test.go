package sandboxes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/wgkey"
)

// Model bootstrap's HTTPS callback and private response persistence without a
// database, executable bootstrap, live token or actual provider.
type nestedHealthBootstrap struct{ client *http.Client }

func (n nestedHealthBootstrap) Bootstrap(ctx context.Context, server string, id uuid.UUID, generation int64, directory, _ string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server+"/api/v1/sandbox/bootstrap", nil)
	if err != nil {
		return err
	}
	out, err := n.client.Do(req)
	if err != nil {
		return err
	}
	out.Body.Close()
	if out.StatusCode != http.StatusNoContent {
		return ErrDisabled
	}
	if err = os.Mkdir(directory, 0700); err != nil {
		return err
	}
	state, _ := json.Marshal(map[string]any{"server": server, "sandbox_id": id, "peer_id": uuid.New(), "generation": generation})
	private, public, err := wgkey.Generate()
	if err != nil {
		return err
	}
	config := "[Interface]\nPrivateKey = " + private + "\nAddress = 10.99.0.4/32\n\n[Peer]\nPublicKey = " + public + "\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 10.99.0.0/24\n"
	for name, content := range map[string][]byte{"state.json": state, "wireguard.conf": []byte(config), "runtime-credential": []byte("tnx_sandbox_runtime_" + base64.RawURLEncoding.EncodeToString(make([]byte, 32)))} {
		if err = os.WriteFile(filepath.Join(directory, name), content, 0600); err != nil {
			return err
		}
	}
	return nil
}

func TestRemoteActualTLSNestedEnrollmentHealth(t *testing.T) {
	b := persistentTestBinding()
	worker, client, ctx := remoteSkillsTLSFixture(t, b)
	entered := make(chan error, 1)
	release := make(chan struct{})
	defer close(release)
	bootstrap := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkCtx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		err := client.CheckBinding(checkCtx, b)
		entered <- err
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-release:
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(bootstrap.Close)
	files, err := NewFileBootstrapTransport(worker.ControlRoot, bootstrap.URL, nestedHealthBootstrap{bootstrap.Client()})
	if err != nil {
		t.Fatal(err)
	}
	worker.Files = files
	a := testAuthorization(b, 0)
	if err = client.AuthorizeRuntime(ctx, a); err != nil {
		t.Fatal(err)
	}
	hash, _ := sandboxruntime.Fingerprint(a.spec())
	plan := WorkspacePlan{Authorization: &a, SandboxID: a.SandboxID, OrgID: a.OrgID, Generation: 1, SpecHash: hash}
	if _, _, err = client.MaterializeCreationAssets(ctx, plan, []string{publicTerminalKey(t)}); err != nil {
		t.Fatal(err)
	}
	if err = client.Create(ctx, a.spec()); err != nil {
		t.Fatal(err)
	}
	status, err := client.Inspect(ctx, a.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	handoff := LaunchHandoff{OperationID: uuid.New(), OrgID: b.OrgID, SandboxID: a.SandboxID, GatewayID: b.GatewayID, Generation: 1, RuntimeID: status.RuntimeID, SpecHash: hash, BootstrapToken: "tnx_sandbox_bootstrap_" + strings.Repeat("a", 43)}
	type result struct {
		launch PersistedLaunch
		err    error
	}
	done := make(chan result, 1)
	go func() {
		launch, err := client.Enroll(ctx, handoff)
		done <- result{launch, err}
	}()
	select {
	case err = <-entered:
		if err != nil {
			t.Fatal("nested bootstrap health could not complete during enrollment", err)
		}
	case <-ctx.Done():
		t.Fatal("nested bootstrap never reached health callback")
	}
	// A second effect remains unavailable while enrollment is pending; only
	// the read-only binding check can use the independent authenticated lane.
	if _, err = client.Inspect(ctx, a.SandboxID); !errors.Is(err, ErrDisabled) {
		t.Fatal("second effect admitted while enrollment pending", err)
	}
	foreign := b
	foreign.GatewayID = uuid.New()
	if err = client.CheckBinding(ctx, foreign); !errors.Is(err, ErrDisabled) {
		t.Fatal("independent health accepted mismatched binding", err)
	}
	release <- struct{}{}
	got := <-done
	if got.err != nil || got.launch.Handoff.SandboxID != a.SandboxID || got.launch.Handoff.OperationID != handoff.OperationID || got.launch.Handoff.RuntimeID != status.RuntimeID || !got.launch.Handoff.Persisted {
		t.Fatal("same pinned enrollment did not finish", got.err)
	}
	// The ping lane must still obey the durable retirement fence.
	if err = worker.ControlRoot.WriteFile("api-retired.json", []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = client.CheckBinding(ctx, b); !errors.Is(err, ErrDisabled) {
		t.Fatal("retired worker remained healthy", err)
	}
}
