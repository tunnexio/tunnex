package sandboxes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	appcrypto "github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/wgkey"
)

func launchTestSealer(t *testing.T) handoffSealer {
	t.Helper()
	sealer, err := appcrypto.NewSealer(make([]byte, appcrypto.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return sealer
}

type enrollmentInvokerFixture struct {
	f            fixture
	calls        int
	uncertain    bool
	afterPersist func()
}

func (p *enrollmentInvokerFixture) Bootstrap(ctx context.Context, server string, id uuid.UUID, generation int64, directory, token string) error {
	p.calls++
	private, public, err := wgkey.Generate()
	if err != nil {
		return err
	}
	response, err := devices.NewService(p.f.pool, nil, nil).Create(ctx, devices.CreateInput{SandboxBootstrapToken: token, PublicKey: public})
	if err != nil {
		return err
	}
	if err = os.Mkdir(directory, 0700); err != nil {
		return err
	}
	state, _ := json.Marshal(map[string]any{"server": server, "sandbox_id": id, "peer_id": response.Device.ID, "generation": generation})
	for name, body := range map[string][]byte{"state.json": state, "wireguard.conf": []byte(strings.Replace(response.Config, "__TUNNEX_PRIVATE_KEY__", private, 1)), "runtime-credential": []byte(response.RuntimeCredential + "\n")} {
		if err = os.WriteFile(filepath.Join(directory, name), body, 0600); err != nil {
			return err
		}
	}
	if p.afterPersist != nil {
		p.afterPersist()
	}
	if p.uncertain {
		return ErrDisabled
	}
	return nil
}

func TestEnrollmentPostgresRecoversPersistedResponseWithoutNewPeer(t *testing.T) {
	f := newFixture(t)
	_, public, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE nodes SET endpoint='127.0.0.1:51820',wg_public_key=$2 WHERE id=$1`, f.node, public); err != nil {
		t.Fatal(err)
	}
	sandbox, _, err := f.store.Create(f.ctx, f.org, f.user, f.input("control-enrollment"))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.ReconcileQuarantinedStart(f.ctx, sandbox.Identity.ID, &startProvider{}); err != nil {
		t.Fatal(err)
	}
	h, err := f.store.PrepareLaunch(f.ctx, sandbox.Identity.ID, f.node, launchTestSealer(t))
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	invoker := &enrollmentInvokerFixture{f: f, uncertain: true}
	transport, err := NewFileBootstrapTransport(root, "https://fixture.example", invoker)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.EnrollPreparedLaunch(f.ctx, h, transport); !errors.Is(err, ErrDisabled) {
		t.Fatal("uncertain invocation not reported", err)
	}
	recovery, err := f.store.ExistingLaunchOperation(f.ctx, sandbox.Identity.ID)
	if err != nil || recovery.BootstrapToken != "" {
		t.Fatal("recovery minted or exposed token", err)
	}
	// A syntactically valid credential or key from another enrollment cannot
	// confirm this bound peer. Restore the fixture files before recovering.
	credentialPath := filepath.Join(root.Name(), h.SandboxID.String(), h.OperationID.String(), "enrollment/runtime-credential")
	credential, err := os.ReadFile(credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	wrongCredential := "tnx_sandbox_runtime_" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if err = os.WriteFile(credentialPath, []byte(wrongCredential), 0600); err != nil {
		t.Fatal(err)
	}
	if err = f.store.EnrollPreparedLaunch(f.ctx, recovery, transport); !errors.Is(err, ErrConflict) || invoker.calls != 1 {
		t.Fatal("unrelated persisted credential confirmed enrollment", err)
	}
	if err = os.WriteFile(credentialPath, credential, 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(filepath.Dir(credentialPath), "wireguard.conf")
	config, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	wrongPrivate, _, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(config), "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "PrivateKey") {
			lines[i] = "PrivateKey = " + wrongPrivate
		}
	}
	if err = os.WriteFile(configPath, []byte(strings.Join(lines, "\n")), 0600); err != nil {
		t.Fatal(err)
	}
	if err = f.store.EnrollPreparedLaunch(f.ctx, recovery, transport); !errors.Is(err, ErrConflict) || invoker.calls != 1 {
		t.Fatal("unrelated persisted WireGuard key confirmed enrollment", err)
	}
	if err = os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	if err = f.store.EnrollPreparedLaunch(f.ctx, recovery, transport); err != nil || invoker.calls != 1 {
		t.Fatal("persisted recovery re-enrolled", err)
	}
	var ciphertext *string
	var peers int
	if err = f.pool.QueryRow(f.ctx, `SELECT handoff_ciphertext FROM sandbox_launch_operations WHERE id=$1`, h.OperationID).Scan(&ciphertext); err != nil || ciphertext != nil {
		t.Fatal("confirmed secret not cleared", err)
	}
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM devices WHERE org_id=$1 AND kind='sandbox'`, f.org).Scan(&peers); err != nil || peers != 1 {
		t.Fatal("duplicate peer", peers, err)
	}
	current, err := f.store.Get(f.ctx, f.org, f.user, sandbox.Identity.ID)
	if err != nil || current.State != StateStarting {
		t.Fatal("enrollment persistence became Ready", err)
	}
	path := filepath.Join(h.SandboxID.String(), h.OperationID.String(), "enrollment/runtime-credential")
	if err = root.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = f.store.EnrollPreparedLaunch(f.ctx, recovery, transport); !errors.Is(err, ErrConflict) || invoker.calls != 1 {
		t.Fatal("missing persisted credential re-enrolled", err)
	}
}

func TestEnrollmentPostgresStopWinsBeforeConfirmation(t *testing.T) {
	f := newFixture(t)
	_, public, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE nodes SET endpoint='127.0.0.1:51820',wg_public_key=$2 WHERE id=$1`, f.node, public); err != nil {
		t.Fatal(err)
	}
	sandbox, _, err := f.store.Create(f.ctx, f.org, f.user, f.input("control-stop"))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.ReconcileQuarantinedStart(f.ctx, sandbox.Identity.ID, &startProvider{}); err != nil {
		t.Fatal(err)
	}
	h, err := f.store.PrepareLaunch(f.ctx, sandbox.Identity.ID, f.node, launchTestSealer(t))
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	invoker := &enrollmentInvokerFixture{f: f, afterPersist: func() {
		if _, err := f.store.SetDesired(f.ctx, f.org, f.user, sandbox.Identity.ID, sandbox.Revision, "stopped"); err != nil {
			t.Fatal(err)
		}
	}}
	transport, err := NewFileBootstrapTransport(root, "https://fixture.example", invoker)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.EnrollPreparedLaunch(f.ctx, h, transport); !errors.Is(err, ErrConflict) {
		t.Fatal("stop lost enrollment-confirmation race", err)
	}
	var retained bool
	if err = f.pool.QueryRow(f.ctx, `SELECT handoff_ciphertext IS NOT NULL FROM sandbox_launch_operations WHERE id=$1`, h.OperationID).Scan(&retained); err != nil || !retained {
		t.Fatal("stale generation cleared handoff", err)
	}
}
