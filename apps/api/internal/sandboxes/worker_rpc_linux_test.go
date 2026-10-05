//go:build linux

package sandboxes

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"golang.org/x/crypto/ssh"
)

type rpcUnusedFiles struct{}

func (rpcUnusedFiles) Enroll(context.Context, LaunchHandoff) (PersistedLaunch, error) {
	return PersistedLaunch{}, ErrDisabled
}
func (rpcUnusedFiles) ReadPrivateNetworkConfig(context.Context, PrivateNetworkTarget) ([]byte, error) {
	return nil, ErrDisabled
}
func TestWorkerRPCLinuxKernelPeerCredentials(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("rootless Unix RPC contract requires an unprivileged process")
	}
	for _, scenario := range []string{"matching", "wrong-api-uid", "wrong-worker-uid"} {
		t.Run(scenario, func(t *testing.T) {
			root, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			assets, _ := sandboxruntime.NewFilesystemAssets(root)
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			identity, _ := ssh.NewSignerFromKey(key)
			network := &composedNetworkFixture{}
			b := boundedTestBinding()
			handler := &WorkerRPCServer{Binding: b, AssetsRoot: root, ControlRoot: root, Assets: assets, Provider: &runningProvider{}, Files: rpcUnusedFiles{}, Network: network, Gateway: network, Probe: network, Identity: identity, RetiredSignal: make(chan struct{})}
			socket := filepath.Join(t.TempDir(), "control.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			if err = os.Chmod(socket, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			apiUID, workerUID := uint32(os.Geteuid()), uint32(os.Geteuid())
			if scenario == "wrong-api-uid" {
				apiUID--
			}
			if scenario == "wrong-worker-uid" {
				workerUID--
			}
			done := make(chan error, 1)
			go func() { done <- ServeWorkerRPC(ctx, listener, apiUID, handler) }()
			client, err := NewWorkerRPCClient(socket, workerUID, identity.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			checkCtx, checkCancel := context.WithTimeout(ctx, 2*time.Second)
			defer checkCancel()
			err = client.CheckBinding(checkCtx, b)
			if scenario == "matching" && err != nil {
				t.Fatal("actual Unix peer denied", err)
			}
			if scenario != "matching" && !errors.Is(err, ErrDisabled) {
				t.Fatal("foreign Unix peer admitted", err)
			}
			if scenario == "matching" {
				id := uuid.New()
				spec := sandboxruntime.Spec{ID: id, ImageDigest: b.ImageDigest, MemoryMiB: b.MemoryMiB, CPUs: b.CPUs, PIDs: b.PIDs}
				hash, _ := sandboxruntime.Fingerprint(spec)
				plan := WorkspacePlan{SandboxID: id, OrgID: b.OrgID, Generation: 1, SpecHash: hash}
				if _, _, err = client.MaterializeCreationAssets(checkCtx, plan, []string{string(ssh.MarshalAuthorizedKey(identity.PublicKey()))}); err != nil {
					t.Fatal("pin materialization", err)
				}
				if err = client.RetireRuntime(checkCtx, id); err != nil {
					t.Fatal("retirement", err)
				}
				if err = client.CheckBinding(checkCtx, b); !errors.Is(err, ErrDisabled) {
					t.Fatal("retired worker available", err)
				}
				if err = client.CloseRetiredRuntime(checkCtx, id); err != nil {
					t.Fatal("socket retirement", err)
				}
				select {
				case err = <-done:
					if err != nil {
						t.Fatal("retirement exit failed", err)
					}
				case <-time.After(time.Second):
					t.Fatal("retirement did not close listener")
				}
				if _, err = os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("retired socket still exists", err)
				}
				return
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("RPC shutdown blocked")
			}
		})
	}
}
