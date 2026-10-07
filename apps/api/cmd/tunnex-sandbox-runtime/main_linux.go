//go:build linux

// The rootless runtime owns only local workload effects and its own enrollment
// files. Main lifecycle/policy/sealing authority stays in the API process.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	goruntime "runtime"
	"syscall"

	"github.com/tunnexio/tunnex/apps/api/internal/sandboxes"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxproduct"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxrunner"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"golang.org/x/crypto/ssh"
)

func privateFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > limit {
		return nil, sandboxes.ErrInvalid
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil, sandboxes.ErrInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, sandboxes.ErrInvalid
	}
	defer file.Close()
	current, err := file.Stat()
	if err != nil || !os.SameFile(info, current) {
		return nil, sandboxes.ErrInvalid
	}
	return io.ReadAll(io.LimitReader(file, limit+1))
}
func ownedRoot(path string) (*os.Root, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, sandboxes.ErrInvalid
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil, sandboxes.ErrInvalid
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	current, err := root.Lstat(".")
	if err != nil || !os.SameFile(info, current) {
		root.Close()
		return nil, sandboxes.ErrInvalid
	}
	return root, nil
}
func main() {
	// TODO(sandbox-reentry): docs/S-sandbox-shelved-main-reentry.md.
	if sandboxproduct.Shelved {
		fmt.Fprintln(os.Stderr, sandboxproduct.Message)
		os.Exit(1)
	}
	path := flag.String("config", state+"/worker/main-config.json", "private runtime operator configuration")
	role := flag.String("role", roleCombined, "operator-selected combined, actor or transport process")
	flag.Parse()
	if flag.NArg() != 0 || os.Geteuid() == 0 || !cleanRoot(*path) {
		fail()
	}
	raw, err := privateFile(*path, 32768)
	if err != nil {
		fail()
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var cfg config
	if decoder.Decode(&cfg) != nil || decoder.Decode(new(any)) != io.EOF {
		fail()
	}
	paths, err := cfg.paths()
	if err != nil || *path != paths.State+"/worker/main-config.json" {
		fail()
	}
	publicProbe, err := validateRole(cfg, *role, uint32(os.Geteuid()))
	if err != nil {
		fail()
	}
	if cfg.Binding.Persistent() && goruntime.GOARCH != "amd64" {
		fail()
	}
	if *role == roleTransport {
		// Transport does not construct providers, asset/control roots, bootstrap
		// transports or a private probe identity. Actor is the only effect owner.
		protocolRoot, err := ownedRoot(paths.State + "/worker/runner-protocol")
		if err != nil {
			fail()
		}
		defer protocolRoot.Close()
		client, err := remoteClient(cfg.Remote, protocolRoot)
		if err != nil {
			fail()
		}
		forwarder, err := sandboxes.NewUnixControlForwarder(paths.Run+"/api/control.sock", cfg.Supervision.ActorUID, publicProbe, cfg.Binding)
		if err != nil {
			fail()
		}
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		if err = client.Run(ctx, forwarder.ForwardRemoteControl); err != nil && ctx.Err() == nil {
			fail()
		}
		return
	}
	probeKey, err := privateFile(cfg.ProbeKeyFile, 16384)
	if err != nil {
		fail()
	}
	identity, err := ssh.ParsePrivateKey(probeKey)
	if err != nil {
		fail()
	}
	if *role == roleActor && !bytes.Equal(identity.PublicKey().Marshal(), publicProbe.Marshal()) {
		fail()
	}
	assetRoot, err := ownedRoot(paths.State + "/workload-assets")
	if err != nil {
		fail()
	}
	defer assetRoot.Close()
	controlPath := paths.State + "/worker/main-control"
	if cfg.Binding.Persistent() {
		controlPath = paths.State + "/worker/persistent-control"
	}
	// Persistent activation owns a new exclusive root. Old trial retirement proof
	// is retained and continues to close the original trial authority.
	controlRoot, err := ownedRoot(controlPath)
	if err != nil {
		fail()
	}
	defer controlRoot.Close()
	assets, err := sandboxruntime.NewFilesystemAssets(assetRoot)
	if err != nil {
		fail()
	}
	runner := sandboxruntime.RootlessRunner{Root: paths.State + "/worker/storage", RunRoot: paths.Run + "/worker/storage", Home: paths.State + "/worker/home"}
	var guard *sandboxruntime.ActorCgroupLeaseGuard
	var provider *sandboxruntime.Podman
	if *role == roleActor {
		guard, err = sandboxruntime.NewActorCgroupLeaseGuardAt(paths.ActorControl)
		if err != nil {
			fail()
		}
		defer guard.Close()
		provider, err = sandboxruntime.NewActorPodman(runner, assets, guard)
	} else {
		provider, err = sandboxruntime.NewPodmanWithAssets(runner, assets)
	}
	if err != nil {
		fail()
	}
	files, err := sandboxes.NewFileBootstrapTransport(controlRoot, cfg.Server, sandboxes.CommandBootstrap{Binary: cfg.BootstrapBinary, SHA256: cfg.BootstrapSHA256, CAFile: cfg.CAFile})
	if err != nil {
		fail()
	}
	network := &sandboxes.SocketNetwork{Provider: provider, Files: files, Socket: paths.Run + "/helper/control.sock", ProbePrivateKey: probeKey}
	handler := &sandboxes.WorkerRPCServer{Binding: cfg.Binding, AssetsRoot: assetRoot, ControlRoot: controlRoot, Assets: assets, Provider: provider, Files: files, Network: network, Gateway: network, Probe: network, Identity: identity, LeaseGuard: guard, RetiredSignal: make(chan struct{})}
	// Deployment owns the exclusive socket directory/group ACL. Refuse unknown
	// stale sockets instead of unlinking/adopting someone else's endpoint.
	retired, err := handler.CheckRetirement()
	if err != nil {
		fail()
	}
	if retired {
		return
	}
	if cfg.Remote != nil && *role == roleCombined {
		if !cfg.Binding.Persistent() {
			fail()
		}
		protocolRoot, err := ownedRoot(paths.State + "/worker/runner-protocol")
		if err != nil {
			fail()
		}
		defer protocolRoot.Close()
		client, err := remoteClient(cfg.Remote, protocolRoot)
		if err != nil {
			fail()
		}
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		if err = handler.RunRemoteWorker(ctx, client, sandboxrunner.LeaseStore{Root: protocolRoot}); err != nil && ctx.Err() == nil {
			fail()
		}
		return
	}
	socket := paths.Run + "/api/control.sock"
	if *role == roleActor {
		apiRoot, err := ownedRoot(paths.Run + "/api")
		if err != nil {
			fail()
		}
		err = removeStoppedActorSocket(apiRoot, uint32(os.Geteuid()), uint32(os.Getegid()))
		apiRoot.Close()
		if err != nil {
			fail()
		}
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		fail()
	}
	if *role == roleActor {
		// Never unlink a replaced path on shutdown. The next singleton actor
		// verifies and removes only its own refused stale socket.
		listener.SetUnlinkOnClose(false)
	}
	defer listener.Close()
	if os.Chmod(socket, 0660) != nil {
		fail()
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	guardFailed := make(chan struct{}, 1)
	peerUID := cfg.APIUID
	if *role == roleActor {
		protocolRoot, err := ownedRoot(paths.State + "/worker/runner-protocol")
		if err != nil {
			fail()
		}
		defer protocolRoot.Close()
		store := sandboxrunner.LeaseStore{Root: protocolRoot}
		handler.LeaseStore = &store
		peerUID = cfg.Supervision.SupervisorUID
		guardDone := make(chan struct{})
		go func() {
			defer close(guardDone)
			select {
			case <-ctx.Done():
			case <-guard.Fatal():
				// The manager then kills the complete actor tree. No provider
				// error, cgroup path or private runtime data enters the log.
				guardFailed <- struct{}{}
				cancel()
			}
		}()
		defer func() { cancel(); <-guardDone }()
		actorDone := make(chan error, 1)
		go func() {
			actorErr := handler.RunRuntimeActor(ctx, func(error) {
				// Stable retry signal only; provider/helper stderr and private
				// runtime material never enter operator logs.
				fmt.Fprintln(os.Stderr, "sandbox expiry retry pending")
			})
			if actorErr != nil && ctx.Err() == nil {
				cancel()
			}
			actorDone <- actorErr
		}()
		defer func() { cancel(); <-actorDone }()
	}
	if err = sandboxes.ServeWorkerRPC(ctx, listener, peerUID, handler); err != nil && ctx.Err() == nil {
		fail()
	}
	select {
	case <-guardFailed:
		fail()
	default:
	}
}

func remoteClient(cfg *remoteConfig, protocolRoot *os.Root) (*sandboxrunner.Client, error) {
	if cfg == nil || protocolRoot == nil {
		return nil, sandboxes.ErrInvalid
	}
	certPEM, err := privateFile(cfg.CertificateFile, 32768)
	if err != nil {
		return nil, err
	}
	keyPEM, err := privateFile(cfg.PrivateKeyFile, 32768)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	caPEM, err := privateFile(cfg.CAFile, 32768)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, sandboxes.ErrInvalid
	}
	return sandboxrunner.NewClient(cfg.URL, cfg.ServerName, cfg.ControllerURI, cert, roots, protocolRoot)
}
func fail() { fmt.Fprintln(os.Stderr, "sandbox runtime unavailable"); os.Exit(1) }
