package sandboxes

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxrunner"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"golang.org/x/crypto/ssh"
)

// RemoteWorkerConfig is operator-only. It opens a dedicated private-IP mTLS
// listener, not public REST/UID RPC. Deployment separately owns SG/cert enrollment.
type RemoteWorkerConfig struct {
	Listen, RunnerURI, CertificateFile, PrivateKeyFile, CAFile, CAKeyFile string
	Revoked                                                               bool
}
type brokerTransport struct{ broker *sandboxrunner.Broker }

func (t brokerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	body, e := io.ReadAll(io.LimitReader(r.Body, sandboxrunner.PayloadLimit+1))
	r.Body.Close()
	if e != nil || len(body) > sandboxrunner.PayloadLimit {
		return nil, ErrInvalid
	}
	var request workerRequest
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(&request) != nil || d.Decode(new(any)) != io.EOF {
		return nil, ErrInvalid
	}
	var result json.RawMessage
	if reflect.DeepEqual(request, workerRequest{Version: workerRPCVersion, Operation: "ping"}) {
		result, e = t.broker.CallHealth(r.Context())
	} else {
		result, e = t.broker.Call(r.Context(), body)
	}
	if e != nil {
		return nil, e
	}
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(result)), Request: r}, nil
}
func NewRemoteWorkerRPCClient(c RemoteWorkerConfig, probe ssh.PublicKey) (*WorkerRPCClient, error) {
	host, _, e := net.SplitHostPort(c.Listen)
	ip := net.ParseIP(host)
	if e != nil || ip == nil || !ip.IsPrivate() || probe == nil {
		return nil, ErrInvalid
	}
	broker, e := sandboxrunner.NewBroker(c.RunnerURI)
	if e != nil {
		return nil, ErrInvalid
	}
	cert, e := tls.LoadX509KeyPair(c.CertificateFile, c.PrivateKeyFile)
	if e != nil {
		return nil, ErrInvalid
	}
	raw, e := os.ReadFile(c.CAFile)
	if e != nil {
		return nil, ErrInvalid
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(raw) {
		return nil, ErrInvalid
	}
	config, e := sandboxrunner.TLSConfig(cert, roots)
	if e != nil {
		return nil, ErrInvalid
	}
	caKey, e := os.ReadFile(c.CAKeyFile)
	if e != nil {
		return nil, ErrInvalid
	}
	issuer, e := sandboxrunner.NewIssuer(raw, caKey, cert, c.RunnerURI)
	if e != nil {
		return nil, ErrInvalid
	}
	config.GetCertificate = issuer.GetCertificate
	config.Certificates = nil
	broker.Renew = issuer.RenewRunner
	broker.Revoked = c.Revoked
	listener, e := net.Listen("tcp", c.Listen)
	if e != nil {
		return nil, ErrDisabled
	}
	server := &http.Server{Handler: broker, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	go func() { _ = server.Serve(tls.NewListener(listener, config)) }()
	return &WorkerRPCClient{client: &http.Client{Transport: brokerTransport{broker}, Timeout: 25 * time.Second}, probe: probe, close: server.Close}, nil
}
func (c *WorkerRPCClient) Close() error {
	if c != nil && c.close != nil {
		return c.close()
	}
	return nil
}

// ExecuteRemoteControl is invoked only behind the pinned-controller client, not
// exposed as HTTP. The same dispatch pins/envelopes as Unix RPC remain authoritative.
func (s *WorkerRPCServer) ExecuteRemoteControl(ctx context.Context, command sandboxrunner.Command) (json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(command.Payload))
	d.DisallowUnknownFields()
	var request workerRequest
	if d.Decode(&request) != nil || d.Decode(new(any)) != io.EOF || request.Version != workerRPCVersion {
		return nil, ErrInvalid
	}
	out, e := s.dispatch(ctx, request)
	out.Version = workerRPCVersion
	out.Error = workerErrorCode(e)
	raw, e := json.Marshal(out)
	if e != nil || len(raw) > sandboxrunner.PayloadLimit {
		return nil, ErrInvalid
	}
	return raw, nil
}

// FenceExpiredRuntime stops exact pinned execution locally. It does not claim
// gateway ACK, destroy assets, set canonical Deleted or release an address.
func (s *WorkerRPCServer) FenceExpiredRuntime(ctx context.Context, lease sandboxrunner.Lease) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fenceExpiredRuntimeLocked(ctx, lease)
}

// The retained actor calls this while holding the same effect mutex as dispatch
// and durable authorization. An execution receipt never implies network cleanup.
func (s *WorkerRPCServer) fenceExpiredRuntimeLocked(ctx context.Context, lease sandboxrunner.Lease) error {
	if e := s.loadPin(); e != nil {
		// Durable authority loss closes command effects. Expiry may still stop
		// the cached exact identity, only if the pin is truly absent; corrupt,
		// inaccessible or replaced pins never qualify for this recovery path.
		if s.ControlRoot == nil {
			return e
		}
		_, absent := s.ControlRoot.Lstat("api-binding.json")
		if !errors.Is(absent, os.ErrNotExist) || s.active == nil || !s.active.valid(s.Binding) || s.sandboxID != s.active.SandboxID {
			return e
		}
	}
	if lease.SandboxID == uuid.Nil || lease.Generation <= 0 || lease.CreatedAt.IsZero() || !lease.ExpiresAt.After(lease.CreatedAt) || lease.ExpiresAt.Sub(lease.CreatedAt) > time.Duration(s.Binding.MaxTTLSeconds)*time.Second || time.Now().Before(lease.ExpiresAt) {
		return ErrForbidden
	}
	a := s.active
	if a == nil || a.SandboxID != lease.SandboxID {
		if done, e := s.completed(lease.SandboxID); e == nil {
			if !done.Authorization.CreatedAt.Equal(lease.CreatedAt) || !done.Authorization.ExpiresAt.Equal(lease.ExpiresAt) {
				return ErrForbidden
			}
			return nil
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		// A crash before first pin publication may leave an inert lease. Prove
		// exact provider absence before receipting it; never stop an unpinned ID.
		if s.LeaseGuard != nil {
			scope, err := s.LeaseGuard.Prepare(lease)
			if err != nil {
				return err
			}
			ctx = scope.Context(ctx)
		}
		if _, e := s.Provider.Inspect(ctx, lease.SandboxID); errors.Is(e, sandboxruntime.ErrMissing) {
			return nil
		}
		return ErrConflict
	}
	// A validated authorization may publish its lease before a failed pin write.
	// A newer lease generation is safe for stop-only expiry of the same immutable
	// lifetime; it never grants execution or changes canonical generation.
	if a.SandboxID != lease.SandboxID || lease.Generation <= 0 || !a.CreatedAt.Equal(lease.CreatedAt) || !a.ExpiresAt.Equal(lease.ExpiresAt) || time.Now().Before(a.ExpiresAt) {
		return ErrForbidden
	}
	if s.LeaseGuard != nil {
		copy := *a
		copy.Generation = lease.Generation
		if err := s.prepareActorScope(copy); err != nil {
			return err
		}
		ctx = s.actorScope.Context(ctx)
	}
	status, e := s.Provider.Inspect(ctx, a.SandboxID)
	if errors.Is(e, sandboxruntime.ErrMissing) {
		return nil
	}
	if e != nil {
		return e
	}
	if sandboxruntime.Matches(a.spec(), status) != nil {
		return ErrConflict
	}
	if s.epoch != nil && status.RuntimeID != s.epoch.RuntimeID {
		return ErrConflict
	}
	if !status.Running {
		return nil
	}
	// Stop first: a failed or unavailable network helper cannot consume the stop
	// budget or leave exact owned execution running after its original lifetime.
	if e = s.Provider.Stop(ctx, a.SandboxID); e != nil {
		return e
	}
	stopped, e := s.Provider.Inspect(ctx, a.SandboxID)
	if !errors.Is(e, sandboxruntime.ErrMissing) {
		if e != nil {
			return e
		}
		if sandboxruntime.Matches(a.spec(), stopped) != nil || stopped.RuntimeID != status.RuntimeID {
			return ErrConflict
		}
		if stopped.Running {
			return sandboxruntime.ErrUnavailable
		}
	}
	if s.epoch != nil && s.Files != nil && s.Network != nil {
		if config, readErr := s.Files.ReadPrivateNetworkConfig(ctx, *s.epoch); readErr == nil {
			// Best effort only. Keep the original epoch, withdrawal flag, assets
			// and canonical intent until ordinary reconciliation confirms cleanup.
			_ = s.Network.RemovePrivateNetwork(ctx, *s.epoch, config)
		}
	}
	return nil
}

// RunRemoteWorker supervises offline expiry independently of CP reachability.
// Its single effect lock serializes durable leases with command effects.
func (s *WorkerRPCServer) RunRemoteWorker(ctx context.Context, c *sandboxrunner.Client, store sandboxrunner.LeaseStore) error {
	if c == nil || store.Root == nil || !s.Binding.Persistent() {
		return ErrInvalid
	}
	var effects sync.Mutex
	var supervisor sync.WaitGroup
	supervisor.Add(1)
	defer supervisor.Wait()
	go func() {
		defer supervisor.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				effects.Lock()
				sweepCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
				_ = store.Sweep(sweepCtx, time.Now().UTC(), s.FenceExpiredRuntime)
				cancel()
				effects.Unlock()
			}
		}
	}()
	return c.Run(ctx, func(ctx context.Context, command sandboxrunner.Command) (json.RawMessage, error) {
		var request workerRequest
		d := json.NewDecoder(bytes.NewReader(command.Payload))
		d.DisallowUnknownFields()
		if d.Decode(&request) != nil || d.Decode(new(any)) != io.EOF {
			return nil, ErrInvalid
		}
		if reflect.DeepEqual(request, workerRequest{Version: workerRPCVersion, Operation: "ping"}) {
			return s.ExecuteRemoteControl(ctx, command)
		}
		effects.Lock()
		defer effects.Unlock()
		// Persist the immutable lifetime before granting execution. Failed dispatch
		// leaves only a bounded lease whose exact-provider fence remains deny-safe.
		if request.Operation == "authorize" {
			a := request.Authorization
			if a == nil || !a.valid(s.Binding) || request.ID != a.SandboxID || request.Generation != a.Generation || request.Version != workerRPCVersion {
				return nil, ErrForbidden
			}
			s.mu.Lock()
			pinErr := s.loadPin()
			if pinErr == nil && s.active != nil && (!sameWorkload(*s.active, *a) || a.Generation < s.active.Generation || (a.Generation == s.active.Generation && a.Desired != s.active.Desired)) {
				pinErr = ErrForbidden
			}
			s.mu.Unlock()
			if pinErr != nil {
				return nil, pinErr
			}
			if err := store.Put(sandboxrunner.Lease{SandboxID: a.SandboxID, Generation: a.Generation, CreatedAt: a.CreatedAt, ExpiresAt: a.ExpiresAt}); err != nil {
				return nil, err
			}
		}
		return s.ExecuteRemoteControl(ctx, command)
	})
}
