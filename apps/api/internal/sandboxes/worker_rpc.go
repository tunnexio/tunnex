package sandboxes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxrunner"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"golang.org/x/crypto/ssh"
)

const workerRPCVersion = 1
const workerRPCLimit = 1 << 20

type workerRequest struct {
	Generation    int64
	Authorization *RuntimeAuthorization
	Version       int
	Operation     string
	ID            uuid.UUID
	Plan          *WorkspacePlan
	Keys          []string
	Spec          *sandboxruntime.Spec
	Handoff       *LaunchHandoff
	Target        *PrivateNetworkTarget
	Assets        *sandboxruntime.RuntimeAssets
	HostPublicKey string
}
type workerResponse struct {
	Version       int
	Error         string                         `json:",omitempty"`
	Assets        *sandboxruntime.RuntimeAssets  `json:",omitempty"`
	Terminal      *TerminalDelivery              `json:",omitempty"`
	Status        *sandboxruntime.Status         `json:",omitempty"`
	Launch        *PersistedLaunch               `json:",omitempty"`
	Network       *PrivateNetworkObservation     `json:",omitempty"`
	Probe         *sandboxruntime.SSHProbeResult `json:",omitempty"`
	HostPublicKey string                         `json:",omitempty"`
	Binding       *BoundedRuntimeBinding         `json:",omitempty"`
	Retired       bool                           `json:",omitempty"`
}

func workerErrorCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, sandboxruntime.ErrMissing):
		return "missing"
	case errors.Is(err, ErrInvalid), errors.Is(err, sandboxruntime.ErrInvalid):
		return "invalid"
	case errors.Is(err, ErrConflict), errors.Is(err, sandboxruntime.ErrOwnership):
		return "conflict"
	case errors.Is(err, ErrForbidden):
		return "forbidden"
	default:
		return "unavailable"
	}
}
func workerError(code string) error {
	switch code {
	case "":
		return nil
	case "missing":
		return sandboxruntime.ErrMissing
	case "invalid":
		return ErrInvalid
	case "conflict":
		return ErrConflict
	case "forbidden":
		return ErrForbidden
	default:
		return ErrDisabled
	}
}

// WorkerRPCClient has no database or main encryption credential. Only the
// one-time sandbox launch token crosses the private authenticated socket.
// Protected enrollment/WG/host/probe keys remain worker-local.
type WorkerRPCClient struct {
	mu     sync.Mutex
	grants map[uuid.UUID]int64
	client *http.Client
	probe  ssh.PublicKey
	close  func() error
}

func NewWorkerRPCClient(socket string, workerUID uint32, probe ssh.PublicKey) (*WorkerRPCClient, error) {
	if !filepath.IsAbs(socket) || filepath.Clean(socket) != socket || workerUID == 0 || probe == nil {
		return nil, ErrInvalid
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if err := verifyWorkerSocket(socket, workerUID); err != nil {
			return nil, err
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
		if err != nil {
			return nil, err
		}
		if err = verifyConnectedWorker(conn, workerUID); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}, DisableKeepAlives: true, MaxResponseHeaderBytes: 4096}
	return &WorkerRPCClient{client: &http.Client{Transport: transport, Timeout: 25 * time.Second}, probe: probe}, nil
}
func (c *WorkerRPCClient) call(ctx context.Context, in workerRequest) (workerResponse, error) {
	if c == nil || c.client == nil {
		return workerResponse{}, ErrDisabled
	}
	in.Version = workerRPCVersion
	if in.ID != uuid.Nil && in.Operation != "authorize" {
		c.mu.Lock()
		in.Generation = c.grants[in.ID]
		c.mu.Unlock()
	}
	raw, err := json.Marshal(in)
	if err != nil || len(raw) > workerRPCLimit {
		return workerResponse{}, ErrInvalid
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://sandbox-worker/v1/control", bytes.NewReader(raw))
	if err != nil {
		return workerResponse{}, ErrInvalid
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return workerResponse{}, ErrDisabled
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return workerResponse{}, ErrDisabled
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, workerRPCLimit+1))
	if err != nil || len(body) > workerRPCLimit {
		return workerResponse{}, ErrConflict
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var out workerResponse
	if decoder.Decode(&out) != nil || decoder.Decode(new(any)) != io.EOF || out.Version != workerRPCVersion {
		return workerResponse{}, ErrConflict
	}
	return out, workerError(out.Error)
}
func (c *WorkerRPCClient) CheckBinding(ctx context.Context, b BoundedRuntimeBinding) error {
	out, err := c.call(ctx, workerRequest{Operation: "ping"})
	if err != nil || out.Binding == nil || !bindingEqual(*out.Binding, b) || out.HostPublicKey != string(ssh.MarshalAuthorizedKey(c.probe)) {
		return ErrDisabled
	}
	return nil
}
func (c *WorkerRPCClient) ProbePublicKey() ssh.PublicKey { return c.probe }
func (c *WorkerRPCClient) Create(ctx context.Context, s sandboxruntime.Spec) error {
	_, err := c.call(ctx, workerRequest{Operation: "create", ID: s.ID, Spec: &s})
	return err
}
func (c *WorkerRPCClient) Inspect(ctx context.Context, id uuid.UUID) (sandboxruntime.Status, error) {
	out, err := c.call(ctx, workerRequest{Operation: "inspect", ID: id})
	if err != nil {
		return sandboxruntime.Status{}, err
	}
	if out.Status == nil {
		return sandboxruntime.Status{}, ErrConflict
	}
	return *out.Status, nil
}
func (c *WorkerRPCClient) Start(ctx context.Context, id uuid.UUID) error {
	_, err := c.call(ctx, workerRequest{Operation: "start", ID: id})
	return err
}
func (c *WorkerRPCClient) Stop(ctx context.Context, id uuid.UUID) error {
	_, err := c.call(ctx, workerRequest{Operation: "stop", ID: id})
	return err
}
func (c *WorkerRPCClient) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := c.call(ctx, workerRequest{Operation: "delete", ID: id})
	return err
}
func (c *WorkerRPCClient) ResolveAssets(ctx context.Context, id uuid.UUID) (sandboxruntime.RuntimeAssets, error) {
	out, err := c.call(ctx, workerRequest{Operation: "resolve", ID: id})
	if err != nil {
		return sandboxruntime.RuntimeAssets{}, err
	}
	if out.Assets == nil {
		return sandboxruntime.RuntimeAssets{}, ErrConflict
	}
	return *out.Assets, nil
}
func (c *WorkerRPCClient) MaterializeCreationAssets(ctx context.Context, p WorkspacePlan, k []string) (sandboxruntime.RuntimeAssets, TerminalDelivery, error) {
	out, err := c.call(ctx, workerRequest{Operation: "materialize", ID: p.SandboxID, Plan: &p, Keys: k})
	if err != nil {
		return sandboxruntime.RuntimeAssets{}, TerminalDelivery{}, err
	}
	if out.Assets == nil || out.Terminal == nil {
		return sandboxruntime.RuntimeAssets{}, TerminalDelivery{}, ErrConflict
	}
	return *out.Assets, *out.Terminal, nil
}
func (c *WorkerRPCClient) VerifyTerminalAssets(ctx context.Context, a sandboxruntime.RuntimeAssets) (ssh.PublicKey, error) {
	out, err := c.call(ctx, workerRequest{Operation: "verify-assets", ID: a.SandboxID, Assets: &a})
	if err != nil {
		return nil, err
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(out.HostPublicKey))
	if err != nil {
		return nil, ErrConflict
	}
	return key, nil
}
func (c *WorkerRPCClient) Enroll(ctx context.Context, h LaunchHandoff) (PersistedLaunch, error) {
	out, err := c.call(ctx, workerRequest{Operation: "enroll", ID: h.SandboxID, Handoff: &h})
	if err != nil {
		return PersistedLaunch{}, err
	}
	if out.Launch == nil {
		return PersistedLaunch{}, ErrConflict
	}
	return *out.Launch, nil
}

// The API carries an opaque marker, never reads the worker's WG private key.
// Network methods resolve the exact persisted config again inside the worker.
func (c *WorkerRPCClient) ReadPrivateNetworkConfig(ctx context.Context, t PrivateNetworkTarget) ([]byte, error) {
	_, err := c.call(ctx, workerRequest{Operation: "check-config", ID: t.SandboxID, Target: &t})
	return nil, err
}
func (c *WorkerRPCClient) ApplyPrivateNetwork(ctx context.Context, t PrivateNetworkTarget, _ []byte) error {
	_, err := c.call(ctx, workerRequest{Operation: "apply-network", ID: t.SandboxID, Target: &t})
	return err
}
func (c *WorkerRPCClient) RemovePrivateNetwork(ctx context.Context, t PrivateNetworkTarget, _ []byte) error {
	_, err := c.call(ctx, workerRequest{Operation: "remove-network", ID: t.SandboxID, Target: &t})
	return err
}
func (c *WorkerRPCClient) InspectGatewayAbsence(ctx context.Context, t PrivateNetworkTarget, _ []byte) error {
	_, err := c.call(ctx, workerRequest{Operation: "gateway-absence", ID: t.SandboxID, Target: &t})
	return err
}
func (c *WorkerRPCClient) InspectPrivateNetwork(ctx context.Context, t PrivateNetworkTarget) (PrivateNetworkObservation, error) {
	out, err := c.call(ctx, workerRequest{Operation: "inspect-network", ID: t.SandboxID, Target: &t})
	if err != nil {
		return PrivateNetworkObservation{}, err
	}
	if out.Network == nil {
		return PrivateNetworkObservation{}, ErrConflict
	}
	return *out.Network, nil
}
func (c *WorkerRPCClient) ProbePrivateTerminal(ctx context.Context, t PrivateNetworkTarget, host ssh.PublicKey, identity ssh.Signer) (sandboxruntime.SSHProbeResult, error) {
	if host == nil || identity == nil || !bytes.Equal(identity.PublicKey().Marshal(), c.probe.Marshal()) {
		return sandboxruntime.SSHProbeResult{}, ErrInvalid
	}
	out, err := c.call(ctx, workerRequest{Operation: "probe", ID: t.SandboxID, Target: &t, HostPublicKey: string(ssh.MarshalAuthorizedKey(host))})
	if err != nil {
		return sandboxruntime.SSHProbeResult{}, err
	}
	if out.Probe == nil {
		return sandboxruntime.SSHProbeResult{}, ErrConflict
	}
	return *out.Probe, nil
}

// WorkerRPCServer has external effect adapters and exclusive local roots only:
// no PG pool, policy compiler, master key, API login or user private SSH key.
// ServeWorkerRPC authenticates the actual Unix peer before invoking this handler.
type WorkerRPCServer struct {
	Binding                 BoundedRuntimeBinding
	AssetsRoot, ControlRoot *os.Root
	Assets                  sandboxruntime.AssetResolver
	Provider                sandboxruntime.Provider
	Files                   LaunchControlTransport
	Network                 PrivateNetworkControl
	Gateway                 GatewayAbsenceInspector
	Probe                   TargetSSHProber
	Identity                ssh.Signer
	// LeaseStore opts the retained actor into durable execution expiry. Configure
	// it before serving; this process exclusively owns its Put and Sweep calls.
	LeaseStore *sandboxrunner.LeaseStore
	// LeaseGuard is an actor-local independent deadline fence. A nil guard keeps
	// the existing runtime contract; enable it only with retained supervision.
	LeaseGuard              *sandboxruntime.ActorCgroupLeaseGuard
	mu                      sync.Mutex
	actorScope              *sandboxruntime.CgroupLeaseScope
	actorScopeAuthorization *RuntimeAuthorization
	sandboxID               uuid.UUID
	active                  *RuntimeAuthorization
	epoch                   *PrivateNetworkTarget
	withdrawn               bool
	epochGeneration         int64
	retired                 bool
	RetiredSignal           chan struct{}
	retirementOnce          sync.Once
}
type workerPin struct {
	Authorization   *RuntimeAuthorization `json:",omitempty"`
	Epoch           *PrivateNetworkTarget `json:",omitempty"`
	Withdrawn       bool                  `json:",omitempty"`
	EpochGeneration int64                 `json:",omitempty"`
	Binding         BoundedRuntimeBinding
	SandboxID       uuid.UUID
}

func (s *WorkerRPCServer) loadPin() error {
	if s.ControlRoot == nil {
		return ErrDisabled
	}
	_, err := s.ControlRoot.Lstat("api-binding.json")
	if errors.Is(err, os.ErrNotExist) {
		// Cached identity can still stop owned execution during expiry, but
		// missing durable authority must never permit another effect.
		if s.Binding.Persistent() && (s.active != nil || s.sandboxID != uuid.Nil) {
			return ErrConflict
		}
		return nil
	}
	if err != nil {
		return ErrConflict
	}
	raw, err := readControlFile(s.ControlRoot, "api-binding.json", 32768)
	if err != nil {
		return ErrConflict
	}
	var p workerPin
	if json.Unmarshal(raw, &p) != nil || !bindingEqual(p.Binding, s.Binding) || p.SandboxID == uuid.Nil {
		return ErrConflict
	}
	if s.Binding.Persistent() {
		if p.Authorization == nil || !p.Authorization.valid(s.Binding) || p.Authorization.SandboxID != p.SandboxID {
			return ErrConflict
		}
		if done, err := s.completed(p.SandboxID); err == nil {
			if !reflect.DeepEqual(done, p) {
				return ErrConflict
			}
			if s.ControlRoot.Remove("api-binding.json") != nil || syncTerminalDirectory(s.ControlRoot) != nil {
				return ErrConflict
			}
			s.sandboxID = uuid.Nil
			s.active = nil
			s.epoch = nil
			s.withdrawn = false
			s.epochGeneration = 0
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		s.active = p.Authorization
		s.epoch = p.Epoch
		s.withdrawn = p.Withdrawn
		s.epochGeneration = p.EpochGeneration
	}
	s.sandboxID = p.SandboxID
	return nil
}
func (s *WorkerRPCServer) pin(id uuid.UUID) error {
	if s.sandboxID != uuid.Nil {
		if s.sandboxID != id {
			return ErrForbidden
		}
		return nil
	}
	raw, err := json.Marshal(workerPin{Binding: s.Binding, SandboxID: id})
	if err != nil {
		return ErrInvalid
	}
	f, err := s.ControlRoot.OpenFile("api-binding.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ErrConflict
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || syncTerminalDirectory(s.ControlRoot) != nil {
		return ErrConflict
	}
	s.sandboxID = id
	return nil
}
func (s *WorkerRPCServer) loadRetirement() error {
	_, err := s.ControlRoot.Lstat("api-retired.json")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return ErrConflict
	}
	raw, err := readControlFile(s.ControlRoot, "api-retired.json", 16384)
	var p workerPin
	if err != nil || json.Unmarshal(raw, &p) != nil || !bindingEqual(p.Binding, s.Binding) || p.SandboxID != s.sandboxID || p.SandboxID == uuid.Nil {
		return ErrConflict
	}
	s.retired = true
	return nil
}

// CheckRetirement is called before binding a new listener on process restart.
func (s *WorkerRPCServer) CheckRetirement() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadPin(); err != nil {
		return false, err
	}
	if err := s.loadRetirement(); err != nil {
		return false, err
	}
	return s.retired, nil
}
func (s *WorkerRPCServer) retire(ctx context.Context, id uuid.UUID) error {
	if s.retired {
		return nil
	}
	if _, err := s.Provider.Inspect(ctx, id); !errors.Is(err, sandboxruntime.ErrMissing) {
		return ErrConflict
	}
	// Only the exact pinned sandbox is removed, after API cleanup tombstone
	// authority and independent provider absence. Other retained assets survive.
	if err := s.AssetsRoot.RemoveAll(id.String()); err != nil {
		return ErrConflict
	}
	if err := s.ControlRoot.RemoveAll(id.String()); err != nil {
		return ErrConflict
	}
	raw, _ := json.Marshal(workerPin{Binding: s.Binding, SandboxID: id})
	file, err := s.ControlRoot.OpenFile("api-retired.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ErrConflict
	}
	_, err = file.Write(raw)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil || syncTerminalDirectory(s.ControlRoot) != nil {
		return ErrConflict
	}
	s.retired = true
	return nil
}
func (c *WorkerRPCClient) RetireRuntime(ctx context.Context, id uuid.UUID) error {
	out, err := c.call(ctx, workerRequest{Operation: "retire", ID: id})
	if err != nil {
		return err
	}
	if !out.Retired {
		return ErrConflict
	}
	return nil
}
func (c *WorkerRPCClient) CloseRetiredRuntime(ctx context.Context, id uuid.UUID) error {
	out, err := c.call(ctx, workerRequest{Operation: "retire-close", ID: id})
	if err != nil {
		return err
	}
	if !out.Retired {
		return ErrConflict
	}
	return nil
}
func (s *WorkerRPCServer) dispatch(ctx context.Context, r workerRequest) (workerResponse, error) {
	if s.Binding.deniesRuntimeID(r.ID) {
		return workerResponse{}, ErrForbidden
	}
	// Enrollment calls the API, whose health gate calls back into this worker.
	// Read-only ping must not wait on the effect mutex held by enrollment.
	// The durable retirement marker closes ping without reading mutable state.
	if r.Version == workerRPCVersion && r.Operation == "ping" {
		if s.Binding.Validate() != nil || s.ControlRoot == nil || s.Identity == nil {
			return workerResponse{}, ErrDisabled
		}
		if _, err := s.ControlRoot.Lstat("api-retired.json"); !errors.Is(err, os.ErrNotExist) {
			return workerResponse{}, ErrDisabled
		}
		return workerResponse{Binding: &s.Binding, HostPublicKey: string(ssh.MarshalAuthorizedKey(s.Identity.PublicKey()))}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Binding.Validate() != nil || s.AssetsRoot == nil || s.ControlRoot == nil || s.Assets == nil || s.Provider == nil || s.Files == nil || s.Network == nil || s.Gateway == nil || s.Probe == nil || s.Identity == nil {
		return workerResponse{}, ErrDisabled
	}
	if err := s.loadPin(); err != nil {
		return workerResponse{}, err
	}
	if err := s.loadRetirement(); err != nil {
		return workerResponse{}, err
	}
	if s.Binding.Persistent() && r.Version == workerRPCVersion && r.Operation == "authorize" {
		if r.Authorization == nil || r.ID != r.Authorization.SandboxID || r.Generation != r.Authorization.Generation {
			return workerResponse{}, ErrInvalid
		}
		return workerResponse{}, s.authorize(ctx, *r.Authorization)
	}
	if r.Version == workerRPCVersion && (r.Operation == "retire" || r.Operation == "retire-close") {
		if s.Binding.Persistent() {
			if r.Operation == "retire-close" {
				return workerResponse{}, ErrForbidden
			}
			err := s.retirePersistent(ctx, r.ID, r.Generation)
			return workerResponse{Retired: err == nil}, err
		}
		if r.ID == uuid.Nil || r.ID != s.sandboxID {
			return workerResponse{}, ErrForbidden
		}
		if r.Operation == "retire-close" && !s.retired {
			return workerResponse{}, ErrConflict
		}
		err := s.retire(ctx, r.ID)
		return workerResponse{Retired: err == nil}, err
	}
	if s.retired {
		return workerResponse{}, ErrDisabled
	}
	if r.Version == workerRPCVersion && r.Operation == "ping" {
		return workerResponse{Binding: &s.Binding, HostPublicKey: string(ssh.MarshalAuthorizedKey(s.Identity.PublicKey()))}, nil
	}
	if r.Version != workerRPCVersion || r.ID == uuid.Nil {
		return workerResponse{}, ErrInvalid
	}
	spec := sandboxruntime.Spec{ID: r.ID, ImageDigest: s.Binding.ImageDigest, MemoryMiB: s.Binding.MemoryMiB, CPUs: s.Binding.CPUs, PIDs: s.Binding.PIDs}
	if s.Binding.Persistent() {
		if s.active == nil || r.ID != s.sandboxID || r.Generation != s.active.Generation {
			return workerResponse{}, ErrForbidden
		}
		if !time.Now().Before(s.active.ExpiresAt) {
			switch r.Operation {
			case "create", "start", "enroll", "apply-network", "probe":
				return workerResponse{}, ErrDisabled
			}
		}
		switch r.Operation {
		case "create", "start", "enroll", "apply-network", "probe":
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, s.active.ExpiresAt)
			defer cancel()
		}
		spec = s.active.spec()
		var err error
		ctx, err = s.actorProviderContext(ctx, *s.active)
		if err != nil {
			return workerResponse{}, err
		}
		if s.LeaseGuard != nil && s.actorScope.Generation() != s.active.Generation {
			// A failed pin publication may leave a newer durable lease/scope.
			// Its token is cleanup-only until that exact grant is published.
			switch r.Operation {
			case "create", "start", "enroll", "apply-network", "probe":
				return workerResponse{}, ErrForbidden
			}
		}
	}
	hash, _ := sandboxruntime.Fingerprint(spec)
	if s.sandboxID == uuid.Nil && r.Operation == "resolve" {
		return workerResponse{}, sandboxruntime.ErrMissing
	}
	if r.Operation == "materialize" {
		if !s.Binding.available(time.Now()) || r.Plan == nil || r.Plan.SandboxID != r.ID || r.Plan.OrgID != s.Binding.OrgID || r.Plan.Generation != 1 || r.Plan.RuntimeID != "" || r.Plan.SpecHash != hash {
			return workerResponse{}, ErrForbidden
		}
		if s.Binding.Persistent() && (r.Plan.Authorization == nil || !sameWorkload(*r.Plan.Authorization, *s.active) || r.Plan.Authorization.Generation != s.active.Generation || r.Plan.Authorization.Desired != s.active.Desired || s.active.Desired != "started" || !time.Now().Before(s.active.ExpiresAt)) {
			return workerResponse{}, ErrForbidden
		}
		if err := s.pin(r.ID); err != nil {
			return workerResponse{}, err
		}
	} else if s.sandboxID != r.ID {
		return workerResponse{}, ErrForbidden
	}
	if r.Operation == "create" || r.Operation == "start" || r.Operation == "enroll" || r.Operation == "apply-network" || r.Operation == "probe" {
		if !s.Binding.available(time.Now()) || (s.Binding.Persistent() && (s.active.Desired != "started" || !time.Now().Before(s.active.ExpiresAt))) {
			return workerResponse{}, ErrDisabled
		}
	}
	out := workerResponse{}
	switch r.Operation {
	case "materialize":
		root, err := privateControlChild(s.AssetsRoot, r.ID.String())
		if err != nil {
			return out, err
		}
		defer root.Close()
		a, t, err := MaterializeRuntimeAssets(root, *r.Plan, r.Keys)
		out.Assets, out.Terminal = &a, &t
		return out, err
	case "resolve":
		a, err := s.Assets.ResolveAssets(ctx, r.ID)
		out.Assets = &a
		return out, err
	case "verify-assets":
		a, err := s.Assets.ResolveAssets(ctx, r.ID)
		if err != nil {
			return out, err
		}
		if r.Assets == nil || *r.Assets != a {
			return out, ErrConflict
		}
		key, err := verifyLocalTerminalAssets(a)
		if err == nil {
			out.HostPublicKey = string(ssh.MarshalAuthorizedKey(key))
		}
		return out, err
	case "create":
		if r.Spec == nil || *r.Spec != spec {
			return out, ErrForbidden
		}
		return out, s.Provider.Create(ctx, spec)
	case "inspect":
		status, err := s.Provider.Inspect(ctx, r.ID)
		out.Status = &status
		return out, err
	case "start":
		if s.Binding.Persistent() && (s.active.Desired != "started" || !time.Now().Before(s.active.ExpiresAt)) {
			return out, ErrDisabled
		}
		status, err := s.Provider.Inspect(ctx, r.ID)
		if err != nil {
			return out, err
		}
		if sandboxruntime.Matches(spec, status) != nil {
			return out, ErrConflict
		}
		return out, s.Provider.Start(ctx, r.ID)
	case "stop":
		return out, s.Provider.Stop(ctx, r.ID)
	case "delete":
		return out, s.Provider.Delete(ctx, r.ID)
	case "enroll":
		h := r.Handoff
		if h == nil || h.OrgID != s.Binding.OrgID || h.GatewayID != s.Binding.GatewayID || h.SandboxID != r.ID || h.Generation != 1 || h.SpecHash != hash {
			return out, ErrForbidden
		}
		status, err := s.Provider.Inspect(ctx, r.ID)
		if err != nil || sandboxruntime.Matches(spec, status) != nil || status.RuntimeID != h.RuntimeID {
			return out, ErrConflict
		}
		receipt, err := s.Files.Enroll(ctx, *h)
		out.Launch = &receipt
		return out, err
	case "check-config", "apply-network", "remove-network", "inspect-network", "gateway-absence", "probe":
		t := r.Target
		if t == nil || t.OrgID != s.Binding.OrgID || t.GatewayID != s.Binding.GatewayID || t.SandboxID != r.ID || (!s.Binding.Persistent() && t.Generation != 1) || t.SpecHash != hash {
			return out, ErrForbidden
		}
		if s.Binding.Persistent() {
			if err := s.persistentTarget(ctx, r.Operation, t); err != nil {
				return out, err
			}
		}
		config, err := s.Files.ReadPrivateNetworkConfig(ctx, *t)
		if err != nil {
			return out, err
		}
		switch r.Operation {
		case "check-config":
			return out, nil
		case "apply-network":
			return out, s.Network.ApplyPrivateNetwork(ctx, *t, config)
		case "remove-network":
			return out, s.Network.RemovePrivateNetwork(ctx, *t, config)
		case "gateway-absence":
			err := s.Gateway.InspectGatewayAbsence(ctx, *t, config)
			if err == nil && s.Binding.Persistent() {
				p := s.currentPin()
				p.Withdrawn = true
				err = s.writePin(p)
			}
			return out, err
		case "inspect-network":
			observation, err := s.Network.InspectPrivateNetwork(ctx, *t)
			out.Network = &observation
			return out, err
		case "probe":
			a, err := s.Assets.ResolveAssets(ctx, r.ID)
			if err != nil {
				return out, err
			}
			key, err := verifyLocalTerminalAssets(a)
			if err != nil || r.HostPublicKey != string(ssh.MarshalAuthorizedKey(key)) {
				return out, ErrConflict
			}
			result, err := s.Probe.ProbePrivateTerminal(ctx, *t, key, s.Identity)
			out.Probe = &result
			return out, err
		}
	}
	return out, ErrInvalid
}
func (s *WorkerRPCServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The peer flag can only be installed by ServeWorkerRPC's Unix ConnContext.
	if allowed, _ := r.Context().Value(workerPeerContext{}).(bool); !allowed {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/v1/control" || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "invalid", http.StatusBadRequest)
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, workerRPCLimit))
	decoder.DisallowUnknownFields()
	var in workerRequest
	if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF {
		http.Error(w, "invalid", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	out, err := s.dispatch(ctx, in)
	out.Version = workerRPCVersion
	out.Error = workerErrorCode(err)
	// Never echo raw errors, request tokens, configuration or private key bytes.
	w.Header().Set("Content-Type", "application/json")
	if json.NewEncoder(w).Encode(out) == nil && err == nil && in.Operation == "retire-close" && !s.Binding.Persistent() && s.RetiredSignal != nil {
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		s.retirementOnce.Do(func() { close(s.RetiredSignal) })
	}
}

type workerPeerContext struct{}

var _ WorkerRuntime = (*WorkerRPCClient)(nil)
