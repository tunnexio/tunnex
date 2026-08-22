package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
)

// ManagedAgentConfig is the complete server-owned mutable configuration for
// one AI-agent WireGuard peer. The runtime credential and private key are
// intentionally absent: neither is configuration data, and neither may be
// returned by the steady-state poll.
type ManagedAgentConfig struct {
	Revision                   int64
	DeviceID                   string
	OrgID                      string
	Address                    string
	GatewayEndpoint            string
	GatewayPublicKey           string
	AllowedIPs                 []string
	DNS                        []string
	PersistentKeepalive        int
	MCPUpstream                *string
	CredentialRotationRevision *int64
	WireGuardCurrentRevision   int64
	WireGuardRotationRevision  *int64
	WireGuardRotationState     *string
}

// AgentRuntimeReport contains bounded facts only. ErrorCode is a stable code,
// never a raw command error that could contain a path, token or config body.
type AgentRuntimeReport struct {
	AppliedRevision   int64
	AttemptedRevision int64
	ClientVersion     string
	ErrorCode         string
	MCPInventory      map[string]interface{}
	MCPOAuthDiscovery map[string]interface{}
}

// AgentRuntimeSource is implemented by the F04 authenticated poll/report API.
// The applied revision is sent with the poll so the server can answer without
// shipping a body when the client is current.
type AgentRuntimeSource interface {
	Poll(ctx context.Context, appliedRevision int64, clientVersion string) (ManagedAgentConfig, error)
	Report(ctx context.Context, report AgentRuntimeReport) error
}

// AgentRuntimeApplier owns the privileged, atomic replacement of the local
// WireGuard configuration. Disable must be idempotent and fail closed.
type AgentRuntimeApplier interface {
	Apply(ctx context.Context, cfg ManagedAgentConfig) error
	Disable(ctx context.Context) error
}

var ErrRuntimeUnauthorized = errors.New("managed agent runtime credential refused")

type AgentRuntimeOutcome string

const (
	AgentRuntimeApplied      AgentRuntimeOutcome = "applied"
	AgentRuntimeUnchanged    AgentRuntimeOutcome = "unchanged"
	AgentRuntimeInconclusive AgentRuntimeOutcome = "inconclusive"
)

// AgentRuntime reconciles one managed AI agent. Cold start is fail-closed: no
// valid server configuration means no tunnel. After one successful apply, a
// transient poll or apply failure keeps the last-good configuration in place;
// stripping it would turn a control-plane blip into an outage. A revision is
// advanced only after the privileged atomic apply succeeds.
type AgentRuntime struct {
	mu            sync.Mutex
	source        AgentRuntimeSource
	applier       AgentRuntimeApplier
	clientVersion string
	applied       int64
	initialized   bool
}

func NewAgentRuntime(source AgentRuntimeSource, applier AgentRuntimeApplier, clientVersion string) (*AgentRuntime, error) {
	return NewAgentRuntimeAt(source, applier, clientVersion, 0, false)
}

func NewAgentRuntimeAt(source AgentRuntimeSource, applier AgentRuntimeApplier, clientVersion string, applied int64, initialized bool) (*AgentRuntime, error) {
	if source == nil || applier == nil {
		return nil, errors.New("agent runtime requires a source and applier")
	}
	clientVersion = strings.TrimSpace(clientVersion)
	if clientVersion == "" || len(clientVersion) > 128 {
		return nil, errors.New("agent runtime requires a bounded client version")
	}
	if applied < 0 {
		return nil, errors.New("agent runtime applied revision must be nonnegative")
	}
	return &AgentRuntime{source: source, applier: applier, clientVersion: clientVersion, applied: applied, initialized: initialized}, nil
}

func (r *AgentRuntime) AppliedRevision() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.applied
}

// CheckOnce performs one poll/apply/report cycle. Report failure is surfaced
// but never rolls back an already-applied local revision; the next poll carries
// that revision again and repairs CP observability without configuration churn.
func (r *AgentRuntime) CheckOnce(ctx context.Context) (AgentRuntimeOutcome, error) {
	// Reconcile cycles are deliberately single-flight. Overlapping polls can
	// return different revisions and their privileged applies may finish out of
	// order; serializing the complete cycle prevents an older config from
	// overwriting a newer last-good config or regressing the reported revision.
	r.mu.Lock()
	defer r.mu.Unlock()

	cfg, err := r.source.Poll(ctx, r.applied, r.clientVersion)
	if err != nil {
		if errors.Is(err, ErrRuntimeUnauthorized) {
			return AgentRuntimeInconclusive, r.offboardUnauthorized(ctx)
		}
		return r.coldStartFailure(ctx, fmt.Errorf("agent config poll: %w", err))
	}
	if cfg.Revision < r.applied {
		return AgentRuntimeInconclusive, fmt.Errorf("agent config revision moved backwards: got %d, applied %d", cfg.Revision, r.applied)
	}
	if cfg.Revision == r.applied && !r.initialized {
		if err := r.applier.Disable(ctx); err != nil {
			return AgentRuntimeInconclusive, fmt.Errorf("disable pending agent tunnel: %w", err)
		}
		return AgentRuntimeInconclusive, nil
	}
	if cfg.Revision == r.applied && r.initialized {
		report := AgentRuntimeReport{
			AppliedRevision: r.applied, AttemptedRevision: r.applied,
			ClientVersion: r.clientVersion,
		}
		if err := r.source.Report(ctx, report); err != nil {
			if errors.Is(err, ErrRuntimeUnauthorized) {
				return AgentRuntimeInconclusive, r.offboardUnauthorized(ctx)
			}
			return AgentRuntimeInconclusive, fmt.Errorf("agent config heartbeat: %w", err)
		}
		return AgentRuntimeUnchanged, nil
	}
	if err := validateManagedAgentConfig(cfg); err != nil {
		if reportErr := r.reportFailure(ctx, cfg.Revision, "invalid_config"); errors.Is(reportErr, ErrRuntimeUnauthorized) {
			return AgentRuntimeInconclusive, r.offboardUnauthorized(ctx)
		}
		return r.coldStartFailure(ctx, fmt.Errorf("invalid agent config: %w", err))
	}
	if err := r.applier.Apply(ctx, cfg); err != nil {
		if reportErr := r.reportFailure(ctx, cfg.Revision, "apply_failed"); errors.Is(reportErr, ErrRuntimeUnauthorized) {
			return AgentRuntimeInconclusive, r.offboardUnauthorized(ctx)
		}
		return r.coldStartFailure(ctx, fmt.Errorf("apply agent config: %w", err))
	}

	r.applied = cfg.Revision
	r.initialized = true
	report := AgentRuntimeReport{
		AppliedRevision: cfg.Revision, AttemptedRevision: cfg.Revision,
		ClientVersion: r.clientVersion,
	}
	if err := r.source.Report(ctx, report); err != nil {
		if errors.Is(err, ErrRuntimeUnauthorized) {
			return AgentRuntimeInconclusive, r.offboardUnauthorized(ctx)
		}
		return AgentRuntimeInconclusive, fmt.Errorf("report applied agent config: %w", err)
	}
	return AgentRuntimeApplied, nil
}

func (r *AgentRuntime) offboardUnauthorized(ctx context.Context) error {
	if err := r.applier.Disable(ctx); err != nil {
		return errors.Join(ErrRuntimeUnauthorized, fmt.Errorf("disable revoked agent tunnel: %w", err))
	}
	// The applied revision describes the live data plane. A successful
	// terminal offboard removes that data plane, so persist revision zero. A
	// later opt-in can then re-apply the current server revision instead of
	// treating an absent interface as already current.
	r.applied = 0
	r.initialized = false
	return ErrRuntimeUnauthorized
}

func (r *AgentRuntime) reportFailure(ctx context.Context, attempted int64, code string) error {
	return r.source.Report(ctx, AgentRuntimeReport{
		AppliedRevision: r.applied, AttemptedRevision: attempted,
		ClientVersion: r.clientVersion, ErrorCode: code,
	})
}

func (r *AgentRuntime) coldStartFailure(ctx context.Context, cause error) (AgentRuntimeOutcome, error) {
	if r.initialized {
		return AgentRuntimeInconclusive, cause
	}
	if err := r.applier.Disable(ctx); err != nil {
		return AgentRuntimeInconclusive, errors.Join(cause, fmt.Errorf("disable unconfigured agent tunnel: %w", err))
	}
	return AgentRuntimeInconclusive, cause
}

func validateManagedAgentConfig(cfg ManagedAgentConfig) error {
	if cfg.Revision < 1 {
		return errors.New("revision must be positive")
	}
	if strings.TrimSpace(cfg.DeviceID) == "" || strings.TrimSpace(cfg.OrgID) == "" {
		return errors.New("device and organization are required")
	}
	addr, err := netip.ParsePrefix(strings.TrimSpace(cfg.Address))
	if err != nil || !addr.Addr().IsValid() {
		return errors.New("invalid interface address")
	}
	if _, _, err := net.SplitHostPort(strings.TrimSpace(cfg.GatewayEndpoint)); err != nil {
		return errors.New("invalid gateway endpoint")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cfg.GatewayPublicKey))
	if err != nil || len(key) != 32 {
		return errors.New("invalid gateway public key")
	}
	if len(cfg.AllowedIPs) == 0 {
		return errors.New("allowed IPs must not be empty")
	}
	for _, raw := range cfg.AllowedIPs {
		if _, err := netip.ParsePrefix(strings.TrimSpace(raw)); err != nil {
			return fmt.Errorf("invalid allowed IP %q", raw)
		}
	}
	for _, raw := range cfg.DNS {
		if _, err := netip.ParseAddr(strings.TrimSpace(raw)); err != nil {
			return fmt.Errorf("invalid DNS address %q", raw)
		}
	}
	if cfg.PersistentKeepalive < 0 || cfg.PersistentKeepalive > 65535 {
		return errors.New("invalid persistent keepalive")
	}
	return nil
}
