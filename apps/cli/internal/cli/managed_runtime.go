package cli

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/tunnexio/tunnex/apps/cli/internal/api"
)

const (
	ManagedRuntimeBinary    = "tunnex-agent-runtime"
	ManagedRuntimeUnit      = "tunnex-agent-runtime.service"
	ManagedRuntimeConfig    = "/etc/wireguard/runtime.conf"
	ManagedRuntimeToken     = "/etc/tunnex-agent/runtime-credential"
	ManagedRuntimeStatePath = "/var/lib/tunnex-agent/runtime-state.json"
)

type ManagedRuntimeState struct {
	Server          string `json:"server"`
	AppliedRevision int64  `json:"applied_revision"`
	ClientVersion   string `json:"client_version"`
}

type ManagedRuntimeOptions struct {
	StatePath      string
	CredentialPath string
	ConfigPath     string
	ClientVersion  string
	PollWait       int
	Interval       time.Duration
	Backoff        time.Duration
	MaxBackoff     time.Duration
	Jitter         func(time.Duration) time.Duration
	ApplyCommand   func(context.Context, string, string) error
}

func DefaultManagedRuntimeOptions() ManagedRuntimeOptions {
	return ManagedRuntimeOptions{StatePath: ManagedRuntimeStatePath, CredentialPath: ManagedRuntimeToken,
		ConfigPath: ManagedRuntimeConfig, ClientVersion: ManagedRuntimeBinary, PollWait: 30,
		Interval: 30 * time.Second, Backoff: time.Second, MaxBackoff: time.Minute,
		Jitter: boundedRuntimeJitter, ApplyCommand: runWireGuardQuick}
}

func BootstrapManagedAgent(ctx context.Context, server, token, configPath, credentialPath, statePath, clientVersion string) error {
	if server == "" || token == "" || configPath == "" || credentialPath == "" || statePath == "" {
		return errors.New("managed-agent bootstrap requires server, token, and paths")
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	pub := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	client, err := api.NewClientWithResponses(strings.TrimRight(server, "/"))
	if err != nil {
		return err
	}
	resp, err := client.BootstrapAgentWithResponse(ctx, api.AgentBootstrapRequest{BootstrapToken: token, PublicKey: pub})
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.RuntimeCredential == "" {
		return fmt.Errorf("managed-agent bootstrap refused (HTTP %d)", resp.StatusCode())
	}
	config := strings.Replace(resp.JSON200.Config, "__TUNNEX_PRIVATE_KEY__", base64.StdEncoding.EncodeToString(key.Bytes()), 1)
	if strings.Contains(config, "__TUNNEX_PRIVATE_KEY__") || !strings.Contains(config, "PrivateKey = ") {
		return errors.New("managed-agent bootstrap returned an invalid config template")
	}
	// Write all three files as one recoverable handoff. A later failure restores
	// pre-existing files and removes only files created by this attempt.
	files := map[string][]byte{
		configPath:     []byte(config),
		credentialPath: []byte(resp.JSON200.RuntimeCredential + "\n"),
		statePath:      mustJSON(ManagedRuntimeState{Server: server, ClientVersion: clientVersion}),
	}
	old := make(map[string][]byte)
	existed := make(map[string]bool)
	for path := range files {
		b, readErr := os.ReadFile(path)
		if readErr == nil {
			old[path], existed[path] = b, true
		} else if !errors.Is(readErr, os.ErrNotExist) {
			return readErr
		}
	}
	for path, contents := range files {
		if err := WriteFileAtomic0600(path, contents); err != nil {
			for restorePath := range files {
				if existed[restorePath] {
					_ = WriteFileAtomic0600(restorePath, old[restorePath])
				} else {
					_ = os.Remove(restorePath)
				}
			}
			return err
		}
	}
	return nil
}

func RunManagedAgent(ctx context.Context, opts ManagedRuntimeOptions) error {
	if opts.StatePath == "" || opts.CredentialPath == "" || opts.ConfigPath == "" {
		return errors.New("managed-agent runtime paths are required")
	}
	if opts.Interval <= 0 || opts.Backoff <= 0 || opts.MaxBackoff < opts.Backoff || opts.PollWait < 0 || opts.PollWait > 60 {
		return errors.New("managed-agent runtime timing is outside bounds")
	}
	if opts.Jitter == nil {
		opts.Jitter = boundedRuntimeJitter
	}
	state, err := loadManagedRuntimeState(opts.StatePath)
	if err != nil {
		return err
	}
	credential, err := loadRuntimeCredential(opts.CredentialPath)
	if err != nil {
		return err
	}
	source, err := newManagedRuntimeSource(state.Server, credential, opts.PollWait)
	if err != nil {
		return err
	}
	applier := &wireGuardRuntimeApplier{path: opts.ConfigPath, command: opts.ApplyCommand}
	runtime, err := NewAgentRuntimeAt(source, applier, state.ClientVersion, state.AppliedRevision, state.AppliedRevision > 0)
	if err != nil {
		return err
	}
	backoff := opts.Backoff
	for {
		outcome, checkErr := runtime.CheckOnce(ctx)
		if runtime.AppliedRevision() != state.AppliedRevision {
			state.AppliedRevision = runtime.AppliedRevision()
			if err := saveManagedRuntimeState(opts.StatePath, state); err != nil {
				return err
			}
		}
		// A terminal credential refusal is a successful offboard only when the
		// data-plane disable completed. Exit cleanly so Restart=on-failure leaves
		// the service inactive; a joined disable error remains nonzero below.
		if checkErr == ErrRuntimeUnauthorized {
			return nil
		}
		if errors.Is(checkErr, ErrRuntimeUnauthorized) {
			return checkErr
		}
		if checkErr != nil || outcome == AgentRuntimeInconclusive {
			delay := opts.Jitter(backoff)
			if delay <= 0 || delay > backoff {
				return errors.New("managed-agent runtime jitter is outside bounds")
			}
			if !sleepContext(ctx, delay) {
				return ctx.Err()
			}
			backoff *= 2
			if backoff > opts.MaxBackoff {
				backoff = opts.MaxBackoff
			}
			continue
		}
		backoff = opts.Backoff
		timer := time.NewTimer(opts.Interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// boundedRuntimeJitter spreads fleet retries across the upper half of the
// current exponential-backoff window. Keeping a positive lower bound avoids a
// busy retry loop while the upper bound preserves the configured maximum.
func boundedRuntimeJitter(delay time.Duration) time.Duration {
	half := delay / 2
	if half <= 0 {
		return delay
	}
	return half + time.Duration(mathrand.Int64N(int64(delay-half)+1))
}

type managedRuntimeSource struct {
	client *api.ClientWithResponses
	wait   int
}

func newManagedRuntimeSource(server, credential string, wait int) (*managedRuntimeSource, error) {
	client, err := api.NewClientWithResponses(strings.TrimRight(server, "/"), api.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+credential)
		return nil
	}))
	if err != nil {
		return nil, err
	}
	return &managedRuntimeSource{client: client, wait: wait}, nil
}

func (s *managedRuntimeSource) Poll(ctx context.Context, applied int64, version string) (ManagedAgentConfig, error) {
	resp, err := s.client.PollAgentRuntimeWithResponse(ctx, &api.PollAgentRuntimeParams{AppliedRevision: applied, ClientVersion: version, WaitSeconds: &s.wait})
	if err != nil {
		return ManagedAgentConfig{}, err
	}
	if resp.StatusCode() == http.StatusUnauthorized {
		return ManagedAgentConfig{}, ErrRuntimeUnauthorized
	}
	if resp.StatusCode() == http.StatusNoContent {
		return ManagedAgentConfig{Revision: applied}, nil
	}
	if resp.JSON200 == nil {
		return ManagedAgentConfig{}, fmt.Errorf("runtime poll failed with HTTP %d", resp.StatusCode())
	}
	c := resp.JSON200
	return ManagedAgentConfig{Revision: c.Revision, DeviceID: c.DeviceId.String(), OrgID: c.OrgId.String(), Address: c.Address, GatewayEndpoint: c.GatewayEndpoint, GatewayPublicKey: c.GatewayPublicKey, AllowedIPs: c.AllowedIps, DNS: c.Dns, PersistentKeepalive: c.PersistentKeepalive}, nil
}

func (s *managedRuntimeSource) Report(ctx context.Context, report AgentRuntimeReport) error {
	code := api.AgentRuntimeReportErrorCode(report.ErrorCode)
	resp, err := s.client.ReportAgentRuntimeWithResponse(ctx, api.AgentRuntimeReport{AppliedRevision: report.AppliedRevision, AttemptedRevision: report.AttemptedRevision, ClientVersion: report.ClientVersion, ErrorCode: code})
	if err != nil {
		return err
	}
	if resp.StatusCode() == http.StatusUnauthorized {
		return ErrRuntimeUnauthorized
	}
	if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
		return fmt.Errorf("runtime report failed with HTTP %d", resp.StatusCode())
	}
	return nil
}

type wireGuardRuntimeApplier struct {
	path    string
	command func(context.Context, string, string) error
}

func (a *wireGuardRuntimeApplier) Apply(ctx context.Context, cfg ManagedAgentConfig) error {
	old, err := os.ReadFile(a.path)
	if err != nil {
		return err
	}
	privateKey := configValue(string(old), "PrivateKey")
	if privateKey == "" {
		return errors.New("managed-agent config has no local private key")
	}
	candidate := renderManagedConfig(privateKey, cfg)
	if err := WriteFileAtomic0600(a.path, []byte(candidate)); err != nil {
		return err
	}
	if a.command == nil {
		return nil
	}
	if err := a.command(ctx, a.path, "apply"); err != nil {
		if restoreErr := WriteFileAtomic0600(a.path, old); restoreErr != nil {
			return errors.Join(err, fmt.Errorf("restore last-good agent config: %w", restoreErr))
		}
		// wg-quick apply is a down/up replacement. A candidate can fail after
		// the old interface has already been removed, so restoring only the
		// file would leave the recorded last-good revision unavailable on the
		// wire. Re-apply the restored bytes before surfacing the candidate
		// failure; a restore failure is joined so the caller cannot report a
		// healthy last-good tunnel that is actually down.
		if restoreErr := a.command(ctx, a.path, "apply"); restoreErr != nil {
			return errors.Join(err, fmt.Errorf("re-apply last-good agent config: %w", restoreErr))
		}
		return err
	}
	return nil
}

func (a *wireGuardRuntimeApplier) Disable(ctx context.Context) error {
	if a.command == nil {
		return nil
	}
	return a.command(ctx, a.path, "disable")
}

func runWireGuardQuick(ctx context.Context, path, action string) error {
	if action == "disable" {
		return runWireGuardQuickDown(ctx, path)
	}
	if err := runWireGuardQuickDown(ctx, path); err != nil {
		return err
	}
	return exec.CommandContext(ctx, "wg-quick", "up", path).Run()
}

func runWireGuardQuickDown(ctx context.Context, path string) error {
	cmd := exec.CommandContext(ctx, "wg-quick", "down", path)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	message := strings.ToLower(string(out))
	// Only the documented absent-interface forms are idempotent. Command,
	// permission, malformed-config, and other failures stay fatal so revoke
	// cannot report success while a tunnel remains active.
	if strings.Contains(message, "does not exist") || strings.Contains(message, "no such device") || strings.Contains(message, "cannot find device") || strings.Contains(message, "is not up") || strings.Contains(message, "is not a wireguard interface") {
		return nil
	}
	return fmt.Errorf("wg-quick down failed: %w", err)
}

func configValue(config, key string) string {
	for _, line := range strings.Split(config, "\n") {
		name, value, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(name) == key {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func renderManagedConfig(privateKey string, cfg ManagedAgentConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s\n", privateKey, cfg.Address)
	if len(cfg.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(cfg.DNS, ", "))
	}
	b.WriteString("MTU = 1420\n\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = %d\n", cfg.GatewayPublicKey, cfg.GatewayEndpoint, strings.Join(cfg.AllowedIPs, ", "), cfg.PersistentKeepalive)
	return b.String()
}

func loadRuntimeCredential(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	got := strings.TrimSpace(string(b))
	if got == "" || !strings.HasPrefix(got, "tnx_runtime_") {
		return "", errors.New("managed-agent runtime credential is invalid")
	}
	return got, nil
}

func saveManagedRuntimeState(path string, state ManagedRuntimeState) error {
	if state.Server == "" || state.ClientVersion == "" {
		return errors.New("managed-agent runtime state is incomplete")
	}
	return WriteFileAtomic0600(path, mustJSON(state))
}

func loadManagedRuntimeState(path string) (ManagedRuntimeState, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return ManagedRuntimeState{}, err
	}
	var legacy struct {
		Credential *string `json:"credential"`
	}
	if err := json.Unmarshal(b, &legacy); err != nil {
		return ManagedRuntimeState{}, err
	}
	if legacy.Credential != nil {
		return ManagedRuntimeState{}, errors.New("managed-agent runtime state contains an embedded credential")
	}
	var state ManagedRuntimeState
	if err := json.Unmarshal(b, &state); err != nil {
		return ManagedRuntimeState{}, err
	}
	return state, nil
}

func mustJSON(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func RuntimeStateDir(path string) string { return filepath.Dir(path) }
