package cli

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	Server                     string `json:"server"`
	AppliedRevision            int64  `json:"applied_revision"`
	ClientVersion              string `json:"client_version"`
	WireGuardRevision          int64  `json:"wireguard_revision"`
	WireGuardCandidateRevision int64  `json:"wireguard_candidate_revision,omitempty"`
	WireGuardCandidateApplied  bool   `json:"wireguard_candidate_applied,omitempty"`
}

type ManagedRuntimeOptions struct {
	StatePath        string
	CredentialPath   string
	ConfigPath       string
	ClientVersion    string
	PollWait         int
	Interval         time.Duration
	Backoff          time.Duration
	MaxBackoff       time.Duration
	Jitter           func(time.Duration) time.Duration
	ApplyCommand     func(context.Context, string, string) error
	RotateKeyCommand func(context.Context, string, string) error
}

func DefaultManagedRuntimeOptions() ManagedRuntimeOptions {
	return ManagedRuntimeOptions{StatePath: ManagedRuntimeStatePath, CredentialPath: ManagedRuntimeToken,
		ConfigPath: ManagedRuntimeConfig, ClientVersion: ManagedRuntimeBinary, PollWait: 30,
		Interval: 30 * time.Second, Backoff: time.Second, MaxBackoff: time.Minute,
		Jitter: boundedRuntimeJitter, ApplyCommand: runWireGuardQuick,
		RotateKeyCommand: runWireGuardKeySwap}
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
		statePath:      mustJSON(ManagedRuntimeState{Server: server, ClientVersion: clientVersion, WireGuardRevision: 1}),
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
	if state.WireGuardRevision == 0 {
		state.WireGuardRevision = 1
	}
	credential, err := loadRuntimeCredential(opts.CredentialPath)
	if err != nil {
		return err
	}
	source, err := newManagedRuntimeSource(state.Server, credential, opts.CredentialPath, opts.ConfigPath,
		opts.StatePath, &state, opts.PollWait, opts.RotateKeyCommand)
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
	client         *api.ClientWithResponses
	server         string
	credential     string
	credentialPath string
	wait           int
	configPath     string
	statePath      string
	state          *ManagedRuntimeState
	rotateKey      func(context.Context, string, string) error
}

func newManagedRuntimeSource(server, credential, credentialPath, configPath, statePath string,
	state *ManagedRuntimeState, wait int, rotateKey func(context.Context, string, string) error) (*managedRuntimeSource, error) {
	s := &managedRuntimeSource{server: strings.TrimRight(server, "/"), credentialPath: credentialPath,
		configPath: configPath, statePath: statePath, state: state, wait: wait, rotateKey: rotateKey}
	if err := s.setCredential(credential); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *managedRuntimeSource) setCredential(credential string) error {
	client, err := api.NewClientWithResponses(s.server, api.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+credential)
		return nil
	}))
	if err != nil {
		return err
	}
	s.client = client
	s.credential = credential
	return nil
}

func (s *managedRuntimeSource) Poll(ctx context.Context, applied int64, version string) (ManagedAgentConfig, error) {
	resp, err := s.poll(ctx, applied, version)
	if err != nil {
		return ManagedAgentConfig{}, err
	}
	previousPath := s.credentialPath + ".previous"
	if previous, readErr := loadRuntimeCredential(previousPath); readErr == nil {
		if resp.StatusCode() == http.StatusUnauthorized {
			if err := WriteFileAtomic0600(s.credentialPath, []byte(previous+"\n")); err != nil {
				return ManagedAgentConfig{}, err
			}
			if err := s.setCredential(previous); err != nil {
				return ManagedAgentConfig{}, err
			}
			_ = os.Remove(previousPath)
			_ = os.Remove(s.credentialPath + ".candidate")
			if err := s.cancelLocalWireGuardCandidate(ctx); err != nil {
				return ManagedAgentConfig{}, err
			}
			return ManagedAgentConfig{}, ErrRuntimeUnauthorized
		}
		// Any non-401 proves the candidate authenticated; promotion happens in
		// the auth transaction even if a later edition/handler gate refuses.
		_ = os.Remove(previousPath)
		_ = os.Remove(s.credentialPath + ".candidate")
	}
	if resp.JSON200 != nil && resp.JSON200.CredentialRotationRevision != nil {
		resp, err = s.rotateCredential(ctx, applied, version, *resp.JSON200.CredentialRotationRevision)
		if err != nil {
			return ManagedAgentConfig{}, err
		}
	}
	if resp.JSON200 != nil {
		if err := s.reconcileWireGuardRotation(ctx, resp.JSON200); err != nil {
			return ManagedAgentConfig{}, err
		}
	} else if resp.StatusCode() == http.StatusNoContent {
		if err := s.cancelLocalWireGuardCandidate(ctx); err != nil {
			return ManagedAgentConfig{}, err
		}
	}
	if resp.StatusCode() == http.StatusUnauthorized {
		// Suspension/revocation invalidates any uncommitted successor. Discard it
		// and restore any locally switched WireGuard key before F04 cleanly
		// offboards the interface. A later resume must start from the canonical
		// current key, never from a cancelled candidate.
		_ = os.Remove(s.credentialPath + ".candidate")
		if err := s.cancelLocalWireGuardCandidate(ctx); err != nil {
			return ManagedAgentConfig{}, err
		}
		return ManagedAgentConfig{}, ErrRuntimeUnauthorized
	}
	if resp.StatusCode() == http.StatusNoContent {
		return ManagedAgentConfig{Revision: applied}, nil
	}
	if resp.JSON200 == nil {
		return ManagedAgentConfig{}, fmt.Errorf("runtime poll failed with HTTP %d", resp.StatusCode())
	}
	c := resp.JSON200
	return ManagedAgentConfig{Revision: c.Revision, DeviceID: c.DeviceId.String(), OrgID: c.OrgId.String(), Address: c.Address, GatewayEndpoint: c.GatewayEndpoint, GatewayPublicKey: c.GatewayPublicKey, AllowedIPs: c.AllowedIps, DNS: c.Dns, PersistentKeepalive: c.PersistentKeepalive, CredentialRotationRevision: c.CredentialRotationRevision,
		WireGuardCurrentRevision:  c.WireguardCurrentRevision,
		WireGuardRotationRevision: c.WireguardRotationRevision,
		WireGuardRotationState:    wireGuardRotationState(c.WireguardRotationState)}, nil
}

func (s *managedRuntimeSource) poll(ctx context.Context, applied int64, version string) (*api.PollAgentRuntimeResponse, error) {
	wgRevision := int64(1)
	if s.state != nil && s.state.WireGuardRevision > 0 {
		wgRevision = s.state.WireGuardRevision
	}
	return s.client.PollAgentRuntimeWithResponse(ctx, &api.PollAgentRuntimeParams{AppliedRevision: applied, ClientVersion: version, WaitSeconds: &s.wait, WireguardRevision: &wgRevision})
}

func wireGuardRotationState(state *api.ManagedAgentConfigWireguardRotationState) *string {
	if state == nil {
		return nil
	}
	v := string(*state)
	return &v
}

func (s *managedRuntimeSource) reconcileWireGuardRotation(ctx context.Context, cfg *api.ManagedAgentConfig) error {
	if s.state == nil || s.statePath == "" || s.configPath == "" {
		return errors.New("managed-agent WireGuard rotation state is unavailable")
	}
	// An older control plane omits the additive field; revision 1 is the legacy
	// current key and preserves rolling-upgrade compatibility.
	if cfg.WireguardCurrentRevision == 0 {
		cfg.WireguardCurrentRevision = 1
	}
	candidatePath := s.configPath + ".candidate-key"
	previousPath := s.configPath + ".previous"
	if s.state.WireGuardCandidateRevision > 0 && cfg.WireguardCurrentRevision == s.state.WireGuardCandidateRevision {
		s.state.WireGuardRevision = cfg.WireguardCurrentRevision
		s.state.WireGuardCandidateRevision = 0
		s.state.WireGuardCandidateApplied = false
		if err := saveManagedRuntimeState(s.statePath, *s.state); err != nil {
			return err
		}
		_ = os.Remove(candidatePath)
		_ = os.Remove(previousPath)
		return nil
	}
	if cfg.WireguardRotationRevision == nil || cfg.WireguardRotationState == nil {
		if s.state.WireGuardCandidateRevision > 0 {
			return s.cancelLocalWireGuardCandidate(ctx)
		}
		s.state.WireGuardRevision = cfg.WireguardCurrentRevision
		_ = os.Remove(candidatePath)
		return saveManagedRuntimeState(s.statePath, *s.state)
	}
	revision := *cfg.WireguardRotationRevision
	state := string(*cfg.WireguardRotationState)
	if state == "requested" {
		privateKey, publicKey, err := loadOrCreateWireGuardCandidate(candidatePath)
		if err != nil {
			return err
		}
		_ = privateKey // plaintext remains in the mode-0600 candidate file
		resp, err := s.client.PrepareAgentRuntimeWireGuardWithResponse(ctx, api.AgentWireGuardCandidate{Revision: revision, PublicKey: publicKey})
		if err != nil {
			return err
		}
		if resp.StatusCode() == http.StatusUnauthorized {
			return ErrRuntimeUnauthorized
		}
		if resp.StatusCode() != http.StatusNoContent {
			return fmt.Errorf("runtime WireGuard prepare failed with HTTP %d", resp.StatusCode())
		}
		return nil
	}
	if state == "prepared" {
		if _, _, err := readWireGuardCandidate(candidatePath); err != nil {
			return fmt.Errorf("prepared WireGuard candidate is not recoverable locally: %w", err)
		}
		return nil
	}
	if state != "staged" {
		return errors.New("runtime WireGuard rotation state is invalid")
	}
	if _, _, err := readWireGuardCandidate(candidatePath); err != nil {
		return fmt.Errorf("staged WireGuard candidate is not recoverable locally: %w", err)
	}
	if s.state.WireGuardCandidateRevision != revision {
		s.state.WireGuardCandidateRevision = revision
		s.state.WireGuardCandidateApplied = false
		if err := saveManagedRuntimeState(s.statePath, *s.state); err != nil {
			s.state.WireGuardCandidateRevision = 0
			return err
		}
	}
	if s.state.WireGuardCandidateApplied {
		return nil
	}
	if err := s.applyLocalWireGuardCandidate(ctx, candidatePath, previousPath); err != nil {
		s.state.WireGuardCandidateRevision = 0
		s.state.WireGuardCandidateApplied = false
		_ = saveManagedRuntimeState(s.statePath, *s.state)
		return err
	}
	s.state.WireGuardCandidateApplied = true
	return saveManagedRuntimeState(s.statePath, *s.state)
}

func loadOrCreateWireGuardCandidate(path string) (string, string, error) {
	privateKey, publicKey, err := readWireGuardCandidate(path)
	if err == nil {
		return privateKey, publicKey, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", "", err
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	privateKey = base64.StdEncoding.EncodeToString(key.Bytes())
	publicKey = base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	if err := WriteFileAtomic0600(path, []byte(privateKey+"\n")); err != nil {
		return "", "", err
	}
	return privateKey, publicKey, nil
}

func readWireGuardCandidate(path string) (string, string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	privateKey := strings.TrimSpace(string(b))
	raw, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil || len(raw) != 32 {
		return "", "", errors.New("WireGuard candidate private key is invalid")
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", "", err
	}
	return privateKey, base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func (s *managedRuntimeSource) applyLocalWireGuardCandidate(ctx context.Context, candidatePath, previousPath string) error {
	live, err := os.ReadFile(s.configPath)
	if err != nil {
		return err
	}
	candidate, _, err := readWireGuardCandidate(candidatePath)
	if err != nil {
		return err
	}
	current := live
	if existing, readErr := os.ReadFile(previousPath); readErr == nil {
		current = existing
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	} else if err := WriteFileAtomic0600(previousPath, current); err != nil {
		return err
	}
	if configValue(string(current), "PrivateKey") == "" {
		return errors.New("managed-agent config has no local private key")
	}
	next := replaceConfigPrivateKey(string(current), candidate)
	if err := WriteFileAtomic0600(s.configPath, []byte(next)); err != nil {
		return err
	}
	if s.rotateKey == nil {
		return nil
	}
	if err := s.rotateKey(ctx, s.configPath, candidatePath); err != nil {
		if restoreErr := s.restorePreviousWireGuardConfig(ctx, previousPath); restoreErr != nil {
			return errors.Join(err, restoreErr)
		}
		return err
	}
	return nil
}

func (s *managedRuntimeSource) cancelLocalWireGuardCandidate(ctx context.Context) error {
	candidatePath := s.configPath + ".candidate-key"
	previousPath := s.configPath + ".previous"
	if s.state != nil && s.state.WireGuardCandidateRevision > 0 {
		if err := s.restorePreviousWireGuardConfig(ctx, previousPath); err != nil {
			return err
		}
		s.state.WireGuardCandidateRevision = 0
		s.state.WireGuardCandidateApplied = false
		if err := saveManagedRuntimeState(s.statePath, *s.state); err != nil {
			return err
		}
	}
	_ = os.Remove(candidatePath)
	_ = os.Remove(previousPath)
	return nil
}

func (s *managedRuntimeSource) restorePreviousWireGuardConfig(ctx context.Context, previousPath string) error {
	previous, err := os.ReadFile(previousPath)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("last-good WireGuard config is unavailable")
	}
	if err != nil {
		return err
	}
	if err := WriteFileAtomic0600(s.configPath, previous); err != nil {
		return err
	}
	if s.rotateKey == nil {
		return nil
	}
	privateKey := configValue(string(previous), "PrivateKey")
	if privateKey == "" {
		return errors.New("last-good WireGuard config has no private key")
	}
	restoreKeyPath := s.configPath + ".restore-key"
	if err := WriteFileAtomic0600(restoreKeyPath, []byte(privateKey+"\n")); err != nil {
		return err
	}
	defer os.Remove(restoreKeyPath) //nolint:errcheck
	return s.rotateKey(ctx, s.configPath, restoreKeyPath)
}

func replaceConfigPrivateKey(config, privateKey string) string {
	lines := strings.Split(config, "\n")
	for i, line := range lines {
		name, _, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(name) == "PrivateKey" {
			lines[i] = "PrivateKey = " + privateKey
			return strings.Join(lines, "\n")
		}
	}
	return config
}

func (s *managedRuntimeSource) rotateCredential(ctx context.Context, applied int64, version string, revision int64) (*api.PollAgentRuntimeResponse, error) {
	candidatePath := s.credentialPath + ".candidate"
	previousPath := s.credentialPath + ".previous"
	candidate, err := loadRuntimeCredential(candidatePath)
	if errors.Is(err, os.ErrNotExist) {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		candidate = "tnx_runtime_" + base64.RawURLEncoding.EncodeToString(raw)
		if err := WriteFileAtomic0600(candidatePath, []byte(candidate+"\n")); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	hash := sha256.Sum256([]byte(candidate))
	prepared, err := s.client.PrepareAgentRuntimeCredentialWithResponse(ctx, api.AgentCredentialCandidate{Revision: revision, TokenHash: hex.EncodeToString(hash[:])})
	if err != nil {
		return nil, err // candidate file makes the same hash retryable
	}
	if prepared.StatusCode() == http.StatusUnauthorized {
		return nil, ErrRuntimeUnauthorized
	}
	if prepared.StatusCode() != http.StatusNoContent {
		return nil, fmt.Errorf("runtime credential prepare failed with HTTP %d", prepared.StatusCode())
	}
	old := s.credential
	if err := WriteFileAtomic0600(previousPath, []byte(old+"\n")); err != nil {
		return nil, err
	}
	if err := WriteFileAtomic0600(s.credentialPath, []byte(candidate+"\n")); err != nil {
		_ = os.Remove(previousPath)
		return nil, err
	}
	if err := s.setCredential(candidate); err != nil {
		_ = WriteFileAtomic0600(s.credentialPath, []byte(old+"\n"))
		_ = os.Remove(previousPath)
		return nil, err
	}
	resp, err := s.poll(ctx, applied, version)
	if err != nil {
		// Unknown outcome: keep candidate active plus the 0600 previous file.
		// Restart retries candidate authentication without touching the tunnel.
		return nil, err
	}
	if resp.StatusCode() == http.StatusUnauthorized {
		if restoreErr := WriteFileAtomic0600(s.credentialPath, []byte(old+"\n")); restoreErr != nil {
			return nil, restoreErr
		}
		if restoreErr := s.setCredential(old); restoreErr != nil {
			return nil, restoreErr
		}
		_ = os.Remove(previousPath)
		_ = os.Remove(candidatePath)
		return nil, ErrRuntimeUnauthorized
	}
	_ = os.Remove(previousPath)
	_ = os.Remove(candidatePath)
	return resp, nil
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

// runWireGuardKeySwap changes only the live interface private key. The service,
// interface, address, peer, routes, and DNS remain in place during F05.2.
func runWireGuardKeySwap(ctx context.Context, configPath, keyPath string) error {
	name := strings.TrimSuffix(filepath.Base(configPath), filepath.Ext(configPath))
	if name == "" || strings.ContainsAny(name, " /\\") {
		return errors.New("managed-agent WireGuard interface name is invalid")
	}
	return exec.CommandContext(ctx, "wg", "set", name, "private-key", keyPath).Run()
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
	if state.WireGuardRevision == 0 {
		state.WireGuardRevision = 1
	}
	if state.WireGuardRevision < 1 || state.WireGuardCandidateRevision < 0 ||
		(state.WireGuardCandidateRevision > 0 && state.WireGuardCandidateRevision <= state.WireGuardRevision) ||
		(state.WireGuardCandidateApplied && state.WireGuardCandidateRevision == 0) {
		return errors.New("managed-agent WireGuard rotation state is invalid")
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
	if state.WireGuardRevision == 0 {
		state.WireGuardRevision = 1
	}
	if state.WireGuardRevision < 1 || state.WireGuardCandidateRevision < 0 ||
		(state.WireGuardCandidateRevision > 0 && state.WireGuardCandidateRevision <= state.WireGuardRevision) ||
		(state.WireGuardCandidateApplied && state.WireGuardCandidateRevision == 0) {
		return ManagedRuntimeState{}, errors.New("managed-agent WireGuard rotation state is invalid")
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
