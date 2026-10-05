package sandboxes

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

type BootstrapInvoker interface {
	Bootstrap(context.Context, string, uuid.UUID, int64, string, string) error
}

// CommandBootstrap invokes the preloaded client; tokens never enter argv,
// environment or diagnostics. SHA256 is supplied by trusted image/deployment
// verification, not by a browser. No download or package install occurs here.
type CommandBootstrap struct {
	Binary, SHA256 string
	CAFile         string
}

func (b CommandBootstrap) Bootstrap(ctx context.Context, server string, id uuid.UUID, generation int64, directory, token string) error {
	if !filepath.IsAbs(b.Binary) || filepath.Clean(b.Binary) != b.Binary || len(b.SHA256) != 64 {
		return ErrInvalid
	}
	info, err := os.Lstat(b.Binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 || info.Size() > 67108864 {
		return ErrInvalid
	}
	file, err := os.Open(b.Binary)
	if err != nil {
		return ErrDisabled
	}
	hash := sha256.New()
	_, readErr := io.Copy(hash, io.LimitReader(file, 67108865))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || hex.EncodeToString(hash.Sum(nil)) != b.SHA256 {
		return ErrInvalid
	}
	args := []string{"--server", server, "--sandbox-id", id.String(), "--generation", strconv.FormatInt(generation, 10), "--handoff-dir", directory}
	if b.CAFile != "" {
		if !filepath.IsAbs(b.CAFile) || filepath.Clean(b.CAFile) != b.CAFile {
			return ErrInvalid
		}
		args = append(args, "--ca-file", b.CAFile)
	}
	cmd := exec.CommandContext(ctx, b.Binary, args...)
	cmd.Stdin = strings.NewReader(token + "\n")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/bin"}
	if cmd.Run() != nil {
		return ErrDisabled
	}
	return nil
}

type controlBinding struct {
	OperationID, OrgID, SandboxID, GatewayID uuid.UUID
	Generation                               int64
	RuntimeID, SpecHash, Server              string
}

func (t *FileBootstrapTransport) binding(h LaunchHandoff) controlBinding {
	return controlBinding{h.OperationID, h.OrgID, h.SandboxID, h.GatewayID, h.Generation, h.RuntimeID, h.SpecHash, t.server}
}

// LaunchControlTransport is a trusted control boundary, never a browser route.
// A remote worker keeps protected enrollment files outside the API/workload.
type LaunchControlTransport interface {
	Enroll(context.Context, LaunchHandoff) (PersistedLaunch, error)
	ReadPrivateNetworkConfig(context.Context, PrivateNetworkTarget) ([]byte, error)
}

type PersistedLaunch struct {
	Handoff            HandoffConfirmation
	WireGuardPublicKey string
	CredentialHash     [32]byte
}

// FileBootstrapTransport root is exclusive control storage outside all workload
// mounts. The caller holds the sandbox lifecycle lease during Enroll. It never
// turns a persisted enrollment into a network or SSH readiness assertion.
type FileBootstrapTransport struct {
	root    *os.Root
	server  string
	invoker BootstrapInvoker
}

func NewFileBootstrapTransport(root *os.Root, server string, invoker BootstrapInvoker) (*FileBootstrapTransport, error) {
	parsed, err := url.Parse(server)
	if root == nil || invoker == nil || err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, ErrInvalid
	}
	return &FileBootstrapTransport{root, strings.TrimRight(server, "/"), invoker}, nil
}

func privateControlChild(root *os.Root, name string) (*os.Root, error) {
	if _, err := uuid.Parse(name); err != nil {
		return nil, ErrInvalid
	}
	info, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		if err = root.Mkdir(name, 0700); err != nil {
			return nil, err
		}
	} else if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrConflict
	}
	return root.OpenRoot(name)
}

func (t *FileBootstrapTransport) Enroll(ctx context.Context, h LaunchHandoff) (PersistedLaunch, error) {
	if h.OperationID == uuid.Nil || h.OrgID == uuid.Nil || h.SandboxID == uuid.Nil || h.GatewayID == uuid.Nil || h.Generation < 1 || len(h.RuntimeID) != 64 || len(h.SpecHash) != 64 {
		return PersistedLaunch{}, ErrInvalid
	}
	owned, err := privateControlChild(t.root, h.SandboxID.String())
	if err != nil {
		return PersistedLaunch{}, err
	}
	defer owned.Close()
	job, err := privateControlChild(owned, h.OperationID.String())
	if err != nil {
		return PersistedLaunch{}, err
	}
	defer job.Close()
	binding := t.binding(h)
	raw, _ := json.Marshal(binding)
	if _, err = job.Lstat("binding.json"); errors.Is(err, fs.ErrNotExist) {
		file, err := job.OpenFile("binding.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return PersistedLaunch{}, err
		}
		_, err = file.Write(raw)
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			return PersistedLaunch{}, ErrConflict
		}
		if err = syncTerminalDirectory(job); err != nil {
			return PersistedLaunch{}, err
		}
	} else {
		stored, err := readControlFile(job, "binding.json", 16384)
		if err != nil || !bytes.Equal(stored, raw) {
			return PersistedLaunch{}, ErrConflict
		}
	}
	if _, err = job.Lstat("enrollment"); errors.Is(err, fs.ErrNotExist) {
		// Recovery with an already bound peer intentionally carries no token.
		if !strings.HasPrefix(h.BootstrapToken, "tnx_sandbox_bootstrap_") || len(h.BootstrapToken) != 65 {
			return PersistedLaunch{}, ErrConflict
		}
		base, err := filepath.EvalSymlinks(job.Name())
		if err != nil {
			return PersistedLaunch{}, ErrConflict
		}
		if err = t.invoker.Bootstrap(ctx, t.server, h.SandboxID, h.Generation, filepath.Join(base, "enrollment"), h.BootstrapToken); err != nil {
			return PersistedLaunch{}, err
		}
	} else if err != nil {
		return PersistedLaunch{}, ErrConflict
	}
	return readPersistedLaunch(job, h, t.server)
}

func readControlFile(root *os.Root, name string, maximum int64) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() < 1 || info.Size() > maximum {
		return nil, ErrConflict
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, ErrConflict
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(body)) > maximum {
		return nil, ErrConflict
	}
	return body, nil
}

func readPersistedLaunch(job *os.Root, h LaunchHandoff, server string) (PersistedLaunch, error) {
	info, err := job.Lstat("enrollment")
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return PersistedLaunch{}, ErrConflict
	}
	root, err := job.OpenRoot("enrollment")
	if err != nil {
		return PersistedLaunch{}, ErrConflict
	}
	defer root.Close()
	stateRaw, err := readControlFile(root, "state.json", 16384)
	if err != nil {
		return PersistedLaunch{}, err
	}
	var state struct {
		Server     string    `json:"server"`
		SandboxID  uuid.UUID `json:"sandbox_id"`
		PeerID     uuid.UUID `json:"peer_id"`
		Generation int64     `json:"generation"`
	}
	decoder := json.NewDecoder(bytes.NewReader(stateRaw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || decoder.Decode(new(any)) != io.EOF || state.Server != server || state.SandboxID != h.SandboxID || state.PeerID == uuid.Nil || state.Generation != h.Generation {
		return PersistedLaunch{}, ErrConflict
	}
	credential, err := readControlFile(root, "runtime-credential", 128)
	if err != nil {
		return PersistedLaunch{}, err
	}
	const prefix = "tnx_sandbox_runtime_"
	value := strings.TrimSpace(string(credential))
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+43 || err != nil || len(raw) != 32 {
		return PersistedLaunch{}, ErrConflict
	}
	config, err := readControlFile(root, "wireguard.conf", 65536)
	if err != nil {
		return PersistedLaunch{}, err
	}
	public, err := persistedWireGuardPublicKey(config)
	if err != nil {
		return PersistedLaunch{}, err
	}
	return PersistedLaunch{HandoffConfirmation{h.OperationID, h.SandboxID, state.PeerID, h.Generation, h.RuntimeID, true}, public, sha256.Sum256([]byte(value))}, nil
}

func persistedWireGuardPublicKey(config []byte) (string, error) {
	section := ""
	private := ""
	sections, seen := map[string]bool{}, map[string]bool{}
	for _, line := range strings.Split(string(config), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "[Interface]" || line == "[Peer]" {
			if sections[line] {
				return "", ErrConflict
			}
			sections[line] = true
			section = line
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return "", ErrConflict
		}
		name, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		key := section + name
		if value == "" || seen[key] {
			return "", ErrConflict
		}
		seen[key] = true
		switch section + name {
		case "[Interface]PrivateKey":
			private = value
		case "[Interface]Address":
			p, err := netip.ParsePrefix(value)
			if err != nil || !p.Addr().Is4() || !p.Addr().IsPrivate() || p.Bits() != 32 {
				return "", ErrConflict
			}
		case "[Interface]MTU":
			mtu, err := strconv.Atoi(value)
			if err != nil || mtu < 576 || mtu > 9000 {
				return "", ErrConflict
			}
		case "[Interface]DNS", "[Peer]PublicKey", "[Peer]Endpoint", "[Peer]AllowedIPs", "[Peer]PersistentKeepalive":
		default:
			return "", ErrConflict
		}
	}
	if !sections["[Interface]"] || !sections["[Peer]"] || !seen["[Interface]Address"] || !seen["[Peer]PublicKey"] || !seen["[Peer]Endpoint"] || !seen["[Peer]AllowedIPs"] {
		return "", ErrConflict
	}
	key, err := base64.StdEncoding.DecodeString(private)
	if err != nil || len(key) != 32 {
		return "", ErrConflict
	}
	identity, err := ecdh.X25519().NewPrivateKey(key)
	if err != nil {
		return "", ErrConflict
	}
	return base64.StdEncoding.EncodeToString(identity.PublicKey().Bytes()), nil
}
