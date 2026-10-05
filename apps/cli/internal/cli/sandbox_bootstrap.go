package cli

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/cli/internal/api"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var ErrSandboxBootstrap = errors.New("sandbox bootstrap handoff could not be confirmed; reconcile the existing operation before retrying")

type SandboxBootstrapOptions struct {
	Server, Token, HandoffDir string
	SandboxID                 uuid.UUID
	Generation                int64
	HTTPClient                *http.Client
	CACertificatePEM          []byte
}
type SandboxBootstrapState struct {
	Server     string    `json:"server"`
	SandboxID  uuid.UUID `json:"sandbox_id"`
	PeerID     uuid.UUID `json:"peer_id"`
	Generation int64     `json:"generation"`
}

// BootstrapSandbox performs exactly one redemption and creates a private empty
// handoff. It never applies networking, runs an agent/proxy, or asserts Ready.
func BootstrapSandbox(ctx context.Context, opts SandboxBootstrapOptions) (SandboxBootstrapState, error) {
	var state SandboxBootstrapState
	server, err := url.Parse(opts.Server)
	if err != nil || server.Scheme != "https" || server.Host == "" || server.User != nil || server.RawQuery != "" || server.Fragment != "" || opts.SandboxID == uuid.Nil || opts.Generation < 1 || !filepath.IsAbs(opts.HandoffDir) || filepath.Clean(opts.HandoffDir) == "/" || !strings.HasPrefix(opts.Token, "tnx_sandbox_bootstrap_") || len(opts.Token) != 65 {
		return state, ErrSandboxBootstrap
	}
	entropy, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(opts.Token, "tnx_sandbox_bootstrap_"))
	if err != nil || len(entropy) != 32 {
		return state, ErrSandboxBootstrap
	}
	var fixtureTransport *http.Transport
	if len(opts.CACertificatePEM) > 0 {
		if opts.HTTPClient != nil || len(opts.CACertificatePEM) > 32768 {
			return state, ErrSandboxBootstrap
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(opts.CACertificatePEM) {
			return state, ErrSandboxBootstrap
		}
		fixtureTransport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
		defer fixtureTransport.CloseIdleConnections()
	}
	// Mkdir is the exclusive reservation: existing user files/directories/symlinks
	// refuse before the single-use POST. No existing credential file is read.
	if err = os.Mkdir(opts.HandoffDir, 0700); err != nil {
		return state, ErrSandboxBootstrap
	}
	root, err := os.OpenRoot(opts.HandoffDir)
	if err != nil {
		_ = os.Remove(opts.HandoffDir)
		return state, ErrSandboxBootstrap
	}
	defer root.Close()
	committed := false
	defer func() {
		if !committed {
			for _, name := range []string{"wireguard.conf", "runtime-credential", "state.json"} {
				_ = root.Remove(name)
			}
			_ = os.Remove(opts.HandoffDir)
		}
	}()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return state, ErrSandboxBootstrap
	}
	transport := http.Client{Timeout: 15 * time.Second}
	if fixtureTransport != nil {
		transport.Transport = fixtureTransport
	}
	if opts.HTTPClient != nil {
		transport = *opts.HTTPClient
		transport.Timeout = 15 * time.Second
	}
	transport.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client, err := api.NewClient(strings.TrimRight(opts.Server, "/"), api.WithHTTPClient(&transport))
	if err != nil {
		return state, ErrSandboxBootstrap
	}
	response, err := client.BootstrapSandbox(ctx, api.SandboxBootstrapRequest{BootstrapToken: opts.Token, PublicKey: base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())})
	if err != nil {
		return state, ErrSandboxBootstrap
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return state, ErrSandboxBootstrap
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 262145))
	if err != nil || len(body) > 262144 {
		return state, ErrSandboxBootstrap
	}
	var result api.SandboxBootstrapResponse
	if json.Unmarshal(body, &result) != nil || result.SandboxId != opts.SandboxID || result.PeerId == uuid.Nil || result.Generation != opts.Generation || !sandboxConfigTemplate(result.Config) {
		return state, ErrSandboxBootstrap
	}
	const prefix = "tnx_sandbox_runtime_"
	if !strings.HasPrefix(result.RuntimeCredential, prefix) || len(result.RuntimeCredential) != len(prefix)+43 {
		return state, ErrSandboxBootstrap
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(result.RuntimeCredential, prefix))
	if err != nil || len(raw) != 32 {
		return state, ErrSandboxBootstrap
	}
	config := strings.Replace(result.Config, "__TUNNEX_PRIVATE_KEY__", base64.StdEncoding.EncodeToString(key.Bytes()), 1)
	state = SandboxBootstrapState{opts.Server, result.SandboxId, result.PeerId, result.Generation}
	encoded, _ := json.Marshal(state)
	for _, file := range []struct {
		name  string
		value []byte
	}{{"wireguard.conf", []byte(config)}, {"runtime-credential", []byte(result.RuntimeCredential + "\n")}, {"state.json", encoded}} {
		f, e := root.OpenFile(file.name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return SandboxBootstrapState{}, ErrSandboxBootstrap
		}
		_, e = f.Write(file.value)
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil || closeErr != nil {
			return SandboxBootstrapState{}, ErrSandboxBootstrap
		}
	}
	// Sync the directory before acknowledging the recoverable local handoff.
	dir, err := root.Open(".")
	if err != nil {
		return SandboxBootstrapState{}, ErrSandboxBootstrap
	}
	err = dir.Sync()
	closeErr := dir.Close()
	if err != nil || closeErr != nil {
		return SandboxBootstrapState{}, ErrSandboxBootstrap
	}
	committed = true
	return state, nil
}
func sandboxConfigTemplate(config string) bool {
	if len(config) > 131072 || strings.Count(config, "__TUNNEX_PRIVATE_KEY__") != 1 {
		return false
	}
	section := ""
	seen := map[string]bool{}
	interfaceCount, peerCount := 0, 0
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "[Interface]" {
			section = "interface"
			interfaceCount++
			continue
		}
		if line == "[Peer]" {
			section = "peer"
			peerCount++
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return false
		}
		key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		full := section + ":" + key
		if seen[full] || value == "" {
			return false
		}
		seen[full] = true
		if section == "interface" {
			switch key {
			case "PrivateKey":
				if value != "__TUNNEX_PRIVATE_KEY__" {
					return false
				}
			case "Address":
				p, e := netip.ParsePrefix(value)
				if e != nil || !p.Addr().Is4() || p.Bits() != 32 {
					return false
				}
			case "MTU":
				mtu, e := strconv.Atoi(value)
				if e != nil || mtu < 576 || mtu > 9000 {
					return false
				}
			case "DNS":
				for _, address := range strings.Split(value, ",") {
					if _, e := netip.ParseAddr(strings.TrimSpace(address)); e != nil {
						return false
					}
				}
			default:
				return false
			}
		} else if section == "peer" {
			switch key {
			case "PublicKey":
				decoded, e := base64.StdEncoding.DecodeString(value)
				if e != nil || len(decoded) != 32 {
					return false
				}
			case "Endpoint":
				host, port, e := net.SplitHostPort(value)
				if e != nil || host == "" || len(host) > 253 || strings.ContainsAny(host, " \t\r\n@/;\\") {
					return false
				}
				number, e := strconv.Atoi(port)
				if e != nil || number < 1 || number > 65535 {
					return false
				}
			case "PersistentKeepalive":
				seconds, e := strconv.Atoi(value)
				if e != nil || seconds < 0 || seconds > 65535 {
					return false
				}
			case "AllowedIPs":
				for _, cidr := range strings.Split(value, ",") {
					p, e := netip.ParsePrefix(strings.TrimSpace(cidr))
					if e != nil || !p.Addr().Is4() || p.Bits() == 0 {
						return false
					}
				}
			default:
				return false
			}
		} else {
			return false
		}
	}
	return interfaceCount == 1 && peerCount == 1 && seen["interface:PrivateKey"] && seen["interface:Address"] && seen["peer:PublicKey"] && seen["peer:Endpoint"] && seen["peer:AllowedIPs"]
}
