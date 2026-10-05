//go:build linux

package sandboxnetwork

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

type ProbeInput struct {
	Address       netip.Addr `json:"address"`
	HostPublicKey string     `json:"host_public_key"`
	PrivateKey    string     `json:"private_key"`
}
type SSHObservation struct {
	HostKeyFingerprint string
	ObservedAt         time.Time
	UID                int
}
type GatewayObservation struct {
	GatewayID  uuid.UUID `json:"gateway_id"`
	PublicKey  string    `json:"public_key"`
	Absent     bool      `json:"absent"`
	ObservedAt time.Time `json:"observed_at"`
}
type GatewayInspector interface {
	Probe(context.Context, Plan, ProbeInput) (SSHObservation, error)
	PeerAbsence(context.Context, Plan) (GatewayObservation, error)
}

// DockerGateway performs read-only metadata lookup for one preconfigured,
// immutable explicitly bound gateway. It never calls Docker exec/write APIs.
type DockerGateway struct {
	NodeID                                                      uuid.UUID
	OrgID                                                       uuid.UUID
	RuntimeID, ImageDigest, Interface, ProbeBinary, ProbeSHA256 string
}

var gatewayNamespace = regexp.MustCompile(`^/var/run/docker/netns/[a-f0-9]{12,64}$`)
var gatewayInterface = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)

type gatewayMetadata struct {
	PID       int
	Namespace string
}

func (g DockerGateway) metadata(ctx context.Context, p Plan) (gatewayMetadata, error) {
	if g.NodeID == uuid.Nil || g.NodeID != p.Binding.GatewayID || !hexIdentity.MatchString(g.RuntimeID) || !strings.HasPrefix(g.ImageDigest, "sha256:") || !hexIdentity.MatchString(strings.TrimPrefix(g.ImageDigest, "sha256:")) || !gatewayInterface.MatchString(g.Interface) {
		return gatewayMetadata{}, ErrUnavailable
	}
	// This output projection contains no environment, mounts or credentials.
	format := `{"id":{{json .Id}},"image":{{json .Image}},"pid":{{json .State.Pid}},"running":{{json .State.Running}},"namespace":{{json .NetworkSettings.SandboxKey}},"org":{{json (index .Config.Labels "io.tunnex.sandbox.fixture.gateway")}}}`
	raw, err := runDockerMetadata(ctx, g.RuntimeID, format)
	if err != nil {
		return gatewayMetadata{}, err
	}
	return g.parseMetadata(raw, p)
}
func (g DockerGateway) parseMetadata(raw []byte, p Plan) (gatewayMetadata, error) {
	var result struct {
		ID, Image, Org string
		Namespace      string
		PID            int
		Running        bool
	}
	if json.Unmarshal(raw, &result) != nil || result.ID != g.RuntimeID || result.Image != g.ImageDigest || (g.OrgID == uuid.Nil && result.Org != p.Binding.OrgID.String()) || (g.OrgID != uuid.Nil && g.OrgID != p.Binding.OrgID) || !result.Running || result.PID <= 1 || !gatewayNamespace.MatchString(result.Namespace) {
		return gatewayMetadata{}, ErrOwnership
	}
	return gatewayMetadata{result.PID, result.Namespace}, nil
}
func runDockerMetadata(ctx context.Context, id, format string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/docker", "inspect", "--type=container", "--format", format, id)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/bin", "LC_ALL=C", "DOCKER_HOST=unix:///var/run/docker.sock"}
	cmd.Stderr = io.Discard
	buf := &boundedOutput{limit: 16384}
	cmd.Stdout = buf
	if cmd.Run() != nil {
		return nil, ErrUnavailable
	}
	return buf.Bytes(), nil
}
func (g DockerGateway) namespace(ctx context.Context, p Plan) (*os.File, error) {
	metadata, err := g.metadata(ctx, p)
	if err != nil {
		return nil, err
	}
	path := metadata.Namespace
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	current, err := g.metadata(ctx, p)
	if err != nil || current != metadata {
		file.Close()
		return nil, ErrOwnership
	}
	owned, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, ErrUnavailable
	}
	live, err := os.Stat(path)
	if err != nil || !os.SameFile(owned, live) {
		file.Close()
		return nil, ErrOwnership
	}
	kind, namespaceErr := unix.IoctlRetInt(int(file.Fd()), unix.NS_GET_NSTYPE)
	if namespaceErr != nil || kind != unix.CLONE_NEWNET {
		file.Close()
		return nil, ErrOwnership
	}
	public, err := output(ctx, file, nil, "wg", "show", g.Interface, "public-key")
	if err != nil || strings.TrimSpace(string(public)) != p.GatewayPublicKey {
		file.Close()
		return nil, ErrOwnership
	}
	return file, nil
}
func (g DockerGateway) Probe(ctx context.Context, p Plan, input ProbeInput) (SSHObservation, error) {
	var result SSHObservation
	if input.Address != p.Address.Addr() || len(input.HostPublicKey) < 32 || len(input.HostPublicKey) > 8192 || len(input.PrivateKey) < 64 || len(input.PrivateKey) > 16384 || !filepath.IsAbs(g.ProbeBinary) || filepath.Clean(g.ProbeBinary) != g.ProbeBinary || !hexIdentity.MatchString(g.ProbeSHA256) {
		return result, ErrInvalid
	}
	info, err := os.Lstat(g.ProbeBinary)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 || info.Size() > 67108864 {
		return result, ErrOwnership
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return result, ErrOwnership
	}
	file, err := os.Open(g.ProbeBinary)
	if err != nil {
		return result, ErrUnavailable
	}
	hash := sha256.New()
	_, err = io.Copy(hash, io.LimitReader(file, 67108865))
	defer file.Close()
	if err != nil || hex.EncodeToString(hash.Sum(nil)) != g.ProbeSHA256 {
		return result, ErrOwnership
	}
	namespace, err := g.namespace(ctx, p)
	if err != nil {
		return result, err
	}
	defer namespace.Close()
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	body, _ := json.Marshal(input)
	cmd := exec.CommandContext(ctx, "/usr/bin/nsenter", "--net=/proc/self/fd/3", "--", "/proc/self/fd/4")
	cmd.ExtraFiles = []*os.File{namespace, file}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/bin"}
	cmd.Stdin = bytes.NewReader(body)
	cmd.Stderr = io.Discard
	out := &boundedOutput{limit: 4096}
	cmd.Stdout = out
	if cmd.Run() != nil {
		return result, ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(out.Bytes()))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || result.UID != 1001 || result.HostKeyFingerprint == "" || time.Since(result.ObservedAt) < 0 || time.Since(result.ObservedAt) >= 10*time.Second {
		return SSHObservation{}, ErrUnavailable
	}
	return result, nil
}
func (g DockerGateway) PeerAbsence(ctx context.Context, p Plan) (GatewayObservation, error) {
	namespace, err := g.namespace(ctx, p)
	if err != nil {
		return GatewayObservation{}, err
	}
	defer namespace.Close()
	raw, err := output(ctx, namespace, nil, "wg", "show", g.Interface, "peers")
	if err != nil {
		return GatewayObservation{}, err
	}
	for _, peer := range strings.Fields(string(raw)) {
		if !validKey(peer) {
			return GatewayObservation{}, ErrOwnership
		}
		if peer == p.PublicKey {
			return GatewayObservation{}, ErrUnavailable
		}
	}
	return GatewayObservation{g.NodeID, p.PublicKey, true, time.Now().UTC()}, nil
}
