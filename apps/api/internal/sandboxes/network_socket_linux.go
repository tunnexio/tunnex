//go:build linux

package sandboxes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"os"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"golang.org/x/sys/unix"
)

// SocketNetwork connects only the trusted host worker to the root node helper.
// Neither this socket nor protected enrollment files enter workload mounts.
type SocketNetwork struct {
	Provider        *sandboxruntime.Podman
	Files           *FileBootstrapTransport
	Socket          string
	ProbePrivateKey []byte
}
type NetworkHelperError struct{ Code string }

func (e *NetworkHelperError) Error() string { return "sandbox network helper rejected: " + e.Code }
func (e *NetworkHelperError) Unwrap() error { return ErrConflict }

type wireNamespace struct {
	Device   uint64 `json:"device"`
	Inode    uint64 `json:"inode"`
	OwnerUID uint32 `json:"owner_uid"`
}
type wireReceipt struct {
	Manifest struct {
		Plan      networkWirePlan `json:"plan"`
		Namespace wireNamespace   `json:"namespace"`
	} `json:"manifest"`
	ObservedAt time.Time `json:"observed_at"`
	Interface  string    `json:"interface"`
	PlanHash   string    `json:"plan_hash"`
}
type wireResponse struct {
	Version int                            `json:"version"`
	Receipt *wireReceipt                   `json:"receipt,omitempty"`
	Removed bool                           `json:"removed,omitempty"`
	Error   string                         `json:"error,omitempty"`
	Probe   *sandboxruntime.SSHProbeResult `json:"probe,omitempty"`
	Gateway *wireGatewayObservation        `json:"gateway,omitempty"`
}

func (n *SocketNetwork) ApplyPrivateNetwork(ctx context.Context, target PrivateNetworkTarget, config []byte) error {
	_, err := n.call(ctx, "apply", target, config)
	return err
}
func (n *SocketNetwork) RemovePrivateNetwork(ctx context.Context, target PrivateNetworkTarget, config []byte) error {
	_, err := n.call(ctx, "remove", target, config)
	return err
}
func (n *SocketNetwork) InspectPrivateNetwork(ctx context.Context, target PrivateNetworkTarget) (PrivateNetworkObservation, error) {
	if n.Files == nil {
		return PrivateNetworkObservation{}, ErrDisabled
	}
	config, err := n.Files.ReadPrivateNetworkConfig(ctx, target)
	if err != nil {
		return PrivateNetworkObservation{}, err
	}
	receipt, err := n.call(ctx, "inspect", target, config)
	if err != nil {
		return PrivateNetworkObservation{}, err
	}
	return PrivateNetworkObservation{Target: target, ObservedAt: receipt.ObservedAt}, nil
}

type wireGatewayObservation struct {
	GatewayID  string    `json:"gateway_id"`
	PublicKey  string    `json:"public_key"`
	Absent     bool      `json:"absent"`
	ObservedAt time.Time `json:"observed_at"`
}
type wireProbeInput struct {
	Address       string `json:"address"`
	HostPublicKey string `json:"host_public_key"`
	PrivateKey    string `json:"private_key"`
}

func (n *SocketNetwork) ProbePrivateTerminal(ctx context.Context, target PrivateNetworkTarget, host ssh.PublicKey, identity ssh.Signer) (sandboxruntime.SSHProbeResult, error) {
	if n.Files == nil || host == nil || identity == nil {
		return sandboxruntime.SSHProbeResult{}, ErrDisabled
	}
	dedicated, err := ssh.ParsePrivateKey(n.ProbePrivateKey)
	if err != nil || !bytes.Equal(dedicated.PublicKey().Marshal(), identity.PublicKey().Marshal()) {
		return sandboxruntime.SSHProbeResult{}, ErrForbidden
	}
	config, err := n.Files.ReadPrivateNetworkConfig(ctx, target)
	if err != nil {
		return sandboxruntime.SSHProbeResult{}, err
	}
	input := &wireProbeInput{target.Address.String(), string(ssh.MarshalAuthorizedKey(host)), string(n.ProbePrivateKey)}
	response, err := n.exchange(ctx, "probe", target, config, input)
	if err != nil {
		return sandboxruntime.SSHProbeResult{}, err
	}
	if response.Probe == nil || response.Probe.UID != 1001 || response.Probe.HostKeyFingerprint != ssh.FingerprintSHA256(host) || !freshEvidence(time.Now().UTC(), response.Probe.ObservedAt, 10*time.Second) {
		return sandboxruntime.SSHProbeResult{}, ErrConflict
	}
	return *response.Probe, nil
}
func (n *SocketNetwork) InspectGatewayAbsence(ctx context.Context, target PrivateNetworkTarget, config []byte) error {
	response, err := n.exchange(ctx, "gateway-absence", target, config, nil)
	if err != nil {
		return err
	}
	observation := response.Gateway
	if observation == nil || !observation.Absent || observation.GatewayID != target.GatewayID.String() || observation.PublicKey != target.PublicKey || !freshEvidence(time.Now().UTC(), observation.ObservedAt, 10*time.Second) {
		return ErrConflict
	}
	return nil
}
func (n *SocketNetwork) call(ctx context.Context, operation string, target PrivateNetworkTarget, config []byte) (*wireReceipt, error) {
	response, err := n.exchange(ctx, operation, target, config, nil)
	if err != nil {
		return nil, err
	}
	return response.Receipt, nil
}
func (n *SocketNetwork) exchange(ctx context.Context, operation string, target PrivateNetworkTarget, config []byte, probe *wireProbeInput) (*wireResponse, error) {
	if n.Provider == nil || n.Socket == "" {
		return nil, ErrDisabled
	}
	plan, private, err := privateNetworkPlan(target, config)
	if err != nil {
		return nil, err
	}
	if operation != "apply" {
		private = ""
	}
	namespace, err := n.Provider.OpenNetworkNamespace(ctx, target.SandboxID, target.RuntimeID, target.SpecHash)
	inactive := false
	if err != nil {
		if operation != "remove" && operation != "gateway-absence" {
			return nil, err
		}
		if err = n.Provider.VerifyInactiveNetwork(ctx, target.SandboxID, target.RuntimeID, target.SpecHash); err != nil {
			return nil, err
		}
		inactive = true
	} else {
		defer namespace.Close()
	}
	connection, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unixpacket", n.Socket)
	if err != nil {
		return nil, ErrDisabled
	}
	defer connection.Close()
	local, ok := connection.(*net.UnixConn)
	if !ok {
		return nil, ErrDisabled
	}
	raw, err := local.SyscallConn()
	if err != nil {
		return nil, ErrDisabled
	}
	root := false
	_ = raw.Control(func(fd uintptr) {
		credentials, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		root = e == nil && credentials.Uid == 0
	})
	if !root {
		return nil, ErrForbidden
	}
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if local.SetDeadline(deadline) != nil {
		return nil, ErrDisabled
	}
	stop := context.AfterFunc(ctx, func() { local.Close() })
	defer stop()
	wireOperation := operation
	if inactive {
		wireOperation += "-inactive"
	}
	request := struct {
		Version    int             `json:"version"`
		Operation  string          `json:"operation"`
		Plan       networkWirePlan `json:"plan"`
		PrivateKey string          `json:"private_key,omitempty"`
		Probe      *wireProbeInput `json:"probe,omitempty"`
	}{1, wireOperation, plan, private, probe}
	body, _ := json.Marshal(request)
	if len(body) > 65536 {
		return nil, ErrInvalid
	}
	var rights []byte
	if namespace != nil {
		rights = unix.UnixRights(int(namespace.Fd()))
	}
	if _, _, err = local.WriteMsgUnix(body, rights, nil); err != nil {
		return nil, ErrDisabled
	}
	buffer := make([]byte, 65536)
	count, _, flags, _, err := local.ReadMsgUnix(buffer, nil)
	if err != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return nil, ErrDisabled
	}
	decoder := json.NewDecoder(bytes.NewReader(buffer[:count]))
	decoder.DisallowUnknownFields()
	var response wireResponse
	if decoder.Decode(&response) != nil || decoder.Decode(new(any)) != io.EOF || response.Version != 1 {
		return nil, ErrConflict
	}
	if response.Error != "" {
		switch response.Error {
		case "ownership", "missing", "invalid", "unauthorized", "unavailable":
			return nil, &NetworkHelperError{response.Error}
		default:
			return nil, ErrConflict
		}
	}
	if inactive {
		if err = n.Provider.VerifyInactiveNetwork(ctx, target.SandboxID, target.RuntimeID, target.SpecHash); err != nil {
			return nil, err
		}
	}
	if operation != "probe" && response.Probe != nil || operation != "gateway-absence" && response.Gateway != nil {
		return nil, ErrConflict
	}
	if operation == "gateway-absence" {
		if response.Receipt != nil || response.Removed || response.Gateway == nil {
			return nil, ErrConflict
		}
		return &response, nil
	}
	if operation == "remove" {
		if !response.Removed || response.Receipt != nil {
			return nil, ErrConflict
		}
		return &response, nil
	}
	if response.Removed || response.Receipt == nil {
		return nil, ErrConflict
	}
	var stat unix.Stat_t
	if unix.Fstat(int(namespace.Fd()), &stat) != nil {
		return nil, ErrConflict
	}
	receipt := response.Receipt
	hash := networkPlanHash(plan)
	if networkPlanHash(receipt.Manifest.Plan) != hash || receipt.PlanHash != hash || receipt.Interface != "tx"+networkInterfaceSuffix(target.OperationID) || receipt.Manifest.Namespace.Device != uint64(stat.Dev) || receipt.Manifest.Namespace.Inode != stat.Ino || receipt.Manifest.Namespace.OwnerUID != uint32(os.Geteuid()) || !freshEvidence(time.Now().UTC(), receipt.ObservedAt, 10*time.Second) {
		return nil, ErrConflict
	}
	return &response, nil
}
func networkInterfaceSuffix(operation uuid.UUID) string {
	sum := sha256.Sum256(operation[:])
	return hex.EncodeToString(sum[:])[:12]
}
