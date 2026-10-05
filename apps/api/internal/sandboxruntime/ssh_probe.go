package sandboxruntime

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type SSHProbeResult struct {
	HostKeyFingerprint string
	ObservedAt         time.Time
	UID                int
}
type privateDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// ProbePrivateSSH uses a trusted configured network route, an already-pinned
// host key and a dedicated probe identity. It accepts no hostname, user,
// command, key path or password from browsers/runtimes. A successful probe is
// one readiness input, not a policy acknowledgement or isolation attestation.
func ProbePrivateSSH(ctx context.Context, addr netip.Addr, hostKey ssh.PublicKey, identity ssh.Signer) (SSHProbeResult, error) {
	return probePrivateSSH(ctx, &net.Dialer{Timeout: 5 * time.Second}, addr, hostKey, identity)
}

func probePrivateSSH(ctx context.Context, dialer privateDialer, addr netip.Addr, hostKey ssh.PublicKey, identity ssh.Signer) (SSHProbeResult, error) {
	if dialer == nil || hostKey == nil || identity == nil || !addr.Is4() || !addr.IsPrivate() {
		return SSHProbeResult{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	endpoint := net.JoinHostPort(addr.String(), "22")
	conn, err := dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return SSHProbeResult{}, ErrUnavailable
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err = conn.SetDeadline(deadline); err != nil {
			return SSHProbeResult{}, ErrUnavailable
		}
	}
	config := &ssh.ClientConfig{User: "sandbox", Auth: []ssh.AuthMethod{ssh.PublicKeys(identity)}, HostKeyCallback: ssh.FixedHostKey(hostKey), Timeout: 5 * time.Second}
	transport, channels, requests, err := ssh.NewClientConn(conn, endpoint, config)
	if err != nil {
		return SSHProbeResult{}, ErrUnavailable
	}
	client := ssh.NewClient(transport, channels, requests)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return SSHProbeResult{}, ErrUnavailable
	}
	defer session.Close()
	output := &probeOutput{}
	session.Stdout = output
	session.Stderr = io.Discard
	if err = session.Run("/usr/bin/id -u"); err != nil || output.failed {
		return SSHProbeResult{}, ErrUnavailable
	}
	uid, err := strconv.Atoi(strings.TrimSpace(output.value))
	if err != nil || uid != 1001 || ctx.Err() != nil {
		return SSHProbeResult{}, ErrUnavailable
	}
	return SSHProbeResult{ssh.FingerprintSHA256(hostKey), time.Now().UTC(), uid}, nil
}

type probeOutput struct {
	value  string
	failed bool
}

func (w *probeOutput) Write(p []byte) (int, error) {
	if len(w.value)+len(p) > 32 {
		w.failed = true
		return 0, errors.New("probe output exceeds limit")
	}
	w.value += string(p)
	return len(p), nil
}
