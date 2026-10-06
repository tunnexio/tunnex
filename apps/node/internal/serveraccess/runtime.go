// Package serveraccess implements leased browser terminals and native editor SSH.
package serveraccess

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"github.com/tunnexio/tunnex/packages/apptransport/terminalwire"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func Run(ctx context.Context, client *control.Client) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var mu sync.Mutex
	active := map[string]bool{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var desired []terminalwire.Assignment
			if client.TerminalRPC(ctx, "GET", "desired-state", nil, &desired) != nil {
				continue
			}
			for _, a := range desired {
				if _, e := uuid.Parse(a.ID); e != nil || a.Kind != "check" && a.Kind != "terminal" && a.Kind != "editor" {
					continue
				}
				mu.Lock()
				if active[a.ID] || len(active) >= 16 {
					mu.Unlock()
					continue
				}
				active[a.ID] = true
				mu.Unlock()
				go func(a terminalwire.Assignment) {
					defer func() { mu.Lock(); delete(active, a.ID); mu.Unlock() }()
					result := classifyResult(execute(ctx, client, a))
					report, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					client.TerminalRPC(report, "POST", "sessions/"+a.ID+"/status", map[string]string{"result": result}, nil)
				}(a)
			}
		}
	}
}
func execute(parent context.Context, client *control.Client, a terminalwire.Assignment) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	defer clear(key)
	signer, e := ssh.NewSignerFromKey(key)
	if e != nil {
		return e
	}
	var m terminalwire.Material
	if e = client.TerminalRPC(ctx, "POST", "sessions/"+a.ID+"/material", map[string]string{"public_key": string(ssh.MarshalAuthorizedKey(signer.PublicKey()))}, &m); e != nil {
		return e
	}
	ip, e := netip.ParseAddr(m.IP)
	if e != nil || !ip.IsPrivate() || ip.Zone() != "" || ip.IsLoopback() || ip.IsLinkLocalUnicast() || m.SessionID != a.ID || m.Kind != a.Kind || m.Port < 1 || m.Port > 65535 || m.Account == "root" {
		return errors.New("invalid terminal material")
	}
	if !m.LeaseUntil.After(time.Now()) || m.LeaseUntil.After(time.Now().Add(5*time.Second)) || m.LeaseUntil.After(m.ExpiresAt) {
		return errors.New("invalid terminal lease")
	}
	if e = client.TerminalDestination(ctx, ip); e != nil {
		return e
	}
	var deadline atomic.Int64
	deadline.Store(m.LeaseUntil.UnixNano())
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if time.Now().UnixNano() >= deadline.Load() {
					cancel()
					return
				}
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var lease terminalwire.Lease
				if client.TerminalRPC(ctx, "POST", "sessions/"+a.ID+"/lease", nil, &lease) != nil || !lease.Until.After(time.Now()) || lease.Until.After(time.Now().Add(5*time.Second)) || lease.Until.After(m.ExpiresAt) {
					cancel()
					return
				}
				deadline.Store(lease.Until.UnixNano())
			}
		}
	}()
	if m.OS == "windows" {
		return executeRDP(ctx, client, a, m)
	}
	pub, _, _, rest, e := ssh.ParseAuthorizedKey([]byte(m.Certificate))
	if e != nil || len(rest) != 0 {
		return errors.New("invalid certificate")
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return errors.New("invalid certificate")
	}
	certSigner, e := ssh.NewCertSigner(cert, signer)
	if e != nil {
		return e
	}
	raw, e := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(m.IP, strconv.Itoa(m.Port)))
	if e != nil {
		return e
	}
	defer raw.Close()
	go func() { <-ctx.Done(); raw.Close() }()
	raw.SetDeadline(time.Now().Add(2 * time.Second))
	config := &ssh.ClientConfig{User: m.Account, Auth: []ssh.AuthMethod{ssh.PublicKeys(certSigner)}, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if ssh.FingerprintSHA256(key) != m.Fingerprint {
			return errHostKeyMismatch
		}
		return nil
	}}
	conn, chans, reqs, e := ssh.NewClientConn(raw, net.JoinHostPort(m.IP, strconv.Itoa(m.Port)), config)
	if e != nil {
		return e
	}
	raw.SetDeadline(time.Time{})
	sshClient := ssh.NewClient(conn, chans, reqs)
	defer sshClient.Close()
	if a.Kind == "check" {
		return nil
	}
	channel, e := client.TerminalChannel(ctx, a.ID)
	if e != nil {
		return e
	}
	defer channel.Close()
	go func() { <-ctx.Done(); channel.Close() }()
	if a.Kind == "editor" {
		return serveEditor(ctx, channel, sshClient, m)
	}
	session, e := sshClient.NewSession()
	if e != nil {
		return e
	}
	defer session.Close()
	stdin, e := session.StdinPipe()
	if e != nil {
		return e
	}
	writer := &outputWriter{conn: channel}
	session.Stdout = writer
	session.Stderr = writer
	if e = session.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{}); e != nil {
		return errPTY
	}
	if e = session.Shell(); e != nil {
		return e
	}
	go func() {
		defer cancel()
		reader := bufio.NewReaderSize(channel, terminalwire.MaxFrameBytes)
		for {
			f, e := terminalwire.Read(reader)
			if e != nil || f.ValidateInput() != nil {
				return
			}
			if f.Type == "resize" {
				if session.WindowChange(f.Rows, f.Cols) != nil {
					return
				}
			} else {
				if _, e = stdin.Write(f.Data); e != nil {
					return
				}
			}
		}
	}()
	e = session.Wait()
	return e
}

type outputWriter struct {
	mu   sync.Mutex
	conn net.Conn
}

func (w *outputWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	written := 0
	for len(b) > 0 {
		n := len(b)
		if n > terminalwire.MaxDataBytes {
			n = terminalwire.MaxDataBytes
		}
		w.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if e := terminalwire.Write(w.conn, terminalwire.Frame{Type: "output", Data: b[:n]}); e != nil {
			return written, e
		}
		written += n
		b = b[n:]
	}
	return written, nil
}

var _ io.Writer = (*outputWriter)(nil)

var errHostKeyMismatch = errors.New("host key mismatch")
var errPTY = errors.New("PTY refused")

func classifyResult(err error) string {
	if err == nil {
		return "ok"
	}
	if errors.Is(err, errHostKeyMismatch) {
		return "ssh_host_key_mismatch"
	}
	if errors.Is(err, errPTY) {
		return "ssh_pty_failed"
	}
	var dial *net.OpError
	if errors.As(err, &dial) {
		return "ssh_unreachable"
	}
	if strings.Contains(err.Error(), "unable to authenticate") {
		return "ssh_authentication_failed"
	}
	return "failed"
}
