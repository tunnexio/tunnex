package serveraccess

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"github.com/tunnexio/tunnex/packages/apptransport/rdpwire"
	"github.com/tunnexio/tunnex/packages/apptransport/terminalwire"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// probeRDP negotiates NLA and verifies the independently pinned TLS certificate.
func probeRDP(ctx context.Context, m terminalwire.Material) error {
	c, e := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(m.IP, strconv.Itoa(m.Port)))
	if e != nil {
		return e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	go func() { <-ctx.Done(); c.Close() }()
	request := []byte{3, 0, 0, 19, 14, 224, 0, 0, 0, 0, 0, 1, 0, 8, 0, 2, 0, 0, 0}
	if _, e = c.Write(request); e != nil {
		return e
	}
	head := make([]byte, 4)
	if _, e = io.ReadFull(c, head); e != nil {
		return e
	}
	n := int(head[2])<<8 | int(head[3])
	if head[0] != 3 || n < 19 || n > 4096 {
		return errors.New("invalid RDP negotiation")
	}
	body := make([]byte, n-4)
	if _, e = io.ReadFull(c, body); e != nil {
		return e
	}
	if body[len(body)-8] != 2 || body[len(body)-4] != 2 {
		return errors.New("RDP requires NLA")
	}
	t := tls.Client(c, pinnedRDPTLSConfig(m.Fingerprint))
	return t.HandshakeContext(ctx)
}

// pinnedRDPTLSConfig replaces public CA/hostname verification with the exact
// certificate fingerprint independently verified by the administrator. Windows
// RDP commonly uses self-signed certificates; unpinned certificates are rejected.
func pinnedRDPTLSConfig(fingerprint string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12,
		InsecureSkipVerify: true, // VerifyPeerCertificate performs mandatory pin verification.
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errHostKeyMismatch
			}
			sum := sha256.Sum256(rawCerts[0])
			if "SHA256:"+base64.RawStdEncoding.EncodeToString(sum[:]) != fingerprint {
				return errHostKeyMismatch
			}
			return nil
		}}
}

func executeRDP(ctx context.Context, client *control.Client, a terminalwire.Assignment, m terminalwire.Material) (result error) {
	stage := "readiness"
	defer func() {
		if result != nil && a.Kind != "check" {
			slog.Warn("rdp_session_failed", "session_id", a.ID, "stage", stage)
		}
	}()
	if a.Kind == "check" {
		return probeRDP(ctx, m)
	}
	stage = "gateway_channel"
	channel, e := client.TerminalChannel(ctx, a.ID)
	if e != nil {
		return e
	}
	defer channel.Close()
	go func() { <-ctx.Done(); channel.Close() }()
	channel.SetReadDeadline(time.Now().Add(20 * time.Second))
	reader := bufio.NewReaderSize(channel, terminalwire.MaxFrameBytes)
	stage = "credentials_read"
	f, e := terminalwire.Read(reader)
	if e != nil {
		return e
	}
	stage = "credentials_validation"
	var cred rdpwire.Credentials
	if f.Type != "credentials" || json.Unmarshal(f.Data, &cred) != nil || cred.Account != m.Account || cred.Password == "" || len(cred.Password) > 1024 {
		return errors.New("invalid RDP credential frame")
	}
	clear(f.Data)
	defer func() { cred.Password = "" }()
	channel.SetReadDeadline(time.Time{})
	stage = "adapter_connection"
	addr := os.Getenv("TUNNEX_GUACD_ADDR")
	if addr == "" {
		return errors.New("RDP adapter unavailable")
	}
	host, _, e := net.SplitHostPort(addr)
	ip := net.ParseIP(host)
	if e != nil || ip == nil || !ip.IsLoopback() {
		return errors.New("guacd must use loopback")
	}
	guac, e := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", addr)
	if e != nil {
		return e
	}
	defer guac.Close()
	go func() { <-ctx.Done(); guac.Close() }()
	guac.SetDeadline(time.Now().Add(10 * time.Second))
	if _, e = guac.Write(rdpwire.Encode("select", "rdp")); e != nil {
		return e
	}
	gr := bufio.NewReader(guac)
	stage = "adapter_arguments"
	args, e := rdpwire.Read(gr)
	if e != nil || len(args) == 0 || args[0] != "args" {
		return errors.New("RDP handshake failed")
	}
	fp, e := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(m.Fingerprint, "SHA256:"))
	if e != nil || len(fp) != 32 {
		return errors.New("invalid RDP fingerprint")
	}
	values := map[string]string{"VERSION_1_5_0": "VERSION_1_5_0", "width": "1280", "height": "720", "dpi": "96", "color-depth": "32", "disable-gfx": "true", "hostname": m.IP, "port": strconv.Itoa(m.Port), "username": m.Account, "password": cred.Password, "domain": m.Domain, "security": "nla", "ignore-cert": "false", "cert-tofu": "false", "cert-fingerprints": guacCertificateFingerprint(fp), "disable-audio": "true", "enable-audio-input": "false", "enable-drive": "false", "enable-printing": "false", "disable-copy": strconv.FormatBool(!rdpwire.CanCopy(m.ClipboardPolicy)), "disable-paste": strconv.FormatBool(!rdpwire.CanPaste(m.ClipboardPolicy)), "resize-method": "display-update", "server-layout": "en-us-qwerty"}
	pinned := false
	clipboardCopy, clipboardPaste := false, false
	connect := []string{"connect"}
	for _, name := range args[1:] {
		if name == "disable-copy" {
			clipboardCopy = true
		}
		if name == "disable-paste" {
			clipboardPaste = true
		}
		if name == "cert-fingerprints" {
			pinned = true
		}
		connect = append(connect, values[name])
	}
	if !clipboardCopy || !clipboardPaste {
		return errors.New("guacd lacks clipboard policy enforcement")
	}
	if !pinned {
		return errors.New("guacd lacks certificate pinning")
	}
	for _, p := range [][]string{{"size", "1280", "720", "96"}, {"audio"}, {"video"}, {"image", "image/png", "image/jpeg"}} {
		if _, e = guac.Write(rdpwire.Encode(p...)); e != nil {
			return e
		}
	}
	encoded := rdpwire.Encode(connect...)
	_, e = guac.Write(encoded)
	clear(encoded)
	cred.Password = ""
	values["password"] = ""
	connect = nil
	if e != nil {
		return e
	}
	stage = "desktop_admission"
	ready, e := rdpwire.Read(gr)
	if e != nil || len(ready) != 2 || ready[0] != "ready" {
		return errors.New("RDP connection refused")
	}
	stage = "desktop_stream"
	guac.SetDeadline(time.Time{})
	out := &outputWriter{conn: channel}
	done := make(chan error, 2)
	go func() { _, e := io.Copy(out, gr); done <- e }()
	go func() {
		for {
			f, e := terminalwire.Read(reader)
			if e != nil {
				done <- e
				return
			}
			data := f.Data
			if f.Type == "clipboard" {
				data, e = rdpwire.EncodeClipboardPaste(m.ClipboardPolicy, f.Data)
			} else if f.Type != "desktop" {
				e = errors.New("unsupported desktop input")
			} else {
				e = rdpwire.ValidateInput(f.Data)
			}
			if e != nil {
				done <- errors.New("unsupported desktop input")
				return
			}
			guac.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if _, e = guac.Write(data); e != nil {
				done <- e
				return
			}
		}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case e := <-done:
		return e
	}
}

// guacCertificateFingerprint uses the colon-separated digest required by
// FreeRDP 2 and also accepted by FreeRDP 3. It never enables trust-on-first-use.
func guacCertificateFingerprint(digest []byte) string {
	parts := make([]string, len(digest))
	for i, b := range digest {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return "sha256:" + strings.Join(parts, ":")
}
