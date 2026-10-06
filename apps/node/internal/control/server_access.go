package control

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/packages/apptransport/terminalwire"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

func (c *Client) TerminalRPC(ctx context.Context, method, path string, input, output any) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var body io.Reader
	if input != nil {
		raw, e := json.Marshal(input)
		if e != nil {
			return e
		}
		body = bytes.NewReader(raw)
	}
	req, e := http.NewRequestWithContext(ctx, method, c.base+"/agent/server-access/"+path, body)
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tunnex-Editor-Version", "1")
	resp, e := c.http.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("terminal authority refused (%d)", resp.StatusCode)
	}
	if output != nil {
		limit := int64(65536)
		if strings.HasPrefix(path, "enrollments") {
			limit = 1048576
		}
		return json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(output)
	}
	return nil
}
func (c *Client) TerminalChannel(ctx context.Context, id string) (net.Conn, error) {
	if _, e := uuid.Parse(id); e != nil {
		return nil, e
	}
	target, config, e := c.AppAccessTLSConfig("")
	if e != nil {
		return nil, e
	}
	port := target.Port()
	if port == "" {
		port = "443"
	}
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 2 * time.Second}, Config: config}
	conn, e := d.DialContext(ctx, "tcp", net.JoinHostPort(target.Hostname(), port))
	if e != nil {
		return nil, e
	}
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	req, e := http.NewRequest("CONNECT", target.String()+"/agent/server-access/sessions/"+id+"/channel", nil)
	if e != nil {
		conn.Close()
		return nil, e
	}
	req.Header.Set("X-Tunnex-Purpose", terminalwire.Purpose)
	if e = req.Write(conn); e != nil {
		conn.Close()
		return nil, e
	}
	reader := bufio.NewReaderSize(conn, terminalwire.MaxFrameBytes)
	resp, e := http.ReadResponse(reader, req)
	if e != nil || resp.StatusCode != 200 {
		conn.Close()
		return nil, fmt.Errorf("terminal channel refused")
	}
	conn.SetDeadline(time.Time{})
	return &terminalReaderConn{conn, reader}, nil
}

type terminalReaderConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *terminalReaderConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// TerminalDestination refuses the control plane and gateway's own addresses.
func (c *Client) TerminalDestination(ctx context.Context, ip netip.Addr) error {
	target, e := url.Parse(c.base)
	if e != nil {
		return e
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	addresses, e := net.DefaultResolver.LookupNetIP(bounded, "ip", target.Hostname())
	if e != nil {
		return e
	}
	for _, a := range addresses {
		if a.Unmap() == ip.Unmap() {
			return fmt.Errorf("control destination refused")
		}
	}
	local, e := net.InterfaceAddrs()
	if e != nil {
		return e
	}
	for _, a := range local {
		prefix, e := netip.ParsePrefix(a.String())
		if e == nil && prefix.Addr().Unmap() == ip.Unmap() {
			return fmt.Errorf("gateway destination refused")
		}
	}
	return nil
}
