//go:build linux

package aivpn

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// This proof requires only a disposable container's network namespace. It never
// opens host ports, accesses a provider, or changes a deployed gateway. Run with
// TUNNEX_TEST_AI_VPN_WIRE=1, ip/wg, NET_ADMIN and SYS_ADMIN (for ip netns).
func TestAIVPNRealWireGuardOnlyIngress(t *testing.T) {
	if os.Getenv("TUNNEX_TEST_AI_VPN_WIRE") != "1" {
		t.Skip("requires isolated native WireGuard test namespace")
	}
	if os.Geteuid() != 0 {
		t.Fatal("isolated test needs network namespace privileges")
	}
	for _, program := range []string{"ip", "wg"} {
		if _, err := exec.LookPath(program); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	run := func(input, name string, args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stdin = strings.NewReader(input)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated network command %s failed: %v", name, err)
		}
		return strings.TrimSpace(string(out))
	}
	ns := "tnx-ai-client"
	gw, clientIf, underlay, remote := "tnx-ai-wg", "tnx-client-wg", "tnx-ai-link", "tnx-peer-link"
	run("", "ip", "netns", "add", ns)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "delete", ns).Run() })
	run("", "ip", "link", "add", underlay, "type", "veth", "peer", "name", remote)
	t.Cleanup(func() { _ = exec.Command("ip", "link", "delete", underlay).Run() })
	run("", "ip", "link", "set", remote, "netns", ns)
	run("", "ip", "address", "add", "192.0.2.1/30", "dev", underlay)
	run("", "ip", "link", "set", underlay, "up")
	nsrun := func(input string, args ...string) string {
		return run(input, "ip", append([]string{"netns", "exec", ns}, args...)...)
	}
	nsrun("", "ip", "address", "add", "192.0.2.2/30", "dev", remote)
	nsrun("", "ip", "link", "set", remote, "up")
	nsrun("", "ip", "link", "set", "lo", "up")
	gwKey, clientKey := run("", "wg", "genkey"), run("", "wg", "genkey")
	gwPub, clientPub := run(gwKey, "wg", "pubkey"), run(clientKey, "wg", "pubkey")
	run("", "ip", "link", "add", gw, "type", "wireguard")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "delete", gw).Run() })
	run(gwKey, "wg", "set", gw, "private-key", "/dev/stdin", "listen-port", "39999", "peer", clientPub, "allowed-ips", "10.88.0.2/32,fd88::2/128")
	run("", "ip", "address", "add", "10.88.0.1/24", "dev", gw)
	run("", "ip", "address", "add", "fd88::1/64", "dev", gw)
	run("", "ip", "link", "set", gw, "mtu", "1380", "up")
	nsrun("", "ip", "link", "add", clientIf, "type", "wireguard")
	nsrun(clientKey, "wg", "set", clientIf, "private-key", "/dev/stdin", "peer", gwPub, "allowed-ips", "10.88.0.1/32", "endpoint", "192.0.2.1:39999", "persistent-keepalive", "1")
	nsrun("", "ip", "address", "add", "10.88.0.2/24", "dev", clientIf)
	nsrun("", "ip", "link", "set", clientIf, "mtu", "1380", "up")

	readback := run("", "wg", "show", gw, "allowed-ips")
	if _, err := PeerKey(readback, "10.88.0.2"); err != nil {
		fields := strings.Fields(readback)
		t.Fatalf("real WireGuard allowed-IP format rejected: %q: %v", fields[1:], err)
	}
	target, _ := url.Parse("https://control.test:8443")
	var calls atomic.Int32
	r := NewRuntime(gw, target, roundTrip(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		if req.URL.Path != "/agent/ai-http/v1/chat/completions" || req.Header.Get("X-Tunnex-VPN-IP") != "10.88.0.2" || req.Header.Get("X-Tunnex-VPN-Key") != clientPub {
			return nil, fmt.Errorf("incorrect kernel peer evidence")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(strings.Repeat("vpn-only\n", 32768)))}, nil
	}), func() bool { return true }, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.SetDesired("10.88.0.1/24,fd88::1/64")
	r.Reconcile(ctx)
	t.Cleanup(r.Close)
	if ready, address := r.Status(); !ready || address != "10.88.0.1" {
		t.Fatal("real private listener did not become ready")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	request := func(allow bool, source string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "ip", "netns", "exec", ns, binary, "-test.run", "^TestAIVPNWireClient$", "-test.count=1")
		cmd.Env = append(os.Environ(), "TUNNEX_TEST_WIRE_CLIENT=1", fmt.Sprintf("TUNNEX_TEST_WIRE_ALLOW=%t", allow), "TUNNEX_TEST_WIRE_SOURCE="+source)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated VPN client check failed: %v: %s", err, out)
		}
	}
	request(true, "")
	if calls.Load() != 1 {
		t.Fatal("real VPN request did not carry peer identity")
	}
	handshake := strings.Fields(run("", "wg", "show", gw, "latest-handshakes"))
	if len(handshake) != 2 || handshake[0] != clientPub || handshake[1] == "0" {
		t.Fatal("positive request had no authenticated WireGuard handshake")
	}

	// Deliberately route the same destination outside the tunnel. Even using
	// the same locally owned source IP must not defeat SO_BINDTODEVICE.
	nsrun("", "ip", "route", "add", "10.88.0.1/32", "via", "192.0.2.1", "dev", remote)
	request(false, "")
	request(false, "10.88.0.2")
	if calls.Load() != 1 {
		t.Fatal("off-VPN request reached the inference transport")
	}
	nsrun("", "ip", "route", "delete", "10.88.0.1/32")
	request(true, "")
	if calls.Load() != 2 {
		t.Fatal("restored VPN route did not restore access")
	}

	run("", "ip", "link", "delete", gw)
	r.Reconcile(ctx)
	if ready, address := r.Status(); ready || address != "" {
		t.Fatal("removed WireGuard interface retained readiness")
	}
	request(false, "")
	t.Log("real WireGuard: dual-stack individual peer and 288 KiB response passed; ordinary/spoofed-source underlay ingress denied; interface loss withdrew listener")
}

// Launched by the wire test inside its isolated client namespace. No request is
// made when this helper is discovered by an ordinary unit-test invocation.
func TestAIVPNWireClient(t *testing.T) {
	if os.Getenv("TUNNEX_TEST_WIRE_CLIENT") != "1" {
		t.Skip("isolated wire-test client only")
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	if source := os.Getenv("TUNNEX_TEST_WIRE_SOURCE"); source != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(source)}
	}
	tr := &http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	response, err := client.Post("http://10.88.0.1:8083/ai/v1/chat/completions", "application/json", strings.NewReader(`{"model":"test"}`))
	if os.Getenv("TUNNEX_TEST_WIRE_ALLOW") != "true" {
		if err == nil {
			response.Body.Close()
			t.Fatal("request outside a working WireGuard path reached an HTTP listener")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || string(body) != strings.Repeat("vpn-only\n", 32768) {
		t.Fatalf("VPN response failed: status=%d bytes=%d", response.StatusCode, len(body))
	}
}
