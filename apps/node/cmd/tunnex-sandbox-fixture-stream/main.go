// Command tunnex-sandbox-fixture-stream is a stdio-only qualification transport.
// It runs inside the isolated fixture gateway; it opens no listener and holds
// no SSH credentials. Source binding makes the namespace's creator-client
// WireGuard route traverse the ordinary gateway forwarding policy.
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/sandboxproduct"
)

func main() {
	// TODO(sandbox-reentry): see docs/S-sandbox-shelved-main-reentry.md.
	// Refuse before parsing addresses, dialing or consuming stream input.
	if !sandboxproduct.Available {
		fmt.Fprintln(os.Stderr, sandboxproduct.ErrShelved)
		os.Exit(1)
	}
	source := flag.String("source", "", "fixture client IPv4 address")
	target := flag.String("target", "", "fixture sandbox IPv4 address")
	flag.Parse()
	s, se := netip.ParseAddr(*source)
	t, te := netip.ParseAddr(*target)
	prefix := netip.MustParsePrefix("10.254.242.0/24")
	if flag.NArg() != 0 || se != nil || te != nil || !prefix.Contains(s) || !prefix.Contains(t) || s == t || s == prefix.Addr() || t == prefix.Addr() {
		os.Exit(2)
	}
	dialer := net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.IP(s.AsSlice())}}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(t.String(), "22"))
	if err != nil {
		os.Exit(1)
	}
	defer conn.Close()
	go func() {
		_, _ = io.Copy(conn, os.Stdin)
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	if _, err = io.Copy(os.Stdout, conn); err != nil {
		os.Exit(1)
	}
}
