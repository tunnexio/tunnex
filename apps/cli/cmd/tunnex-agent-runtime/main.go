// Command tunnex-agent-runtime runs the managed-agent steady-state channel.
// Bootstrap is deliberately separate: F03 owns one-time enrollment and this
// process only consumes the resulting local contract.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/tunnexio/tunnex/apps/cli/internal/cli"
)

var version = "dev"

func main() {
	if err := preflight(); err != nil {
		fmt.Fprintln(os.Stderr, "tunnex-agent-runtime: startup refused:", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	opts := cli.DefaultManagedRuntimeOptions()
	opts.ClientVersion = version
	if endpoints := strings.TrimSpace(os.Getenv("TUNNEX_MCP_INVENTORY_ENDPOINTS")); endpoints != "" {
		opts.MCPInventoryEndpoints = strings.Split(endpoints, ",")
	}
	// The managed runtime always exposes its loopback proxy by default. An
	// optional environment value may override its listener for compatibility,
	// but an absent value must not erase the safe default.
	if listen := strings.TrimSpace(os.Getenv("TUNNEX_MCP_PROXY_LISTEN")); listen != "" {
		opts.MCPProxyListen = listen
	}
	if upstream := strings.TrimSpace(os.Getenv("TUNNEX_MCP_PROXY_UPSTREAM")); upstream != "" {
		opts.MCPProxyUpstream = upstream
	}
	if err := cli.RunManagedAgent(ctx, opts); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "tunnex-agent-runtime: stopped:", err)
		os.Exit(1)
	}
}

// preflight refuses to start without WireGuard's own tool. resolvconf is no longer required (AI-UX-1): on a
// host without it the runtime leaves the DNS servers out of the tunnel configuration, so wg-quick never
// calls it, and reports that private DNS names pushed through the tunnel do not resolve there.
func preflight() error {
	if _, err := exec.LookPath("wg"); err != nil {
		return errors.New("wg is required")
	}
	return nil
}
