package main

import (
	"log/slog"

	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"github.com/tunnexio/tunnex/apps/node/internal/mcpgw"
)

// configureMCPGatewayRuntime builds the gateway's MCP listener (AI-SEC-2). Unlike the AI listener it has
// no setting: it exists whenever the gateway runs the kernel WireGuard backend, because the caller's
// identity is read from the kernel peer table. On any other backend it returns nil, the capability is
// reported as absent, and the control plane sends no MCP through this gateway. A nil runtime never
// affects ordinary VPN readiness.
func configureMCPGatewayRuntime(backend, iface string, client *control.Client, healthy func() bool, notify func(), logger *slog.Logger) *mcpgw.Runtime {
	if backend != "wgctrl" || client == nil {
		return nil
	}
	return mcpgw.NewRuntime(iface, client, healthy, notify, logger)
}
