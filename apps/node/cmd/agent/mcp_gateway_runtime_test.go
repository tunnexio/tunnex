package main

import (
	"io"
	"log/slog"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/control"
)

// The MCP gateway listener is not behind a setting: it is configured whenever the backend is the kernel
// WireGuard one, and only then.
func TestMCPGatewayRuntimeFollowsTheWireGuardBackend(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	client := &control.Client{}
	for _, backend := range []string{"mem", "", "userspace"} {
		runtime := configureMCPGatewayRuntime(backend, "wg0", client, func() bool { return true }, nil, logger)
		if runtime != nil {
			t.Fatalf("backend %q started the MCP gateway listener", backend)
		}
		// The absent runtime reports no capability and tolerates the calls main makes.
		runtime.SetDesired("10.77.0.9/24")
		if ready, address := runtime.Status(); ready || address != "" {
			t.Fatalf("backend %q reports the MCP gateway capability", backend)
		}
		runtime.Close()
	}
	if configureMCPGatewayRuntime("wgctrl", "wg0", nil, func() bool { return true }, nil, logger) != nil {
		t.Fatal("a listener was configured with no control channel to decide on")
	}
	runtime := configureMCPGatewayRuntime("wgctrl", "missing-test-wg", client, func() bool { return true }, nil, logger)
	if runtime == nil {
		t.Fatal("the kernel WireGuard backend did not configure the MCP gateway listener")
	}
	defer runtime.Close()
	// Configured is not ready: nothing is bound until the interface, the address and the socket exist.
	runtime.SetDesired("10.77.0.9/24")
	if ready, address := runtime.Status(); ready || address != "" {
		t.Fatal("an unbound MCP gateway listener reports the capability")
	}
	if !agentReady(true, true, false, false, false) {
		t.Fatal("an unbound MCP gateway listener withdrew ordinary VPN readiness")
	}
}
