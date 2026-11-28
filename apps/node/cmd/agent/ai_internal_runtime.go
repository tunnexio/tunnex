package main

import (
	"log/slog"
	"net/netip"

	"github.com/tunnexio/tunnex/apps/node/internal/aiinternal"
	"github.com/tunnexio/tunnex/apps/node/internal/control"
)

// configureAIInternalRuntime builds the internal AI endpoint listener (AI-KEYS-1). It has no setting
// and no backend requirement (it does not read the WireGuard peer table): it exists whenever the agent
// talks to the control plane over the authenticated HTTPS channel with the rotating node certificate,
// and listens only while the control plane configures an endpoint for this gateway. Without that
// channel it returns nil, the capability is reported as absent, and ordinary VPN readiness is untouched.
// notify and serving must not block.
func configureAIInternalRuntime(client *control.Client, notify func(), serving func([]netip.Addr, int), logger *slog.Logger) *aiinternal.Runtime {
	if client == nil {
		return nil
	}
	target, transport, err := client.AIInternalTransport()
	if err != nil {
		logger.Info("ai_internal_control_channel_unavailable")
		return nil
	}
	return aiinternal.NewRuntime(aiinternal.Config{Control: client, Target: target, Transport: transport,
		Notify: notify, Serving: serving, Logger: logger})
}

// aiInternalReport fills the internal AI endpoint fields of the capability report. A nil runtime
// reports version 0 and nothing else.
func aiInternalReport(ps *control.PolicyStatus, runtime *aiinternal.Runtime) {
	ps.AIInternalEndpointAddresses = []string{}
	if runtime == nil {
		return
	}
	s := runtime.Status()
	ps.AIInternalEndpointVersion = aiinternal.DesiredVersion
	ps.AIInternalEndpointReady = s.Ready
	ps.AIInternalEndpointAddresses = s.Addresses
	ps.AIInternalEndpointPort = s.Port
	ps.AIInternalEndpointRevision = s.Revision
	ps.AIInternalEndpointError = s.Error
	ps.AIInternalEndpointCertNotAfter = s.CertNotAfter
	ps.AIInternalEndpointCertSHA256 = s.CertSHA256
}
