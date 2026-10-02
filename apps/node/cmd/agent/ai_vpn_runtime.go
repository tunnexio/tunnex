package main

import (
	"log/slog"
	"strconv"
	"strings"

	"github.com/tunnexio/tunnex/apps/node/internal/aivpn"
	"github.com/tunnexio/tunnex/apps/node/internal/control"
)

// An optional AI setup failure must not terminate ordinary VPN reconciliation.
// Returning nil publishes the dedicated AI capability as unavailable.
func configureAIVPNRuntime(setting, backend, iface string, client *control.Client, healthy func() bool, notify func(), logger *slog.Logger) *aivpn.Runtime {
	if strings.TrimSpace(setting) == "" {
		return nil
	}
	enabled, err := strconv.ParseBool(setting)
	if err != nil {
		logger.Error("invalid_ai_vpn_auto_setting")
		return nil
	}
	if !enabled {
		return nil
	}
	if backend != "wgctrl" {
		logger.Error("ai_vpn_requires_native_wireguard")
		return nil
	}
	target, transport, err := client.AIVPNTransport()
	if err != nil {
		logger.Error("ai_vpn_control_channel_unavailable")
		return nil
	}
	return aivpn.NewRuntime(iface, target, transport, healthy, notify, logger)
}
