//go:build windows

package helper

import (
	"errors"
	"testing"
)

// TestWindowsFullTunnelRequiresDNS: a full tunnel that carries NO DNS server is refused
// (full_tunnel_requires_dns) BEFORE any adapter/WFP state is created — otherwise the base WFP
// block would drop all port-53 with no tunnel resolver = a silent total resolution outage
// (S6.10 review). Checked before CreateTUN so it needs no wintun driver.
func TestWindowsFullTunnelRequiresDNS(t *testing.T) {
	wb := &windowsBackend{}
	cfg := fullConfig()
	cfg.DNS = nil // no resolver

	err := wb.Up(cfg)
	var pe *ProtocolError
	if !errors.As(err, &pe) || pe.Code != "full_tunnel_requires_dns" {
		t.Fatalf("full tunnel with no DNS must be refused with full_tunnel_requires_dns, got %v", err)
	}
	if wb.armed || wb.dev != nil || wb.tunDev != nil {
		t.Fatalf("empty-DNS refusal must arm/create nothing: armed=%v dev=%v tun=%v", wb.armed, wb.dev, wb.tunDev)
	}
}
