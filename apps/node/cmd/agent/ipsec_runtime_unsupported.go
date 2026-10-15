//go:build !linux

package main

import (
	"context"
	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"log/slog"
)

func startIPsecRuntime(context.Context, *control.Client, string, *slog.Logger, *ipsec.DNSRuntimeTransport, *ipsec.RuntimeFQDNPolicySource, *ipsec.DesktopNATSource) (func() error, error) {
	return func() error { return nil }, nil
}
