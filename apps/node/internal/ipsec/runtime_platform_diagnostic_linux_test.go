//go:build linux

package ipsec

import (
	"context"
	"os"
	"testing"
	"time"
)

// Fixed nonsecret stages; no receipt attaches to the live controller and nft
// remains check-only. This is diagnostics, never a capability override.
func TestRuntimePlatformDiagnosticNative(t *testing.T) {
	if os.Getenv("TUNNEX_IPSEC_PLATFORM_DIAGNOSTIC") != "1" {
		t.Skip("authorized native read-only diagnostic")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	daemon, err := NewDaemonClient("/run/tunnex-ipsec/charon.vici")
	if err != nil {
		t.Fatal("diagnostic daemon unavailable")
	}
	p, err := newRuntimePlatformProbe("/sbin/ip", "/usr/sbin/nft", daemon, func() bool { return true })
	if err != nil {
		t.Fatal("diagnostic construction unavailable")
	}
	for _, s := range []struct {
		name  string
		probe func(context.Context) error
	}{{"privilege", p.privilege}, {"package", p.packaged}, {"daemon", p.daemon}, {"kernel", p.kernel}, {"xfrm", p.xfrm}, {"environment", p.environment}, {"nft-check", p.nft}} {
		err := s.probe(ctx)
		t.Logf("platform_stage=%s pass=%t", s.name, err == nil)
	}
	_, err = p.probe(ctx)
	t.Logf("platform_receipt pass=%t", err == nil)
}
