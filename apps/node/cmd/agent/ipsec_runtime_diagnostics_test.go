package main

import (
	"bytes"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"log/slog"
	"strings"
	"testing"
)

func TestIPsecDNSDiagnosticLabOptIn(t *testing.T) {
	for _, tc := range []struct {
		name         string
		opt, refused bool
		operation    string
		visible      bool
	}{{"default DNS", false, false, "dns_exchange", false}, {"lab DNS", true, false, "dns_exchange", true}, {"other unchanged", true, false, "heartbeat", false}, {"refusal unchanged", false, true, "dns_exchange", true}} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			l := slog.New(slog.NewJSONHandler(&b, &slog.HandlerOptions{Level: slog.LevelInfo}))
			ipsecDiagnosticSink(l, tc.opt)(ipsec.RuntimeDiagnostic{Operation: tc.operation, Stage: "dns_socket", ElapsedMillis: 7, Refused: tc.refused, ContextState: "active"})
			if (b.Len() > 0) != tc.visible {
				t.Fatal("log visibility changed")
			}
			if tc.visible && (!strings.Contains(b.String(), "elapsed_ms") || strings.Contains(b.String(), "payload")) {
				t.Fatal("fields changed")
			}
		})
	}
}

func TestIPsecBGPDiagnosticRecoveryVisibility(t *testing.T) {
	for _, tc := range []struct {
		operation, stage string
		refused, visible bool
	}{
		{"bgp_candidate_guard", "route_change_required", false, true},
		{"bgp_exact_refresh", "ready_for_retry", false, true},
		{"bgp_candidate_guard", "peer_summary", true, true},
		{"bgp_exact_refresh", "material_fetch", true, true},
		{"bgp_native_guard", "tunnel_mtu", false, false},
		{"bgp_exact_refresh", "material_current", false, false},
		{"heartbeat", "ready_for_retry", false, false},
		{"bgp_candidate_guard", "route_change_required_extra", false, false},
	} {
		t.Run(tc.operation+"/"+tc.stage, func(t *testing.T) {
			var b bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&b, &slog.HandlerOptions{Level: slog.LevelInfo}))
			ipsecDiagnosticSink(logger, false)(ipsec.RuntimeDiagnostic{Operation: tc.operation, Stage: tc.stage, Refused: tc.refused, ContextState: "active"})
			if (b.Len() > 0) != tc.visible {
				t.Fatal("unexpected fixed-event visibility", b.String())
			}
			if tc.visible {
				level, message := `"level":"INFO"`, "ipsec_runtime_diagnostic_completed"
				if tc.refused {
					level, message = `"level":"WARN"`, "ipsec_runtime_diagnostic_refused"
				}
				if !strings.Contains(b.String(), level) || !strings.Contains(b.String(), message) || strings.Contains(b.String(), "payload") {
					t.Fatal("recovered route observation confused with refusal", b.String())
				}
			}
		})
	}
}
