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
