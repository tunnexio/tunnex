package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
)

func TestK8sHostPrepareCommandIsClosedAndBoundedJSON(t *testing.T) {
	for _, args := range [][]string{nil, {}, {"--check"}, {"--apply", "net.ipv4.ip_forward=0"}} {
		var out bytes.Buffer
		code := runK8sHostPrepare(args, &out, func(context.Context) k8snetprep.HostPrepareReport {
			t.Fatal("invalid invocation must not reach host preparation")
			return k8snetprep.HostPrepareReport{}
		})
		if code != 2 {
			t.Fatalf("args=%v code=%d, want 2", args, code)
		}
		var report k8snetprep.HostPrepareReport
		if err := json.Unmarshal(out.Bytes(), &report); err != nil {
			t.Fatalf("args=%v invalid JSON: %v; output=%q", args, err, out.String())
		}
		if report.Status != k8snetprep.StateBlocked || len(out.Bytes()) > 1024 {
			t.Fatalf("args=%v report=%+v bytes=%d", args, report, len(out.Bytes()))
		}
	}
}

func TestK8sHostPrepareCommandReturnsPreparationOutcome(t *testing.T) {
	tests := []struct {
		name   string
		status k8snetprep.State
		code   int
	}{
		{name: "ready", status: k8snetprep.StateReady, code: 0},
		{name: "blocked", status: k8snetprep.StateBlocked, code: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			code := runK8sHostPrepare([]string{"--apply"}, &out, func(context.Context) k8snetprep.HostPrepareReport {
				return k8snetprep.HostPrepareReport{SchemaVersion: 1, Operation: "k8s_host_prepare", Status: tt.status}
			})
			if code != tt.code {
				t.Fatalf("code=%d, want %d", code, tt.code)
			}
		})
	}
}

func TestRunNodeSubcommandLeavesOrdinaryAgentArgumentsUntouched(t *testing.T) {
	handled, code := runNodeSubcommand([]string{"ordinary-agent-argument"}, &bytes.Buffer{})
	if handled || code != 0 {
		t.Fatalf("unknown argument handled=%v code=%d", handled, code)
	}
}
