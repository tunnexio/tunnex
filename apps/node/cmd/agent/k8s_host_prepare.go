package main

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
)

type hostPrepareFunc func(context.Context) k8snetprep.HostPrepareReport

// runNodeSubcommand recognizes only closed node-agent subcommands. Unknown
// arguments retain the historical behavior of starting the ordinary agent.
func runNodeSubcommand(args []string, out io.Writer) (handled bool, exitCode int) {
	if len(args) == 0 {
		return false, 0
	}
	switch args[0] {
	case "k8s-host-prepare":
		return true, runK8sHostPrepare(args[1:], out, k8snetprep.PrepareHost)
	case "k8s-host-posture-manager":
		return true, runK8sHostPostureManager(args[1:], out)
	case "k8s-host-posture-check":
		return true, runK8sHostPostureCheck(args[1:], out)
	default:
		return false, 0
	}
}

func runK8sHostPrepare(args []string, out io.Writer, prepare hostPrepareFunc) int {
	if len(args) != 1 || args[0] != "--apply" {
		report := k8snetprep.HostPrepareReport{
			SchemaVersion: 1,
			Operation:     "k8s_host_prepare",
			Status:        k8snetprep.StateBlocked,
			Checks: []k8snetprep.ComponentStatus{{
				Name:   "invocation",
				State:  k8snetprep.StateBlocked,
				Reason: "the only supported invocation is k8s-host-prepare --apply",
			}},
		}
		if json.NewEncoder(out).Encode(report) != nil {
			return 1
		}
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	report := prepare(ctx)
	if json.NewEncoder(out).Encode(report) != nil {
		return 1
	}
	if !report.Ready() {
		return 1
	}
	return 0
}
