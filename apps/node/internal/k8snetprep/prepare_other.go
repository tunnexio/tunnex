//go:build !linux

package k8snetprep

import (
	"context"
	"runtime"
)

// PrepareHost fails closed off Linux; the gateway data plane is Linux-only.
func PrepareHost(context.Context) HostPrepareReport {
	return HostPrepareReport{
		SchemaVersion: 1,
		Operation:     "k8s_host_prepare",
		Status:        StateBlocked,
		Checks: []ComponentStatus{{
			Name:   "platform",
			State:  StateBlocked,
			Reason: "Linux is required; current platform is " + runtime.GOOS,
		}},
	}
}
