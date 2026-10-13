//go:build !linux

package ipsec

import (
	"context"
	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
)

func startRuntimeBGPSession(context.Context, string, uuid.UUID, uint64, bgpengine.Config, func(bgpengine.ProcessIdentity) error) (runtimeBGPSession, error) {
	return nil, ErrRuntimeController
}

func recoverRuntimeBGPProcess(bgpengine.ProcessIdentity) error { return ErrRuntimeController }

func recoverRetiredRuntimeBGPProcess(id bgpengine.ProcessIdentity, boot, ns string) error {
	return ErrRuntimeController
}

func proveUncertainRuntimeBGPProcess(id bgpengine.ProcessIdentity) error { return ErrRuntimeController }

func recoverUncertainRuntimeBGPProcess(id bgpengine.ProcessIdentity) error {
	return ErrRuntimeController
}
