//go:build linux

package ipsec

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"path/filepath"
)

func startRuntimeBGPSession(ctx context.Context, dir string, id uuid.UUID, generation uint64, cfg bgpengine.Config, checkpoint func(bgpengine.ProcessIdentity) error) (runtimeBGPSession, error) {
	return bgpengine.StartProcessWithCheckpoint(ctx, filepath.Join(dir, fmt.Sprintf("bgp-%s-g%d", id.String(), generation)), cfg, checkpoint)
}

func recoverRuntimeBGPProcess(id bgpengine.ProcessIdentity) error {
	return bgpengine.RecoverProcess(id)
}

func recoverRetiredRuntimeBGPProcess(id bgpengine.ProcessIdentity, boot, ns string) error {
	return bgpengine.RecoverRetiredProcess(id, boot, ns)
}

func proveUncertainRuntimeBGPProcess(id bgpengine.ProcessIdentity) error {
	return bgpengine.ProveUncertainRetirement(id)
}

func recoverUncertainRuntimeBGPProcess(id bgpengine.ProcessIdentity) error {
	return bgpengine.RecoverUncertainProcess(id)
}

func startRuntimeBGPSessionWithLocalExportProof(ctx context.Context, dir string, id uuid.UUID, generation uint64, cfg bgpengine.Config, checkpoint func(bgpengine.ProcessIdentity) error, proof bgpengine.LocalExportProof) (runtimeBGPSession, error) {
	return bgpengine.StartProcessWithCheckpointAndLocalExportProof(ctx, filepath.Join(dir, fmt.Sprintf("bgp-%s-g%d", id.String(), generation)), cfg, checkpoint, proof)
}
