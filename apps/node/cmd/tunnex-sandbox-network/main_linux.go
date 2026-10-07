//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/google/uuid"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/tunnexio/tunnex/apps/node/internal/sandboxnetwork"
	"github.com/tunnexio/tunnex/apps/node/internal/sandboxproduct"
)

func main() {
	// TODO(sandbox-reentry): see docs/S-sandbox-shelved-main-reentry.md.
	// Refuse before configuration, filesystem inspection or privileged work.
	if !sandboxproduct.Available {
		fmt.Fprintln(os.Stderr, sandboxproduct.ErrShelved)
		os.Exit(1)
	}
	socket := flag.String("socket", "/run/tunnex-sandbox-network/control.sock", "root-owned local control socket")
	state := flag.String("state", "/var/lib/tunnex-sandbox-network", "existing exclusive root-owned state")
	worker := flag.Uint("worker-uid", 0, "approved rootless worker UID")
	subStart := flag.Uint("subuid-start", 0, "approved existing subordinate UID start")
	subCount := flag.Uint("subuid-count", 0, "approved existing subordinate UID count")
	gatewayOrg := flag.String("gateway-org-id", "", "optional exact native organization UUID; empty requires fixture org label")
	gatewayNode := flag.String("gateway-node-id", "", "optional exact qualification gateway UUID")
	gatewayRuntime := flag.String("gateway-runtime-id", "", "immutable task gateway container ID")
	gatewayImage := flag.String("gateway-image-digest", "", "immutable task gateway image ID")
	gatewayInterface := flag.String("gateway-interface", "", "gateway WireGuard interface")
	probeBinary := flag.String("probe-binary", "", "root-owned fixed SSH probe binary")
	probeSHA := flag.String("probe-sha256", "", "pinned SSH probe executable digest")
	flag.Parse()
	if flag.NArg() != 0 || os.Geteuid() != 0 || *worker == 0 || *worker > 1<<32-1 || *subStart > 1<<32-1 || *subCount == 0 || *subCount > 1<<32-1 || !filepath.IsAbs(*state) || filepath.Clean(*state) != *state {
		fail()
	}
	st, err := os.Lstat(*state)
	if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		fail()
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		fail()
	}
	root, err := os.OpenRoot(*state)
	if err != nil {
		fail()
	}
	defer root.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	controller := sandboxnetwork.Controller{Store: sandboxnetwork.FilesystemManifests{Root: root}, Driver: sandboxnetwork.LinuxDriver{}}
	var inspectors []sandboxnetwork.GatewayInspector
	if *gatewayOrg != "" || *gatewayNode != "" || *gatewayRuntime != "" || *gatewayImage != "" || *gatewayInterface != "" || *probeBinary != "" || *probeSHA != "" {
		id, e := uuid.Parse(*gatewayNode)
		if e != nil || id == uuid.Nil || *gatewayRuntime == "" || *gatewayImage == "" || *gatewayInterface == "" || *probeBinary == "" || *probeSHA == "" {
			fail()
		}
		var orgID uuid.UUID
		if *gatewayOrg != "" {
			orgID, e = uuid.Parse(*gatewayOrg)
			if e != nil || orgID == uuid.Nil {
				fail()
			}
		}
		inspectors = append(inspectors, sandboxnetwork.DockerGateway{NodeID: id, OrgID: orgID, RuntimeID: *gatewayRuntime, ImageDigest: *gatewayImage, Interface: *gatewayInterface, ProbeBinary: *probeBinary, ProbeSHA256: *probeSHA})
	}
	if err = sandboxnetwork.ServeUnix(ctx, *socket, sandboxnetwork.Admission{WorkerUID: uint32(*worker), SubUIDStart: uint32(*subStart), SubUIDCount: uint32(*subCount)}, controller, inspectors...); err != nil && ctx.Err() == nil {
		fail()
	}
}
func fail() { fmt.Fprintln(os.Stderr, "sandbox network helper unavailable"); os.Exit(1) }
