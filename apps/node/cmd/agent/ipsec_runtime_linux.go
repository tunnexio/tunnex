//go:build linux

package main

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// Existing obligations restore refusal synchronously before any WireGuard
// forwarding. New hosts discover opt-in in the background and bind no IKE ports
// until authoritative opt-in is true. There is no local capability override.
func startIPsecRuntime(ctx context.Context, client *control.Client, stateDir string, logger *slog.Logger) error {
	dir := filepath.Join(stateDir, "ipsec")
	org, node, err := ipsec.ReadRuntimeJournalIdentity(dir)
	existing := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("IPsec saved refusal unavailable")
	}
	var controller *ipsec.RuntimeController
	construct := func() error {
		environment, e := ipsec.NewRuntimeEnvironmentInspector("/sbin/ip", "/usr/sbin/nft")
		if e != nil {
			return e
		}
		if e = os.Mkdir(dir, 0700); e != nil && !errors.Is(e, os.ErrExist) {
			return e
		}
		controller, e = ipsec.NewRuntimeController(ipsec.RuntimeControllerConfig{OrgID: org, GatewayID: node, JournalDir: dir, IPPath: "/sbin/ip", NFTPath: "/usr/sbin/nft", Environment: environment}, client)
		if e != nil {
			return e
		}
		if e = controller.Start(ctx); e != nil {
			controller.Close()
			controller = nil
			return e
		}
		client.AttachIPsecController(controller)
		return nil
	}
	if existing {
		if err = construct(); err != nil {
			return errors.New("IPsec saved refusal unavailable")
		}
	}
	go func() {
		var process *ipsec.DaemonProcess
		qualified := false
		defer func() {
			if process != nil {
				process.Close()
			}
			if controller != nil {
				controller.Close()
			}
		}()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			if ctx.Err() != nil {
				return
			}
			// Validate process-local authority even when CP discovery fails or
			// returns no work. This never renews a lease and never blocks cleanup.
			if controller != nil {
				if err := controller.Validate(ctx); err != nil {
					logger.Warn("ipsec_runtime_authority_withdrawn")
				}
			}
			page, cleanupPending, e := discoverIPsecRuntime(ctx, client)
			if e == nil {
				if controller != nil && (page.OrgID != org || page.NodeID != node) {
					logger.Warn("ipsec_runtime_identity_refused")
					return
				}
				if controller == nil && (page.IPsecEnabled || cleanupPending) {
					org, node = page.OrgID, page.NodeID
					if e = construct(); e != nil {
						logger.Warn("ipsec_runtime_start_refused")
					}
				}
				// Existing cleanup obligations remain serviceable after organization opt-out.
				if controller != nil && (page.IPsecEnabled || cleanupPending) {
					if process == nil {
						process, e = ipsec.StartDaemonProcess(ctx)
						if e == nil {
							if e = controller.AttachDaemon(process.Client, process.Alive); e != nil {
								process.Close()
								process = nil
							}
						}
					}
					if e == nil && process != nil {
						if !qualified && page.IPsecEnabled {
							receipt, probeErr := ipsec.ProbeRuntimePlatform(ctx, "/sbin/ip", "/usr/sbin/nft", process.Client, process.Alive)
							if probeErr == nil {
								probeErr = controller.AttachQualification(receipt)
							}
							if probeErr == nil {
								qualified = true
							} else {
								logger.Warn("ipsec_runtime_platform_refused")
							}
						}
						// Cleanup remains available without activation qualification; Apply requires
						// the attached current receipt and cannot grant permits without it.
						bound := &boundIPsecClient{Client: client, org: org, node: node}
						if e = control.PollIPsecRuntime(ctx, bound, controller); e != nil {
							logger.Warn("ipsec_runtime_reconcile_refused")
						}
					} else {
						logger.Warn("ipsec_runtime_daemon_unavailable")
					}
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return nil
}

type boundIPsecClient struct {
	*control.Client
	org, node uuid.UUID
}

func (c *boundIPsecClient) IPsecPending(ctx context.Context, after *uuid.UUID, limit int) (ipsec.RuntimePendingPage, error) {
	p, e := c.Client.IPsecPending(ctx, after, limit)
	if e != nil || p.OrgID != c.org || p.NodeID != c.node {
		return ipsec.RuntimePendingPage{}, control.ErrIPsecControl
	}
	return p, nil
}
