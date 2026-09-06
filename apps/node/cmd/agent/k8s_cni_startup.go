package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
)

// startKubernetesCNIAuthorityObserver earns this process's initial admission
// and keeps its observation history fresh across slow control-plane fetches.
// The signal is only a startup barrier: no grant escapes this function, and
// every data-plane operation must still acquire its own current authority.
func startKubernetesCNIAuthorityObserver(ctx context.Context, guard k8snetprep.AuthorityGuard, every time.Duration, logger *slog.Logger) <-chan struct{} {
	admitted := make(chan struct{})
	if every <= 0 {
		every = k8sNetPrepPollInterval
	}
	go func() {
		var announced bool
		var lastReason string
		for {
			if ctx.Err() != nil {
				return
			}
			var err error
			if guard == nil {
				err = fmt.Errorf("runtime CNI authority guard is unavailable")
			} else {
				grant, release, probeErr := guard(ctx)
				// Never retain the node-local lock while waiting, logging or
				// notifying startup. Even a refused probe may return a release.
				if release != nil {
					release()
				}
				err = probeErr
				if err == nil && (release == nil || !time.Now().Before(grant.NotAfter) ||
					(grant.Scope != k8snetprep.ScopeIPMasqOnly && grant.Scope != k8snetprep.ScopeIPMasqAndAWS && grant.Scope != k8snetprep.ScopeIPMasqAndAWSTransit)) {
					err = fmt.Errorf("runtime CNI admission probe has no current scoped grant")
				}
			}
			if ctx.Err() != nil {
				return
			}
			if err == nil {
				if !announced {
					close(admitted)
					announced = true
					if logger != nil {
						logger.Info("k8s_cni_runtime_admitted")
					}
				}
				lastReason = ""
			} else if reason := boundedPostureReason(err.Error()); reason != lastReason {
				if logger != nil {
					logger.Warn("k8s_cni_runtime_waiting", "reason", reason)
				}
				lastReason = reason
			}
			if !sleepCtx(ctx, every) {
				return
			}
		}
	}()
	return admitted
}
