package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/hostposture"
	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
)

type postureCommandReport struct {
	SchemaVersion int    `json:"schema_version"`
	Operation     string `json:"operation"`
	Status        string `json:"status"`
	Reason        string `json:"reason,omitempty"`
}

func runK8sHostPostureManager(args []string, out io.Writer) int {
	if len(args) != 1 || args[0] != "--run" {
		return writePostureReport(out, "k8s_host_posture_manager", "blocked", "the only supported invocation is k8s-host-posture-manager --run", 2)
	}
	nodeName := os.Getenv("TUNNEX_HOST_POSTURE_NODE_NAME")
	managerUID := os.Getenv("TUNNEX_HOST_POSTURE_MANAGER_UID")
	stateDir := getenv("TUNNEX_HOST_POSTURE_STATE_DIR", hostposture.DefaultStateDir)
	procSys := getenv("TUNNEX_HOST_POSTURE_PROC_SYS", hostposture.DefaultHostProcSys)
	interval, err := time.ParseDuration(getenv("TUNNEX_HOST_POSTURE_RECONCILE_INTERVAL", hostposture.DefaultReconcileInterval.String()))
	if err != nil || interval < 500*time.Millisecond || interval > 30*time.Second {
		return writePostureReport(out, "k8s_host_posture_manager", "blocked", "reconcile interval must be between 500ms and 30s", 1)
	}
	requestTimeout, err := time.ParseDuration(getenv("TUNNEX_HOST_POSTURE_API_TIMEOUT", hostposture.DefaultAPIRequestTimeout.String()))
	if err != nil || requestTimeout < time.Second || requestTimeout > 30*time.Second {
		return writePostureReport(out, "k8s_host_posture_manager", "blocked", "API timeout must be between 1s and 30s", 1)
	}
	maxOwners, err := strconv.Atoi(getenv("TUNNEX_HOST_POSTURE_MAX_OWNERS", strconv.Itoa(hostposture.DefaultMaxOwners)))
	if err != nil {
		return writePostureReport(out, "k8s_host_posture_manager", "blocked", "max owners is invalid", 1)
	}
	store, err := hostposture.NewStore(stateDir)
	if err != nil {
		return writePostureReport(out, "k8s_host_posture_manager", "blocked", err.Error(), 1)
	}
	lock, err := hostposture.AcquireProcessLock(store.LockPath())
	if err != nil {
		return writePostureReport(out, "k8s_host_posture_manager", "blocked", err.Error(), 1)
	}
	defer lock.Close()
	source, err := hostposture.NewInClusterOwnerSource(requestTimeout)
	if err != nil {
		return writePostureReport(out, "k8s_host_posture_manager", "blocked", err.Error(), 1)
	}
	kernel, err := hostposture.NewLinuxKernel(procSys, nil)
	if err != nil {
		return writePostureReport(out, "k8s_host_posture_manager", "blocked", err.Error(), 1)
	}
	logger := slog.New(slog.NewJSONHandler(out, &slog.HandlerOptions{Level: slog.LevelInfo}))
	manager, err := hostposture.NewManager(hostposture.Config{
		NodeName: nodeName, ManagerUID: managerUID, MaxOwners: maxOwners, ReconcileInterval: interval,
	}, source, kernel, store, logger)
	if err != nil {
		return writePostureReport(out, "k8s_host_posture_manager", "blocked", err.Error(), 1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger.Info("k8s_host_posture_manager_started", "contract", hostposture.Contract, "node", nodeName)
	if err := manager.Run(ctx); err != nil {
		return writePostureReport(out, "k8s_host_posture_manager", "blocked", err.Error(), 1)
	}
	return 0
}

func runK8sHostPostureCheck(args []string, out io.Writer) int {
	if len(args) != 1 || (args[0] != "--wait" && args[0] != "--ready" && args[0] != "--live") {
		return writePostureReport(out, "k8s_host_posture_check", "blocked", "supported invocations are --wait, --ready, or --live", 2)
	}
	store, err := hostposture.OpenStore(getenv("TUNNEX_HOST_POSTURE_STATE_DIR", hostposture.DefaultStateDir))
	if err != nil {
		return writePostureReport(out, "k8s_host_posture_check", "blocked", err.Error(), 1)
	}
	nodeName := os.Getenv("TUNNEX_HOST_POSTURE_NODE_NAME")
	if args[0] == "--wait" {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		err = hostposture.WaitForCNIOwner(ctx, store, nodeName, os.Getenv("TUNNEX_HOST_POSTURE_OWNER_UID"), time.Now, nil)
	} else {
		err = hostposture.CheckManagerHeartbeat(store, nodeName, args[0] == "--live", time.Now())
	}
	if err != nil {
		return writePostureReport(out, "k8s_host_posture_check", "blocked", err.Error(), 1)
	}
	return writePostureReport(out, "k8s_host_posture_check", "ready", "", 0)
}

// A runtime process earns its own advancing CNI proofs after init. Retain this
// one read-only Store across reconciles so its bounded proof history is not
// reset on every call. Neither construction nor refusal creates host files.
func newKubernetesCNIAuthorityGuard(stateDir, nodeName, ownerUID string) (k8snetprep.AuthorityGuard, error) {
	if strings.TrimSpace(nodeName) == "" || strings.TrimSpace(ownerUID) == "" {
		return nil, fmt.Errorf("exact Kubernetes node and gateway Pod UID are required for CNI authority")
	}
	store, err := hostposture.OpenStore(stateDir)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) (k8snetprep.AuthorityGrant, func(), error) {
		return store.AcquireCNIAuthority(ctx, nodeName, ownerUID, time.Now())
	}, nil
}

func writePostureReport(out io.Writer, operation, status, reason string, code int) int {
	report := postureCommandReport{SchemaVersion: 1, Operation: operation, Status: status, Reason: boundedPostureReason(reason)}
	if err := json.NewEncoder(out).Encode(report); err != nil {
		return 1
	}
	return code
}

func boundedPostureReason(value string) string {
	if len(value) > hostposture.MaxReasonBytes {
		return value[:hostposture.MaxReasonBytes]
	}
	return value
}
