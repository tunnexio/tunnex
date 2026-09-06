//go:build !linux

package egress

import (
	"context"
	"fmt"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/flowlog"
	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// Manager is a no-op off Linux (the gateway data plane is Linux-only). Reconcile always
// reports NOT egress-capable so a non-Linux build never claims full-tunnel egress.
type Manager struct{}

func New(_ string) *Manager { return &Manager{} }

func (m *Manager) Reconcile(_ context.Context) (bool, bool, error) { return false, false, nil }

// K8sNetPrepReady is false off Linux because the gateway data plane is Linux-only.
func (m *Manager) K8sNetPrepReady() bool { return false }

// SetKubernetesMode is a no-op off Linux; readiness remains fail-closed there.
func (m *Manager) SetKubernetesMode(bool) {}

// SetKubernetesCNIAuthority cannot enable a non-Linux gateway data plane.
func (m *Manager) SetKubernetesCNIAuthority(k8snetprep.AuthorityGuard) {}

// ReconcileK8sNetPrep fails closed off Linux; the gateway data plane is Linux-only.
func (m *Manager) ReconcileK8sNetPrep(context.Context) error {
	return fmt.Errorf("Kubernetes network preparation requires Linux")
}

func (m *Manager) Teardown(_ context.Context) {}

// SetPolicy is a no-op off Linux (no forward chain to program).
func (m *Manager) SetPolicy(_ *nodepolicy.Compiled) {}

// SetFQDNBaselinePath is a no-op off Linux: this build has no gateway
// enforcement or conntrack state to reconcile.
func (m *Manager) SetFQDNBaselinePath(_ string) {}

// DeviceForIP off Linux resolves nothing (no flow logging off Linux).
func (m *Manager) DeviceForIP(_ string) string { return "" }

// FlowAttribution off Linux records nothing because no gateway policy is
// applied and no flow collector exists.
func (m *Manager) FlowAttribution(_ string) flowlog.Attribution { return flowlog.Attribution{} }

// SetFlowLogGroup is a no-op off Linux (nflog is Linux-only; the agent runs on Linux
// gateways — this only keeps non-Linux builds compiling).
func (m *Manager) SetFlowLogGroup(_ int) {}

// AppliedStatus off Linux reports "nothing applied" (version 0, no hash, no error) —
// a non-Linux agent never claims a policy is in force.
func (m *Manager) AppliedStatus() (int, string, time.Time, error) { return 0, "", time.Time{}, nil }

// RefusedVersion off Linux is always 0 (no policy is ever applied or refused). This keeps the
// cross-platform agent main package building on darwin (the S8.1 refusal state was Linux-only, tripping
// a native `go build ./...`; this stub is the ledgered fix — apps/node builds on all platforms, the real
// gateway data plane stays Linux).
func (m *Manager) RefusedVersion() int { return 0 }
