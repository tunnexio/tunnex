//go:build !linux

package k8snetprep

import (
	"context"
	"fmt"
)

type NFTRunner func(context.Context, ...string) (string, error)

type Reconciler struct{ awsAware bool }

type OwnedRuleReceipt struct {
	Handle    uint64 `json:"handle"`
	CIDR      string `json:"cidr"`
	Interface string `json:"interface"`
	Marker    string `json:"marker"`
	Direction string `json:"direction"`
}

func New(string, NFTRunner) *Reconciler { return &Reconciler{} }

func NewWithAWS(string, NFTRunner, IPTablesRunner, AuthorityGuard) *Reconciler {
	return &Reconciler{awsAware: true}
}

func (r *Reconciler) Reconcile(context.Context, string) (ReconcileStatus, error) {
	status := blockedStatusOther()
	return status, fmt.Errorf("Kubernetes network preparation requires Linux")
}

func (r *Reconciler) Withdraw(context.Context) (ReconcileStatus, error) {
	if r.awsAware {
		return blockedStatusOther(), fmt.Errorf("Kubernetes network preparation requires Linux")
	}
	return ReconcileStatus{
		Host:     ComponentStatus{Name: "wireguard_rp_filter", State: StateNotApplicable, Reason: "Linux-only"},
		Adapters: []ComponentStatus{{Name: "ip_masq_agent", State: StateNotApplicable, Reason: "Linux-only"}},
	}, nil
}

func (r *Reconciler) OwnedArtifacts(context.Context) ([]OwnedRuleReceipt, State, error) {
	return nil, StateBlocked, fmt.Errorf("Kubernetes network preparation requires Linux")
}

func blockedStatusOther() ReconcileStatus {
	return ReconcileStatus{
		Host:     ComponentStatus{Name: "wireguard_rp_filter", State: StateBlocked, Reason: "Linux is required"},
		Adapters: []ComponentStatus{{Name: "ip_masq_agent", State: StateBlocked, Reason: "Linux is required"}},
	}
}
