package ipsec

import (
	"context"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func TestPriorityDueRetainsFiniteOwnersWithoutClaimingValidation(t *testing.T) {
	r, client := fqdnMultiOwnerCadenceRig(t)
	prior := map[uuid.UUID]runtimeActive{}
	for id, a := range r.c.active {
		prior[id] = cloneMaintenanceActive(a)
	}
	proofs, replacements, publications := 0, 0, 0
	r.c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error {
		proofs++
		return ErrRuntimeController
	}
	r.c.replace = func(context.Context, GuardIntent) (GuardManifest, error) {
		replacements++
		return GuardManifest{}, ErrRuntimeController
	}
	err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, func(context.Context, RuntimeDelivery, RuntimeStatusReport) error { publications++; return nil }, nil)
	if err != nil || proofs != 0 || replacements != 0 || publications != 0 || client.requests != 0 || client.reads != 0 {
		t.Fatalf("retained scheduling did work or claimed observation: err=%v proofs=%d replace=%d reports=%d lease=%d material=%d", err, proofs, replacements, publications, client.requests, client.reads)
	}
	if !reflect.DeepEqual(prior, r.c.active) {
		t.Fatal("scheduling changed original active authority")
	}
}

func TestPriorityDueMissingAdviceCannotSkipOrdinaryProof(t *testing.T) {
	r, _ := fqdnMultiOwnerCadenceRig(t)
	r.c.ordinaryNativeWindows = nil
	proofs := 0
	r.c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error {
		proofs++
		return ErrRuntimeController
	}
	_ = r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil)
	if proofs == 0 {
		t.Fatal("missing native advice skipped ordinary proof")
	}
}
