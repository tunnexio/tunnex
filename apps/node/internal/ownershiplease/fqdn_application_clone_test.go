package ownershiplease

import (
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
	"github.com/tunnexio/tunnex/apps/node/internal/reconcile"
	"testing"
)

func TestFQDNApplicationPathSnapshotDoesNotAliasDesired(t *testing.T) {
	original := reconcile.DesiredState{Policy: &nodepolicy.Compiled{FQDNGenerations: []nodepolicy.FQDNGeneration{{ApplicationIPsecPath: &nodepolicy.FQDNApplicationIPsecPath{ConnectionID: "owned", ConfigurationRevision: 7}}}}}
	snapshot := cloneDesiredState(original)
	original.Policy.FQDNGenerations[0].ApplicationIPsecPath.ConfigurationRevision++
	if snapshot.Policy.FQDNGenerations[0].ApplicationIPsecPath.ConfigurationRevision != 7 {
		t.Fatal("mutable desired path changed snapshot")
	}
}
