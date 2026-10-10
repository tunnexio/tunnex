package ipsec

import (
	"github.com/google/uuid"
	"testing"
)

func otherRestartFixture() (RuntimeJournalEntry, RuntimeJournalEntry, DaemonInventory, KernelInventory, XFRMInventory) {
	e, d, k, x := runtimeProofFixture()
	e.Phase = RuntimeApplied
	e.Allocation.Namespace = x.Namespace
	k.Namespace = x.Namespace
	target := e
	target.DeliveryID = uuid.New()
	target.Allocation.ConnectionID = uuid.New()
	for i := range target.Engines {
		target.Engines[i].ReqID += 10000
		target.Engines[i].XFRMID += 10000
		target.Engines[i].TunnelID = uuid.New()
	}
	return target, e, d, k, x
}
func TestRestartOtherProviderExactTransport(t *testing.T) {
	target, e, d, k, x := otherRestartFixture()
	if !restartInventoryOwnedByOthers(target, []RuntimeJournalEntry{e}, d, k, x) {
		t.Fatal("exact independently owned static transport refused")
	}
	// Transport proof is selector/profile specific, not a static/BGP alias.
	for i := range e.Engines {
		e.Engines[i].BGP = true
	}
	if restartInventoryOwnedByOthers(target, []RuntimeJournalEntry{e}, d, k, x) {
		t.Fatal("BGP claimed static selectors")
	}
}
func TestRestartOthersRejectForeignPartialAndStale(t *testing.T) {
	for name, change := range map[string]func(*RuntimeJournalEntry, *RuntimeJournalEntry, *DaemonInventory, *KernelInventory, *XFRMInventory){
		"foreign SPI": func(_, _ *RuntimeJournalEntry, _ *DaemonInventory, _ *KernelInventory, x *XFRMInventory) {
			x.States[0].SPI++
		},
		"foreign policy": func(_, _ *RuntimeJournalEntry, _ *DaemonInventory, _ *KernelInventory, x *XFRMInventory) {
			x.Policies[0].TemplateSPI++
		},
		"partial pair": func(_, _ *RuntimeJournalEntry, _ *DaemonInventory, _ *KernelInventory, x *XFRMInventory) {
			x.States = x.States[1:]
		},
		"foreign extra": func(_, _ *RuntimeJournalEntry, _ *DaemonInventory, _ *KernelInventory, x *XFRMInventory) {
			s := x.States[0]
			s.IfID += 100
			s.ReqID += 100
			x.States = append(x.States, s)
		},
		"replacement interface": func(_, _ *RuntimeJournalEntry, _ *DaemonInventory, k *KernelInventory, _ *XFRMInventory) {
			k.Links[0].Index++
		},
		"wrong namespace": func(_, e *RuntimeJournalEntry, _ *DaemonInventory, _ *KernelInventory, _ *XFRMInventory) {
			e.Allocation.Namespace = "net:[999]"
		},
		"wrong phase": func(_, e *RuntimeJournalEntry, _ *DaemonInventory, _ *KernelInventory, _ *XFRMInventory) {
			e.Phase = RuntimeCleanupPending
		},
		"target collision": func(target, e *RuntimeJournalEntry, _ *DaemonInventory, _ *KernelInventory, _ *XFRMInventory) {
			target.Engines[0].ReqID = e.Engines[0].ReqID
		},
		"duplicate IKE": func(_, _ *RuntimeJournalEntry, d *DaemonInventory, _ *KernelInventory, _ *XFRMInventory) {
			d.SAs = append(d.SAs, d.SAs[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			target, e, d, k, x := otherRestartFixture()
			change(&target, &e, &d, &k, &x)
			if restartInventoryOwnedByOthers(target, []RuntimeJournalEntry{e}, d, k, x) {
				t.Fatal("unproven transport excluded")
			}
		})
	}
}
func TestRestartOthersKnownRekeyOnly(t *testing.T) {
	_, _, _, _, _ = otherRestartFixture()
	e, d, k, x := rekeyHandoverFixture()
	e.Phase = RuntimeApplied
	e.Allocation.Namespace = x.Namespace
	k.Namespace = x.Namespace
	target, _, _, _, _ := otherRestartFixture()
	if !restartInventoryOwnedByOthers(target, []RuntimeJournalEntry{e}, d, k, x) {
		t.Fatal("native-proven exact rekey union refused")
	}
	if restartInventoryOwnedByOthers(target, []RuntimeJournalEntry{e, e}, d, k, x) {
		t.Fatal("ambiguous journal claim accepted")
	}
}
