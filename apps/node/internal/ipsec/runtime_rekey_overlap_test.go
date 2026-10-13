package ipsec

import "testing"

// Synthetic exact ownership documents current refusal, not real rekey or cloud loss.
func TestRuntimeOwnedCHILDOverlapCurrentlyRefuses(t *testing.T) {
	e, d, k, x := runtimeProofFixture()
	if got := runtimeTunnelStatuses(e, d, k, x); got != [2]string{"up", "up"} {
		t.Fatal("baseline", got)
	}
	next := d.SAs[0].Children[0]
	next.UniqueID += 100
	next.SPIIn += 1000
	next.SPIOut += 1000
	d.SAs[0].Children = append(d.SAs[0].Children, next)
	out, in := x.States[0], x.States[1]
	out.SPI = next.SPIOut
	in.SPI = next.SPIIn
	x.States = append(x.States, out, in)
	if got := runtimeTunnelStatuses(e, d, k, x); got != [2]string{"unknown", "up"} {
		t.Fatal("overlap", got)
	}
	if runtimeInventoryMatches(e, d, k, x) == nil {
		t.Fatal("current proof accepted overlap")
	}
	d.SAs[0].Children = []DaemonChild{next}
	x.States = append(x.States[2:4], out, in)
	if got := runtimeTunnelStatuses(e, d, k, x); got != [2]string{"up", "up"} {
		t.Fatal("new pair", got)
	}
	if err := runtimeInventoryMatches(e, d, k, x); err != nil {
		t.Fatal("new pair proof", err)
	}
	foreign := out
	foreign.SPI++
	x.States = append(x.States, foreign)
	if got := runtimeTunnelStatuses(e, d, k, x); got[0] != "unknown" {
		t.Fatal("foreign SPI", got)
	}
	if runtimeInventoryMatches(e, d, k, x) == nil {
		t.Fatal("unwitnessed SPI accepted")
	}
}

func rekeyHandoverFixture() (RuntimeJournalEntry, DaemonInventory, KernelInventory, XFRMInventory) {
	e, d, k, x := runtimeProofFixture()
	old := d.SAs[0].Children[0]
	old.State = "DELETED"
	old.Installed = false
	next := old
	next.UniqueID += 100
	next.SPIIn += 1000
	next.SPIOut += 1000
	next.State = "INSTALLED"
	next.Installed = true
	d.SAs[0].Children = []DaemonChild{old, next}
	out, in := x.States[0], x.States[1]
	out.SPI = next.SPIOut
	in.SPI = next.SPIIn
	// Native shape: original inbound retained, original outbound removed.
	x.States = append(x.States[1:], out, in)
	return e, d, k, x
}
func TestRuntimeNativeDeletedCHILDHandover(t *testing.T) {
	e, d, k, x := rekeyHandoverFixture()
	if got := runtimeTunnelStatuses(e, d, k, x); got != [2]string{"up", "up"} {
		t.Fatal("native handover", got)
	}
	if err := runtimeInventoryMatches(e, d, k, x); err != nil {
		t.Fatal("ownership proof", err)
	}
	sa, active, _, err := ownedRuntimeChildren(e.Engines[0], d)
	if err != nil || sa == nil || active.UniqueID != 101 {
		t.Fatal("active pair selection")
	}
	for name, mutate := range map[string]func(*DaemonInventory, *XFRMInventory){
		"unrelated child in owned IKE": func(d *DaemonInventory, _ *XFRMInventory) {
			v := d.SAs[1].Children[0]
			d.SAs[0].Children = append(d.SAs[0].Children, v)
		},
		"two deleted": func(d *DaemonInventory, _ *XFRMInventory) {
			d.SAs[0].Children[1].State = "DELETED"
			d.SAs[0].Children[1].Installed = false
		},
		"two installed": func(d *DaemonInventory, _ *XFRMInventory) {
			d.SAs[0].Children[0].State = "INSTALLED"
			d.SAs[0].Children[0].Installed = true
		},
		"unknown old state": func(d *DaemonInventory, _ *XFRMInventory) { d.SAs[0].Children[0].State = "REKEYING" },
		"untyped old state": func(d *DaemonInventory, _ *XFRMInventory) { d.SAs[0].Children[0].State = "" },
		"duplicate IKE":     func(d *DaemonInventory, _ *XFRMInventory) { d.SAs = append(d.SAs, d.SAs[0]) },
		"duplicate child ID": func(d *DaemonInventory, _ *XFRMInventory) {
			d.SAs[0].Children[1].UniqueID = d.SAs[0].Children[0].UniqueID
		},
		"foreign child reqid":       func(d *DaemonInventory, _ *XFRMInventory) { d.SAs[0].Children[0].ReqID++ },
		"partial active pair":       func(_ *DaemonInventory, x *XFRMInventory) { x.States = x.States[:len(x.States)-1] },
		"unknown SPI":               func(_ *DaemonInventory, x *XFRMInventory) { v := x.States[0]; v.SPI++; x.States = append(x.States, v) },
		"duplicate retained SPI":    func(_ *DaemonInventory, x *XFRMInventory) { x.States = append(x.States, x.States[0]) },
		"foreign retained endpoint": func(_ *DaemonInventory, x *XFRMInventory) { x.States[0].Source = e.Engines[0].LocalAddress },
	} {
		t.Run(name, func(t *testing.T) {
			e, d, k, x := rekeyHandoverFixture()
			mutate(&d, &x)
			if got := runtimeTunnelStatuses(e, d, k, x); got[0] != "unknown" {
				t.Fatal("unsafe overlap", got)
			}
			if runtimeInventoryMatches(e, d, k, x) == nil {
				t.Fatal("unsafe proof")
			}
		})
	}
}

func TestRuntimeDeletedCHILDFullRetainedPair(t *testing.T) {
	e, d, k, x := rekeyHandoverFixture()
	oldOut := x.States[len(x.States)-2]
	oldOut.SPI = d.SAs[0].Children[0].SPIOut
	x.States = append(x.States, oldOut)
	if got := runtimeTunnelStatuses(e, d, k, x); got != [2]string{"up", "up"} {
		t.Fatal(got)
	}
	if err := runtimeInventoryMatches(e, d, k, x); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeNativeDeletingCHILDHandover(t *testing.T) {
	e, d, k, x := rekeyHandoverFixture()
	d.SAs[0].Children[0].State = "DELETING"
	if got := runtimeTunnelStatuses(e, d, k, x); got != [2]string{"up", "up"} {
		t.Fatal(got)
	}
	if err := runtimeInventoryMatches(e, d, k, x); err != nil {
		t.Fatal(err)
	}
}
