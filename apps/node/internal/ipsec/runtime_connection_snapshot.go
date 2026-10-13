package ipsec

// Readers still parse and validate the entire namespace. Select every tuple
// touching either ownership key, so partial collisions cannot disappear during
// a comparison. Complete independent ownership validation precedes comparison.
func connectionXFRMSnapshot(e RuntimeJournalEntry, x XFRMInventory) XFRMInventory {
	out := XFRMInventory{Namespace: x.Namespace}
	for _, s := range x.States {
		for _, t := range e.Engines {
			if s.IfID == t.XFRMID || s.ReqID == t.ReqID {
				out.States = append(out.States, s)
				break
			}
		}
	}
	for _, p := range x.Policies {
		for _, t := range e.Engines {
			if p.IfID == t.XFRMID || p.ReqID == t.ReqID {
				out.Policies = append(out.Policies, p)
				break
			}
		}
	}
	return out
}
func connectionKernelSnapshot(e RuntimeJournalEntry, k KernelInventory) KernelInventory {
	out := KernelInventory{Namespace: k.Namespace}
	for _, l := range k.Links {
		for _, o := range e.Observed {
			if l.Name == o.InterfaceName || l.Index == o.InterfaceIndex || l.XFRMID == o.XFRMID {
				out.Links = append(out.Links, l)
				break
			}
		}
	}
	for _, r := range k.Routes {
		relevant := false
		for i, o := range e.Observed {
			relevant = relevant || r.OutputInterface == o.InterfaceIndex
			for _, p := range e.Allocation.Tunnels[i].RemotePrefixes {
				relevant = relevant || r.Destination.Overlaps(p)
			}
		}
		if relevant {
			out.Routes = append(out.Routes, r)
		}
	}
	return out
}
