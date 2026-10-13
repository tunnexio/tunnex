package ipsec

// ownedRuntimeChildren permits only the native-proven strongSwan handover:
// one current INSTALLED child plus one DELETING/DELETED child retaining its old inbound
// SPI. This does not grant authority or accept another IKE/generation.
func ownedRuntimeChildren(t EngineTunnel, d DaemonInventory) (*DaemonIKE, *DaemonChild, *DaemonChild, error) {
	var sa *DaemonIKE
	children := []*DaemonChild{}
	for i := range d.SAs {
		candidate := &d.SAs[i]
		if candidate.Name == engineName(t) {
			if sa != nil || candidate.LocalAddress != t.LocalAddress || candidate.RemoteAddress != t.RemoteAddress {
				return nil, nil, nil, ErrRuntimeController
			}
			sa = candidate
		}
		for j := range candidate.Children {
			c := &candidate.Children[j]
			if c.Name != engineName(t) && c.ReqID != t.ReqID && c.IfIDIn != t.XFRMID && c.IfIDOut != t.XFRMID {
				if candidate.Name == engineName(t) {
					return nil, nil, nil, ErrRuntimeController
				}
				continue
			}
			if candidate.Name != engineName(t) || c.Name != engineName(t) || c.ReqID != t.ReqID || c.IfIDIn != t.XFRMID || c.IfIDOut != t.XFRMID || !sameEnginePrefixes(c.LocalPrefixes, engineTransportPrefixes(t, true)) || !sameEnginePrefixes(c.RemotePrefixes, engineTransportPrefixes(t, false)) || c.State != "" && (c.Installed != (c.State == "INSTALLED")) {
				return nil, nil, nil, ErrRuntimeController
			}
			children = append(children, c)
		}
	}
	if len(children) > 2 {
		return nil, nil, nil, ErrRuntimeController
	}
	if len(children) == 0 {
		return sa, nil, nil, nil
	}
	if len(children) == 1 {
		return sa, children[0], nil, nil
	}
	var active, retired *DaemonChild
	for _, c := range children {
		if c.Installed && c.State == "INSTALLED" {
			if active != nil {
				return nil, nil, nil, ErrRuntimeController
			}
			active = c
		} else if !c.Installed && (c.State == "DELETING" || c.State == "DELETED") {
			if retired != nil {
				return nil, nil, nil, ErrRuntimeController
			}
			retired = c
		} else {
			return nil, nil, nil, ErrRuntimeController
		}
	}
	if active == nil || retired == nil || active.UniqueID == 0 || retired.UniqueID == 0 || active.UniqueID == retired.UniqueID || active.SPIIn == 0 || active.SPIOut == 0 || retired.SPIIn == 0 || retired.SPIOut == 0 || active.SPIIn == retired.SPIIn || active.SPIOut == retired.SPIOut {
		return nil, nil, nil, ErrRuntimeController
	}
	return sa, active, retired, nil
}

func ownedRuntimeSPIStates(t EngineTunnel, active, retired *DaemonChild, x XFRMInventory) (int, int, error) {
	in, out, oldIn, oldOut := 0, 0, 0, 0
	for _, s := range x.States {
		if s.IfID != t.XFRMID && s.ReqID != t.ReqID {
			continue
		}
		if s.IfID != t.XFRMID || s.ReqID != t.ReqID {
			return 0, 0, ErrRuntimeController
		}
		if s.Source == t.LocalAddress && s.Destination == t.RemoteAddress && (s.Direction == "" || s.Direction == "out") {
			if active == nil || s.SPI == active.SPIOut {
				out++
			} else if retired != nil && s.SPI == retired.SPIOut {
				oldOut++
			} else {
				return 0, 0, ErrRuntimeController
			}
		} else if s.Source == t.RemoteAddress && s.Destination == t.LocalAddress && (s.Direction == "" || s.Direction == "in") {
			if active == nil || s.SPI == active.SPIIn {
				in++
			} else if retired != nil && s.SPI == retired.SPIIn {
				oldIn++
			} else {
				return 0, 0, ErrRuntimeController
			}
		} else {
			return 0, 0, ErrRuntimeController
		}
	}
	if in > 1 || out > 1 || oldIn > 1 || oldOut > 1 || retired != nil && (in != 1 || out != 1 || oldIn != 1) {
		return 0, 0, ErrRuntimeController
	}
	return in, out, nil
}
