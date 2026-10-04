package apptransport

// Capacity contains aggregate gauges only; no bindings, identities or tokens.
type Capacity struct {
	Connections        int
	Active             int
	Ready              int
	PendingAdmissions  int
	AuthorityCallbacks int
	Closed             bool
	AdmissionSaturated uint64
}

func (b *Broker) Capacity() Capacity {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := Capacity{Connections: len(b.connections), PendingAdmissions: b.pendingCount, AuthorityCallbacks: len(b.authoritySlots), Closed: b.closed, AdmissionSaturated: b.admissionSaturated.Load()}
	for channel := range b.connections {
		if channel.claimed {
			out.Active++
		} else {
			out.Ready++
		}
	}
	return out
}
