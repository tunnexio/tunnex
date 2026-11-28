package aigateway

// InternalEndpoints manages the internal AI endpoint served by gateways
// (AI-KEYS-1 phase 2).
type InternalEndpoints struct {
	w *Workloads
}

func NewInternalEndpoints(w *Workloads, keys *StaticKeys) *InternalEndpoints {
	return &InternalEndpoints{w: w}
}
