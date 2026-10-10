package fqdnrpc

import (
	"context"
	"sync"
	"time"
)

// LookupTiming contains bounded scalars only. It belongs to one callback; no
// request identity, DNS input, answer, or shared registry is retained.
type LookupPhaseTiming struct {
	Count       int   `json:"count"`
	Successful  int   `json:"successful"`
	Refused     int   `json:"refused"`
	TotalMillis int64 `json:"total_ms"`
	MaxMillis   int64 `json:"max_ms"`
}
type LookupTiming struct {
	TransportTimingObserved    bool              `json:"transport_timing_observed"`
	AttemptedExchanges         int               `json:"attempted_exchanges"`
	CompletedExchanges         int               `json:"completed_exchanges"`
	BeforeProof                LookupPhaseTiming `json:"before_proof"`
	AfterProof                 LookupPhaseTiming `json:"after_proof"`
	Socket                     LookupPhaseTiming `json:"socket"`
	ReductionObserved          bool              `json:"reduction_observed"`
	RemainingAtReductionMillis int64             `json:"remaining_at_reduction_ms"`
	Outcome                    string            `json:"outcome"`
}
type LookupTimingAccumulator struct {
	mu    sync.Mutex
	value LookupTiming
}
type lookupTimingContextKey struct{}

func WithLookupTiming(ctx context.Context) (context.Context, *LookupTimingAccumulator) {
	a := &LookupTimingAccumulator{value: LookupTiming{Outcome: "not_observed"}}
	return context.WithValue(ctx, lookupTimingContextKey{}, a), a
}
func lookupTiming(ctx context.Context) *LookupTimingAccumulator {
	a, _ := ctx.Value(lookupTimingContextKey{}).(*LookupTimingAccumulator)
	return a
}

const lookupExchangeCeiling = 8 * 9 * 2

func lookupBoundMillis(d time.Duration, signed bool) int64 {
	v := d.Milliseconds()
	if v > 300000 {
		return 300000
	}
	if signed && v < -300000 {
		return -300000
	}
	if !signed && v < 0 {
		return 0
	}
	return v
}

// RecordLookupPhase accepts only fixed stages; unknown labels are ignored.
func RecordLookupPhase(ctx context.Context, phase string, elapsed time.Duration, success bool) {
	a := lookupTiming(ctx)
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var p *LookupPhaseTiming
	switch phase {
	case "before":
		p = &a.value.BeforeProof
	case "after":
		p = &a.value.AfterProof
	case "socket":
		p = &a.value.Socket
	default:
		return
	}
	if p.Count >= lookupExchangeCeiling {
		return
	}
	p.Count++
	if success {
		p.Successful++
	} else {
		p.Refused++
	}
	ms := lookupBoundMillis(elapsed, false)
	p.TotalMillis += ms
	if p.TotalMillis > 300000 {
		p.TotalMillis = 300000
	}
	if ms > p.MaxMillis {
		p.MaxMillis = ms
	}
}
func RecordLookupExchange(ctx context.Context, success bool) {
	a := lookupTiming(ctx)
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.value.AttemptedExchanges >= lookupExchangeCeiling {
		return
	}
	a.value.TransportTimingObserved = true
	a.value.AttemptedExchanges++
	if success {
		a.value.CompletedExchanges++
	}
}
func finishLookupTiming(ctx context.Context, err error) {
	a := lookupTiming(ctx)
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.value.ReductionObserved = true
	a.value.Outcome = "success"
	if err != nil {
		a.value.Outcome = "resolver_failure"
	}
	if ctx.Err() == context.DeadlineExceeded {
		a.value.Outcome = "deadline"
	} else if ctx.Err() != nil {
		a.value.Outcome = "canceled"
	}
	if d, ok := ctx.Deadline(); ok {
		a.value.RemainingAtReductionMillis = lookupBoundMillis(time.Until(d), true)
	}
}
func (a *LookupTimingAccumulator) Snapshot() LookupTiming {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.value
}
