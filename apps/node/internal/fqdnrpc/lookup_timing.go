package fqdnrpc

import (
	"context"
	"sync"
	"time"
)

// LookupTiming contains bounded scalars only. It belongs to one callback; no
// request identity, DNS input, answer, or shared registry is retained.
// SummedMillis sums independent phase durations across concurrent endpoints;
// it is not lookup wall time. Count and outcome counts cover returned phases.
type LookupPhaseTiming struct {
	Count        int   `json:"count"`
	Successful   int   `json:"successful"`
	Refused      int   `json:"refused"`
	SummedMillis int64 `json:"summed_ms"`
	MaxMillis    int64 `json:"max_ms"`
}
type LookupTiming struct {
	// StatsSaturated means at least one counter/sample was capped or scalar clamped;
	// drained workers do not imply an uncapped measurement.
	StatsSaturated bool `json:"stats_saturated"`
	// ReturnedExchanges counts transport calls that returned, including refusals;
	// CompletedExchanges counts successful complete transport proof brackets.
	EndpointWorkersDrained     bool              `json:"endpoint_workers_drained"`
	TransportTimingObserved    bool              `json:"transport_timing_observed"`
	ReturnedExchanges          int               `json:"returned_exchanges"`
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

// Eight endpoints, nine CNAME steps, two record types, and one UDP→TCP retry.
const lookupExchangeCeiling = 8 * 9 * 2 * 2

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
		a.value.StatsSaturated = true
		return
	}
	p.Count++
	if success {
		p.Successful++
	} else {
		p.Refused++
	}
	ms := lookupBoundMillis(elapsed, false)
	if elapsed < 0 || elapsed.Milliseconds() > 300000 {
		a.value.StatsSaturated = true
	}
	p.SummedMillis += ms
	if p.SummedMillis > 300000 {
		p.SummedMillis = 300000
		a.value.StatsSaturated = true
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
	if a.value.ReturnedExchanges >= lookupExchangeCeiling {
		a.value.StatsSaturated = true
		return
	}
	a.value.TransportTimingObserved = true
	a.value.ReturnedExchanges++
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
	a.value.ReductionObserved = a.value.EndpointWorkersDrained
	a.value.Outcome = "success"
	if err != nil {
		a.value.Outcome = "resolver_failure"
	}
	if ctx.Err() == context.DeadlineExceeded {
		a.value.Outcome = "deadline"
	} else if ctx.Err() != nil {
		a.value.Outcome = "canceled"
	}
	if d, ok := ctx.Deadline(); ok && a.value.ReductionObserved {
		remaining := time.Until(d)
		if remaining.Milliseconds() > 300000 || remaining.Milliseconds() < -300000 {
			a.value.StatsSaturated = true
		}
		a.value.RemainingAtReductionMillis = lookupBoundMillis(remaining, true)
	}
}
func (a *LookupTimingAccumulator) Snapshot() LookupTiming {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.value
}

func markLookupWorkersDrained(ctx context.Context) {
	a := lookupTiming(ctx)
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.value.EndpointWorkersDrained = true
}
