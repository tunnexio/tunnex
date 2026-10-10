package main

import (
	"context"
	"errors"
	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"time"
)

// Only fixed categories and bounded durations; never request/response contents.
type fqdnRPCTiming struct {
	DispatchUTC             string `json:"dispatch_utc"`
	DeadlineRemainingMillis int64  `json:"deadline_remaining_ms"`
	StartDelayMillis        int64  `json:"start_delay_ms"`
	HandleMillis            int64  `json:"handle_ms"`
	Status                  string `json:"status"`
	Result                  string `json:"result"`
	ReportMillis            int64  `json:"report_ms"`
	Delivery                string `json:"delivery"`
	Context                 string `json:"context"`
}

func boundedFQDNMillis(d time.Duration, signed bool) int64 {
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

func timedFQDNResolve(ctx context.Context, node string, request fqdnrpc.Request, dispatch time.Time, enabled bool,
	handle func(context.Context, string, fqdnrpc.Request) fqdnrpc.Response,
	report func(context.Context, fqdnrpc.Response) error,
	now func() time.Time, emit func(fqdnRPCTiming)) (fqdnrpc.Response, error) {
	if !enabled {
		response := handle(ctx, node, request)
		return response, report(ctx, response)
	}
	start := now()
	response := handle(ctx, node, request)
	handled := now()
	err := report(ctx, response)
	finished := now()
	event := fqdnRPCTiming{DispatchUTC: dispatch.UTC().Format(time.RFC3339Nano), DeadlineRemainingMillis: boundedFQDNMillis(request.Deadline.Sub(dispatch), true), StartDelayMillis: boundedFQDNMillis(start.Sub(dispatch), false), HandleMillis: boundedFQDNMillis(handled.Sub(start), false), ReportMillis: boundedFQDNMillis(finished.Sub(handled), false), Status: "unknown", Result: "unknown", Delivery: "success", Context: "active"}
	switch response.Status {
	case fqdnrpc.StatusNoError:
		event.Status = "NOERROR"
	case fqdnrpc.StatusNXDomain:
		event.Status = "NXDOMAIN"
	case fqdnrpc.StatusServFail:
		event.Status = "SERVFAIL"
	}
	switch response.ErrorCode {
	case "":
		event.Result = "none"
	case "unsupported_version", "deadline_exceeded", "disconnected", "resolver_unavailable", "resolver_disagreement":
		event.Result = response.ErrorCode
	}
	if err != nil {
		event.Delivery = "failure"
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		event.Context = "deadline"
	} else if ctx.Err() != nil {
		event.Context = "canceled"
	}
	if emit != nil {
		emit(event)
	}
	return response, err
}
