package main

import (
	"context"
	"sync/atomic"
	"time"
)

type policyReportStatusSource interface {
	AppliedStatus() (int, string, time.Time, error)
	RefusedVersion() int
	ConntrackFlushFailing() bool
	EndpointsUnavailable() bool
}

// policyReportState contains actual outcomes carried by the capability report,
// never the desired policy. Identical fetches must not create report/watch loops.
type policyReportState struct {
	version                   int
	hash                      string
	failingSince              time.Time
	applyError                string
	refusedVersion            int
	egressNAT, egressIPv6     bool
	conntrackFlushUnavailable bool
	k8sEndpointsUnavailable   bool
}

func boundedPolicyApplyError(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if len(message) > 300 {
		message = message[:300]
	}
	return message
}

func snapshotPolicyReportState(source policyReportStatusSource, egressNAT, egressIPv6 *atomic.Bool) policyReportState {
	v, h, failingSince, applyErr := source.AppliedStatus()
	return policyReportState{
		version: v, hash: h, failingSince: failingSince,
		applyError: boundedPolicyApplyError(applyErr), refusedVersion: source.RefusedVersion(),
		egressNAT: egressNAT.Load(), egressIPv6: egressIPv6.Load(),
		conntrackFlushUnavailable: source.ConntrackFlushFailing(),
		k8sEndpointsUnavailable:   source.EndpointsUnavailable(),
	}
}

// reconcileWithPolicyReportWake snapshots before SetPolicy as well as apply, so
// refusals and failed applies are reported without claiming the desired hash.
// The wake coalesces while the sole report producer is already sending.
func reconcileWithPolicyReportWake(source policyReportStatusSource, egressNAT, egressIPv6 *atomic.Bool, wake chan<- struct{}, apply func() error) error {
	before := snapshotPolicyReportState(source, egressNAT, egressIPv6)
	err := apply()
	if before != snapshotPolicyReportState(source, egressNAT, egressIPv6) {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
	return err
}

// runReportLoop keeps every HTTP report serialized, including retries
// after startup. A changed outcome can interrupt backoff, but never an in-flight
// report; its buffered wake is consumed after that report finishes.
func runReportLoop(ctx context.Context, wake <-chan struct{}, every time.Duration, report func(context.Context) bool) {
	const retryFloor = time.Second
	const retryCeiling = 30 * time.Second
	backoff := retryFloor
	var ticker *time.Ticker
	var periodic <-chan time.Time
	defer func() {
		if ticker != nil {
			ticker.Stop()
		}
	}()
	for {
		if ctx.Err() != nil {
			return
		}
		ok := report(ctx)
		if ctx.Err() != nil {
			return
		}
		if ok {
			backoff = retryFloor
			if ticker == nil {
				// Preserve startup behavior: periodic reporting begins only after
				// the first successful report.
				ticker = time.NewTicker(every)
				periodic = ticker.C
			}
			select {
			case <-ctx.Done():
				return
			case <-wake:
			case <-periodic:
			}
			continue
		}
		retry := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			retry.Stop()
			return
		case <-wake:
		case <-retry.C:
			if backoff < retryCeiling {
				backoff *= 2
				if backoff > retryCeiling {
					backoff = retryCeiling
				}
			}
		}
		retry.Stop()
	}
}
