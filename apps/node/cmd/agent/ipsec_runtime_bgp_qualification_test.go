package main

import (
	"context"
	"errors"
	"github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"testing"
)

func TestIPsecBGPQualificationRetriesFailedFreshPreflight(t *testing.T) {
	attached := false
	calls, attaches := 0, 0
	failure := errors.New("first failure")
	fresh := new(bgp.PreflightQualification)
	qualify := func(context.Context) (*bgp.PreflightQualification, error) {
		calls++
		if calls == 1 {
			return nil, failure
		}
		return fresh, nil
	}
	attach := func(q *bgp.PreflightQualification) error {
		attaches++
		if q != fresh {
			t.Fatal("receipt changed or reused")
		}
		return nil
	}
	stage, err := qualifyIPsecRuntimeBGP(context.Background(), &attached, qualify, attach)
	if stage != "bgp_preflight" || !errors.Is(err, failure) || attached || attaches != 0 {
		t.Fatal("failed preflight published attachment")
	}
	stage, err = qualifyIPsecRuntimeBGP(context.Background(), &attached, qualify, attach)
	if err != nil || stage != "bgp_attach" || !attached || calls != 2 || attaches != 1 {
		t.Fatal("later poll did not qualify freshly")
	}
	_, err = qualifyIPsecRuntimeBGP(context.Background(), &attached, qualify, attach)
	if err != nil || calls != 2 || attaches != 1 {
		t.Fatal("attached qualification reprobed")
	}
}
func TestIPsecBGPQualificationAttachFailureRequiresFreshReceipt(t *testing.T) {
	attached := false
	receipts := []*bgp.PreflightQualification{new(bgp.PreflightQualification), new(bgp.PreflightQualification)}
	calls, attaches := 0, 0
	qualify := func(context.Context) (*bgp.PreflightQualification, error) {
		q := receipts[calls]
		calls++
		return q, nil
	}
	attach := func(q *bgp.PreflightQualification) error {
		if q != receipts[attaches] {
			t.Fatal("cached failed receipt")
		}
		attaches++
		if attaches == 1 {
			return errors.New("attach refused")
		}
		return nil
	}
	if stage, err := qualifyIPsecRuntimeBGP(context.Background(), &attached, qualify, attach); stage != "bgp_attach" || err == nil || attached {
		t.Fatal("failed attach published")
	}
	if _, err := qualifyIPsecRuntimeBGP(context.Background(), &attached, qualify, attach); err != nil || !attached || calls != 2 {
		t.Fatal("retry not fresh")
	}
}
func TestIPsecBGPQualificationCancellationNeverAttaches(t *testing.T) {
	for _, during := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		attached := false
		calls, attaches := 0, 0
		if !during {
			cancel()
		}
		qualify := func(context.Context) (*bgp.PreflightQualification, error) {
			calls++
			cancel()
			return new(bgp.PreflightQualification), nil
		}
		attach := func(*bgp.PreflightQualification) error { attaches++; return nil }
		_, err := qualifyIPsecRuntimeBGP(ctx, &attached, qualify, attach)
		if !errors.Is(err, context.Canceled) || attached || attaches != 0 || (!during && calls != 0) || (during && calls != 1) {
			t.Fatal("canceled qualification acquired attachment")
		}
	}
}
