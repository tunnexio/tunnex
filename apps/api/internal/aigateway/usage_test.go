package aigateway

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

type usageEngineFixture struct {
	PolicyEngine
	price func(context.Context, string, string) (Price, error)
	usage func(context.Context, []string, time.Time, time.Time) (Usage, error)
}

func (f usageEngineFixture) Price(ctx context.Context, provider, model string) (Price, error) {
	return f.price(ctx, provider, model)
}
func (f usageEngineFixture) Usage(ctx context.Context, ids []string, from, to time.Time) (Usage, error) {
	return f.usage(ctx, ids, from, to)
}

type usageRowsFixture struct {
	pgx.Rows
	ids   []string
	index int
	err   error
}

func (r *usageRowsFixture) Next() bool {
	if r.index >= len(r.ids) {
		return false
	}
	r.index++
	return true
}
func (r *usageRowsFixture) Scan(dest ...any) error {
	if len(dest) != 1 || r.index < 1 {
		return errors.New("invalid fixture scan")
	}
	*(dest[0].(*string)) = r.ids[r.index-1]
	return nil
}
func (r *usageRowsFixture) Err() error { return r.err }
func (r *usageRowsFixture) Close()     {}

type usageTxFixture struct {
	pgx.Tx
	query func(context.Context, string, ...any) (pgx.Rows, error)
}

func (tx usageTxFixture) Query(ctx context.Context, query string, args ...any) (pgx.Rows, error) {
	return tx.query(ctx, query, args...)
}
func usageStatus(err error) int {
	if err == nil {
		return 0
	}
	var e *apierr.Error
	if errors.As(err, &e) {
		return e.Status
	}
	return -1
}

func TestCostAdmissionRefusesUnknownOrIncompleteNativeUsage(t *testing.T) {
	org, team := uuid.New(), uuid.New()
	one := 1.0
	zero := 0.0
	for _, tc := range []struct {
		name     string
		price    Price
		priceErr error
		usage    Usage
		usageErr error
		ids      []string
		dbErr    error
		want     int
	}{
		{name: "known below", price: Price{true, &one, &one}, usage: Usage{TotalRequests: 1, TotalCost: .25}, ids: []string{"old-team-key", "current-team-key"}},
		{name: "known zero-priced", price: Price{true, &zero, &zero}, usage: Usage{}, ids: []string{"key"}},
		{name: "unknown", price: Price{}, ids: []string{"key"}, want: 403},
		{name: "missing price field", price: Price{Known: true, InputCostPerToken: &one}, ids: []string{"key"}, want: 403},
		{name: "pricing unavailable", priceErr: errors.New("private pricing cause"), ids: []string{"key"}, want: 503},
		{name: "native stats unavailable", price: Price{true, &one, &one}, usageErr: errors.New("private stats cause"), ids: []string{"key"}, want: 503},
		{name: "uncosted native requests", price: Price{true, &one, &one}, usage: Usage{TotalRequests: 1, UncostedRequests: 1}, ids: []string{"key"}, want: 503},
		{name: "invalid counts", price: Price{true, &one, &one}, usage: Usage{TotalRequests: -1}, ids: []string{"key"}, want: 503},
		{name: "invalid costs", price: Price{true, &one, &one}, usage: Usage{TotalCost: math.NaN()}, ids: []string{"key"}, want: 503},
		{name: "binding absent", price: Price{true, &one, &one}, want: 503},
		{name: "binding read fails", price: Price{true, &one, &one}, dbErr: errors.New("private database cause"), want: 503},
		{name: "at threshold", price: Price{true, &one, &one}, usage: Usage{TotalCost: 1}, ids: []string{"key"}, want: 403},
		{name: "above threshold", price: Price{true, &one, &one}, usage: Usage{TotalCost: 9}, ids: []string{"key"}, want: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			tx := usageTxFixture{query: func(_ context.Context, q string, args ...any) (pgx.Rows, error) {
				if args[0] != org || args[1].(*uuid.UUID) == nil || *args[1].(*uuid.UUID) != team || args[2].(*uuid.UUID) != nil {
					t.Error("cost attribution query escaped org/team scope")
				}
				return &usageRowsFixture{ids: tc.ids}, tc.dbErr
			}}
			p := &Policies{engine: usageEngineFixture{
				price: func(_ context.Context, provider, model string) (Price, error) {
					if provider != "openrouter" || model != "openai/gpt-4o-mini" {
						t.Error("exact native price scope incorrect")
					}
					return tc.price, tc.priceErr
				},
				usage: func(_ context.Context, ids []string, from, to time.Time) (Usage, error) {
					calls++
					if !sameEngineSet(ids, tc.ids) {
						t.Error("native IDs changed")
					}
					if from.Location() != time.UTC || from.Hour() != 0 || from.Minute() != 0 || from.Second() != 0 || from.Nanosecond() != 0 || to.Sub(from) > 24*time.Hour {
						t.Error("daily window is not UTC day")
					}
					return tc.usage, tc.usageErr
				},
			}}
			err := p.enforceCost(context.Background(), tx, org, team, "openrouter/openai/gpt-4o-mini", &one)
			if got := usageStatus(err); got != tc.want {
				t.Fatalf("status=%d want=%d err=%v", got, tc.want, err)
			}
			if len(tc.ids) == 0 && calls != 0 {
				t.Fatal("empty IDs reached native unfiltered stats")
			}
			if err != nil && strings.Contains(err.Error(), "private") {
				t.Fatal("native failure details leaked")
			}
		})
	}
}
func TestCostAdmissionNoLimitAndInvalidLimitsDoNotReadNative(t *testing.T) {
	var p *Policies
	if err := p.enforceCost(context.Background(), nil, uuid.Nil, uuid.Nil, "", nil); err != nil {
		t.Fatal("absent monetary policy should not query prices or usage")
	}
	for _, limit := range []float64{0, -1, 100001, math.NaN(), math.Inf(1)} {
		if got := usageStatus(p.enforceCost(context.Background(), nil, uuid.New(), uuid.New(), "openrouter/model", &limit)); got != 400 {
			t.Fatalf("invalid limit status=%d", got)
		}
	}
}
func TestCostAdmissionSoftThresholdDoesNotReserveConcurrentSpend(t *testing.T) {
	const count = 8
	entered := make(chan struct{}, count)
	release := make(chan struct{})
	var exceeded atomic.Bool
	limit := 1.0
	org, team := uuid.New(), uuid.New()
	p := &Policies{engine: usageEngineFixture{price: func(context.Context, string, string) (Price, error) { return Price{true, &limit, &limit}, nil }, usage: func(context.Context, []string, time.Time, time.Time) (Usage, error) {
		if exceeded.Load() {
			return Usage{TotalCost: 1}, nil
		}
		entered <- struct{}{}
		<-release
		return Usage{}, nil
	}}}
	done := make(chan error, count)
	for i := 0; i < count; i++ {
		go func() {
			tx := usageTxFixture{query: func(context.Context, string, ...any) (pgx.Rows, error) {
				return &usageRowsFixture{ids: []string{"team-key"}}, nil
			}}
			done <- p.enforceCost(context.Background(), tx, org, team, "openrouter/model", &limit)
		}()
	}
	for i := 0; i < count; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			close(release)
			t.Fatal("concurrent observational reads did not proceed")
		}
	}
	close(release)
	for i := 0; i < count; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	exceeded.Store(true)
	tx := usageTxFixture{query: func(context.Context, string, ...any) (pgx.Rows, error) {
		return &usageRowsFixture{ids: []string{"team-key"}}, nil
	}}
	if got := usageStatus(p.enforceCost(context.Background(), tx, org, team, "openrouter/model", &limit)); got != 403 {
		t.Fatalf("subsequent charged observation status=%d", got)
	}
}
func TestBindingUsageIDsRejectsOverflowAndUnsafeIDs(t *testing.T) {
	ids := make([]string, 65)
	for i := range ids {
		ids[i] = fmt.Sprintf("key-%d", i)
	}
	for _, bad := range [][]string{ids, {""}, {"*"}, {"one,two"}, {"duplicate", "duplicate"}} {
		tx := usageTxFixture{query: func(context.Context, string, ...any) (pgx.Rows, error) { return &usageRowsFixture{ids: bad}, nil }}
		if _, err := bindingUsageIDs(context.Background(), tx, uuid.New(), nil, nil); err == nil {
			t.Fatal("invalid retained key scope accepted")
		}
	}
}
func TestUsageWindowDefaultsUTCAndBounds(t *testing.T) {
	now := time.Date(2026, 9, 7, 6, 30, 0, 0, time.FixedZone("fixture", 19800))
	from, to, err := usageWindow(time.Time{}, time.Time{}, now)
	if err != nil || !from.Equal(time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)) || !to.Equal(now) {
		t.Fatalf("wrong default UTC window %v %v %v", from, to, err)
	}
	for _, duration := range []time.Duration{0, -time.Second, 31*24*time.Hour + time.Nanosecond} {
		if _, _, err := usageWindow(now.Add(-duration), now, now); err == nil {
			t.Fatalf("invalid window accepted %v", duration)
		}
	}
	if _, _, err := usageWindow(now.Add(-31*24*time.Hour), now, now); err != nil {
		t.Fatal(err)
	}
}
