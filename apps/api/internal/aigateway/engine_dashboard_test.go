package aigateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAIEngineDashboardScopedAggregates(t *testing.T) {
	for _, mode := range []string{"valid", "foreign", "duplicate", "negative", "missing-field", "wrong-time", "missing-array", "overflow"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
			to := from.Add(7 * 24 * time.Hour)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				q := r.URL.Query()
				if q.Get("virtual_key_ids") != "key-a" || q.Get("start_time") != from.Format(time.RFC3339Nano) || q.Get("end_time") != to.Format(time.RFC3339Nano) {
					t.Error("scope/window changed")
				}
				missing := q.Get("missing_cost_only") == "true"
				var response any
				switch r.URL.Path {
				case "/api/logs/stats":
					response = map[string]any{"total_requests": 2, "total_tokens": 12, "prompt_tokens": 7, "completion_tokens": 5, "total_cost": 0.25}
					if missing {
						response = map[string]any{"total_requests": 1}
					}
				case "/api/logs/rankings/by-dimension":
					if q.Get("dimension") != "virtual_key" || q.Get("limit") != "65" {
						t.Error("unbounded ranking")
					}
					rows := []map[string]any{{"id": "key-a", "total_requests": 2, "total_tokens": 12, "total_cost": 0.25}}
					if missing {
						rows[0]["total_requests"] = 1
					}
					if mode == "foreign" {
						rows[0]["id"] = "foreign"
					}
					if mode == "duplicate" {
						rows = append(rows, rows[0])
					}
					response = map[string]any{"dimension": "virtual_key", "rankings": rows}
				default:
					b := map[string]any{"timestamp": from, "count": 2, "success": 1, "error": 1, "cancelled": 0, "total_tokens": 12, "total_cost": 0.25, "by_model": map[string]float64{"openai/gpt-4o-mini": 0.25}}
					if missing {
						b["count"] = 1
					}
					if mode == "negative" {
						b["count"] = -1
					}
					if mode == "missing-field" {
						delete(b, "count")
					}
					if mode == "wrong-time" {
						b["timestamp"] = from.Add(-24 * time.Hour)
					}
					buckets := []map[string]any{b}
					if mode == "overflow" {
						b["count"] = int64(9223372036854775807)
						c := map[string]any{}
						for k, v := range b {
							c[k] = v
						}
						c["timestamp"] = from.Add(time.Hour)
						buckets = append(buckets, c)
					}
					response = map[string]any{"bucket_size_seconds": 3600, "buckets": buckets}
					if mode == "missing-array" {
						response = map[string]any{"bucket_size_seconds": 3600}
					}
				}
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer srv.Close()
			engine, err := NewEngine(srv.URL, "fixture-admin", "fixture-password")
			if err != nil {
				t.Fatal(err)
			}
			got, err := engine.Dashboard(context.Background(), []string{"key-a"}, from, to)
			if mode != "valid" {
				if err == nil {
					t.Fatal("invalid native result accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if calls != 8 || got.Usage.TotalRequests != 2 || len(got.Dashboard.Daily) != 1 || got.Dashboard.Daily[0].Requests != 2 || got.Dashboard.Daily[0].UncostedRequests != 1 || got.Keys["key-a"].UncostedRequests != 1 || got.Dashboard.FailedRequests != 1 {
				t.Fatalf("wrong scoped aggregate: calls=%d", calls)
			}
			raw, _ := json.Marshal(got.Dashboard)
			if strings.Contains(string(raw), "key-a") {
				t.Fatal("native key leaked")
			}
		})
	}
}
func TestAIEngineDashboardEmptyScopeAndCancellation(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; <-r.Context().Done() }))
	defer srv.Close()
	e, _ := NewEngine(srv.URL, "admin", "fixture")
	now := time.Now()
	if _, err := e.Dashboard(context.Background(), nil, now.Add(-time.Hour), now); err == nil || calls != 0 {
		t.Fatal("empty key scope accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := e.Dashboard(ctx, []string{"key"}, now.Add(-time.Hour), now); err == nil || time.Since(start) > time.Second {
		t.Fatal("caller cancellation not bounded")
	}
}
