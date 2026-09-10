package aigateway

import (
	"context"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
)

type nativeRanking struct {
	ID       string   `json:"id"`
	Requests *int64   `json:"total_requests"`
	Tokens   *int64   `json:"total_tokens"`
	Cost     *float64 `json:"total_cost"`
}
type nativeBucket struct {
	Timestamp time.Time          `json:"timestamp"`
	Count     *int64             `json:"count"`
	Success   *int64             `json:"success"`
	Error     *int64             `json:"error"`
	Cancelled *int64             `json:"cancelled"`
	Tokens    *int64             `json:"total_tokens"`
	Cost      *float64           `json:"total_cost"`
	Models    map[string]float64 `json:"by_model"`
}
type nativeHistogram struct {
	Buckets []nativeBucket `json:"buckets"`
	Size    int64          `json:"bucket_size_seconds"`
}
type EngineDashboard struct {
	Usage     Usage
	Dashboard api.AIUsageDashboard
	Keys      map[string]api.AIUsageAttribution
}

func emptyDashboard() api.AIUsageDashboard {
	return api.AIUsageDashboard{Daily: []api.AIUsageDay{}, Models: []api.AIUsageModel{}, Teams: []api.AIUsageAttribution{}, Agents: []api.AIUsageAttribution{}}
}
func countOK(v *int64) bool { return v != nil && *v >= 0 }
func addCount(dst *int64, v int64) bool {
	if v < 0 || *dst > math.MaxInt64-v {
		return false
	}
	*dst += v
	return true
}
func addCost(dst *float64, v float64) bool {
	if !validEngineCost(v) || !validEngineCost(*dst+v) {
		return false
	}
	*dst += v
	return true
}

// Dashboard performs a fixed eight scoped aggregate reads under one deadline.
// Native reads are independent observations, not an atomic billing snapshot.
func (e *Engine) Dashboard(ctx context.Context, ids []string, from, to time.Time) (EngineDashboard, error) {
	out := EngineDashboard{Dashboard: emptyDashboard(), Keys: map[string]api.AIUsageAttribution{}}
	if len(ids) > maxAIUsageBindings || !validEngineList(ids, false) || from.IsZero() || to.IsZero() || !to.After(from) || to.Sub(from) > 31*24*time.Hour {
		return out, errEngineScope
	}
	allowed := map[string]bool{}
	for _, id := range ids {
		if allowed[id] {
			return out, errEngineScope
		}
		allowed[id] = true
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var err error
	out.Usage, err = e.Usage(ctx, ids, from, to)
	if err != nil {
		return EngineDashboard{}, err
	}
	q := url.Values{"virtual_key_ids": {strings.Join(ids, ",")}, "start_time": {from.UTC().Format(time.RFC3339Nano)}, "end_time": {to.UTC().Format(time.RFC3339Nano)}}
	days := map[string]*api.AIUsageDay{}
	models := map[string]float64{}
	for _, metric := range []string{"requests", "tokens", "cost", "missing"} {
		path := "/api/logs/histogram"
		if metric == "tokens" || metric == "cost" {
			path += "/" + metric
		}
		if metric == "missing" {
			q.Set("missing_cost_only", "true")
		} else {
			q.Del("missing_cost_only")
		}
		var h nativeHistogram
		if _, err = e.request(ctx, http.MethodGet, path, q, nil, &h); err != nil || h.Buckets == nil || h.Size <= 0 || h.Size > 86400 || 86400%h.Size != 0 || len(h.Buckets) > 2000 {
			return EngineDashboard{}, errEngine
		}
		seen := map[int64]bool{}
		for _, b := range h.Buckets {
			ts := b.Timestamp.Unix()
			first := (from.Unix() / h.Size) * h.Size
			if b.Timestamp.IsZero() || b.Timestamp.Nanosecond() != 0 || ts%h.Size != 0 || ts < first || ts > to.Unix() || seen[ts] {
				return EngineDashboard{}, errEngine
			}
			seen[ts] = true
			date := b.Timestamp.UTC().Format("2006-01-02")
			d := days[date]
			if d == nil {
				d = &api.AIUsageDay{Date: date}
				days[date] = d
			}
			switch metric {
			case "requests":
				if !countOK(b.Count) || !countOK(b.Success) || !countOK(b.Error) || !countOK(b.Cancelled) || !addCount(&d.Requests, *b.Count) || !addCount(&out.Dashboard.SuccessfulRequests, *b.Success) || !addCount(&out.Dashboard.FailedRequests, *b.Error) || !addCount(&out.Dashboard.CancelledRequests, *b.Cancelled) {
					return EngineDashboard{}, errEngine
				}
			case "missing":
				if !countOK(b.Count) || !addCount(&d.UncostedRequests, *b.Count) {
					return EngineDashboard{}, errEngine
				}
			case "tokens":
				if !countOK(b.Tokens) || !addCount(&d.Tokens, *b.Tokens) {
					return EngineDashboard{}, errEngine
				}
			case "cost":
				if b.Cost == nil || b.Models == nil || len(b.Models) > 2048 || !addCost(&d.Cost, *b.Cost) {
					return EngineDashboard{}, errEngine
				}
				for model, cost := range b.Models {
					if !engineModel.MatchString(model) {
						return EngineDashboard{}, errEngine
					}
					v := models[model]
					if !addCost(&v, cost) {
						return EngineDashboard{}, errEngine
					}
					models[model] = v
				}
			}
		}
	}
	q.Del("missing_cost_only")
	q.Set("dimension", "virtual_key")
	q.Set("limit", "65")
	for _, missing := range []bool{false, true} {
		if missing {
			q.Set("missing_cost_only", "true")
		}
		var result struct {
			Rankings  []nativeRanking `json:"rankings"`
			Dimension string          `json:"dimension"`
		}
		if _, err = e.request(ctx, http.MethodGet, "/api/logs/rankings/by-dimension", q, nil, &result); err != nil || result.Rankings == nil || result.Dimension != "virtual_key" || len(result.Rankings) > len(ids) {
			return EngineDashboard{}, errEngine
		}
		seen := map[string]bool{}
		for _, r := range result.Rankings {
			if !allowed[r.ID] || seen[r.ID] || !countOK(r.Requests) || !countOK(r.Tokens) || r.Cost == nil || !validEngineCost(*r.Cost) {
				return EngineDashboard{}, errEngine
			}
			seen[r.ID] = true
			v := out.Keys[r.ID]
			if missing {
				v.UncostedRequests = *r.Requests
			} else {
				v.Requests = *r.Requests
				v.Tokens = *r.Tokens
				v.Cost = *r.Cost
			}
			out.Keys[r.ID] = v
		}
	}
	for _, d := range days {
		out.Dashboard.Daily = append(out.Dashboard.Daily, *d)
	}
	sort.Slice(out.Dashboard.Daily, func(i, j int) bool { return out.Dashboard.Daily[i].Date < out.Dashboard.Daily[j].Date })
	for name, cost := range models {
		out.Dashboard.Models = append(out.Dashboard.Models, api.AIUsageModel{Name: name, Cost: cost})
	}
	sort.Slice(out.Dashboard.Models, func(i, j int) bool {
		a, b := out.Dashboard.Models[i], out.Dashboard.Models[j]
		if a.Cost != b.Cost {
			return a.Cost > b.Cost
		}
		return a.Name < b.Name
	})
	return out, nil
}
