// Package appaccess runs purpose-scoped origin checks on an enrolled gateway.
// It provides no browser listener, session authority, or publication mechanism.
package appaccess

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"github.com/tunnexio/tunnex/packages/apptransport/originpolicy"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"net/url"
	"sync"
	"time"
)

type Channel interface {
	Capability(context.Context) error
	Desired(context.Context) (control.AppDesired, error)
	Applied(context.Context, control.AppApplied) error
	Result(context.Context, control.AppCheckResult) error
}
type job struct {
	check      control.AppCheck
	assignment control.AppAssignment
	ctx        context.Context
	cancel     context.CancelFunc
}
type completion struct {
	job    job
	result control.AppCheckResult
}
type Runtime struct {
	Channel      Channel
	ControlHosts []string
	Logger       *slog.Logger
	Check        func(context.Context, control.AppAssignment) originpolicy.Result
	Interval     time.Duration
	Pool         *Pool
}

func New(client *control.AppAccessClient, logger *slog.Logger) *Runtime {
	r := &Runtime{Channel: client, ControlHosts: client.ControlHosts, Logger: logger, Interval: 2 * time.Second}
	r.Pool = NewPool(client, r.check)
	return r
}
func valid(a control.AppAssignment) bool {
	_, e1 := uuid.Parse(a.OrgID)
	_, e2 := uuid.Parse(a.GatewayID)
	_, e3 := uuid.Parse(a.AppID)
	_, e4 := uuid.Parse(a.Generation)
	d, e := hex.DecodeString(a.Digest)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || a.OrgID == uuid.Nil.String() || a.GatewayID == uuid.Nil.String() || a.AppID == uuid.Nil.String() || a.Generation == uuid.Nil.String() || a.Purpose != "origin_check" || a.Revision < 1 || e != nil || len(d) != 32 {
		return false
	}
	p, e := originpolicy.Normalize(a.AllowedDestinationCIDRs, a.OriginCAPEM)
	return e == nil && p.OriginCADigest == a.OriginCADigest
}
func matches(c control.AppCheck, a control.AppAssignment) bool {
	return c.OrgID == a.OrgID && c.GatewayID == a.GatewayID && c.AppID == a.AppID && c.Generation == a.Generation && c.Revision == a.Revision && c.Digest == a.Digest && c.Purpose == a.Purpose
}
func (r *Runtime) check(ctx context.Context, a control.AppAssignment) originpolicy.Result {
	if r.Check != nil {
		return r.Check(ctx, a)
	}
	ips := []netip.Addr{}
	for _, host := range r.ControlHosts {
		values, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if e != nil {
			return originpolicy.Result{Status: "origin_refused"}
		}
		ips = append(ips, values...)
	}
	p, e := originpolicy.Normalize(a.AllowedDestinationCIDRs, a.OriginCAPEM)
	if e != nil {
		return originpolicy.Result{Status: "origin_refused"}
	}
	return (originpolicy.Checker{ControlHosts: r.ControlHosts, ControlAddresses: ips}).Check(ctx, a.OriginURL, p)
}
func result(c control.AppCheck, v originpolicy.Result) control.AppCheckResult {
	out := control.AppCheckResult{RequestID: c.ID, Generation: c.Generation, AppID: c.AppID, Revision: c.Revision, Digest: c.Digest, Purpose: c.Purpose, DNSStatus: "pending", ConnectStatus: "pending", TLSStatus: "pending", ErrorCode: ""}
	stage := func(v string) string {
		if v == "ready" {
			return "passed"
		}
		if v == "failed" || v == "refused" {
			return "failed"
		}
		return "pending"
	}
	out.DNSStatus = stage(v.DNS)
	out.ConnectStatus = stage(v.Connect)
	out.TLSStatus = stage(v.TLS)
	if v.TLS == "not_required" {
		out.TLSStatus = "skipped"
	}
	switch v.Status {
	case "ready":
	case "dns_refused":
		out.ErrorCode = "dns_failed"
		if v.DNS == "refused" {
			out.ErrorCode = "target_refused"
		}
	case "origin_refused":
		out.ErrorCode = "target_refused"
	case "http_failed":
		out.ErrorCode = "http_failed"
	case "tls_refused":
		out.ErrorCode = "tls_failed"
	case "unreachable":
		out.ErrorCode = "connect_failed"
		if v.Connect == "ready" {
			out.ErrorCode = "connector_failed"
		}
	case "timeout":
		out.ErrorCode = "deadline_exceeded"
	case "cancelled":
		out.ErrorCode = "assignment_changed"
	default:
		out.ErrorCode = "connector_failed"
	}
	return out
}
func (r *Runtime) Run(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	queue := make(chan job, 32)
	done := make(chan completion, 40)
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case j := <-queue:
					v := r.check(j.ctx, j.assignment)
					j.cancel()
					select {
					case done <- completion{j, result(j.check, v)}:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	active := map[string]job{}
	completed := map[string]completion{}
	applied := map[string]string{}
	assignments := map[string]control.AppAssignment{}
	withdraw := func() {
		if r.Pool != nil {
			r.Pool.Sync(ctx, map[string]control.AppAssignment{}, nil)
		}
		for _, j := range active {
			j.cancel()
		}
		assignments = map[string]control.AppAssignment{}
		applied = map[string]string{}
	}
	defer func() {
		withdraw()
		cancel()
		workers.Wait()
		if r.Pool != nil {
			r.Pool.Close()
		}
	}()
	interval := r.Interval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	delay := interval
	capable := false
	var capabilityAt time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case c := <-done:
			delete(active, c.job.check.ID)
			if len(completed) < 64 {
				completed[c.job.check.ID] = c
			}
		case <-timer.C:
			pollctx, stop := context.WithTimeout(ctx, 10*time.Second)
			var e error
			if !capable || time.Since(capabilityAt) >= 10*time.Second {
				e = r.Channel.Capability(pollctx)
				capable = e == nil
				if capable {
					capabilityAt = time.Now()
				}
			}
			var desired control.AppDesired
			if e == nil {
				desired, e = r.Channel.Desired(pollctx)
			}
			stop()
			if e != nil {
				withdraw()
				capable = false
				delay *= 2
				if delay > 30*time.Second {
					delay = 30 * time.Second
				}
				timer.Reset(delay + time.Duration(rand.Int64N(int64(delay/4)+1)))
				continue
			}
			delay = interval
			if desired.ProtocolVersion != 1 || desired.Purpose != "origin_check" || desired.Withdrawn || len(desired.Assignments) > 64 || len(desired.Checks) > 8 {
				withdraw()
				timer.Reset(interval)
				continue
			}
			fresh := map[string]control.AppAssignment{}
			org, gateway := "", ""
			invalid := false
			for _, a := range desired.Assignments {
				if !valid(a) || (org != "" && (a.OrgID != org || a.GatewayID != gateway)) {
					invalid = true
					break
				}
				if _, dup := fresh[a.AppID]; dup {
					invalid = true
					break
				}
				org, gateway = a.OrgID, a.GatewayID
				fresh[a.AppID] = a
			}
			if invalid {
				withdraw()
				timer.Reset(interval)
				continue
			}
			assignments = fresh
			if r.Pool != nil {
				r.Pool.Sync(ctx, assignments, desired.Checks)
			}
			for id, j := range active {
				a, ok := assignments[j.assignment.AppID]
				if !ok || !matches(j.check, a) {
					j.cancel()
					delete(active, id)
				}
			}
			for app, generation := range applied {
				a, ok := assignments[app]
				if !ok || a.Generation != generation {
					delete(applied, app)
				}
			}
			reportBudget, endReports := context.WithTimeout(ctx, 2*time.Second)
			for _, a := range assignments {
				if applied[a.AppID] != a.Generation {
					reportctx, stop := context.WithTimeout(reportBudget, 2*time.Second)
					e = r.Channel.Applied(reportctx, control.AppApplied{Generation: a.Generation, AppID: a.AppID, Revision: a.Revision, Digest: a.Digest, Purpose: a.Purpose, Status: "configured", ErrorCode: ""})
					stop()
					if e == nil {
						applied[a.AppID] = a.Generation
					}
				}
			}
			now := time.Now()
			for id, c := range completed {
				if now.After(c.job.check.Deadline) {
					delete(completed, id)
					continue
				}
				reportctx, stop := context.WithTimeout(reportBudget, 2*time.Second)
				_ = r.Channel.Result(reportctx, c.result)
				stop()
			}
			endReports()
			for _, c := range desired.Checks {
				if r.Pool != nil {
					break
				}
				if c.Status != "queued" && c.Status != "running" {
					continue
				}
				if _, ok := active[c.ID]; ok {
					continue
				}
				if _, ok := completed[c.ID]; ok {
					continue
				}
				a, ok := assignments[c.AppID]
				if !ok || !matches(c, a) || !now.Before(c.Deadline) {
					continue
				}
				if id, e := uuid.Parse(c.ID); e != nil || id == uuid.Nil {
					continue
				}
				deadline := c.Deadline
				if max := now.Add(10 * time.Second); deadline.After(max) {
					deadline = max
				}
				workerctx, wcancel := context.WithDeadline(ctx, deadline)
				j := job{c, a, workerctx, wcancel}
				select {
				case queue <- j:
					active[c.ID] = j
				default:
					wcancel()
				}
			}
			timer.Reset(interval)
		}
	}
}
func (r *Runtime) String() string {
	return fmt.Sprintf("app origin check runtime (%d control endpoints)", len(r.ControlHosts))
}

func (r *Runtime) DenyControlEndpoint(raw string) error {
	u, e := url.Parse(raw)
	if e != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("invalid control endpoint")
	}
	r.ControlHosts = append(r.ControlHosts, u.Hostname())
	return nil
}
