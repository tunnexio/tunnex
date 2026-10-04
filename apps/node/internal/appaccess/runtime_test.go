package appaccess

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"github.com/tunnexio/tunnex/packages/apptransport/originpolicy"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeChannel struct {
	mu      sync.Mutex
	desired control.AppDesired
	reports []control.AppApplied
	results []control.AppCheckResult
}

func (f *fakeChannel) Capability(context.Context) error { return nil }
func (f *fakeChannel) Desired(context.Context) (control.AppDesired, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.desired, nil
}
func (f *fakeChannel) Applied(_ context.Context, r control.AppApplied) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, r)
	return nil
}
func (f *fakeChannel) Result(_ context.Context, r control.AppCheckResult) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results = append(f.results, r)
	return nil
}
func assignment() control.AppAssignment {
	return control.AppAssignment{OrgID: uuid.NewString(), GatewayID: uuid.NewString(), AppID: uuid.NewString(), Generation: uuid.NewString(), Revision: 1, Digest: strings.Repeat("a", 64), Purpose: "origin_check", OriginURL: "http://origin.example", AllowedDestinationCIDRs: []string{"10.0.0.0/8"}}
}
func check(a control.AppAssignment) control.AppCheck {
	return control.AppCheck{ID: uuid.NewString(), OrgID: a.OrgID, GatewayID: a.GatewayID, AppID: a.AppID, Generation: a.Generation, Revision: a.Revision, Digest: a.Digest, Purpose: a.Purpose, Status: "queued", Deadline: time.Now().Add(time.Second)}
}
func TestRuntimeBoundsAndWithdrawal(t *testing.T) {
	a := assignment()
	f := &fakeChannel{desired: control.AppDesired{ProtocolVersion: 1, Purpose: "origin_check", Assignments: []control.AppAssignment{a}}}
	for i := 0; i < 8; i++ {
		f.desired.Checks = append(f.desired.Checks, check(a))
	}
	var concurrent, peak atomic.Int32
	entered := make(chan struct{}, 32)
	r := Runtime{Channel: f, Interval: 5 * time.Millisecond, Check: func(ctx context.Context, _ control.AppAssignment) originpolicy.Result {
		n := concurrent.Add(1)
		for n > peak.Load() {
			old := peak.Load()
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		entered <- struct{}{}
		<-ctx.Done()
		concurrent.Add(-1)
		return originpolicy.Result{Status: "cancelled"}
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	for i := 0; i < 8; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("workers absent")
		}
	}
	if peak.Load() != 8 {
		t.Fatal("workers", peak.Load())
	}
	f.mu.Lock()
	f.desired.Withdrawn = true
	f.mu.Unlock()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown leaked")
	}
	if concurrent.Load() != 0 {
		t.Fatal("active worker leaked")
	}
}
func TestExactAssignmentBinding(t *testing.T) {
	a := assignment()
	for _, field := range []string{"org", "gateway", "app", "generation", "revision", "digest", "purpose"} {
		c := check(a)
		switch field {
		case "org":
			c.OrgID = uuid.NewString()
		case "gateway":
			c.GatewayID = uuid.NewString()
		case "app":
			c.AppID = uuid.NewString()
		case "generation":
			c.Generation = uuid.NewString()
		case "revision":
			c.Revision++
		case "digest":
			c.Digest = strings.Repeat("b", 64)
		case "purpose":
			c.Purpose = "browser"
		}
		if matches(c, a) {
			t.Fatal(field)
		}
	}
	if !valid(a) {
		t.Fatal("valid assignment refused")
	}
	a.AllowedDestinationCIDRs = []string{"0.0.0.0/0"}
	if valid(a) {
		t.Fatal("blanketprivate accepted")
	}
}
func TestResultRedactionAndEnums(t *testing.T) {
	a := assignment()
	c := check(a)
	r := result(c, originpolicy.Result{Status: "ready", DNS: "ready", Connect: "ready", TLS: "not_required", HTTPStatus: 401})
	if r.DNSStatus != "passed" || r.TLSStatus != "skipped" || r.ErrorCode != "" || r.Generation != a.Generation {
		t.Fatal(r)
	}
	r = result(c, originpolicy.Result{Status: "dns_refused", DNS: "refused"})
	if r.ErrorCode != "target_refused" {
		t.Fatal(r)
	}
}
