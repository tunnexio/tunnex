package ipsec

import (
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
)

func leaseFixture() (*PermitLeaseAuthority, *time.Duration, PermitLeaseIdentity) {
	now := time.Duration(0)
	a := NewPermitLeaseAuthority()
	a.elapsed = func() time.Duration { return now }
	id := PermitLeaseIdentity{Binding: Binding{OrgID: uuid.New(), GatewayID: uuid.New(), ConnectionID: uuid.New(), DesiredRevision: 1, ConfigurationRevision: 1, PolicyRevision: 1}, DeliveryID: uuid.New()}
	return a, &now, id
}
func TestPermitLeaseStartAndExpiry(t *testing.T) {
	a, now, id := leaseFixture()
	q, e := a.Begin(id)
	if e != nil {
		t.Fatal(e)
	}
	*now = 10 * time.Second
	r := PermitLeaseResponse{q, 60000}
	if e = a.Accept(r); e != nil {
		t.Fatal(e)
	}
	d, e := a.RemainingForApply(id, 5*time.Second)
	if e != nil || d != 45*time.Second {
		t.Fatalf("remaining %v %v", d, e)
	}
	*now += 1500 * time.Microsecond
	d, e = a.RemainingForApply(id, 5*time.Second)
	if e != nil || d != 44998*time.Millisecond {
		t.Fatalf("rounding %v %v", d, e)
	}
	if a.Accept(r) == nil {
		t.Fatal("replay")
	}
	*now = 55 * time.Second
	if _, e = a.RemainingForApply(id, 5*time.Second); e == nil {
		t.Fatal("apply budget exhausted")
	}
	*now = 60 * time.Second
	if _, e = a.RemainingForApply(id, time.Millisecond); e == nil {
		t.Fatal("expired")
	}
}
func TestPermitLeaseRefusals(t *testing.T) {
	for name, mut := range map[string]func(*PermitLeaseResponse){"nonce": func(r *PermitLeaseResponse) { r.Nonce = "wrong" }, "delivery": func(r *PermitLeaseResponse) { r.Identity.DeliveryID = uuid.New() }, "org": func(r *PermitLeaseResponse) { r.Identity.Binding.OrgID = uuid.New() }, "gateway": func(r *PermitLeaseResponse) { r.Identity.Binding.GatewayID = uuid.New() }, "connection": func(r *PermitLeaseResponse) { r.Identity.Binding.ConnectionID = uuid.New() }, "desired": func(r *PermitLeaseResponse) { r.Identity.Binding.DesiredRevision++ }, "configuration": func(r *PermitLeaseResponse) { r.Identity.Binding.ConfigurationRevision++ }, "policy": func(r *PermitLeaseResponse) { r.Identity.Binding.PolicyRevision++ }, "zero": func(r *PermitLeaseResponse) { r.TTLMillis = 0 }, "negative": func(r *PermitLeaseResponse) { r.TTLMillis = -1 }, "oversized": func(r *PermitLeaseResponse) { r.TTLMillis = 60001 }, "overflow": func(r *PermitLeaseResponse) { r.TTLMillis = 1 << 62 }} {
		t.Run(name, func(t *testing.T) {
			a, _, id := leaseFixture()
			q, _ := a.Begin(id)
			r := PermitLeaseResponse{q, 60000}
			mut(&r)
			if a.Accept(r) == nil {
				t.Fatal("invalid accepted")
			}
			if a.Accept(PermitLeaseResponse{q, 60000}) == nil {
				t.Fatal("pending not consumed")
			}
			if _, e := a.RemainingForApply(id, time.Second); e == nil {
				t.Fatal("manufactured authority")
			}
		})
	}
}
func TestPermitLeaseRenewalAndInvalidation(t *testing.T) {
	a, now, id := leaseFixture()
	q, _ := a.Begin(id)
	if e := a.Accept(PermitLeaseResponse{q, 60000}); e != nil {
		t.Fatal(e)
	}
	*now = 20 * time.Second
	r, _ := a.Begin(id)
	if r.Nonce == q.Nonce {
		t.Fatal("nonce reused")
	}
	if a.Accept(PermitLeaseResponse{r, 0}) == nil {
		t.Fatal("bad renewal")
	}
	d, e := a.RemainingForApply(id, time.Second)
	if e != nil || d != 39*time.Second {
		t.Fatalf("old deadline changed %v %v", d, e)
	}
	r, _ = a.Begin(id)
	a.Invalidate()
	if a.Accept(PermitLeaseResponse{r, 60000}) == nil {
		t.Fatal("late response")
	}
	if _, e = a.RemainingForApply(id, time.Second); e == nil {
		t.Fatal("invalidated authority")
	}
	if _, e = NewPermitLeaseAuthority().RemainingForApply(id, time.Second); e == nil {
		t.Fatal("restart authority")
	}
	q, _ = a.Begin(id)
	other := id
	other.Binding.PolicyRevision++
	a.Begin(other)
	if a.Accept(PermitLeaseResponse{q, 60000}) == nil {
		t.Fatal("old generation")
	}
}
func TestPermitLeaseClockAndBudget(t *testing.T) {
	a, now, id := leaseFixture()
	q, _ := a.Begin(id)
	*now = 60 * time.Second
	if a.Accept(PermitLeaseResponse{q, 60000}) == nil {
		t.Fatal("delayed response")
	}
	*now = 61 * time.Second
	q, _ = a.Begin(id)
	if e := a.Accept(PermitLeaseResponse{q, 60000}); e != nil {
		t.Fatal(e)
	}
	for _, b := range []time.Duration{-1, 0, 60 * time.Second} {
		if _, e := a.RemainingForApply(id, b); e == nil {
			t.Fatal("invalid budget")
		}
	}
	other := id
	other.DeliveryID = uuid.New()
	if _, e := a.RemainingForApply(other, time.Second); e == nil {
		t.Fatal("wrong identity")
	}
	*now = 59 * time.Second
	if _, e := a.RemainingForApply(id, time.Second); e == nil {
		t.Fatal("clock regression")
	}
	if _, e := a.Begin(PermitLeaseIdentity{}); e == nil {
		t.Fatal("empty identity")
	}
	var zero PermitLeaseAuthority
	if _, e := zero.Begin(id); e == nil {
		t.Fatal("uninitialized")
	}
}

func TestPermitLeaseOnlyFreshRenewalExtends(t *testing.T) {
	a, now, id := leaseFixture()
	q, _ := a.Begin(id)
	if err := a.Accept(PermitLeaseResponse{q, 60000}); err != nil {
		t.Fatal(err)
	}
	*now = 40 * time.Second
	renewal, _ := a.Begin(id)
	*now = 45 * time.Second
	if err := a.Accept(PermitLeaseResponse{renewal, 60000}); err != nil {
		t.Fatal(err)
	}
	duration, err := a.RemainingForApply(id, time.Second)
	if err != nil || duration != 54*time.Second {
		t.Fatalf("renewal start not authoritative: %v %v", duration, err)
	}
	*now = 46 * time.Second
	duration, err = a.RemainingForApply(id, time.Second)
	if err != nil || duration != 53*time.Second {
		t.Fatalf("read extended authority: %v %v", duration, err)
	}
	other := id
	other.Binding.PolicyRevision++
	if _, err := a.Begin(other); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RemainingForApply(id, time.Second); err == nil {
		t.Fatal("new identity retained old authority")
	}
}

func TestPermitLeaseCanonicalPolicyHashIdentity(t *testing.T) {
	a := NewPermitLeaseAuthority()
	id := PermitLeaseIdentity{Binding: Binding{OrgID: uuid.New(), GatewayID: uuid.New(), ConnectionID: uuid.New(), DesiredRevision: 1, ConfigurationRevision: 1}, DeliveryID: uuid.New(), PolicyHash: strings.Repeat("a", 64)}
	req, err := a.Begin(id)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Accept(PermitLeaseResponse{PermitLeaseRequest: req, TTLMillis: 60000}); err != nil {
		t.Fatal(err)
	}
	other := id
	other.PolicyHash = strings.Repeat("b", 64)
	if _, err = a.RemainingForApply(other, time.Second); err != ErrPermitLease {
		t.Fatal("foreign policy hash borrowed authority")
	}
	bad := id
	bad.PolicyHash = "not-a-hash"
	if _, err = a.Begin(bad); err != ErrPermitLease {
		t.Fatal("invalid policy identity")
	}
}
