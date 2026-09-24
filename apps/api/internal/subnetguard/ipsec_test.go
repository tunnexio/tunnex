package subnetguard

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"testing"
)

type providerSource struct {
	fakeSource
	entries []IPsecReservation
	err     error
}

func (s providerSource) IPsecReservations(context.Context, uuid.UUID) ([]IPsecReservation, error) {
	return s.entries, s.err
}
func TestIPsecReservationsAlwaysCollected(t *testing.T) {
	for _, class := range []OverlapClass{ClassIPsecRemote, ClassIPsecInside, ClassIPsecUnderlay} {
		t.Run(string(class), func(t *testing.T) {
			r, err := Collect(context.Background(), providerSource{entries: []IPsecReservation{{CIDR: "10.40.0.0/24", Class: class}}}, uuid.New())
			if err != nil {
				t.Fatal(err)
			}
			for _, candidate := range []string{"10.40.0.0/24", "10.40.0.128/25", "10.40.0.0/16"} {
				if ov, ok := Check(p(candidate), r.WithoutPool()); ok || ov.Class != class {
					t.Fatalf("provider reservation omitted: %v %v", ov, ok)
				}
			}
			if _, ok := Check(p("10.40.1.0/24"), r); !ok {
				t.Fatal("adjacent range rejected")
			}
		})
	}
}
func TestIPsecReservationFailureIsClosed(t *testing.T) {
	sentinel := errors.New("query failed")
	if _, err := Collect(context.Background(), providerSource{err: sentinel}, uuid.New()); !errors.Is(err, sentinel) {
		t.Fatal("provider query failure ignored")
	}
	for _, entry := range []IPsecReservation{{CIDR: "broken", Class: ClassIPsecRemote}, {CIDR: "10.0.0.0/24", Class: "unknown"}} {
		if _, err := Collect(context.Background(), providerSource{entries: []IPsecReservation{entry}}, uuid.New()); err == nil {
			t.Fatal("invalid reservation silently omitted")
		}
	}
}
func TestIPsecUnderlayCanShareOnlyUnderlay(t *testing.T) {
	r, err := Collect(context.Background(), providerSource{entries: []IPsecReservation{{CIDR: "8.8.8.8/32", Class: ClassIPsecUnderlay}, {CIDR: "10.40.0.0/24", Class: ClassIPsecRemote}}}, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := CheckUnderlay(p("8.8.8.8/32"), r); !ok {
		t.Fatal("shared underlay dependency refused")
	}
	if ov, ok := CheckUnderlay(p("10.40.0.1/32"), r); ok || ov.Class != ClassIPsecRemote {
		t.Fatal("underlay captured by remote route")
	}
	if _, ok := Check(p("8.8.8.0/24"), r); ok {
		t.Fatal("route captured underlay")
	}
}

func TestIPsecInsideUniquenessIsGatewayScoped(t *testing.T) {
	r, err := Collect(context.Background(), providerSource{entries: []IPsecReservation{{CIDR: "169.254.10.0/30", Class: ClassIPsecInside}, {CIDR: "169.254.20.1/32", Class: ClassIPsecUnderlay}}}, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := CheckInside(p("169.254.10.0/30"), r); !ok {
		t.Fatal("cross-gateway inside reservation refused before scoped DB uniqueness")
	}
	if _, ok := CheckInside(p("169.254.20.0/30"), r); ok {
		t.Fatal("inside reservation captured underlay")
	}
}
