package ipalloc

import (
	"testing"

	"github.com/google/uuid"
)

func TestIPv6DeviceAddrStableAndOrgScoped(t *testing.T) {
	a := uuid.MustParse("018f1f5e-2d2a-7b0a-9b58-7f6e5b7d0001")
	b := uuid.MustParse("018f1f5e-2d2a-7b0a-9b58-7f6e5b7d0002")
	one, err := IPv6DeviceAddr("fd7a:1b2c:3d4e:1111::/64", a, "10.99.0.7")
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := IPv6DeviceAddr("fd7a:1b2c:3d4e:1111::/64", a, "10.99.0.7"); again != one {
		t.Fatalf("address is not stable: %s vs %s", one, again)
	}
	other, err := IPv6DeviceAddr("fd7a:1b2c:3d4e:2222::/64", b, "10.99.0.7")
	if err != nil {
		t.Fatal(err)
	}
	if other == one {
		t.Fatalf("different organizations unexpectedly share address %s", one)
	}
}

func TestIPv6GatewayCIDRUsesOrgPool(t *testing.T) {
	got, err := IPv6GatewayCIDR("fd7a:1b2c:3d4e:1111::/64", uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if got != "fd7a:1b2c:3d4e:1111::1/64" {
		t.Fatalf("unexpected gateway CIDR: %s", got)
	}
}

func TestIPv6RejectsNonIPv6Pool(t *testing.T) {
	if _, err := IPv6OrgPrefix("10.99.0.0/24", uuid.New()); err == nil {
		t.Fatal("IPv4 pool must not be accepted as IPv6 pool")
	}
}
