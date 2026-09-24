package control

import (
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"testing"
)

func TestIPsecCapabilityRequiresActualQualifiedController(t *testing.T) {
	c := &Client{}
	if c.ipsecCapability() != 0 {
		t.Fatal("default capability")
	}
	c.AttachIPsecController(&ipsec.RuntimeController{})
	if c.ipsecCapability() != 0 {
		t.Fatal("unstarted controller advertised")
	}
	c.AttachIPsecController(nil)
	if c.ipsecCapability() != 0 {
		t.Fatal("detached capability")
	}
}
