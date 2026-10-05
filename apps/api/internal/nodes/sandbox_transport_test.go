package nodes

import "testing"

func TestSandboxQualificationTransportDoesNotChangeOrdinaryPort(t *testing.T) {
	ordinary := &Service{}
	fixture := &Service{}
	fixture.UseSandboxQualificationTransport()
	if ordinary.wireGuardListenPort() != 51820 || fixture.wireGuardListenPort() != 51830 {
		t.Fatal("fixture changed ordinary listener")
	}
}
