package serveraccess

import (
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/packages/apptransport/rdpwire"
	"github.com/tunnexio/tunnex/packages/apptransport/terminalwire"
	"testing"
)

func TestRDPInputBindsAccountAndExcludesRedirection(t *testing.T) {
	os := api.ServerAccessServerOs("windows")
	s := api.ServerAccessServer{Os: &os}
	for _, f := range []terminalwire.Frame{{Type: "credentials", Data: []byte(`{"account":"Administrator","password":"test"}`)}, {Type: "desktop", Data: rdpwire.Encode("key", "65", "1")}} {
		if e := validateBrowserFrame(s, "Administrator", f); e != nil {
			t.Fatal(e)
		}
	}
	for _, f := range []terminalwire.Frame{{Type: "credentials", Data: []byte(`{"account":"other","password":"test"}`)}, {Type: "desktop", Data: rdpwire.Encode("connect", "10.0.0.1")}, {Type: "desktop", Data: rdpwire.Encode("clipboard", "secret")}, {Type: "input", Data: []byte("command")}} {
		if validateBrowserFrame(s, "Administrator", f) == nil {
			t.Fatalf("accepted %#v", f)
		}
	}
}
