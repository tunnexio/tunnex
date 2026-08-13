package nodes

import "testing"

func TestValidEndpoint(t *testing.T) {
	good := []string{"1.2.3.4:51820", "vpn.example.com:51820", "node-agent:51820", "[2001:db8::1]:51820"}
	for _, s := range good {
		if !validEndpoint(s) {
			t.Errorf("expected %q to be valid", s)
		}
	}
	bad := []string{
		"",                                      // empty
		"1.2.3.4",                               // no port
		"1.2.3.4:0",                             // port out of range
		"1.2.3.4:99999",                         // port out of range
		"host :51820",                           // whitespace
		"1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0", // newline injection
		"1.2.3.4:51820\t",                       // trailing tab
	}
	for _, s := range bad {
		if validEndpoint(s) {
			t.Errorf("expected %q to be REJECTED", s)
		}
	}
}
