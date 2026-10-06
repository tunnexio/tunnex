package serveraccess

import (
	"bytes"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/packages/apptransport/terminalwire"
	"testing"
)

func TestClipboardPolicyBindsBrowserAndAuthority(t *testing.T) {
	os := api.ServerAccessServerOsWindows
	server := api.ServerAccessServer{Os: &os}
	original := serverAuthorityHash(server)
	off := api.ServerAccessServerClipboardPolicyOff
	server.ClipboardPolicy = &off
	if !bytes.Equal(original, serverAuthorityHash(server)) {
		t.Fatal("default off altered existing authority")
	}
	for _, p := range []api.ServerAccessServerClipboardPolicy{off, api.ServerAccessServerClipboardPolicyCopy, api.ServerAccessServerClipboardPolicyPaste, api.ServerAccessServerClipboardPolicyBoth} {
		server.ClipboardPolicy = &p
		err := validateBrowserFrame(server, "Administrator", terminalwire.Frame{Type: "clipboard", Data: []byte("hello")})
		expected := p == api.ServerAccessServerClipboardPolicyPaste || p == api.ServerAccessServerClipboardPolicyBoth
		if (err == nil) != expected {
			t.Fatalf("paste policy %s: %v", p, err)
		}
		if p != off && bytes.Equal(original, serverAuthorityHash(server)) {
			t.Fatal("policy change did not invalidate authority")
		}
	}
}
