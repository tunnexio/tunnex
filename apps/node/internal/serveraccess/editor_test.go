package serveraccess

import (
	"golang.org/x/crypto/ssh"
	"testing"
)

func TestEditorForwardingCannotReachOtherHosts(t *testing.T) {
	for _, host := range []string{"localhost", "127.0.0.1", "::1"} {
		if _, e := editorLoopback(ssh.Marshal(editorForward{Host: host, Port: 32123})); e != nil {
			t.Fatal(e)
		}
	}
	for _, host := range []string{"10.1.2.3", "169.254.169.254", "8.8.8.8", "localhost.evil", "127.0.0.2", "localhost;id"} {
		if _, e := editorLoopback(ssh.Marshal(editorForward{Host: host, Port: 32123})); e == nil {
			t.Fatalf("accepted %s", host)
		}
	}
	for _, port := range []uint32{0, 65536} {
		if _, e := editorLoopback(ssh.Marshal(editorForward{Host: "localhost", Port: port})); e == nil {
			t.Fatal("accepted bad port")
		}
	}
}
func TestEditorEnvironmentCannotInjectDynamicLoader(t *testing.T) {
	for _, name := range []string{"LD_PRELOAD", "PATH", "BASH_ENV", "PYTHONPATH", "SSH_AUTH_SOCK"} {
		if allowedEditorEnv(name, "x") {
			t.Fatal("accepted unsafe environment")
		}
	}
	if !allowedEditorEnv("LANG", "C.UTF-8") {
		t.Fatal("locale refused")
	}
}
