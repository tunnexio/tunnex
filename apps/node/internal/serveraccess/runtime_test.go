package serveraccess

import (
	"errors"
	"fmt"
	"net"
	"testing"
)

func TestResultsNeverExposeRawSSHDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{{nil, "ok"}, {fmt.Errorf("handshake: %w", errHostKeyMismatch), "ssh_host_key_mismatch"}, {errPTY, "ssh_pty_failed"}, {&net.OpError{Op: "dial", Net: "tcp", Err: errors.New("sensitive address")}, "ssh_unreachable"}, {errors.New("ssh: unable to authenticate, private details"), "ssh_authentication_failed"}, {errors.New("secret/raw diagnostic"), "failed"}} {
		if got := classifyResult(tc.err); got != tc.want {
			t.Fatalf("unexpected sanitized result %s", got)
		}
	}
}
