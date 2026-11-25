package serveraccess

import (
	"bytes"
	"encoding/base64"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func validServer() api.ServerAccessServerInput {
	return api.ServerAccessServerInput{GatewayId: uuid.New(), Name: "fixture", PrivateIp: "10.1.2.3", SshPort: 22, HostFingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), Accounts: []string{"fixture"}, IdleTimeoutSeconds: 60, MaxSessionSeconds: 300}
}
func TestServerDestinationAndAccountBounds(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1", "169.254.169.254", "8.8.8.8", "fe80::1", "fd00::1%wg0", "bad"} {
		v := validServer()
		v.PrivateIp = ip
		if ValidateServer(v) == nil {
			t.Fatalf("accepted destination %s", ip)
		}
	}
	for _, a := range [][]string{{"root"}, {"fixture", "fixture"}, {"../fixture"}, {"user;id"}, {}} {
		v := validServer()
		v.Accounts = a
		if ValidateServer(v) == nil {
			t.Fatalf("accepted accounts %v", a)
		}
	}
	v := validServer()
	v.HostFingerprint = "SHA256:" + string(make([]byte, 43))
	if ValidateServer(v) == nil {
		t.Fatal("accepted malformed fingerprint")
	}
	if e := ValidateServer(validServer()); e != nil {
		t.Fatal(e)
	}
}
func TestLiveCloseUnblocksBlockedStream(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	l := &liveSession{gateway: left, done: make(chan struct{}), attached: make(chan struct{})}
	blocked := make(chan struct{})
	go func() { left.Write([]byte("blocked")); close(blocked) }()
	l.close()
	l.close()
	select {
	case <-blocked:
	case <-time.After(time.Second):
		t.Fatal("close did not interrupt blocked stream")
	}
	select {
	case <-l.done:
	default:
		t.Fatal("close did not terminate lifecycle")
	}
}

func TestTerminalOriginUsesObservedTransport(t *testing.T) {
	for _, tc := range []struct {
		origin       string
		secure, want bool
	}{{"https://console.example", true, true}, {"http://console.example", false, true}, {"https://other.example", true, false}, {"https://console.example", false, false}, {"http://console.example", true, false}, {"https://console.example/path", true, false}, {"https://console.example?target=bad", true, false}, {"https://user@console.example", true, false}, {"", true, false}} {
		req := httptest.NewRequest("GET", "http://console.example/", nil)
		req.Header.Set("Origin", tc.origin)
		if got := terminalOriginMatches(req, tc.secure); got != tc.want {
			t.Fatalf("origin %s secure %v got %v", tc.origin, tc.secure, got)
		}
	}
}

func TestRecordingSnapshotDoesNotHideAuthorityChanges(t *testing.T) {
	ip := "10.1.2.3"
	port := 22
	fp := "SHA256:fixture"
	v := api.ServerAccessServer{GatewayId: uuid.New(), PrivateIp: &ip, SshPort: &port, HostFingerprint: &fp, Accounts: []string{"fixture"}, IdleTimeoutSeconds: 300, MaxSessionSeconds: 900, Revision: 1}
	original := serverAuthorityHash(v)
	display := v
	display.Name = "Renamed"
	display.RecordingEnabled = true
	display.Enabled = true
	display.Revision++
	if !bytes.Equal(original, serverAuthorityHash(display)) {
		t.Fatal("recording/display edits changed an existing session policy")
	}
	account := v
	account.Accounts = []string{"other"}
	gateway := v
	gateway.GatewayId = uuid.New()
	destination := v
	otherIP := "10.1.2.4"
	destination.PrivateIp = &otherIP
	duration := v
	duration.MaxSessionSeconds = 600
	host := v
	otherFingerprint := "SHA256:changed"
	host.HostFingerprint = &otherFingerprint
	for _, changed := range []api.ServerAccessServer{account, gateway, destination, duration, host} {
		if bytes.Equal(original, serverAuthorityHash(changed)) {
			t.Fatal("authority edit failed to invalidate the session binding")
		}
	}
}

// SA-UX-3: the pending-trust placeholder is storage only. It is never a pin and never leaves the API.
func TestPendingHostFingerprintIsNeverAPin(t *testing.T) {
	if PendingHostFingerprint != "SHA256:"+strings.Repeat("A", 43) {
		t.Fatal("placeholder changed; stored pending servers would no longer match")
	}
	for _, os := range []api.ServerAccessServerInputOs{"linux", "windows"} {
		v := validServer()
		v.Os = &os
		v.SshPort = 2222
		v.HostFingerprint = PendingHostFingerprint
		var refused *apierr.Error
		if e := ValidateServer(v); !errors.As(e, &refused) || refused.Code != "host_fingerprint_placeholder" {
			t.Fatalf("%s: placeholder accepted as a pin: %v", os, e)
		}
	}
	pending := validServer()
	pending.Accounts, pending.SshPort = []string{}, 2222
	for _, fp := range []string{"", PendingHostFingerprint} {
		pending.HostFingerprint = fp
		if e := ValidateServer(pending); e != nil {
			t.Fatalf("pending server %q refused: %v", fp, e)
		}
		if normalizeServerInput(pending).HostFingerprint != PendingHostFingerprint {
			t.Fatal("pending server not stored with the placeholder")
		}
	}
	// An empty fingerprint is never a way to drop trust from a server that has accounts.
	trusted := validServer()
	trusted.HostFingerprint = ""
	if ValidateServer(trusted) == nil || normalizeServerInput(trusted).HostFingerprint != "" {
		t.Fatal("trusted server accepted without a fingerprint")
	}
	if validFingerprint(PendingHostFingerprint) {
		t.Fatal("placeholder accepted as a management pin or setup result")
	}
	fp, real := PendingHostFingerprint, "SHA256:"+strings.Repeat("B", 43)
	if publicServer(api.ServerAccessServer{HostFingerprint: &fp}).HostFingerprint != nil {
		t.Fatal("placeholder returned to a client")
	}
	if out := publicServer(api.ServerAccessServer{HostFingerprint: &real}).HostFingerprint; out == nil || *out != real {
		t.Fatal("real pin hidden")
	}
}
