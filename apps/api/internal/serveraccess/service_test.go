package serveraccess

import (
	"bytes"
	"encoding/base64"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

func validServer() api.ServerAccessServerInput {
	return api.ServerAccessServerInput{GatewayId: uuid.New(), Name: "fixture", PrivateIp: "10.1.2.3", SshPort: 22, HostFingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)), Accounts: []string{"fixture"}, IdleTimeoutSeconds: 60, MaxSessionSeconds: 300}
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
