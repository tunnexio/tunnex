//go:build linux

package sandboxnetwork

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNamespaceAdmissionRejectsHostUserAndOrdinaryFiles(t *testing.T) {
	for _, path := range []string{"/proc/self/ns/net", "/proc/self/ns/user", os.DevNull} {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = AdmitNamespace(file, Admission{1000, 100000, 65536})
		file.Close()
		if err == nil {
			t.Fatal("unsafe descriptor admitted", path)
		}
	}
}

func TestRouteAndRuleParsingRejectsNativePaths(t *testing.T) {
	for _, raw := range []string{`[{"dst":"default","dev":"eth0"}]`, `[{"dst":"10.0.0.0/8","dev":"eth0","nexthops":[]}]`, `[{"dst":"10.0.0.0/8","dev":"wg0","table":99}]`, `[{"dst":"10.0.0.0/8","dev":"wg0","type":"blackhole"}]`} {
		if _, err := parseRoutes([]byte(raw)); err == nil {
			t.Fatal("ambiguous/native route representation accepted")
		}
	}
	if _, err := parseRoutes([]byte(`[{"type":"local","dst":"10.254.242.2","dev":"wg0","table":"local"},{"dst":"10.254.242.0/24","dev":"wg0"}]`)); err != nil {
		t.Fatal(err)
	}
	default4 := []byte(`[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`)
	default6 := []byte(`[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"}]`)
	if !defaultRules(default4, "-4") || !defaultRules(default6, "-6") || defaultRules(default6, "-4") {
		t.Fatal("default rules profile mismatch")
	}
	if defaultRules([]byte(`[{"priority":0,"src":"all","table":"local","fwmark":"0x1"},{"priority":32766,"src":"all","table":"main"}]`), "-6") {
		t.Fatal("policy rule accepted")
	}
}

func TestUnixRequestRequiresOneFDAndStrictVersionedBody(t *testing.T) {
	p, key := fixturePlan(t)
	for _, scenario := range []string{"valid", "no-fd", "two-fd", "wrong-version", "inspect-secret", "unknown-field"} {
		t.Run(scenario, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "socket")
			listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			client, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			server, err := listener.AcceptUnix()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			file, err := os.Open(os.DevNull)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			request := Request{Version: 1, Operation: "apply", Plan: p, PrivateKey: key}
			if scenario == "wrong-version" {
				request.Version = 2
			}
			if scenario == "inspect-secret" {
				request.Operation = "inspect"
			}
			body, _ := json.Marshal(request)
			if scenario == "unknown-field" {
				body = append(body[:len(body)-1], []byte(`,"command":"sh"}`)...)
			}
			rights := unix.UnixRights(int(file.Fd()))
			if scenario == "no-fd" {
				rights = nil
			}
			if scenario == "two-fd" {
				rights = unix.UnixRights(int(file.Fd()), int(file.Fd()))
			}
			if _, _, err = client.WriteMsgUnix(body, rights, nil); err != nil {
				t.Fatal(err)
			}
			got, descriptor, err := readRequest(server)
			if descriptor != nil {
				defer descriptor.Close()
			}
			if scenario == "valid" {
				if err != nil || descriptor == nil || got.Plan.Binding != p.Binding || got.PrivateKey != key {
					t.Fatal("valid control packet failed", err)
				}
			} else if err == nil {
				t.Fatal("unsafe control packet accepted")
			}
		})
	}
}

func TestOnlyKernelLocalMulticastRouteParses(t *testing.T) {
	for _, scenario := range []struct {
		raw    string
		accept bool
	}{
		{`[{"type":"multicast","dst":"ff00::/8","dev":"wg0","table":"local","protocol":"kernel","metric":256,"flags":[],"pref":"medium"}]`, true},
		{`[{"type":"multicast","dst":"ff00::/8","dev":"wg0","table":"main","protocol":"kernel"}]`, false},
		{`[{"type":"multicast","dst":"ff00::/8","dev":"wg0","table":"local","protocol":"static"}]`, false},
		{`[{"type":"multicast","dst":"ff02::/16","dev":"wg0","table":"local","protocol":"kernel"}]`, false},
	} {
		if _, err := parseRoutes([]byte(scenario.raw)); (err == nil) != scenario.accept {
			t.Fatalf("accept=%v err=%v", scenario.accept, err)
		}
	}
}
