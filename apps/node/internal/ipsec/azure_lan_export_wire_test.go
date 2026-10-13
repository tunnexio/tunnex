package ipsec

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"
)

func azureLANExportWire(conn net.Conn, command string, limit int) ([]byte, error) {
	if command != "show bgp ipv4 unicast neighbors 169.254.21.2 advertised-routes json" && command != "show bgp ipv4 unicast neighbors 169.254.22.2 advertised-routes json" {
		return nil, fmt.Errorf("vty_command_refused")
	}
	request := []byte(command + "\x00")
	for len(request) > 0 {
		n, err := conn.Write(request)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("vty_write_refused")
		}
		request = request[n:]
	}
	out := []byte{}
	chunk := make([]byte, 4096)
	for {
		n, err := conn.Read(chunk)
		if n > 0 {
			out = append(out, chunk[:n]...)
		}
		if len(out) > limit+4 {
			return nil, fmt.Errorf("vty_bound_refused")
		}
		if i := bytes.Index(out, []byte{0, 0, 0}); i >= 0 {
			if len(out) < i+4 && err == nil {
				continue
			}
			if len(out) != i+4 || out[i+3] != 0 || i > limit || bytes.IndexByte(out[:i], 0) >= 0 {
				return nil, fmt.Errorf("vty_frame_refused")
			}
			return out[:i], nil
		}
		if err != nil {
			return nil, fmt.Errorf("vty_read_refused")
		}
	}
}

func TestAzureLANExportWireExactCommandsAndOriginalRefusal(t *testing.T) {
	commands := []string{"show bgp ipv4 unicast neighbors 169.254.21.2 advertised-routes json", "show bgp ipv4 unicast neighbors 169.254.22.2 advertised-routes json"}
	for _, command := range commands {
		client, server := net.Pipe()
		if _, err := azureProofVTYWire(client, command, 64); err == nil {
			t.Fatal("original shared wire unexpectedly admitted export")
		}
		client.Close()
		server.Close()
		client, server = net.Pipe()
		client.SetDeadline(time.Now().Add(time.Second))
		done := make(chan bool, 1)
		go func() {
			defer server.Close()
			request := make([]byte, 256)
			n, e := server.Read(request)
			matched := e == nil && string(request[:n]) == command+"\x00"
			_, e = server.Write(append([]byte(`{"advertisedRoutes":{}}`), 0, 0, 0, 0))
			done <- matched && e == nil
		}()
		raw, err := azureLANExportWire(client, command, 64)
		client.Close()
		matched := <-done
		if err != nil || !matched || string(raw) != `{"advertisedRoutes":{}}` {
			t.Fatal("exact bound export command refused")
		}
	}
	for _, command := range []string{"configure terminal", "show bgp ipv4 unicast json", "show bgp ipv4 unicast neighbors 169.254.99.2 advertised-routes json", "show bgp ipv4 unicast neighbors 169.254.21.2 advertised-routes json\nconfigure terminal"} {
		client, server := net.Pipe()
		if _, err := azureLANExportWire(client, command, 64); err == nil {
			t.Fatal("foreign command accepted")
		}
		client.Close()
		server.Close()
	}
}
func TestAzureLANExportWirePreservesFrameBounds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		chunks [][]byte
		limit  int
		ok     bool
	}{
		{"split_terminator", [][]byte{[]byte(`{"routes":{}}`), {0}, {0, 0}, {0}}, 64, true},
		{"nonzero_return", [][]byte{{'{', '}', 0, 0, 0, 1}}, 64, false},
		{"truncated_return", [][]byte{{'{', '}', 0, 0, 0}}, 64, false},
		{"trailing_bytes", [][]byte{{'{', '}', 0, 0, 0, 0, 1}}, 64, false},
		{"oversized", [][]byte{[]byte(`{"routes":{}}`), {0, 0, 0, 0}}, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			client.SetDeadline(time.Now().Add(time.Second))
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer server.Close()
				request := make([]byte, 128)
				_, _ = server.Read(request)
				for _, chunk := range tc.chunks {
					if _, err := server.Write(chunk); err != nil {
						return
					}
				}
			}()
			out, err := azureLANExportWire(client, "show bgp ipv4 unicast neighbors 169.254.21.2 advertised-routes json", tc.limit)
			if (err == nil) != tc.ok {
				t.Fatalf("expected success=%v", tc.ok)
			}
			if tc.ok && string(out) != `{"routes":{}}` {
				t.Fatal("reply mismatch")
			}
			client.Close()
			<-done
		})
	}
}
