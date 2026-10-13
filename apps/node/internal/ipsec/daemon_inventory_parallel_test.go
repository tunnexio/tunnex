package ipsec

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

var inventoryReadQueries = []string{"stats", "get-algorithms", "get-conns", "get-shared", "list-sas"}

func TestDaemonIndependentInspectVersionBarrierAndJoin(t *testing.T) {
	mutations := 0
	base := daemonInventoryStub([]viciMessage{daemonSAFixture()}, viciMessage{}, &mutations)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	began := make(chan string, 5)
	release := make(chan struct{})
	done := make(chan error, 1)
	var version atomic.Bool
	c := &DaemonClient{request: func(child context.Context, command, event string, m viciMessage) (viciMessage, []viciMessage, error) {
		if command == "version" {
			if child != ctx {
				t.Error("version caller context changed")
			}
			version.Store(true)
			return base.request(child, command, event, m)
		}
		if !version.Load() {
			t.Error("query before version validation")
		}
		a, aok := ctx.Deadline()
		b, bok := child.Deadline()
		if !aok || !bok || a != b {
			t.Error("deadline changed")
		}
		// Every concurrent query receives a fresh independently mutable map.
		m[command] = viciText("independent synthetic request")
		began <- command
		select {
		case <-release:
		case <-child.Done():
			return nil, nil, child.Err()
		}
		return base.request(child, command, event, viciMessage{})
	}}
	go func() { _, err := c.independentReadClient().Inspect(ctx); done <- err }()
	seen := map[string]bool{}
	for range inventoryReadQueries {
		select {
		case command := <-began:
			seen[command] = true
		case <-ctx.Done():
			t.Fatal("five queries did not overlap")
		}
	}
	if len(seen) != 5 {
		t.Fatal("duplicate or missing query", seen)
	}
	select {
	case <-done:
		t.Fatal("returned before queries finished")
	default:
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("queries not joined")
	}
	if mutations != 0 {
		t.Fatal("inventory mutated daemon")
	}
}

func TestDaemonIndependentInspectErrorCancelsAndJoins(t *testing.T) {
	for _, failure := range append(append([]string{}, inventoryReadQueries...), "parent") {
		t.Run(failure, func(t *testing.T) {
			mutations := 0
			base := daemonInventoryStub(nil, viciMessage{}, &mutations)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started := make(chan string, 5)
			fail := make(chan struct{})
			canceled := make(chan string, 5)
			unwind := make(chan struct{})
			done := make(chan error, 1)
			c := &DaemonClient{request: func(child context.Context, command, event string, m viciMessage) (viciMessage, []viciMessage, error) {
				if command == "version" {
					return base.request(child, command, event, m)
				}
				started <- command
				if command == failure {
					<-fail
					return nil, nil, ErrDaemonProtocol
				}
				<-child.Done()
				canceled <- command
				<-unwind
				return nil, nil, child.Err()
			}}
			go func() { _, err := c.independentReadClient().Inspect(ctx); done <- err }()
			for range inventoryReadQueries {
				select {
				case <-started:
				case <-time.After(time.Second):
					t.Fatal("query missing")
				}
			}
			if failure == "parent" {
				cancel()
			} else {
				close(fail)
			}
			count := 4
			if failure == "parent" {
				count = 5
			}
			for i := 0; i < count; i++ {
				select {
				case <-canceled:
				case <-time.After(time.Second):
					t.Fatal("sibling not canceled")
				}
			}
			select {
			case <-done:
				t.Fatal("returned before every child unwound")
			default:
			}
			close(unwind)
			select {
			case err := <-done:
				if err != ErrDaemonProtocol {
					t.Fatal("unsafe/nonstatic result", err)
				}
			case <-time.After(time.Second):
				t.Fatal("not joined")
			}
		})
	}
}

func TestDaemonIndependentInspectPreservesValidationAndLegacyHooks(t *testing.T) {
	for _, kind := range []string{"version", "plugins", "algorithms", "conns_duplicate", "conns_invalid", "keys_duplicate", "keys_invalid", "terminal", "sa"} {
		t.Run(kind, func(t *testing.T) {
			mutations := 0
			base := daemonInventoryStub([]viciMessage{daemonSAFixture()}, viciMessage{}, &mutations)
			var calls atomic.Int32
			c := &DaemonClient{request: func(ctx context.Context, command, event string, m viciMessage) (viciMessage, []viciMessage, error) {
				calls.Add(1)
				out, events, err := base.request(ctx, command, event, m)
				switch {
				case kind == "version" && command == "version":
					out["version"] = viciText("unknown")
				case kind == "plugins" && command == "stats":
					out["plugins"] = viciList("vici")
				case kind == "algorithms" && command == "get-algorithms":
					out = viciMessage{}
				case kind == "conns_duplicate" && command == "get-conns":
					out["conns"] = viciList("one", "one")
				case kind == "conns_invalid" && command == "get-conns":
					out["conns"] = viciList("invalid\nname")
				case kind == "keys_duplicate" && command == "get-shared":
					out["keys"] = viciList("one", "one")
				case kind == "keys_invalid" && command == "get-shared":
					out["keys"] = viciList("")
				case kind == "terminal" && command == "list-sas":
					out = viciMessage{"success": viciText("no")}
				case kind == "sa" && command == "list-sas":
					events = []viciMessage{{"unexpected": viciSection(viciMessage{})}}
				}
				return out, events, err
			}}
			if _, err := c.independentReadClient().Inspect(context.Background()); err != ErrDaemonProtocol {
				t.Fatal("original validation bypassed", kind, err)
			}
			if kind == "version" && calls.Load() != 1 {
				t.Fatal("unvalidated version launched queries")
			}
			if mutations != 0 {
				t.Fatal("mutating command")
			}
		})
	}
	mutations := 0
	base := daemonInventoryStub(nil, viciMessage{}, &mutations)
	ctx := context.Background()
	var order []string
	c := &DaemonClient{request: func(child context.Context, command, event string, m viciMessage) (viciMessage, []viciMessage, error) {
		if child != ctx {
			t.Error("legacy hook context changed")
		}
		order = append(order, command)
		return base.request(child, command, event, m)
	}}
	if _, err := c.Inspect(ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, append([]string{"version"}, inventoryReadQueries...)) {
		t.Fatal("legacy injected order changed", order)
	}
}

func TestDaemonIndependentInspectActualOwnedTransport(t *testing.T) {
	// Use a short portable path, then resolve /tmp on platforms where it is a symlink.
	dir, err := os.MkdirTemp("/tmp", "vici-parallel-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	canonical, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(canonical, "s")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err = os.Chmod(socket, 0600); err != nil {
		t.Fatal(err)
	}
	mutations := 0
	stub := daemonInventoryStub([]viciMessage{daemonSAFixture()}, viciMessage{}, &mutations)
	started := make(chan string, 5)
	release := make(chan struct{})
	serverErrors := make(chan error, 6)
	var connections atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func(conn net.Conn) {
				defer conn.Close()
				packet, err := readVICIPacket(conn)
				event := ""
				if err != nil {
					serverErrors <- err
					return
				}
				if packet[0] == 3 {
					event = string(packet[2 : 2+int(packet[1])])
					if err = writeVICIPacket(conn, []byte{5}); err != nil {
						serverErrors <- err
						return
					}
					packet, err = readVICIPacket(conn)
					if err != nil {
						serverErrors <- err
						return
					}
				}
				if len(packet) < 2 || packet[0] != 0 || int(packet[1])+2 > len(packet) {
					serverErrors <- ErrDaemonProtocol
					return
				}
				command := string(packet[2 : 2+int(packet[1])])
				if command != "version" {
					started <- command
					<-release
				}
				terminal, events, err := stub.request(context.Background(), command, event, viciMessage{})
				if err != nil {
					serverErrors <- err
					return
				}
				for _, m := range events {
					body, _ := encodeVICI(m)
					p, _ := viciNamedPacket(7, event, body)
					if err = writeVICIPacket(conn, p); err != nil {
						serverErrors <- err
						return
					}
				}
				body, _ := encodeVICI(terminal)
				if err = writeVICIPacket(conn, append([]byte{1}, body...)); err != nil {
					serverErrors <- err
					return
				}
			}(conn)
		}
	}()
	c, err := NewDaemonClient(socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		inventory, err := c.Inspect(ctx)
		if err == nil && (len(inventory.SAs) != 1 || inventory.Version != "6.1.0") {
			err = ErrDaemonProtocol
		}
		done <- err
	}()
	seen := map[string]bool{}
	for range inventoryReadQueries {
		select {
		case command := <-started:
			seen[command] = true
		case err := <-serverErrors:
			t.Fatal(err)
		case <-ctx.Done():
			t.Fatal("owned connections did not overlap")
		}
	}
	if len(seen) != 5 || connections.Load() != 6 {
		t.Fatal("not six independent actual connections", seen, connections.Load())
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("owned transport did not finish")
	}
	if mutations != 0 {
		t.Fatal("real transport requested mutation")
	}
	select {
	case err := <-serverErrors:
		t.Fatal(err)
	default:
	}
}
