// Command tunnelctl is a DEV-ONLY driver for the S6.3 mini-smoke: it speaks the
// helper protocol directly so the tunnel + kill-switch can be validated on a Mac
// WITHOUT the full Electron app / ConfigProvider. NOT shipped. It must live inside
// the helper's install dir to pass the caller-path check.
//
//	tunnelctl up   <wg.conf> [--full]   connect, tunnel_up, HOLD the owner
//	                                    connection (heartbeat) until Ctrl-C
//	tunnelctl status                    one-shot status
//	tunnelctl down                      one-shot graceful down
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tunnexio/tunnex/apps/helper"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: tunnelctl up <wg.conf> [--full] | status | down")
		os.Exit(2)
	}
	sock := helper.DefaultSocketPath()
	switch os.Args[1] {
	case "up":
		if len(os.Args) < 3 {
			fatal("up needs a .conf path")
		}
		full := len(os.Args) > 3 && os.Args[3] == "--full"
		cfg := parseConf(mustRead(os.Args[2]), full)
		conn := dial(sock)
		resp := call(conn, &helper.Request{Version: helper.ProtocolVersion, AuthMode: helper.AuthModePathCheck, Verb: helper.VerbTunnelUp, Config: cfg})
		printResp(resp)
		if !resp.OK {
			os.Exit(1)
		}
		hold(conn) // keep the owner connection open so the tunnel stays up
	case "status":
		conn := dial(sock)
		printResp(call(conn, &helper.Request{Version: helper.ProtocolVersion, AuthMode: helper.AuthModePathCheck, Verb: helper.VerbStatus}))
	case "down":
		conn := dial(sock)
		printResp(call(conn, &helper.Request{Version: helper.ProtocolVersion, AuthMode: helper.AuthModePathCheck, Verb: helper.VerbTunnelDown}))
	default:
		fatal("unknown command " + os.Args[1])
	}
}

// hold heartbeats a status every 10s (keeps the owner connection alive under the
// helper's 30s read deadline) and blocks until Ctrl-C, then sends a graceful down.
func hold(conn net.Conn) {
	fmt.Println(">> tunnel up; holding connection (Ctrl-C to disconnect). To test the")
	fmt.Println(">> kill-switch, `sudo kill -9` the HELPER from another terminal.")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			r, err := helper.Do(conn, &helper.Request{Version: helper.ProtocolVersion, AuthMode: helper.AuthModePathCheck, Verb: helper.VerbStatus})
			if err != nil {
				fmt.Println(">> helper connection lost:", err)
				return
			}
			if r.Status != nil {
				fmt.Printf(">> status: state=%s hs=%ds rx=%d tx=%d\n", r.Status.State, r.Status.LastHandshakeSec, r.Status.RxBytes, r.Status.TxBytes)
			}
		case <-sig:
			_, _ = helper.Do(conn, &helper.Request{Version: helper.ProtocolVersion, AuthMode: helper.AuthModePathCheck, Verb: helper.VerbTunnelDown})
			fmt.Println(">> disconnected.")
			return
		}
	}
}

func dial(sock string) net.Conn {
	c, err := net.Dial("unix", sock)
	if err != nil {
		fatal("dial helper: " + err.Error())
	}
	return c
}

func call(conn net.Conn, req *helper.Request) *helper.Response {
	r, err := helper.Do(conn, req)
	if err != nil {
		fatal("request: " + err.Error())
	}
	return r
}

func printResp(r *helper.Response) {
	b, _ := json.MarshalIndent(r, "", "  ")
	fmt.Println(string(b))
}

func mustRead(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		fatal("read conf: " + err.Error())
	}
	return string(b)
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "tunnelctl:", msg)
	os.Exit(1)
}

// parseConf turns a WireGuard .conf into a helper.TunnelConfig (mirrors the TS
// wgconf parser). full sets the full_tunnel intent (helper enforces both families).
func parseConf(text string, full bool) *helper.TunnelConfig {
	iface := map[string]string{}
	peer := map[string]string{}
	sec := ""
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if line == "" {
			continue
		}
		switch strings.ToLower(line) {
		case "[interface]":
			sec = "i"
			continue
		case "[peer]":
			sec = "p"
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		if sec == "i" {
			iface[k] = v
		} else if sec == "p" {
			peer[k] = v
		}
	}
	split := func(s string) []string {
		var out []string
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	cfg := &helper.TunnelConfig{
		PrivateKey:    iface["privatekey"],
		Address:       strings.Split(iface["address"], ",")[0],
		DNS:           split(iface["dns"]),
		PeerPublicKey: peer["publickey"],
		Endpoint:      peer["endpoint"],
		AllowedIPs:    split(peer["allowedips"]),
		FullTunnel:    full,
	}
	cfg.Address = strings.TrimSpace(cfg.Address)
	fmt.Sscanf(iface["mtu"], "%d", &cfg.MTU)
	fmt.Sscanf(peer["persistentkeepalive"], "%d", &cfg.PersistentKeepalive)
	return cfg
}
