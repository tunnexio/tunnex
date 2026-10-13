//go:build linux

package ipsec

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Fixed commands modify only the standalone synthetic peer's export policy.
func TestBGPMEDFixture(t *testing.T) {
	if os.Getenv("TUNNEX_BGP_MED_LAB") != "1" {
		t.Skip("native synthetic peer only")
	}
	action := os.Getenv("TUNNEX_BGP_MED_ACTION")
	commands := []string{"configure terminal"}
	switch action {
	case "initial", "flip":
		commands = append(commands, "ip prefix-list TNX-MED-FIRST seq 10 permit 10.20.0.0/24", "ip prefix-list TNX-MED-SECOND seq 10 permit 10.30.0.0/24")
		for slot := 1; slot <= 2; slot++ {
			for seq := 1; seq <= 2; seq++ {
				metric := 10
				if slot == seq {
					metric = 100
				}
				if action == "flip" {
					metric = 110 - metric
				}
				name := []string{"FIRST", "SECOND"}[seq-1]
				commands = append(commands, fmt.Sprintf("route-map TNX-MED%d permit %d", slot, seq*10), "match ip address prefix-list TNX-MED-"+name, fmt.Sprintf("set metric %d", metric), "exit")
			}
			commands = append(commands, fmt.Sprintf("route-map TNX-MED%d deny 100", slot), "exit")
		}
		commands = append(commands, "router bgp 64512", "address-family ipv4 unicast", "neighbor 169.254.20.1 route-map TNX-MED1 out", "neighbor 169.254.20.5 route-map TNX-MED2 out", "end", "clear bgp ipv4 unicast 169.254.20.1 soft out", "clear bgp ipv4 unicast 169.254.20.5 soft out")
	case "withdraw-first":
		commands = append(commands, "router bgp 64512", "address-family ipv4 unicast", "no network 10.20.0.0/24", "end")
	case "lose-slot1":
		commands = append(commands, "router bgp 64512", "neighbor 169.254.20.1 shutdown", "end")
	default:
		t.Fatal("unknown fixed fixture action")
	}
	args := []string{"--vty_socket", "/run/tunnex-bgp", "-d", "bgpd"}
	for _, c := range commands {
		args = append(args, "-c", c)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(ctx, "/opt/tunnex-bgp/vtysh", args...).CombinedOutput()
	if err != nil {
		t.Fatal("fixture policy rejected", err, string(raw))
	}
	t.Log("fixed standalone peer action", action)
}
