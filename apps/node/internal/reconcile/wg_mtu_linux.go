//go:build linux

package reconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

func (b *wgctrlBackend) underlayMTU(ctx context.Context) (int, error) {
	devices := map[string]bool{}
	for _, family := range []string{"-4", "-6"} {
		out, err := b.runCommand(ctx, "ip", "-j", family, "route", "show", "default")
		if err != nil {
			return 0, err
		}
		var routes []struct {
			Dst      string          `json:"dst"`
			Dev      string          `json:"dev"`
			Type     string          `json:"type"`
			Nexthops json.RawMessage `json:"nexthops"`
		}
		if err := json.Unmarshal([]byte(out), &routes); err != nil {
			return 0, err
		}
		for _, r := range routes {
			if r.Dst != "default" || r.Dev == "" || r.Dev == b.iface || (r.Type != "" && r.Type != "unicast") || len(r.Nexthops) != 0 || strings.ContainsAny(r.Dev, " /\t\n") {
				return 0, fmt.Errorf("unqualified default route")
			}
			devices[r.Dev] = true
		}
	}
	if len(devices) == 0 {
		return 0, fmt.Errorf("no underlay default route")
	}
	minimum := 65536
	for dev := range devices {
		out, err := b.runCommand(ctx, "ip", "-j", "-d", "link", "show", "dev", dev)
		if err != nil {
			return 0, err
		}
		var links []struct {
			Name  string   `json:"ifname"`
			Index int      `json:"ifindex"`
			MTU   int      `json:"mtu"`
			Flags []string `json:"flags"`
			Info  struct {
				Kind string `json:"info_kind"`
			} `json:"linkinfo"`
		}
		if err := json.Unmarshal([]byte(out), &links); err != nil {
			return 0, err
		}
		if len(links) != 1 {
			return 0, fmt.Errorf("unqualified underlay link")
		}
		l := links[0]
		up := false
		for _, f := range l.Flags {
			if f == "UP" {
				up = true
			}
		}
		if l.Name != dev || l.Index <= 0 || !up || l.MTU < 1280 || l.MTU > 65535 || l.Info.Kind == "wireguard" || l.Info.Kind == "xfrm" || l.Info.Kind == "tun" {
			return 0, fmt.Errorf("unqualified underlay link")
		}
		if l.MTU < minimum {
			minimum = l.MTU
		}
	}
	return minimum, nil
}

// AppliedMTU is reportable only after a successful owner Configure and exact
// current link readback. Failed attempts clear the report, never advertise a
// merely calculated ceiling.
func (b *wgctrlBackend) AppliedMTU() int { return int(b.appliedMTU.Load()) }

func (b *wgctrlBackend) verifyAppliedMTU(ctx context.Context, mtu int) error {
	out, err := b.runCommand(ctx, "ip", "-j", "link", "show", "dev", b.iface)
	if err != nil {
		return err
	}
	var links []struct {
		Name  string   `json:"ifname"`
		MTU   int      `json:"mtu"`
		Flags []string `json:"flags"`
	}
	if err := json.Unmarshal([]byte(out), &links); err != nil {
		return err
	}
	if len(links) != 1 || links[0].Name != b.iface || links[0].MTU != mtu {
		return fmt.Errorf("WireGuard MTU readback mismatch")
	}
	up := false
	for _, f := range links[0].Flags {
		if f == "UP" {
			up = true
		}
	}
	if !up {
		return fmt.Errorf("WireGuard link not up")
	}
	b.appliedMTU.Store(int64(mtu))
	return nil
}
