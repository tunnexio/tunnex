//go:build linux

package ipsec

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestNativeOwnedCHILDRekeyOverlap(t *testing.T) {
	if os.Getenv("TUNNEX_IPSEC_ENCRYPTED_LAB") != "1" {
		t.Skip("disconnected owned fixture only")
	}
	var req engineLabRequest
	dec := json.NewDecoder(io.LimitReader(os.Stdin, 4097))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil || req.Role != "gateway" || !req.BGP {
		t.Fatal("invalid lab request")
	}
	cfg := engineLabTunnels(req.Role)[0]
	cfg.BGP = true
	daemon, e := NewDaemonClient("/run/tunnex-ipsec/charon.vici")
	if e != nil {
		t.Fatal(e)
	}
	kr, e := NewKernelReader("/sbin/ip")
	if e != nil {
		t.Fatal(e)
	}
	xr, e := NewXFRMReader("/sbin/ip")
	if e != nil {
		t.Fatal(e)
	}
	// Legacy isolated stage fixture requests reqid0 (charon allocates it).
	// Bind its actual value once from the exact staged child, before observation;
	// all later daemon and independent XFRM evidence must retain that identity.
	initial, err := daemon.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, sa := range initial.SAs {
		if sa.Name == engineName(cfg) && sa.Established && len(sa.Children) == 1 {
			c := sa.Children[0]
			if c.Name != engineName(cfg) || c.IfIDIn != cfg.XFRMID || c.IfIDOut != cfg.XFRMID || !sameEnginePrefixes(c.LocalPrefixes, engineTransportPrefixes(cfg, true)) || !sameEnginePrefixes(c.RemotePrefixes, engineTransportPrefixes(cfg, false)) || c.ReqID == 0 {
				t.Fatal("unbound initial child")
			}
			cfg.ReqID = c.ReqID
		}
	}
	if cfg.ReqID == 0 {
		t.Fatal("no exact initial child")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()
	type child struct {
		ID        uint64
		In, Out   uint32
		Installed bool
		State     string
	}
	type sample struct {
		MS       int64
		Status   string
		Children []child
		States   []uint32
	}
	rows := []sample{}
	observe := func() sample {
		d, e := daemon.Inspect(ctx)
		if e != nil {
			t.Fatal(e)
		}
		k, e := kr.Read(ctx)
		if e != nil {
			t.Fatal(e)
		}
		x, e := xr.Read(ctx)
		if e != nil {
			t.Fatal(e)
		}
		var own Ownership
		for _, l := range k.Links {
			if l.XFRMID == cfg.XFRMID {
				own = Ownership{Namespace: k.Namespace, InterfaceName: l.Name, InterfaceIndex: l.Index, XFRMID: l.XFRMID}
			}
		}
		if own.InterfaceIndex == 0 {
			t.Fatal("owned link missing")
		}
		row := sample{Status: runtimeTunnelStatus(cfg, own, d, k, x), Children: []child{}, States: []uint32{}}
		for _, sa := range d.SAs {
			if sa.Name == engineName(cfg) {
				for _, c := range sa.Children {
					if c.Name != engineName(cfg) || c.ReqID != cfg.ReqID || c.IfIDIn != cfg.XFRMID || c.IfIDOut != cfg.XFRMID || !sameEnginePrefixes(c.LocalPrefixes, engineTransportPrefixes(cfg, true)) || !sameEnginePrefixes(c.RemotePrefixes, engineTransportPrefixes(cfg, false)) {
						t.Fatal("foreign child")
					}
					row.Children = append(row.Children, child{c.UniqueID, c.SPIIn, c.SPIOut, c.Installed, c.State})
				}
			}
		}
		for _, s := range x.States {
			if s.IfID == cfg.XFRMID || s.ReqID == cfg.ReqID {
				if s.IfID != cfg.XFRMID || s.ReqID != cfg.ReqID {
					t.Fatal("foreign state")
				}
				row.States = append(row.States, s.SPI)
			}
		}
		return row
	}
	before := observe()
	if before.Status != "up" || len(before.Children) != 1 {
		t.Fatal("baseline", before)
	}
	start := time.Now()
	cmd := exec.CommandContext(ctx, "/opt/tunnex-ipsec/sbin/swanctl", "--rekey", "--child", engineName(cfg), "--uri", "unix:///run/tunnex-ipsec/charon.vici")
	cmd.Env = append(os.Environ(), "STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf")
	if e := cmd.Run(); e != nil {
		t.Fatal("owned rekey", e)
	}
	captured := false
	for time.Since(start) < 10*time.Second {
		r := observe()
		r.MS = time.Since(start).Milliseconds()
		rows = append(rows, r)
		if !captured && len(r.Children) > 1 {
			captured = true
			evidence := exec.CommandContext(ctx, "/opt/tunnex-ipsec/sbin/swanctl", "--list-sas", "--raw", "--uri", "unix:///run/tunnex-ipsec/charon.vici")
			evidence.Env = append(os.Environ(), "STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf")
			raw, err := evidence.Output()
			if err != nil {
				t.Fatal("raw overlap state", err)
			}
			t.Log("OVERLAP_VICI " + string(raw))
		}
		time.Sleep(50 * time.Millisecond)
	}
	after := observe()
	raw, _ := json.Marshal(struct {
		Before  sample
		Samples []sample
		After   sample
	}{before, rows, after})
	t.Log("REKEY_EVIDENCE " + string(raw))
	for _, r := range rows {
		if r.Status != "up" {
			t.Fatal("handover continuity", r)
		}
	}
	if after.Status != "up" || len(after.Children) != 1 || after.Children[0].In == before.Children[0].In {
		t.Fatal("fresh final", after)
	}
}
