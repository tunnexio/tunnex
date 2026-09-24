package ipsec

import (
	"context"
	"testing"
)

func TestDaemonStagesExplicitOwnedReqID(t *testing.T) {
	cfg := daemonFixture()
	cfg.ReqID = 701
	loaded := false
	c := &DaemonClient{request: func(_ context.Context, cmd, event string, m viciMessage) (viciMessage, []viciMessage, error) {
		switch cmd {
		case "get-conns":
			return viciMessage{"conns": viciList()}, nil, nil
		case "get-shared":
			return viciMessage{"keys": viciList()}, nil, nil
		case "load-conn":
			child := m[engineName(cfg)].section["children"].section[engineName(cfg)].section
			if string(child["reqid"].scalar) != "701" {
				t.Fatal("daemon allocated unbound reqid")
			}
			loaded = true
		}
		return viciMessage{"success": viciText("yes")}, nil, nil
	}}
	if err := c.stageTunnel(context.Background(), cfg, []byte("Synthetic_PSK_123")); err != nil || !loaded {
		t.Fatal("stage failed")
	}
}
func TestDaemonCleanupRefusesForeignReqID(t *testing.T) {
	cfg := daemonFixture()
	cfg.ReqID = 701
	event := daemonSAFixture()
	ike := event["owned"].section
	ike["name"] = viciText(engineName(cfg))
	child := ike["child-sas"].section["child-1"].section
	child["name"] = viciText(engineName(cfg))
	child["reqid"] = viciText("702")
	mutations := 0
	c := daemonInventoryStub([]viciMessage{{engineName(cfg): viciSection(ike)}}, viciMessage{}, &mutations)
	if c.removeTunnel(context.Background(), cfg) == nil || mutations != 0 {
		t.Fatal("foreign reqid mutation allowed")
	}
}
