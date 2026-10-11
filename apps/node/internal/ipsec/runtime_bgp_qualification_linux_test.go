//go:build linux

package ipsec

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"os"
	"testing"
	"time"
)

type qualificationNoLease struct{}

func (qualificationNoLease) RenewIPsecLease(context.Context, uuid.UUID, RuntimeLeaseRequest) (RuntimeLease, error) {
	return RuntimeLease{}, ErrRuntimeController
}

func TestBGPControllerQualificationNative(t *testing.T) {
	if os.Getenv("TUNNEX_BGP_CONTROLLER_QUALIFICATION_LAB") != "1" {
		t.Skip("isolated native actual receipt fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	dir := "/run/bgp-controller-qualification"
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	daemon, err := StartDaemonProcess(ctx)
	if err != nil {
		t.Fatal("managed daemon", err)
	}
	defer daemon.Close()
	environment, err := NewRuntimeEnvironmentInspector("/sbin/ip", "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	controller, err := NewRuntimeController(RuntimeControllerConfig{OrgID: uuid.New(), GatewayID: uuid.New(), JournalDir: dir, IPPath: "/sbin/ip", NFTPath: "/usr/sbin/nft", Daemon: daemon.Client, DaemonAlive: daemon.Alive, Environment: environment}, qualificationNoLease{})
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	if err = controller.Start(ctx); err != nil {
		t.Fatal("empty actual controller", err)
	}
	base, err := ProbeRuntimePlatform(ctx, "/sbin/ip", "/usr/sbin/nft", daemon.Client, daemon.Alive)
	if err != nil {
		t.Fatal("actual base platform", err)
	}
	if err = controller.AttachQualification(base); err != nil {
		t.Fatal("base binding", err)
	}
	receipt, err := bgpengine.QualifyPreflight(ctx, dir)
	if err != nil {
		t.Fatal("actual no-peer preflight", err)
	}
	if err = controller.AttachBGPQualification(receipt); err != nil {
		t.Fatal("actual BGP binding", err)
	}
	ns, err := controller.namespace()
	if err != nil || !receipt.Current() || receipt.Namespace() != ns || controller.bgpQualification != receipt || controller.Capability() != 1 {
		t.Fatal("current actual receipt not bound", err)
	}
	if err = controller.AttachBGPQualification(receipt); err == nil {
		t.Fatal("qualification rebound")
	}
	expected := 0
	if bgpLifecycleAccepted {
		expected = 1
	}
	before := controller.BGPCapability()
	if controller.AzureBGPRecreationCapability() != expected {
		t.Fatal("new capability not bound to actual qualification")
	}
	if before != expected {
		t.Fatal("lifecycle gate not respected", before)
	}
	if err = controller.Close(); err != nil {
		t.Fatal("owned controller close", err)
	}
	if controller.BGPCapability() != 0 || controller.Capability() != 0 || controller.AzureBGPRecreationCapability() != 0 {
		t.Fatal("closed controller advertises support")
	}
	proof := map[string]any{"actual_namespace": ns, "base_capability": 1, "bgp_capability_before_close": before, "bgp_capability_after_close": 0, "actual_preflight_current": receipt.Current(), "one_shot_binding": true, "lease_authority": "none; lease client always refuses", "configured_peers": 0}
	raw, _ := json.Marshal(proof)
	if err = os.WriteFile("/run/bgp-controller-qualification.json", raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("BGP_CONTROLLER_ACTUAL_QUALIFICATION_PASS")
}
