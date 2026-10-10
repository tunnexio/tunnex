package ipsec

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// list-conns exposes semantic fields, not the original load-conn tree. Only
// fields actually returned by that protocol can be claimed as loaded readback.
func azureSchedulerLoadedMatch(events []viciMessage, engines []EngineTunnel, mode string) bool {
	if mode == "" {
		mode = "production"
	}
	if mode != "production" && mode != "accelerated" && mode != "rollback" {
		return false
	}
	if len(events) != len(engines) {
		return false
	}
	seen := map[string]bool{}
	for _, event := range events {
		if len(event) != 1 {
			return false
		}
		for name, value := range event {
			slot := -1
			for i, e := range engines {
				if name == engineName(e) {
					slot = i
				}
			}
			if slot < 0 || seen[name] || value.kind != 1 {
				return false
			}
			seen[name] = true
			e := engines[slot]
			m := value.section
			scalar := func(m viciMessage, k, want string) bool {
				got, ok := viciString(m, k)
				return ok && strings.EqualFold(got, want)
			}
			list := func(m viciMessage, k string, want []string) bool {
				got, ok := viciStrings(m, k)
				return ok && reflect.DeepEqual(got, want)
			}
			if !list(m, "local_addrs", []string{e.LocalAddress.String()}) || !list(m, "remote_addrs", []string{e.RemoteAddress.String()}) || !scalar(m, "version", "IKEv2") || !scalar(m, "reauth_time", "0") || !scalar(m, "dpd_delay", "10") || !scalar(m, "local_port", "500") || !scalar(m, "remote_port", "500") || !reflect.DeepEqual(m["proposals"], azureSchedulerExpectedProposal(true)) {
				return false
			}
			timer, _ := viciString(m, "rekey_time")
			accelerated := fmt.Sprint(120 + slot*30)
			if (mode == "production" && timer != "28800") || (mode == "accelerated" && timer != accelerated) || (mode == "rollback" && timer != "28800" && timer != accelerated) {
				return false
			}
			for key, v := range m {
				if strings.HasPrefix(key, "local-") || strings.HasPrefix(key, "remote-") {
					if (key != "local-1" && key != "remote-1") || v.kind != 1 {
						return false
					}
				}
			}
			for _, side := range []struct{ name, id string }{{"local-1", e.LocalIdentity.String()}, {"remote-1", e.RemoteIdentity.String()}} {
				auth := m[side.name]
				if auth.kind != 1 || !scalar(auth.section, "class", "pre-shared key") || !scalar(auth.section, "id", side.id) {
					return false
				}
				for key, v := range auth.section {
					if key == "class" || key == "id" {
						continue
					}
					if v.kind != 4 || len(v.list) != 0 {
						return false
					}
				}
			}
			kids := m["children"]
			if kids.kind != 1 || len(kids.section) != 1 {
				return false
			}
			child := kids.section[name]
			if child.kind != 1 {
				return false
			}
			c := child.section
			if !reflect.DeepEqual(c["esp_proposals"], azureSchedulerExpectedProposal(false)) || c["ah_proposals"].kind != 1 || len(c["ah_proposals"].section) != 0 {
				return false
			}
			if !scalar(c, "mode", "TUNNEL") || !scalar(c, "rekey_time", "3000") || !scalar(c, "rekey_bytes", "0") || !scalar(c, "rekey_packets", "0") || !scalar(c, "dpd_action", "none") || !scalar(c, "close_action", "none") || !list(c, "local-ts", []string{"0.0.0.0/0"}) || !list(c, "remote-ts", []string{"0.0.0.0/0"}) {
				return false
			}
			for _, key := range []string{"interface", "priority", "label"} {
				if _, ok := c[key]; ok {
					return false
				}
			}
		}
	}
	return len(seen) == len(engines)
}
func azureSchedulerVerifyLoaded(ctx context.Context, d *DaemonClient, engines []EngineTunnel, mode string) error {
	_, events, err := d.request(ctx, "list-conns", "list-conn", nil)
	if err != nil || ctx.Err() != nil || !azureSchedulerLoadedMatch(events, engines, mode) {
		return ErrDaemonProtocol
	}
	return nil
}
func azureSchedulerLoadMessages(engines []EngineTunnel, mode string) ([]viciMessage, error) {
	if mode != "production" && mode != "accelerated" {
		return nil, ErrDaemonProtocol
	}
	messages, err := azureSchedulerMessages(engines)
	if err != nil {
		return nil, err
	}
	if mode == "accelerated" {
		for i, msg := range messages {
			conn := msg[engineName(engines[i])].section
			conn["rekey_time"] = viciText(fmt.Sprintf("%ds", 120+i*30))
			conn["rand_time"] = viciText("0s")
			conn["over_time"] = viciText("2880s")
		}
	}
	return messages, nil
}
func azureSchedulerControl(ctx context.Context, d *DaemonClient, engines []EngineTunnel, action, mode string, slot int) error {
	if ctx.Err() != nil || d == nil || d.request == nil || (action != "verify" && action != "load-production" && action != "load-accelerated" && action != "terminate" && action != "initiate") {
		return ErrDaemonProtocol
	}
	if azureSchedulerVerifyLoaded(ctx, d, engines, mode) != nil {
		return ErrDaemonProtocol
	}
	switch action {
	case "verify":
		return ctx.Err()
	case "load-production", "load-accelerated":
		target := strings.TrimPrefix(action, "load-")
		messages, err := azureSchedulerLoadMessages(engines, target)
		if err != nil {
			return err
		}
		for _, message := range messages {
			if d.success(ctx, "load-conn", message) != nil {
				return ErrDaemonProtocol
			}
		}
		return azureSchedulerVerifyLoaded(ctx, d, engines, target)
	default:
		if slot < 1 || slot > len(engines) {
			return ErrDaemonProtocol
		}
		name := engineName(engines[slot-1])
		message := viciMessage{"ike": viciText(name), "timeout": viciText("20000")}
		if action == "initiate" {
			message["child"] = viciText(name)
		}
		if d.success(ctx, action, message) != nil || ctx.Err() != nil {
			return ErrDaemonProtocol
		}
		return nil
	}
}

func azureSchedulerLoadedFixture(engines []EngineTunnel, mode string) []viciMessage {
	out := []viciMessage{}
	for i, e := range engines {
		timer := "28800"
		if mode == "accelerated" {
			timer = fmt.Sprint(120 + i*30)
		}
		name := engineName(e)
		out = append(out, viciMessage{name: viciSection(viciMessage{"local_addrs": viciList(e.LocalAddress.String()), "remote_addrs": viciList(e.RemoteAddress.String()), "local_port": viciText("500"), "remote_port": viciText("500"), "proposals": azureSchedulerExpectedProposal(true), "version": viciText("IKEv2"), "reauth_time": viciText("0"), "rekey_time": viciText(timer), "dpd_delay": viciText("10"), "local-1": viciSection(viciMessage{"class": viciText("pre-shared key"), "id": viciText(e.LocalIdentity.String()), "groups": viciList()}), "remote-1": viciSection(viciMessage{"class": viciText("pre-shared key"), "id": viciText(e.RemoteIdentity.String()), "groups": viciList()}), "children": viciSection(viciMessage{name: viciSection(viciMessage{"esp_proposals": azureSchedulerExpectedProposal(false), "ah_proposals": viciSection(viciMessage{}), "mode": viciText("TUNNEL"), "rekey_time": viciText("3000"), "rekey_bytes": viciText("0"), "rekey_packets": viciText("0"), "dpd_action": viciText("none"), "close_action": viciText("none"), "local-ts": viciList("0.0.0.0/0"), "remote-ts": viciList("0.0.0.0/0")})})})})
	}
	return out
}
func TestAzureSchedulerLoadedSameNameDriftRefused(t *testing.T) {
	for _, profile := range []string{AzureActiveActiveBGPProfile, AzureActiveStandbyBGPProfile, AzureActiveActiveStaticProfile, AzureActiveStandbyStaticProfile} {
		m := azureMaterialFixture(profile)
		entry, _, _ := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
		engines := entry.Engines[:entry.Allocation.activeTunnelCount()]
		for _, mode := range []string{"production", "accelerated"} {
			events := azureSchedulerLoadedFixture(engines, mode)
			if !azureSchedulerLoadedMatch(events, engines, mode) {
				t.Fatal("valid readback refused")
			}
		}
		for _, field := range []string{"rekey_time", "reauth_time", "local_addrs", "remote_addrs", "version"} {
			events := azureSchedulerLoadedFixture(engines, "production")
			events[0][engineName(engines[0])].section[field] = viciText("drift")
			if azureSchedulerLoadedMatch(events, engines, "production") {
				t.Fatal("same-name drift admitted", field)
			}
		}
		events := azureSchedulerLoadedFixture(engines, "production")
		events[0][engineName(engines[0])].section["children"].section[engineName(engines[0])].section["local-ts"] = viciList("10.0.0.0/8")
		if azureSchedulerLoadedMatch(events, engines, "production") {
			t.Fatal("selector drift admitted")
		}
	}
}
func TestAzureSchedulerControlRefusesExpiredOrDriftBeforeMutation(t *testing.T) {
	m := azureMaterialFixture(AzureActiveStandbyBGPProfile)
	entry, _, _ := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	engines := entry.Engines[:1]
	calls := 0
	d := &DaemonClient{request: func(context.Context, string, string, viciMessage) (viciMessage, []viciMessage, error) {
		calls++
		return nil, nil, ErrDaemonProtocol
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if azureSchedulerControl(ctx, d, engines, "load-accelerated", "production", 0) == nil || calls != 0 {
		t.Fatal("expired proof mutated")
	}
	if azureSchedulerControl(context.Background(), d, engines, "load-accelerated", "production", 0) == nil || calls != 1 {
		t.Fatal("drift did not refuse before mutation")
	}
	for _, action := range []string{"rekey", "unload-conn", "load-shared"} {
		calls = 0
		if azureSchedulerControl(context.Background(), d, engines, action, "production", 0) == nil || calls != 0 {
			t.Fatal("unbounded action admitted")
		}
	}
}

func TestAzureSchedulerBoundControlUsesOnlyFixedRenderedCommands(t *testing.T) {
	m := azureMaterialFixture(AzureActiveActiveBGPProfile)
	entry, _, _ := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	engines := entry.Engines[:2]
	mode := "production"
	loaded := 0
	calls := []string{}
	d := &DaemonClient{request: func(ctx context.Context, command, event string, msg viciMessage) (viciMessage, []viciMessage, error) {
		calls = append(calls, command)
		if command == "list-conns" {
			if event != "list-conn" {
				t.Fatal("incorrect event")
			}
			return nil, azureSchedulerLoadedFixture(engines, mode), nil
		}
		if command == "load-conn" {
			if len(msg) != 1 {
				t.Fatal("arbitrary config")
			}
			loaded++
			expected, _ := azureSchedulerLoadMessages(engines, "accelerated")
			if !reflect.DeepEqual(msg, expected[loaded-1]) {
				t.Fatal("rendered material changed")
			}
			if loaded == 2 {
				mode = "accelerated"
			}
		}
		if command == "terminate" || command == "initiate" {
			if ike, _ := viciString(msg, "ike"); ike != engineName(engines[0]) {
				t.Fatal("unowned name")
			}
			if timeout, _ := viciString(msg, "timeout"); timeout != "20000" {
				t.Fatal("unbounded timeout")
			}
		}
		return viciMessage{"success": viciText("yes")}, nil, nil
	}}
	if azureSchedulerControl(context.Background(), d, engines, "load-accelerated", "production", 0) != nil {
		t.Fatal("valid load refused")
	}
	for _, action := range []string{"terminate", "initiate"} {
		if azureSchedulerControl(context.Background(), d, engines, action, "accelerated", 1) != nil {
			t.Fatal("owned action refused")
		}
	}
	for _, command := range calls {
		if command != "list-conns" && command != "load-conn" && command != "terminate" && command != "initiate" {
			t.Fatal("unexpected control")
		}
	}
	// A rollback may see a legitimate partial load but each timer must still be
	// one of the two pinned values. Arbitrary same-name timers remain refused.
	events := azureSchedulerLoadedFixture(engines, "production")
	events[0][engineName(engines[0])].section["rekey_time"] = viciText("120")
	if !azureSchedulerLoadedMatch(events, engines, "rollback") {
		t.Fatal("partial owned rollback refused")
	}
	events[0][engineName(engines[0])].section["rekey_time"] = viciText("121")
	if azureSchedulerLoadedMatch(events, engines, "rollback") {
		t.Fatal("unowned rollback timer admitted")
	}
}

func TestAzureSchedulerLoadedReadDeadlineCannotAuthorizeMutation(t *testing.T) {
	m := azureMaterialFixture(AzureActiveStandbyStaticProfile)
	e, _, _ := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	engines := e.Engines[:1]
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	d := &DaemonClient{request: func(context.Context, string, string, viciMessage) (viciMessage, []viciMessage, error) {
		calls++
		cancel()
		return nil, azureSchedulerLoadedFixture(engines, "production"), nil
	}}
	if azureSchedulerControl(ctx, d, engines, "load-accelerated", "production", 0) == nil || calls != 1 {
		t.Fatal("expired completed read authorized mutation")
	}
}

func azureSchedulerExpectedProposal(ike bool) viciValue {
	transforms := viciMessage{"encr": viciList("AES_CBC_256"), "integ": viciList("HMAC_SHA2_256_128"), "ke": viciList("MODP_2048")}
	if ike {
		transforms["prf"] = viciList("PRF_HMAC_SHA2_256")
	} else {
		transforms["sn"] = viciList("NO_EXT_SEQ")
	}
	return viciSection(viciMessage{"0": viciSection(transforms)})
}

func TestAzureSchedulerStrongSwan61SemanticReadbackRefusals(t *testing.T) {
	for _, profile := range []string{AzureActiveActiveBGPProfile, AzureActiveStandbyBGPProfile, AzureActiveActiveStaticProfile, AzureActiveStandbyStaticProfile} {
		m := azureMaterialFixture(profile)
		e, _, _ := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
		engines := e.Engines[:e.Allocation.activeTunnelCount()]
		for name, mutate := range map[string]func(viciMessage){
			"non-PSK-auth":          func(c viciMessage) { c["local-1"].section["class"] = viciText("public key") },
			"unexpected-auth-round": func(c viciMessage) { c["local-2"] = c["local-1"] },
			"restart-DPD": func(c viciMessage) {
				c["children"].section[engineName(engines[0])].section["dpd_action"] = viciText("start")
			},
			"trap-DPD": func(c viciMessage) {
				c["children"].section[engineName(engines[0])].section["dpd_action"] = viciText("trap")
			},
			"weak-IKE-proposal":  func(c viciMessage) { c["proposals"].section["0"].section["encr"] = viciList("AES_CBC_128") },
			"extra-IKE-proposal": func(c viciMessage) { c["proposals"].section["1"] = c["proposals"].section["0"] },
			"weak-ESP-proposal": func(c viciMessage) {
				c["children"].section[engineName(engines[0])].section["esp_proposals"].section["0"].section["integ"] = viciList("HMAC_SHA1_96")
			},
			"AH-proposal": func(c viciMessage) {
				c["children"].section[engineName(engines[0])].section["ah_proposals"] = azureSchedulerExpectedProposal(false)
			},
			"wrong-configured-port": func(c viciMessage) { c["remote_port"] = viciText("4500") },
		} {
			t.Run(profile+"/"+name, func(t *testing.T) {
				events := azureSchedulerLoadedFixture(engines, "production")
				mutate(events[0][engineName(engines[0])].section)
				if azureSchedulerLoadedMatch(events, engines, "production") {
					t.Fatal("changed semantic readback admitted")
				}
			})
		}
	}
}
