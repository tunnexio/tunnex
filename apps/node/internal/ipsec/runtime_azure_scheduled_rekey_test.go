package ipsec

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// Configuration comes from the real stage material constructor with a mock
// transport. Neither credential material nor a daemon mutation escapes it.
func azureSchedulerConfig(engines []EngineTunnel) (string, error) {
	out := "connections {\n"
	for _, engine := range engines {
		if !IsAzureRuntimeProfile(engine.ProfileID) || !validEngineTunnel(engine) {
			return "", ErrDaemonProtocol
		}
		var connection viciMessage
		mock := &DaemonClient{request: func(_ context.Context, command, _ string, message viciMessage) (viciMessage, []viciMessage, error) {
			switch command {
			case "get-conns":
				return viciMessage{"conns": viciList()}, nil, nil
			case "get-shared":
				return viciMessage{"keys": viciList()}, nil, nil
			case "load-shared":
				return viciMessage{"success": viciText("yes")}, nil, nil
			case "load-conn":
				connection = message
				return viciMessage{"success": viciText("yes")}, nil, nil
			default:
				return nil, nil, ErrDaemonProtocol
			}
		}}
		if mock.stageTunnel(context.Background(), engine, []byte("mock-only-unused")) != nil {
			return "", ErrDaemonProtocol
		}
		text, err := azureSchedulerSection(connection, "  ")
		if err != nil {
			return "", err
		}
		out += text
	}
	return out + "}\n", nil
}
func azureSchedulerSection(message viciMessage, indent string) (string, error) {
	keys := make([]string, 0, len(message))
	for key := range message {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out strings.Builder
	for _, key := range keys {
		value := message[key]
		switch value.kind {
		case 1:
			nested, e := azureSchedulerSection(value.section, indent+"  ")
			if e != nil {
				return "", e
			}
			fmt.Fprintf(&out, "%s%s {\n%s%s}\n", indent, key, nested, indent)
		case 3:
			text := string(value.scalar)
			if strings.ContainsAny(text, "\n\r{}#\"\\") {
				return "", ErrDaemonProtocol
			}
			fmt.Fprintf(&out, "%s%s = %s\n", indent, key, text)
		case 4:
			values := []string{}
			for _, item := range value.list {
				text := string(item)
				if strings.ContainsAny(text, "\n\r{}#\"\\,") {
					return "", ErrDaemonProtocol
				}
				values = append(values, text)
			}
			fmt.Fprintf(&out, "%s%s = %s\n", indent, key, strings.Join(values, ", "))
		default:
			return "", ErrDaemonProtocol
		}
	}
	return out.String(), nil
}

func TestAzureSchedulerUsesProviderMaterial(t *testing.T) {
	entry, _, _, _ := runtimeProofFixture()
	for _, profile := range []string{AzureActiveActiveBGPProfile, AzureActiveActiveStaticProfile, AzureActiveStandbyBGPProfile, AzureActiveStandbyStaticProfile} {
		t.Run(profile, func(t *testing.T) {
			count := 2
			if IsSingleTunnelProfile(profile) {
				count = 1
			}
			engines := append([]EngineTunnel(nil), entry.Engines[:count]...)
			for i := range engines {
				engines[i].ProfileID = profile
			}
			config, e := azureSchedulerConfig(engines)
			if e != nil || strings.Count(config, "local_ts = 0.0.0.0/0") != count || strings.Count(config, "remote_ts = 0.0.0.0/0") != count || strings.Count(config, "rekey_time = 28800s") != count || strings.Count(config, "life_time = 3600s") != count || strings.Contains(config, "mock-only") {
				t.Fatal("provider material drift")
			}
		})
	}
}
