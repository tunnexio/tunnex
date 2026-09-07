package aigateway

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCustomProxyConfigurationAndReadback(t *testing.T) {
	for _, raw := range []string{"", "https://user:password@proxy:8190", "http://proxy:8190", "http://user@proxy:8190", "http://user:password@proxy:0", "http://user:password@proxy:99999", "http://user:password@proxy:8190/path", "http://user:password@proxy:8190?x"} {
		e := &Engine{}
		if e.ConfigureCustomProxy(raw) == nil {
			t.Fatal("invalid proxy accepted")
		}
	}
	e := &Engine{}
	if e.ConfigureCustomProxy("http://fixture-user:fixture-password@proxy:8190") != nil {
		t.Fatal("valid proxy refused")
	}
	custom := json.RawMessage(`{"base_provider_type":"openai","is_key_less":false,"allowed_requests":{"list_models":true,"chat_completion":true,"chat_completion_stream":true}}`)
	for _, mode := range []string{"valid", "missing-ref", "wrong-ref", "unset", "raw-value", "wrong-mask", "extra-auth", "extra-CA", "wrong-type"} {
		t.Run(mode, func(t *testing.T) {
			value := map[string]any{"type": "env", "ref": "env.TUNNEX_AI_CUSTOM_PROXY_URL", "value": "http" + strings.Repeat("*", 24) + "8190"}
			proxy := map[string]any{"type": "http", "url": value}
			switch mode {
			case "missing-ref":
				delete(value, "ref")
			case "wrong-ref":
				value["ref"] = "env.OTHER"
			case "unset":
				value["value"] = ""
			case "raw-value":
				value["value"] = "http://fixture-user:fixture-password@proxy:8190"
			case "wrong-mask":
				value["value"] = "http" + strings.Repeat("*", 24) + "9999"
			case "extra-auth":
				proxy["username"] = "other"
			case "extra-CA":
				proxy["ca_cert_pem"] = "other"
			case "wrong-type":
				proxy["type"] = "env"
			}
			b, _ := json.Marshal(proxy)
			if e.customConfigExact("https://models.internal", "https://models.internal", true, false, nil, custom, b) != (mode == "valid") {
				t.Fatal("incorrect custom proxy readback decision")
			}
		})
	}
}
