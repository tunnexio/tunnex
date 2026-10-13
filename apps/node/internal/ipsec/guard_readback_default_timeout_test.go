package ipsec

import (
	"encoding/json"
	"testing"
)

func TestGuardSetNativeDefaultTimeoutExact(t *testing.T) {
	for _, scenario := range []string{"exact", "wrongdefault", "noexpiry", "overlong", "foreign", "expired", "extra"} {
		f := map[string]any{"name": "lease_bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb", "type": "iface_index", "flags": []any{"timeout"}, "timeout": json.Number("60")}
		e := map[string]any{"val": json.Number("3"), "expires": json.Number("59")}
		f["elem"] = []any{map[string]any{"elem": e}}
		switch scenario {
		case "wrongdefault":
			f["timeout"] = json.Number("30")
		case "noexpiry":
			delete(e, "expires")
		case "overlong":
			e["expires"] = json.Number("61")
		case "foreign":
			f["name"] = "foreign"
		case "expired":
			e["expires"] = json.Number("0")
		case "extra":
			e["foreign"] = true
		}
		ok := normalizeGuardSet(f)
		if ok != (scenario == "exact") {
			t.Fatal(scenario, f)
		}
		if ok && e["timeout"] != json.Number("60") {
			t.Fatal("missing inherited exacttimeout")
		}
	}
}
