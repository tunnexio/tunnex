//go:build linux

package bgp

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

func TestPreflightEmptyRIBStrict(t *testing.T) {
	for _, raw := range []string{`{}`, `{"routes":{},"tableVersion":0}`} {
		if !preflightEmptyRIB([]byte(raw)) {
			t.Fatal("empty observer RIB refused", raw)
		}
	}
	for _, raw := range []string{`null`, `[]`, `{"routes":null}`, `{"routes":{"10.20.0.0/24":[]}}`, `{"warning":"not ready","routes":{}}`, `{"error":"failed","routes":{}}`} {
		if preflightEmptyRIB([]byte(raw)) {
			t.Fatal("invalid RIB accepted", raw)
		}
	}
}
func TestPreflightOwnedTCPListenersOnly(t *testing.T) {
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
	row := "0: 0100007F:00B3 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 123 1\n"
	if preflightTCPAbsent([]byte(header+row), map[string]bool{"123": true}) {
		t.Fatal("owned TCP179 listener accepted")
	}
	if !preflightTCPAbsent([]byte(header+row), map[string]bool{"124": true}) {
		t.Fatal("unrelated host listener refused")
	}
	if preflightTCPAbsent([]byte(header+"malformed"), nil) {
		t.Fatal("malformed socket census accepted")
	}
	if (&PreflightQualification{}).Current() {
		t.Fatal("empty receipt manufactured qualification")
	}
}
func TestNativeObserverPreflight(t *testing.T) {
	if os.Getenv("TUNNEX_BGP_PREFLIGHT_LAB") != "1" {
		t.Skip("actual native preflight requires explicit owned namespace")
	}
	parent := "/run/tunnex-bgp-preflight-lab"
	if err := os.Mkdir(parent, 0700); err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
	q, err := QualifyPreflight(context.Background(), parent)
	if err != nil {
		t.Fatal(err)
	}
	if !q.Current() || q.Namespace() == "" {
		t.Fatal("actual preflight receipt not current")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatal("preflight residue", err)
	}
	raw, _ := json.Marshal(map[string]any{"namespace": q.namespace, "boot_id": q.bootID, "package_files": q.packageFiles, "passed": true, "cleanup_complete": true})
	t.Log(string(raw))
}
