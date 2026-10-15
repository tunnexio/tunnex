package http

import (
	"encoding/json"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"testing"
)

func TestLANDefaultUpstreamsAPIRoundtrip(t *testing.T) {
	for _, wire := range []string{`{"address":"192.168.1.39","interface":"eth0","allowed_sources":["192.168.1.0/24"]}`, `{"address":"192.168.1.39","interface":"eth0","allowed_sources":["192.168.1.0/24"],"default_upstreams":["1.1.1.1","8.8.8.8"]}`} {
		var in api.FQDNResolverLANListener
		if err := json.Unmarshal([]byte(wire), &in); err != nil {
			t.Fatal(err)
		}
		got, err := json.Marshal(toAPILANListener(fromAPILANListener(&in)))
		if err != nil {
			t.Fatal(err)
		}
		var wantMap, gotMap any
		_ = json.Unmarshal([]byte(wire), &wantMap)
		_ = json.Unmarshal(got, &gotMap)
		wantCanonical, _ := json.Marshal(wantMap)
		gotCanonical, _ := json.Marshal(gotMap)
		if string(wantCanonical) != string(gotCanonical) {
			t.Fatalf("roundtrip changed DNS authority: %s", got)
		}
	}
}
