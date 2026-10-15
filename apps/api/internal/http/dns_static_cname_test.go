package http

import (
	"encoding/json"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdnresources"
	"testing"
)

func TestStaticCNAMEEndpointsAPIRoundtrip(t *testing.T) {
	wire := `{"name":"Aliases","provider_hint":"on_premises","zone_suffixes":["office.test"],"endpoints":[{"address":"1.1.1.1","port":53,"transport":"tcp"}],"static_records":[{"name":"app.office.test","type":"CNAME","value":"outside.example","ttl":300}]}`
	var in api.FQDNResolverProfileRequest
	if err := json.Unmarshal([]byte(wire), &in); err != nil {
		t.Fatal(err)
	}
	profiles := fqdnResolverProfiles([]api.FQDNResolverProfileRequest{in})
	out := toAPIFQDNResolverConfig(fqdnresources.ResolverConfig{Profiles: profiles}).Profiles[0]
	if len(out.Endpoints) != 1 || out.Endpoints[0] != in.Endpoints[0] || out.StaticRecords == nil || (*out.StaticRecords)[0] != (*in.StaticRecords)[0] || out.IpsecPath != nil {
		t.Fatal("API changed static resolver authority", out)
	}
}
