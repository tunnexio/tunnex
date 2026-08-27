package fqdnresolver

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

// This test pins the serialized v1 contract that apps/node mirrors without
// importing this API-internal package. Lane 4's mirror test must use this exact
// JSON field set/types; adding a field or changing a type requires a version
// bump rather than an accidental compatible-looking wire drift.
func TestGatewayDNSRPCV1WireShape(t *testing.T) {
	request := GatewayDNSRequest{
		Version: GatewayDNSRPCVersion, RequestID: uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		OrgID: uuid.MustParse("22222222-2222-2222-2222-222222222222"), ResourceID: uuid.MustParse("33333333-3333-3333-3333-333333333333"),
		SiteID: uuid.MustParse("44444444-4444-4444-4444-444444444444"), GatewayID: uuid.MustParse("55555555-5555-5555-5555-555555555555"),
		Hostname: "orders.internal", RecordTypes: []RecordType{TypeA, TypeAAAA, TypeCNAME}, Deadline: time.Date(2026, 8, 27, 15, 0, 0, 0, time.UTC),
	}
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	wantKeys := []string{"version", "request_id", "org_id", "resource_id", "site_id", "gateway_id", "hostname", "record_types", "deadline"}
	if len(got) != len(wantKeys) {
		t.Fatalf("request fields=%v, want exactly %v", got, wantKeys)
	}
	for _, key := range wantKeys {
		if _, ok := got[key]; !ok {
			t.Fatalf("request missing wire field %q: %s", key, data)
		}
	}

	response := GatewayDNSResponse{Version: GatewayDNSRPCVersion, RequestID: request.RequestID, OrgID: request.OrgID, ResourceID: request.ResourceID, SiteID: request.SiteID, GatewayID: request.GatewayID, Hostname: request.Hostname, RecordTypes: request.RecordTypes, ObservedAt: request.Deadline, Status: StatusNoError, Records: []GatewayDNSRecord{{Name: request.Hostname, Type: TypeA, Address: "10.2.3.4", TTLSeconds: 60}}}
	data, err = json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	got = nil
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	wantKeys = []string{"version", "request_id", "org_id", "resource_id", "site_id", "gateway_id", "hostname", "record_types", "observed_at", "status", "records"}
	if len(got) != len(wantKeys) {
		t.Fatalf("response fields=%v, want exactly %v", got, wantKeys)
	}
	for _, key := range wantKeys {
		if _, ok := got[key]; !ok {
			t.Fatalf("response missing wire field %q: %s", key, data)
		}
	}
	var round GatewayDNSResponse
	if err := json.Unmarshal(data, &round); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(round, response) {
		t.Fatalf("wire round trip=%#v want %#v", round, response)
	}
}

func TestGatewayDNSRPCTransportImplementsSchedulerSeams(t *testing.T) {
	var _ Resolver = (*GatewayDNSRPCTransport)(nil)
	var _ WorkResolver = (*GatewayDNSRPCTransport)(nil)
}
