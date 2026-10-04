package main

import "testing"

func TestProjectionKeepsScopeAndWireNames(t *testing.T) {
	binding := map[string]any{"properties": map[string]any{"org_id": map[string]any{"type": "string", "format": "uuid"}, "origin_ca_pem": map[string]any{"type": "string", "maxLength": 32768}}}
	route := map[string]any{"properties": map[string]any{"binding": map[string]any{"$ref": "#/components/schemas/AppProxyRouteBinding"}}}
	schemas := map[string]any{"AppProxyRouteBinding": binding, "AppProxyRoute": route}
	if err := project(binding, schemas); err != nil {
		t.Fatal(err)
	}
	if err := project(route, schemas); err != nil {
		t.Fatal(err)
	}
	properties := binding["properties"].(map[string]any)
	org := properties["org_id"].(map[string]any)
	if org["type"] != "string" || org["format"] != nil || org["x-go-name"] != "OrgID" {
		t.Fatal("UUID wire representation/acronym changed")
	}
	ca := properties["origin_ca_pem"].(map[string]any)
	if ca["maxLength"] != 32768 || ca["x-go-name"] != "OriginCAPEM" {
		t.Fatal("policy bound or name lost")
	}
}
func TestProjectionRejectsDependencySpill(t *testing.T) {
	for _, ref := range []string{"#/components/schemas/User", "other.yaml#/components/schemas/AppProxyRouteBinding"} {
		if err := project(map[string]any{"$ref": ref}, map[string]any{}); err == nil {
			t.Fatal("accepted schema outside private scope", ref)
		}
	}
}
