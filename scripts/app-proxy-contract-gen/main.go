// app-proxy-contract-gen projects only private proxy wire schemas from the
// central contract. Run from apps/api so the existing kin-openapi build
// dependency is reused; the generated app-proxy models need only the stdlib.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

func main() {
	source := flag.String("source", "../../openapi/openapi.yaml", "central contract")
	output := flag.String("output", "", "temporary projection JSON path")
	flag.Parse()
	if *output == "" {
		fatal(fmt.Errorf("output path required"))
	}
	doc, err := openapi3.NewLoader().LoadFromFile(*source)
	if err != nil {
		fatal(err)
	}
	// Serialize first so transformations never mutate the central schema graph.
	raw, err := json.Marshal(doc)
	if err != nil {
		fatal(err)
	}
	var parsed map[string]any
	if err = json.Unmarshal(raw, &parsed); err != nil {
		fatal(err)
	}
	components, ok := parsed["components"].(map[string]any)
	if !ok {
		fatal(fmt.Errorf("components missing"))
	}
	schemas, ok := components["schemas"].(map[string]any)
	if !ok {
		fatal(fmt.Errorf("schemas missing"))
	}
	selected := map[string]any{}
	for name, schema := range schemas {
		if strings.HasPrefix(name, "AppProxy") {
			selected[name] = schema
		}
	}
	// The private error alias derives from the one central error envelope; its
	// only shared dependency is renamed into the private projection namespace.
	if _, ok := selected["AppProxyError"]; ok {
		selected["AppProxyError"] = schemas["Error"]
		selected["AppProxyErrorDetail"] = schemas["ErrorDetail"]
		remapErrorDetail(selected["AppProxyError"])
	}
	if len(selected) == 0 {
		fatal(fmt.Errorf("no proxy schemas"))
	}
	for _, schema := range selected {
		if err = project(schema, selected); err != nil {
			fatal(err)
		}
	}
	projection := map[string]any{"openapi": parsed["openapi"], "info": map[string]any{"title": "Private App Access proxy wire contract", "version": "1"}, "paths": map[string]any{}, "components": map[string]any{"schemas": selected}}
	data, err := json.MarshalIndent(projection, "", "  ")
	if err != nil {
		fatal(err)
	}
	if err = os.WriteFile(*output, append(data, '\n'), 0600); err != nil {
		fatal(err)
	}
}
func project(value any, schemas map[string]any) error {
	switch v := value.(type) {
	case map[string]any:
		if ref, ok := v["$ref"].(string); ok {
			const prefix = "#/components/schemas/"
			if !strings.HasPrefix(ref, prefix) {
				return fmt.Errorf("external proxy reference %s", ref)
			}
			if _, ok := schemas[strings.TrimPrefix(ref, prefix)]; !ok {
				return fmt.Errorf("proxy schema references non-proxy schema %s", ref)
			}
		}
		if v["format"] == "uuid" {
			delete(v, "format")
		}
		if properties, ok := v["properties"].(map[string]any); ok {
			names := map[string]string{"org_id": "OrgID", "app_id": "AppID", "gateway_id": "GatewayID", "stream_id": "StreamID", "operation_id":"OperationID", "readiness_request_id":"ReadinessRequestID", "public_dns_status":"PublicDNSStatus", "public_tls_status":"PublicTLSStatus", "dns_status":"DNSStatus", "tls_status":"TLSStatus", "origin_url": "OriginURL", "origin_ca_pem": "OriginCAPEM", "origin_ca_digest": "OriginCADigest", "allowed_destination_cidrs": "AllowedDestinationCIDRs"}
			for key, name := range names {
				if property, ok := properties[key].(map[string]any); ok {
					property["x-go-name"] = name
				}
			}
		}
		for _, nested := range v {
			if err := project(nested, schemas); err != nil {
				return err
			}
		}
	case []any:
		for _, nested := range v {
			if err := project(nested, schemas); err != nil {
				return err
			}
		}
	}
	return nil
}
func fatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }

func remapErrorDetail(value any) {
	switch v := value.(type) {
	case map[string]any:
		if v["$ref"] == "#/components/schemas/ErrorDetail" {
			v["$ref"] = "#/components/schemas/AppProxyErrorDetail"
		}
		for _, nested := range v {
			remapErrorDetail(nested)
		}
	case []any:
		for _, nested := range v {
			remapErrorDetail(nested)
		}
	}
}
