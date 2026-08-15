package db_test

import (
	"os"
	"strings"
	"testing"
)

func TestF04RuntimeOpenAPIContract(t *testing.T) {
	spec, err := os.ReadFile("../../../openapi/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(spec)

	assertContains := func(needle string) {
		t.Helper()
		if !strings.Contains(s, needle) {
			t.Errorf("OpenAPI F04 contract missing %q", needle)
		}
	}
	assertContains("runtimeBearer:")
	assertContains("/api/v1/agent/runtime/poll:")
	assertContains("operationId: pollAgentRuntime")
	assertContains("name: applied_revision")
	assertContains("name: client_version")
	assertContains("name: wait_seconds")
	assertContains("schema: { $ref: \"#/components/schemas/ManagedAgentConfig\" }")
	assertContains("\"204\":\n          description: Desired revision is unchanged")
	assertContains("/api/v1/agent/runtime/report:")
	assertContains("operationId: reportAgentRuntime")
	assertContains("schema: { $ref: \"#/components/schemas/AgentRuntimeReport\" }")
	assertContains("required: [applied_revision, attempted_revision, client_version, error_code]")
	assertContains("enum: [\"\", invalid_config, apply_failed]")
	assertContains("/api/v1/organizations/{orgId}/agents/{deviceId}/runtime-status:")
	assertContains("operationId: getAgentRuntimeStatus")
	assertContains("schema: { $ref: \"#/components/schemas/AgentRuntimeStatus\" }")
	assertContains("RuntimeUnauthorized:")
	for _, path := range []string{"/api/v1/agent/runtime/poll:", "/api/v1/agent/runtime/report:"} {
		block := yamlPathSection(s, path)
		if !strings.Contains(block, "        - runtimeBearer: []") {
			t.Errorf("%s must use the machine runtime bearer security scheme", path)
		}
		if !strings.Contains(block, `"401": { $ref: "#/components/responses/RuntimeUnauthorized" }`) {
			t.Errorf("%s must define the uniform no-oracle 401 response", path)
		}
	}
	statusBlock := yamlPathSection(s, "/api/v1/organizations/{orgId}/agents/{deviceId}/runtime-status:")
	if strings.Contains(statusBlock, "runtimeBearer") {
		t.Fatal("organization runtime status must not accept machine runtime credentials")
	}

	for _, schema := range []string{"ManagedAgentConfig", "AgentRuntimeReport", "AgentRuntimeStatus"} {
		block := yamlSection(s, "    "+schema+":", "    ")
		for _, forbidden := range []string{
			"        private_key:",
			"        bootstrap_token:",
			"        runtime_credential:",
			"        token_hash:",
			"        raw_error:",
		} {
			if strings.Contains(block, forbidden) {
				t.Errorf("F04 response schema %s exposes forbidden field %q", schema, strings.TrimSpace(forbidden))
			}
		}
	}
}

func yamlPathSection(spec, path string) string {
	start := strings.Index(spec, "\n  "+path)
	if start < 0 {
		return ""
	}
	start++
	rest := spec[start:]
	if next := strings.Index(rest[1:], "\n  /"); next >= 0 {
		return rest[:next+1]
	}
	return rest
}

func yamlSection(spec, heading, nextIndent string) string {
	start := strings.Index(spec, "\n"+heading)
	if start < 0 {
		return ""
	}
	start += 1
	body := spec[start:]
	lines := strings.Split(body, "\n")
	for i := 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], nextIndent) && !strings.HasPrefix(lines[i], "      ") {
			return strings.Join(lines[:i], "\n")
		}
	}
	return body
}
