package mcptoolpolicy

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

func TestInventoryRulesBindEndpointServerToolAndSchema(t *testing.T) {
	snapshot := []byte(`{"servers":[{"endpoint":"https://mcp.example/rpc","server_name":"billing","tools":[{"name":"read","input_schema_hash":"sha256:a"}]}]}`)
	available := inventoryRules(snapshot)
	if !available[ruleKey(Rule{Endpoint: "https://mcp.example/rpc", ServerName: "billing", ToolName: "read", InputSchemaHash: "sha256:a"})] {
		t.Fatal("exact observed tool was not available")
	}
	if available[ruleKey(Rule{Endpoint: "https://mcp.example/rpc", ServerName: "billing", ToolName: "read", InputSchemaHash: "sha256:b"})] {
		t.Fatal("changed schema hash was accepted")
	}
}

func TestCanonicalRulesRejectMissingStableIdentity(t *testing.T) {
	if got := canonicalRules([]Rule{{Endpoint: "https://mcp.example/rpc", ToolName: "read", InputSchemaHash: "hash"}}); got != nil {
		t.Fatalf("rules = %#v, want rejection", got)
	}
}

func TestOrderServersFirstIsEarliestAndProfilesAppearOnce(t *testing.T) {
	billing, crm := uuid.New(), uuid.New()
	early, late := uuid.New(), uuid.New()
	servers := orderServers([]sqlc.ListAgentMCPServersForDeviceRow{
		{ProfileID: billing, AgentGroupID: early, ServerName: "billing", Endpoint: " http://10.0.0.1/mcp "},
		{ProfileID: crm, AgentGroupID: late, ServerName: "crm", Endpoint: "http://10.0.0.2/mcp"},
		{ProfileID: billing, AgentGroupID: late, ServerName: "billing", Endpoint: "http://10.0.0.1/mcp"},
	})
	if len(servers) != 2 || servers[0].ServerName != "billing" || servers[0].GroupID != early || servers[0].Endpoint != "http://10.0.0.1/mcp" || servers[1].ServerName != "crm" {
		t.Fatalf("servers = %+v", servers)
	}
	for name, want := range map[string]string{"": "billing", "billing": "billing", "crm": "crm"} {
		if got, ok := FindServer(servers, name); !ok || got.ServerName != want {
			t.Fatalf("FindServer(%q) = %+v, %v", name, got, ok)
		}
	}
	if _, ok := FindServer(servers, "other"); ok {
		t.Fatal("an unknown server name was resolved")
	}
	if _, ok := FindServer(nil, ""); ok {
		t.Fatal("an agent with no server has a first server")
	}
}

func TestBuildGroupRulesMapsModesAndPinsDefinitions(t *testing.T) {
	const endpoint = "http://10.0.0.1/mcp"
	hash := func(c byte) string { return strings.Repeat(string(c), 64) }
	server := InventoryServer{Endpoint: endpoint, ServerName: "billing", Status: StatusHealthy, Tools: []InventoryTool{
		{Name: "read", InputSchemaHash: "s1", ToolDefinitionHash: hash('a')},
		{Name: "refund", InputSchemaHash: "s2", ToolDefinitionHash: hash('b')},
		{Name: "drop", InputSchemaHash: "s3", ToolDefinitionHash: hash('c')},
	}}
	rules, err := buildGroupRules(endpoint, server, []ToolSetting{
		{ToolName: "read", Mode: ModeAllow, Effect: EffectReads},
		{ToolName: "refund", Mode: ModeAsk, ToolDefinitionHash: hash('b')},
		{ToolName: "drop", Mode: ModeOff, Effect: EffectDestructive},
		{ToolName: "gone", Mode: ModeOff},
	}, false)
	if err != nil || len(rules) != 2 {
		t.Fatalf("rules = %+v, %v", rules, err)
	}
	byTool := map[string]Rule{}
	for _, rule := range rules {
		byTool[rule.ToolName] = rule
	}
	if read := byTool["read"]; read.StepUpRequired || read.ToolDefinitionHash != hash('a') || read.ServerName != "billing" || read.Endpoint != endpoint || read.InputSchemaHash != "s1" {
		t.Fatalf("allow rule = %+v", read)
	}
	if refund := byTool["refund"]; !refund.StepUpRequired || refund.ToolDefinitionHash != hash('b') {
		t.Fatalf("ask rule = %+v", refund)
	}
	if _, off := byTool["drop"]; off {
		t.Fatal("an Off tool made a rule")
	}
	for name, tc := range map[string]struct {
		tools       []ToolSetting
		requireHash bool
		want        error
	}{
		"changed since shown":       {[]ToolSetting{{ToolName: "refund", Mode: ModeAllow, ToolDefinitionHash: hash('a')}}, false, ErrDefinitionStale},
		"not on the server":         {[]ToolSetting{{ToolName: "gone", Mode: ModeAllow}}, false, ErrUnobservedTool},
		"unknown mode":              {[]ToolSetting{{ToolName: "read", Mode: "maybe"}}, false, ErrInvalid},
		"unknown marker":            {[]ToolSetting{{ToolName: "read", Mode: ModeOff, Effect: "scary"}}, false, ErrInvalid},
		"listed twice":              {[]ToolSetting{{ToolName: "read", Mode: ModeOff}, {ToolName: "read", Mode: ModeAllow}}, false, ErrInvalid},
		"preview without a hash":    {[]ToolSetting{{ToolName: "read", Mode: ModeAllow}}, true, ErrInvalid},
		"malformed definition hash": {[]ToolSetting{{ToolName: "read", Mode: ModeAllow, ToolDefinitionHash: "abc"}}, false, ErrInvalid},
	} {
		if _, err := buildGroupRules(endpoint, server, tc.tools, tc.requireHash); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
	if rules, err := buildGroupRules(endpoint, InventoryServer{}, []ToolSetting{{ToolName: "read", Mode: ModeOff}}, false); err != nil || len(rules) != 0 || rules == nil {
		t.Fatalf("all-off policy with no tool list = %#v, %v", rules, err)
	}
}

func TestMergeEndpointsIsSortedDistinctAndNeverNil(t *testing.T) {
	if got := mergeEndpoints(nil, nil); got == nil || len(got) != 0 {
		t.Fatalf("empty merge = %#v", got)
	}
	got := mergeEndpoints([]string{"b", "a"}, []string{"a", "", "c"})
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("merge = %v", got)
	}
}
