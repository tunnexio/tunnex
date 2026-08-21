package cli

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func modernToolCall(name string) string {
	return `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"` + name + `","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
}

func TestMCPToolGateRejectsForgedHeaderBeforeUpstream(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { upstreamCalls.Add(1); w.WriteHeader(http.StatusOK) })
	gate := MCPToolGate(MCPProtocol20260728, func(tool string) bool { return tool == "safe" }, upstream)
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", strings.NewReader(modernToolCall("dangerous")))
	req.Header.Set("MCP-Protocol-Version", MCPProtocol20260728)
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "safe") // forged routing/authorization hint
	resp := httptest.NewRecorder()
	gate.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.Code)
	}
	if upstreamCalls.Load() != 0 {
		t.Fatal("forged request reached upstream")
	}
	body, _ := io.ReadAll(resp.Result().Body)
	if !strings.Contains(string(body), `"code":-32020`) {
		t.Fatalf("body = %s, want HeaderMismatch", body)
	}
}

func TestMCPToolGateAllowsExactModernTool(t *testing.T) {
	var upstreamCalls atomic.Int32
	gate := MCPToolGate(MCPProtocol20260728, func(tool string) bool { return tool == "safe" }, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", strings.NewReader(modernToolCall("safe")))
	req.Header.Set("MCP-Protocol-Version", MCPProtocol20260728)
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "safe")
	resp := httptest.NewRecorder()
	gate.ServeHTTP(resp, req)
	if resp.Code != http.StatusNoContent || upstreamCalls.Load() != 1 {
		t.Fatalf("status/calls = %d/%d, want 204/1", resp.Code, upstreamCalls.Load())
	}
}

func TestMCPToolGateLegacyAllowsAbsentMirrorsButDeniesUnknownTool(t *testing.T) {
	gate := MCPToolGate(MCPProtocol20251125, func(tool string) bool { return tool == "safe" }, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { t.Fatal("unknown tool reached upstream") }))
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"unknown"}}`
	resp := httptest.NewRecorder()
	gate.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", strings.NewReader(body)))
	if resp.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.Code)
	}
}

func TestValidateMCPToolRequestDecodesMCPName(t *testing.T) {
	body := modernToolCall("café")
	headers := make(http.Header)
	headers.Set("MCP-Protocol-Version", MCPProtocol20260728)
	headers.Set("Mcp-Method", "tools/call")
	headers.Set("Mcp-Name", "=?base64?Y2Fmw6k=?=")
	got, err := ValidateMCPToolRequest(MCPProtocol20260728, headers, []byte(body))
	if err != nil || got.ToolName != "café" {
		t.Fatalf("got %+v, err %v", got, err)
	}
}

func TestMCPToolGateRejectsResourceHeaderMismatchBeforeUpstream(t *testing.T) {
	var upstreamCalls atomic.Int32
	gate := MCPToolGate(MCPProtocol20260728, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	body := `{"jsonrpc":"2.0","id":7,"method":"resources/read","params":{"uri":"file:///private.txt","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", strings.NewReader(body))
	req.Header.Set("MCP-Protocol-Version", MCPProtocol20260728)
	req.Header.Set("Mcp-Method", "resources/read")
	req.Header.Set("Mcp-Name", "file:///public.txt")
	resp := httptest.NewRecorder()
	gate.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest || upstreamCalls.Load() != 0 {
		t.Fatalf("status/calls = %d/%d, want 400/0", resp.Code, upstreamCalls.Load())
	}
}
