package http

import (
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/mcpdecision"
)

// The CSV names a server the way the page does: by the name an administrator gave it, not by what the
// MCP server calls itself.
func TestMCPActivityCSVNamesTheServerAsTheAdministratorDid(t *testing.T) {
	at := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	rows := []mcpdecision.ActivityRow{
		{OccurredAt: at, ToolName: "refund_order", ServerName: "acme-backoffice", Endpoint: "http://10.0.0.5:8080/mcp", Method: "tools/call", Decision: "allow", ResultStatus: "ok"},
		{OccurredAt: at, ToolName: "lookup", ServerName: "old-crm", Endpoint: "http://10.0.0.9:8080/mcp", Method: "tools/call", Decision: "deny", Reason: "policy", ResultStatus: "not_forwarded"},
		{OccurredAt: at, ToolName: "sum", ServerName: "sheet", Endpoint: "http://10.0.0.7:8080/mcp", Method: "tools/call", Decision: "allow", ResultStatus: "ok"},
	}
	names := map[string]string{"http://10.0.0.5:8080/mcp": "Billing database", "http://10.0.0.7:8080/mcp": "=Formulas"}
	records, err := csv.NewReader(strings.NewReader(string(mcpActivityCSV(rows, names)))).ReadAll()
	if err != nil || len(records) != 4 {
		t.Fatalf("csv = %v, %v", records, err)
	}
	column := -1
	for i, name := range records[0] {
		if name == "server" {
			column = i
		}
	}
	if column < 0 {
		t.Fatalf("no server column in %v", records[0])
	}
	// A server that is no longer connected keeps the name it reported; a name is never run as a formula.
	if got := []string{records[1][column], records[2][column], records[3][column]}; got[0] != "Billing database" || got[1] != "old-crm" || got[2] != "'=Formulas" {
		t.Fatalf("server column = %q", got)
	}
	if strings.Contains(string(mcpActivityCSV(rows, names)), "acme-backoffice") {
		t.Fatal("the self-reported name is still in the export for a named server")
	}
	if got := mcpActivityCSV(rows, nil); !strings.Contains(string(got), "acme-backoffice") {
		t.Fatal("without names the reported name is the fallback")
	}
}
