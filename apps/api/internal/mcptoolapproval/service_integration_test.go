package mcptoolapproval

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/mcpfixture"
)

func identity(t *testing.T, arguments string) Identity {
	t.Helper()
	digest, canonical, err := CanonicalDigest("tools/call", "refund", json.RawMessage(arguments))
	if err != nil {
		t.Fatal(err)
	}
	return Identity{PolicyVersion: 3, Endpoint: mcpfixture.Endpoint, ServerName: "billing", ToolName: "refund", InputSchemaHash: strings.Repeat("a", 64), RequestDigest: digest, ToolDefinitionHash: strings.Repeat("b", 64), Arguments: canonical}
}

func TestCanonicalDigestIgnoresKeyOrderAndWhitespaceOnly(t *testing.T) {
	a, canonical, err := CanonicalDigest("tools/call", "refund", json.RawMessage(`{"customer":"zq-customer","amount":10}`))
	if err != nil || string(canonical) != `{"amount":10,"customer":"zq-customer"}` {
		t.Fatalf("canonical = %s, %v", canonical, err)
	}
	b, _, _ := CanonicalDigest("tools/call", "refund", json.RawMessage("{ \"amount\" : 10,\n \"customer\":\"zq-customer\" }"))
	if a != b {
		t.Fatal("byte-different but equal arguments have different digests")
	}
	for name, other := range map[string]string{"value": `{"customer":"zq-customer","amount":11}`, "large integer": `{"customer":"zq-customer","amount":10000000000000001}`, "extra": `{"customer":"zq-customer","amount":10,"note":""}`} {
		if got, _, _ := CanonicalDigest("tools/call", "refund", json.RawMessage(other)); got == a {
			t.Errorf("different %s shares the digest", name)
		}
	}
	big, _, _ := CanonicalDigest("tools/call", "refund", json.RawMessage(`{"amount":10000000000000001}`))
	bigger, _, _ := CanonicalDigest("tools/call", "refund", json.RawMessage(`{"amount":10000000000000002}`))
	if big == bigger {
		t.Fatal("number literals lost precision in the digest")
	}
	empty, _, _ := CanonicalDigest("tools/call", "refund", nil)
	null, _, _ := CanonicalDigest("tools/call", "refund", json.RawMessage(`null`))
	object, _, _ := CanonicalDigest("tools/call", "refund", json.RawMessage(`{}`))
	if empty != null || empty != object {
		t.Fatal("absent, null and empty arguments are not one call")
	}
	if _, _, err := CanonicalDigest("tools/call", "refund", json.RawMessage(`[1]`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-object arguments err = %v", err)
	}
}

func TestStepUpLifecycle(t *testing.T) {
	f := mcpfixture.New(t)
	svc := New(f.Pool)
	clock := time.Now().UTC()
	svc.now = func() time.Time { return clock }

	first, outcome, err := svc.Decide(f.Ctx, f.Org, f.Agent, identity(t, `{"customer":"zq-customer","amount":10}`))
	if err != nil || outcome != OutcomePending || first.State != "pending" || string(first.Arguments) == "" || first.ArgumentsTruncated || first.ToolDefinitionHash == "" {
		t.Fatalf("first = %+v, %s, %v", first, outcome, err)
	}
	var stored map[string]any
	if json.Unmarshal(first.Arguments, &stored) != nil || stored["customer"] != "zq-customer" {
		t.Fatalf("stored arguments = %s", first.Arguments)
	}
	// Duplicate pending: a byte-different but equal call reuses the row.
	again, outcome, err := svc.Decide(f.Ctx, f.Org, f.Agent, identity(t, `{ "amount":10, "customer":"zq-customer" }`))
	if err != nil || outcome != OutcomePending || again.ID != first.ID {
		t.Fatalf("repeat = %+v, %s, %v", again, outcome, err)
	}
	if n := f.Count(`SELECT count(*) FROM agent_mcp_tool_approval_requests WHERE device_id=$1`, f.Agent); n != 1 {
		t.Fatalf("pending rows = %d, want 1", n)
	}
	if f.AuditCount("agent.mcp_tool_approval.requested") != 1 {
		t.Fatal("requested must be audited exactly once")
	}

	// Bind: approving this call does not let different arguments through.
	if _, err := svc.Approve(f.Ctx, f.Org, f.Agent, first.ID, f.Owner); err != nil {
		t.Fatal(err)
	}
	other, outcome, err := svc.Decide(f.Ctx, f.Org, f.Agent, identity(t, `{"customer":"zq-customer","amount":9999}`))
	if err != nil || outcome != OutcomePending || other.ID == first.ID {
		t.Fatalf("different arguments = %+v, %s, %v", other, outcome, err)
	}
	// Single use: the approved call runs once, then needs a new approval.
	used, outcome, err := svc.Decide(f.Ctx, f.Org, f.Agent, identity(t, `{"customer":"zq-customer","amount":10}`))
	if err != nil || outcome != OutcomeAllowed || used.ID != first.ID || used.State != "consumed" {
		t.Fatalf("approved call = %+v, %s, %v", used, outcome, err)
	}
	replay, outcome, err := svc.Decide(f.Ctx, f.Org, f.Agent, identity(t, `{"customer":"zq-customer","amount":10}`))
	if err != nil || outcome != OutcomePending || replay.ID == first.ID {
		t.Fatalf("replay = %+v, %s, %v", replay, outcome, err)
	}
	if _, err := svc.Approve(f.Ctx, f.Org, f.Agent, first.ID, f.Owner); !errors.Is(err, ErrConflict) {
		t.Fatalf("approve consumed err = %v", err)
	}

	// Deny: only a pending request; the denial stands for the call and opens no new request.
	denied, err := svc.Deny(f.Ctx, f.Org, f.Agent, other.ID, f.Owner)
	if err != nil || denied.State != "denied" || denied.DeniedByUserID != f.Owner || denied.DeniedAt.IsZero() {
		t.Fatalf("deny = %+v, %v", denied, err)
	}
	if _, err := svc.Deny(f.Ctx, f.Org, f.Agent, other.ID, f.Owner); !errors.Is(err, ErrConflict) {
		t.Fatalf("deny twice err = %v", err)
	}
	if _, err := svc.Approve(f.Ctx, f.Org, f.Agent, other.ID, f.Owner); !errors.Is(err, ErrConflict) {
		t.Fatalf("approve denied err = %v", err)
	}
	stands, outcome, err := svc.Decide(f.Ctx, f.Org, f.Agent, identity(t, `{"customer":"zq-customer","amount":9999}`))
	if err != nil || outcome != OutcomeDenied || stands.ID != other.ID {
		t.Fatalf("denied retry = %+v, %s, %v", stands, outcome, err)
	}

	// Expiry: an unanswered request expires with a trace, and the next call opens a fresh one.
	clock = clock.Add(lifetime + time.Second)
	items, err := svc.List(f.Ctx, f.Org, f.Agent)
	if err != nil || len(items) != 3 {
		t.Fatalf("list = %d, %v", len(items), err)
	}
	for _, item := range items {
		if item.ID == replay.ID && item.State != "expired" {
			t.Fatalf("unanswered request state = %s", item.State)
		}
	}
	fresh, outcome, err := svc.Decide(f.Ctx, f.Org, f.Agent, identity(t, `{"customer":"zq-customer","amount":9999}`))
	if err != nil || outcome != OutcomePending || fresh.ID == other.ID {
		t.Fatalf("after denial lifetime = %+v, %s, %v", fresh, outcome, err)
	}
	for action, want := range map[string]int{"agent.mcp_tool_approval.requested": 4, "agent.mcp_tool_approval.approved": 1, "agent.mcp_tool_approval.consumed": 1, "agent.mcp_tool_approval.denied": 1, "agent.mcp_tool_approval.expired": 1} {
		if got := f.AuditCount(action); got != want {
			t.Errorf("%s rows = %d, want %d", action, got, want)
		}
	}
	if n := f.Count(`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action LIKE 'agent.mcp_tool_approval.%' AND metadata::text LIKE '%zq-customer%'`, f.Org); n != 0 {
		t.Fatal("arguments leaked into the audit log")
	}
	clock = clock.Add(lifetime + time.Second)
	if n, err := svc.ExpireDue(f.Ctx, 100); err != nil || n != 1 {
		t.Fatalf("sweep expired %d, %v; want 1", n, err)
	}

	// Arguments over the cap are bound by digest but not stored.
	large := `{"note":"` + strings.Repeat("x", MaxStoredArguments) + `"}`
	big, outcome, err := svc.Decide(f.Ctx, f.Org, f.Agent, identity(t, large))
	if err != nil || outcome != OutcomePending || !big.ArgumentsTruncated || len(big.Arguments) != 0 {
		t.Fatalf("large = truncated=%v len=%d, %s, %v", big.ArgumentsTruncated, len(big.Arguments), outcome, err)
	}
}
