package mcptoolapproval

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/alerts"
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

type recordingPublisher struct {
	events []alerts.Event
	fail   bool
}

func (p *recordingPublisher) Publish(_ context.Context, event alerts.Event) error {
	p.events = append(p.events, event)
	if p.fail {
		return errors.New("outbox down")
	}
	return event.Validate()
}

func TestPendingApprovalAlertIsPublishedOncePerRequestWithoutArguments(t *testing.T) {
	f := mcpfixture.New(t)
	svc := New(f.Pool)
	publisher := &recordingPublisher{}
	svc.SetAlertPublisher(publisher)
	const secret = "zq-secret-customer"
	call := identity(t, `{"customer":"`+secret+`","amount":10}`)

	first, outcome, err := svc.Decide(f.Ctx, f.Org, f.Agent, call)
	if err != nil || outcome != OutcomePending {
		t.Fatalf("first = %s, %v", outcome, err)
	}
	// The agent retries; an approver answers; the approved call runs. None of that publishes again.
	for i := 0; i < 3; i++ {
		if again, _, err := svc.Decide(f.Ctx, f.Org, f.Agent, call); err != nil || again.ID != first.ID {
			t.Fatalf("retry = %+v, %v", again, err)
		}
	}
	if _, err := svc.Approve(f.Ctx, f.Org, f.Agent, first.ID, f.Owner); err != nil {
		t.Fatal(err)
	}
	if _, outcome, err := svc.Decide(f.Ctx, f.Org, f.Agent, call); err != nil || outcome != OutcomeAllowed {
		t.Fatalf("approved call = %s, %v", outcome, err)
	}
	if len(publisher.events) != 1 {
		t.Fatalf("published %d alerts for one request, want 1", len(publisher.events))
	}
	event := publisher.events[0]
	if event.Key != alerts.EventAgentMCPApprovalPending || event.OrgID != f.Org || event.DedupKey != "mcp_approval:"+first.ID.String() || event.Validate() != nil ||
		event.Fields["agent"] != "agent" || event.Fields["agent_id"] != f.Agent.String() || event.Fields["tool"] != call.ToolName || event.Fields["server"] != call.ServerName ||
		event.Fields["request_id"] != first.ID.String() || event.Fields["expires_at"] == "" {
		t.Fatalf("event = %+v", event)
	}
	raw, _ := json.Marshal(event)
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), "amount") || strings.Contains(string(raw), call.RequestDigest) {
		t.Fatalf("the alert carries the call's arguments: %s", raw)
	}

	// A new request (the approval was used) is a new alert. A failing outbox never fails the decision.
	publisher.fail = true
	second, outcome, err := svc.Decide(f.Ctx, f.Org, f.Agent, call)
	if err != nil || outcome != OutcomePending || second.ID == first.ID || len(publisher.events) != 2 {
		t.Fatalf("second request = %+v, %s, %v, %d events", second, outcome, err, len(publisher.events))
	}
}

func TestOrganizationInboxCountAndState(t *testing.T) {
	f := mcpfixture.New(t)
	svc := New(f.Pool)
	clock := time.Now().UTC()
	svc.now = func() time.Time { return clock }
	group := identity(t, `{"customer":"g"}`)
	group.PolicySource, group.PolicyGroupID = PolicySourceGroup, f.Group

	var ids []uuid.UUID
	for i, in := range []Identity{identity(t, `{"customer":"a"}`), identity(t, `{"customer":"b"}`), group} {
		r, _, err := svc.Decide(f.Ctx, f.Org, f.Agent, in)
		if err != nil {
			t.Fatal(err)
		}
		f.Exec(`UPDATE agent_mcp_tool_approval_requests SET requested_at=now()-make_interval(secs => $2) WHERE id=$1`, r.ID, float64(10-i))
		ids = append(ids, r.ID)
	}
	// An agent with no owner and a request of a deleted agent.
	other, _, err := svc.Decide(f.Ctx, f.Org, f.OtherAgent, identity(t, `{"customer":"o"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Deny(f.Ctx, f.Org, f.Agent, ids[1], f.Owner); err != nil {
		t.Fatal(err)
	}

	if n, err := svc.CountPending(f.Ctx, f.Org); err != nil || n != 3 {
		t.Fatalf("pending = %d, %v; want 3", n, err)
	}
	if n, err := svc.CountPending(f.Ctx, uuid.New()); err != nil || n != 0 {
		t.Fatalf("another organization's count = %d, %v", n, err)
	}
	pending, next, err := svc.ListOrganization(f.Ctx, f.Org, true, 50, "")
	if err != nil || len(pending) != 3 || next != "" {
		t.Fatalf("pending inbox = %d rows, next %q, %v", len(pending), next, err)
	}
	if pending[0].Request.ID != other.ID || pending[1].Request.ID != ids[2] || pending[2].Request.ID != ids[0] {
		t.Fatal("the inbox is not newest first")
	}
	item := pending[1]
	if item.AgentName != "agent" || item.OwnerEmail == nil || !strings.HasSuffix(*item.OwnerEmail, "@example.com") || item.Request.PolicySource != PolicySourceGroup || item.Request.PolicyGroupID != f.Group ||
		item.Request.DeviceID != f.Agent || string(item.Request.Arguments) == "" || !item.Request.ExpiresAt.After(clock) {
		t.Fatalf("inbox item = %+v", item)
	}
	if pending[2].Request.PolicySource != PolicySourceAgent || pending[2].Request.PolicyGroupID != uuid.Nil {
		t.Fatalf("agent-policy item = %+v", pending[2].Request)
	}

	// All: decided ones too, paged with a cursor, no row twice.
	seen := map[uuid.UUID]bool{}
	cursor := ""
	for page := 0; ; page++ {
		rows, next, err := svc.ListOrganization(f.Ctx, f.Org, false, 3, cursor)
		if err != nil || page > 3 {
			t.Fatalf("page %d: %v", page, err)
		}
		for _, row := range rows {
			if seen[row.Request.ID] {
				t.Fatal("a request appeared on two pages")
			}
			seen[row.Request.ID] = true
		}
		if cursor = next; cursor == "" {
			break
		}
	}
	if len(seen) != 4 || !seen[ids[1]] {
		t.Fatalf("all = %d requests", len(seen))
	}
	if _, _, err := svc.ListOrganization(f.Ctx, f.Org, false, 3, "not-a-cursor"); !errors.Is(err, ErrCursor) {
		t.Fatalf("bad cursor err = %v", err)
	}
	if rows, _, err := svc.ListOrganization(f.Ctx, uuid.New(), false, 50, ""); err != nil || len(rows) != 0 {
		t.Fatalf("another organization's inbox = %d, %v", len(rows), err)
	}

	// State, for a held call: only the agent's own request, and it changes nothing.
	for id, want := range map[uuid.UUID]string{ids[0]: StatePending, ids[1]: StateDenied} {
		if got, err := svc.State(f.Ctx, f.Org, f.Agent, id); err != nil || got != want {
			t.Fatalf("state = %s, %v; want %s", got, err, want)
		}
	}
	if _, err := svc.State(f.Ctx, f.Org, f.OtherAgent, ids[0]); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another agent read the request: %v", err)
	}
	if _, err := svc.State(f.Ctx, uuid.New(), f.Agent, ids[0]); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another organization read the request: %v", err)
	}
	if _, err := svc.Approve(f.Ctx, f.Org, f.Agent, ids[0], f.Owner); err != nil {
		t.Fatal(err)
	}
	if got, _ := svc.State(f.Ctx, f.Org, f.Agent, ids[0]); got != StateApproved {
		t.Fatalf("approved state = %s", got)
	}
	if n := f.Count(`SELECT count(*) FROM agent_mcp_tool_approval_requests WHERE id=$1 AND state='approved'`, ids[0]); n != 1 {
		t.Fatal("reading the state spent the approval")
	}
	if _, outcome, _ := svc.Decide(f.Ctx, f.Org, f.Agent, identity(t, `{"customer":"a"}`)); outcome != OutcomeAllowed {
		t.Fatalf("approved call = %s", outcome)
	}
	if got, _ := svc.State(f.Ctx, f.Org, f.Agent, ids[0]); got != StateExpired {
		t.Fatalf("used approval state = %s, want expired", got)
	}

	// Past its lifetime a request is expired for a waiter and leaves the pending inbox and the count.
	clock = clock.Add(lifetime + time.Second)
	if got, _ := svc.State(f.Ctx, f.Org, f.Agent, ids[2]); got != StateExpired {
		t.Fatalf("state past the lifetime = %s", got)
	}
	f.Exec(`UPDATE agent_mcp_tool_approval_requests SET expires_at=now()-interval '1 second' WHERE org_id=$1 AND state='pending'`, f.Org)
	if rows, _, err := svc.ListOrganization(f.Ctx, f.Org, true, 50, ""); err != nil || len(rows) != 0 {
		t.Fatalf("pending inbox after expiry = %d, %v", len(rows), err)
	}
	if n, _ := svc.CountPending(f.Ctx, f.Org); n != 0 {
		t.Fatalf("pending count after expiry = %d", n)
	}
	// The request of an agent that was removed is not listed.
	f.Exec(`UPDATE devices SET deleted_at=now(), status='revoked' WHERE id=$1`, f.OtherAgent)
	if rows, _, _ := svc.ListOrganization(f.Ctx, f.Org, false, 50, ""); len(rows) != 3 {
		t.Fatalf("inbox after removing an agent = %d, want 3", len(rows))
	}
}
