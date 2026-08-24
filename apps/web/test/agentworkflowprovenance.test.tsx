import { createElement } from "react";
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import { AgentWorkflowProvenancePanel } from "../src/components/AgentWorkflowProvenance";

describe("F15 workflow provenance panel", () => {
  it("renders the verified chain but keeps unverified claim material absent", () => {
    render(createElement(AgentWorkflowProvenancePanel, {
      records: [
        { id: "verified", assertion_id: "a1", key_id: "agent-key", verification_state: "verified", verification_reason: "verified", received_at: "2026-08-21T00:00:00Z", verified_chain: { workflow_id: "deploy", run_id: "run-1", trigger_kind: "user", initiating_subject_ref: "subject-1", tool: "files.read", resource: "repo://docs", issued_at: "2026-08-21T00:00:00Z", expires_at: "2026-08-21T00:01:00Z" } },
        { id: "unverified", assertion_id: "a2", key_id: "unknown", verification_state: "unverified", verification_reason: "bad_signature", received_at: "2026-08-21T00:00:01Z", verified_chain: null },
      ],
    }));

    expect(screen.getByText(/Agent → deploy \/ run-1 → files.read → repo:\/\/docs/)).toBeTruthy();
    expect(screen.getByText(/Unverified context/)).toBeTruthy();
    expect(screen.getByText(/bad_signature/)).toBeTruthy();
    expect(screen.getByText(/initiator subject-1/)).toBeTruthy();
    expect(screen.queryByText("untrusted-workflow")).toBeNull();
  });
});
