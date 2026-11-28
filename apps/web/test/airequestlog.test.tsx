import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AIRequestLog } from "../src/components/AIRequestLog";

// AI-READY-1: the Requests view under Usage & cost.
const api = vi.hoisted(() => ({ GET: vi.fn() }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api }));
beforeEach(() => { vi.resetAllMocks(); });
afterEach(cleanup);

const row = (over: Record<string, unknown>) => ({ id: crypto.randomUUID(), occurred_at: "2026-11-28T10:00:00Z", subject_kind: "user", subject_id: "u-1", subject_name: "Ana", group_name: "Engineering", model: "openai/gpt-4o-mini", mode: "chat", ingress: "public", status_code: 200, outcome: "ok", latency_ms: 812, prompt_tokens: 120, completion_tokens: 30, cost_usd: 0.0021, cost_state: "costed", ...over });

describe("AI request log", () => {
  it("lists requests with subject, status, tokens and cost, then pages with the cursor", async () => {
    api.GET.mockResolvedValueOnce({ data: { items: [row({}), row({ subject_name: "", subject_id: null, outcome: "refused", status_code: 403, refusal_code: "ai_daily_threshold_reached", cost_state: "not_applicable", prompt_tokens: null, completion_tokens: null })], next_cursor: "c1" } })
      .mockResolvedValueOnce({ data: { items: [row({ subject_kind: "workload", subject_name: "billing-api", cost_state: "uncosted", cost_usd: null })] } });
    render(<AIRequestLog orgId="org-1" />);
    expect(await screen.findByText("Ana")).toBeTruthy();
    expect(screen.getByText("Daily limit reached")).toBeTruthy();
    expect(screen.getByText("120 / 30")).toBeTruthy();
    expect(screen.getByText(/Prompts and responses are never stored/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Load more" }));
    expect(await screen.findByText("billing-api")).toBeTruthy();
    expect(screen.getByText("Uncosted")).toBeTruthy();
    expect(api.GET.mock.calls[1][1].params.query.cursor).toBe("c1");
    expect(screen.queryByRole("button", { name: "Load more" })).toBeNull();
  });

  it("sends the subject, status and model filters", async () => {
    api.GET.mockResolvedValue({ data: { items: [] } });
    render(<AIRequestLog orgId="org-1" />);
    await screen.findByText("No AI requests");
    fireEvent.change(screen.getByLabelText("Filter by subject"), { target: { value: "agent" } });
    fireEvent.change(screen.getByLabelText("Filter by status"), { target: { value: "refused" } });
    fireEvent.change(screen.getByLabelText("Filter by model"), { target: { value: "openai/gpt-4o-mini" } });
    fireEvent.submit(screen.getByLabelText("Filter by model").closest("form")!);
    await waitFor(() => {
      const query = api.GET.mock.calls.at(-1)![1].params.query;
      expect(query).toMatchObject({ subject_kind: "agent", outcome: "refused", model: "openai/gpt-4o-mini", limit: 50 });
    });
  });
});
