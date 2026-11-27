import { MemoryRouter } from "react-router-dom";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import AIUsageDashboard, { type AIUsageDashboardProps } from "../src/components/AIUsageDashboard";
import { AIUsagePage } from "../src/components/AIUsageWorkspace";

// Per-agent usage against its budget. The budget is the daily one of the agent's group, which the
// existing responses already carry; there is no user-group budget and no per-user usage (deferred).
const api = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn() }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api }));

const totals = { requests: 12, tokens: 900, inputTokens: 600, outputTokens: 300, cost: 3, uncostedRequests: 0, successfulRequests: 12, failedRequests: 0 };
const agent = { id: "agent-1", name: "builder-01", requests: 8, tokens: 640, cost: 2, uncostedRequests: 0 };
const other = { id: "agent-2", name: "builder-02", requests: 4, tokens: 260, cost: 1, uncostedRequests: 0 };
const board = (props: Partial<AIUsageDashboardProps>) => { render(<AIUsageDashboard status="ready" totals={totals} daily={[]} models={[]} teams={[]} userGroups={[]} {...props} />); fireEvent.click(screen.getByRole("tab", { name: "Agents" })); return within(screen.getByRole("table", { name: "Usage by agent" })); };
beforeEach(() => { vi.resetAllMocks(); });
afterEach(cleanup);

describe("per-agent usage against its budget", () => {
  it("shows requests, tokens and cost against today's budget", () => {
    const table = board({ budgetDay: true, agents: [{ ...agent, budget: { dailyLimit: 5, group: "Build agents" } }] });
    expect(table.getAllByRole("columnheader").map((cell) => cell.textContent)).toEqual(["Agent", "Requests", "Tokens", "Cost", "Daily budget"]);
    const row = table.getByRole("row", { name: /builder-01/ });
    expect(row.textContent).toContain("8");
    expect(row.textContent).toContain("640");
    expect(row.textContent).toContain("$2.00 of $5.00");
    expect(row.textContent).toContain("40% of today's budget. Shared by Build agents.");
  });

  it("marks an agent whose spend reached the budget", () => {
    const table = board({ budgetDay: true, agents: [{ ...agent, cost: 6, budget: { dailyLimit: 5 } }] });
    expect(table.getByText("$6.00 of $5.00").closest(".ai-usage-budget")?.getAttribute("data-over")).toBe("true");
    expect(table.getByRole("row", { name: /builder-01/ }).textContent).toContain("100% of today's budget. Shared by its agent group.");
  });

  it("says 'No budget' for an agent without one, beside agents that have one", () => {
    const table = board({ budgetDay: true, agents: [{ ...agent, budget: { dailyLimit: 5 } }, { ...other, budget: { dailyLimit: null } }] });
    expect(table.getByRole("row", { name: /builder-02/ }).textContent).toContain("No budget");
    expect(table.getByRole("row", { name: /builder-02/ }).textContent).not.toContain(" of ");
  });

  it("does not compare a longer period with a daily budget", () => {
    const table = board({ budgetDay: false, agents: [{ ...agent, budget: { dailyLimit: 5, group: "Build agents" } }] });
    const row = table.getByRole("row", { name: /builder-01/ });
    expect(row.textContent).toContain("$5.00 a day");
    expect(row.textContent).toContain("Choose Today to compare.");
    expect(row.textContent).not.toContain("% of today's budget");
  });

  it("leaves the budget column out when budgets could not be read", () => {
    const table = board({ budgetDay: true, agents: [agent] });
    expect(table.getAllByRole("columnheader").map((cell) => cell.textContent)).toEqual(["Agent", "Requests", "Tokens", "Cost"]);
  });

  it("reads each agent's budget from its group and compares it for today", async () => {
    const report = { total_requests: 12, total_tokens: 900, prompt_tokens: 600, completion_tokens: 300, total_cost: 3, uncosted_requests: 0, semantics: "observed_estimate",
      dashboard: { successful_requests: 12, failed_requests: 0, cancelled_requests: 0, daily: [], models: [], teams: [{ id: "group-a", name: "Build agents", requests: 8, tokens: 640, cost: 2, uncosted_requests: 0 }],
        agents: [{ ...agent, uncosted_requests: 0 }, { ...other, uncosted_requests: 0 }] } };
    api.GET.mockImplementation(async (path: string) => path.endsWith("/usage") ? { data: report }
      : path.endsWith("/ai-gateway/teams") ? { data: [{ team_id: "group-a", models: ["openai/gpt-4o-mini"], key_ids: ["k"], daily_cost_limit: 5, revision: 1 }, { team_id: "group-b", models: ["openai/gpt-4o-mini"], key_ids: ["k"], revision: 1 }] }
      : path.endsWith("/ai-gateway/agents") ? { data: [{ device_id: "agent-1", team_id: "group-a" }, { device_id: "agent-2", team_id: "group-b" }] }
      : path.endsWith("/agent-groups") ? { data: [{ id: "group-a", name: "Build agents" }, { id: "group-b", name: "Research agents" }] }
      : { data: { enabled: true, available: true, revision: 1 } });
    render(<MemoryRouter><AIUsagePage orgId="org" canManage /></MemoryRouter>);
    fireEvent.click(await screen.findByRole("tab", { name: "Agents" }));
    const table = within(await screen.findByRole("table", { name: "Usage by agent" }));
    await waitFor(() => expect(table.getByRole("row", { name: /builder-01/ }).textContent).toContain("$5.00 a day"));
    expect(table.getByRole("row", { name: /builder-02/ }).textContent).toContain("No budget");
    fireEvent.change(screen.getByLabelText("Time range"), { target: { value: "today" } });
    fireEvent.click(await screen.findByRole("tab", { name: "Agents" }));
    const today = within(await screen.findByRole("table", { name: "Usage by agent" }));
    expect(today.getByRole("row", { name: /builder-01/ }).textContent).toContain("$2.00 of $5.00");
    expect(today.getByRole("row", { name: /builder-01/ }).textContent).toContain("Shared by Build agents.");
  });
});
