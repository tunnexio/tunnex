import { createElement } from "react";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AIUsageWorkspace } from "../src/components/AIUsageWorkspace";
import type { AIUsageDashboardProps } from "../src/components/AIUsageDashboard";

const mocks = vi.hoisted(() => ({ GET: vi.fn(), dashboard: vi.fn() }));
vi.mock("../src/lib/api", () => ({ api: mocks }));
vi.mock("../src/components/AIUsageDashboard", async (importOriginal) => ({
  ...await importOriginal<typeof import("../src/components/AIUsageDashboard")>(),
  AIUsageDashboard: (p: AIUsageDashboardProps) => {
    mocks.dashboard(p);
    return createElement("section", null, p.filters,
      createElement("p", { "data-testid": "result" }, p.status === "ready" ? `Cost ${p.totals?.cost}` : p.status),
      p.error ? createElement("p", { role: "alert" }, p.error) : null,
      createElement("button", { onClick: p.onRetry }, "Retry dashboard"));
  },
}));
const inventory = { groups: [{ id: "team-a", name: "Team A" }], devices: [{ id: "agent-a", name: "Agent A" }], teams: [{ team_id: "team-a" }], assignments: [{ device_id: "agent-a" }] };
const report = { total_requests: 8, total_tokens: 56, prompt_tokens: 32, completion_tokens: 24, total_cost: 0.00017, uncosted_requests: 0, semantics: "observed_estimate", dashboard: { successful_requests: 8, failed_requests: 0, cancelled_requests: 0, daily: [], models: [], teams: [], agents: [] } };
const show = (orgId = "org-a") => createElement(AIUsageWorkspace, { orgId, inventory, key: orgId });
beforeEach(() => { vi.resetAllMocks(); mocks.GET.mockResolvedValue({ data: report }); });
afterEach(cleanup);

describe("AI usage dashboard requests", () => {
  it("automatically requests seven UTC days with explicit dashboard aggregation", async () => {
    render(show()); await screen.findByText("Cost 0.00017");
    const [path, request] = mocks.GET.mock.calls[0];
    expect(path).toBe("/api/v1/organizations/{orgId}/ai-gateway/usage");
    expect(request.params.path.orgId).toBe("org-a");
    expect(request.params.query.dashboard).toBe(true);
    const span = Date.parse(request.params.query.to) - Date.parse(request.params.query.from);
    expect(span).toBeGreaterThanOrEqual(6 * 86400000);
    expect(span).toBeLessThanOrEqual(7 * 86400000);
    expect(request.params.query.from).toMatch(/T00:00:00.000Z$/);
    expect(screen.getByText(/older activity may no longer be available/)).toBeTruthy();
  });
  it("clears data immediately and ignores a late response after changing team", async () => {
    let resolve!: (v: unknown) => void;
    mocks.GET.mockImplementationOnce(() => new Promise((r) => { resolve = r; })).mockResolvedValue({ data: { ...report, total_cost: 2 } });
    render(show());
    fireEvent.change(screen.getByLabelText("Usage team"), { target: { value: "team-a" } });
    await screen.findByText("Cost 2");
    await act(async () => resolve({ data: { ...report, total_cost: 999 } }));
    expect(screen.queryByText("Cost 999")).toBeNull();
    expect(mocks.GET.mock.calls[1][1].params.query.team_id).toBe("team-a");
    expect(mocks.GET.mock.calls[0][1].signal.aborted).toBe(true);
  });
  it("ignores another organization's pending data and names", async () => {
    let resolve!: (v: unknown) => void;
    mocks.GET.mockImplementationOnce(() => new Promise((r) => { resolve = r; })).mockResolvedValue({ data: { ...report, total_cost: 3 } });
    const page = render(show()); page.rerender(show("org-b"));
    await screen.findByText("Cost 3");
    await act(async () => resolve({ data: { ...report, total_cost: 999, dashboard: { ...report.dashboard, teams: [{ id: "private", name: "Private other organization" }] } } }));
    expect(screen.queryByText(/Private other organization/)).toBeNull();
    expect(screen.queryByText("Cost 999")).toBeNull();
  });
  it("keeps failed or old-server data unavailable and retries without claiming zero", async () => {
    mocks.GET.mockResolvedValueOnce({ data: { ...report, dashboard: undefined } });
    render(show()); await screen.findByRole("alert");
    expect(screen.getByTestId("result").textContent).toBe("error");
    expect(screen.queryByText("Cost 0")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Retry dashboard" }));
    await screen.findByText("Cost 0.00017");
  });
  it("validates custom bounds before fetching and sends the exact applied UTC range", async () => {
    render(show()); await screen.findByText("Cost 0.00017");
    fireEvent.change(screen.getByLabelText("Time range"), { target: { value: "custom" } });
    fireEvent.change(screen.getByLabelText("From (UTC)"), { target: { value: "2026-08-01T00:00" } });
    fireEvent.change(screen.getByLabelText("To (UTC)"), { target: { value: "2026-09-07T00:00" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply range" }));
    expect(screen.getByRole("alert").textContent).toContain("at most 31 days");
    expect(mocks.GET).toHaveBeenCalledTimes(1);
    fireEvent.change(screen.getByLabelText("From (UTC)"), { target: { value: "2026-09-01T00:00" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply range" }));
    await waitFor(() => expect(mocks.GET).toHaveBeenCalledTimes(2));
    expect(mocks.GET.mock.calls[1][1].params.query.from).toBe("2026-09-01T00:00:00.000Z");
    expect(mocks.GET.mock.calls[1][1].params.query.to).toBe("2026-09-07T00:00:00.000Z");
  });
  it("shows stable workload totals without adding them to the summary or legacy attribution", async () => {
    const agent = { id: "agent-a", name: "Legacy agent", requests: 2, tokens: 12, cost: 0.00003, uncosted_requests: 0 };
    const group = { id: "group-a", name: "People", requests: 1, tokens: 4, cost: 0.00002, uncosted_requests: 0 };
    const workloads = [
      { id: "workload-b", name: "Nightly indexing", requests: 1, tokens: 10, cost: 0.00002, uncosted_requests: 0 },
      { id: "workload-a", name: "Support worker", requests: 4, tokens: 30, cost: 0.0001, uncosted_requests: 1 },
    ];
    mocks.GET.mockResolvedValue({ data: { ...report, uncosted_requests: 1, dashboard: { ...report.dashboard, agents: [agent], user_groups: [group], workloads } } });
    render(show());
    const table = await screen.findByRole("table", { name: "Spend by workload" });
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(3);
    expect(within(rows[1]).getByRole("rowheader").textContent).toBe("Support worker");
    expect(within(rows[1]).getAllByRole("cell").map((cell) => cell.textContent)).toEqual(["4", "30", "$0.000100", "1"]);
    expect(screen.getByText(/Combined usage across each workload's instances/)).toBeTruthy();
    expect(screen.getAllByText("Support worker")).toHaveLength(1);
    const props = mocks.dashboard.mock.lastCall![0] as AIUsageDashboardProps;
    expect(props.totals).toMatchObject({ requests: 8, tokens: 56, cost: 0.00017, uncostedRequests: 1 });
    expect(props.agents).toEqual([{ ...agent, uncostedRequests: 0 }]);
    expect(props.userGroups).toEqual([{ ...group, uncostedRequests: 0 }]);
    expect(props.teams).toEqual([]);
    expect(screen.queryByRole("option", { name: "Support worker" })).toBeNull();
    expect(workloads[0].id).toBe("workload-b");
  });
  it("distinguishes an absent workload breakdown from an empty recorded period", async () => {
    render(show());
    await screen.findByText("Workload breakdown is unavailable.");
    expect(screen.queryByText("No workload usage recorded in this period.")).toBeNull();
    mocks.GET.mockResolvedValue({ data: { ...report, dashboard: { ...report.dashboard, workloads: [] } } });
    fireEvent.click(screen.getByRole("button", { name: "Retry dashboard" }));
    await screen.findByText("No workload usage recorded in this period.");
    expect(screen.queryByText("Workload breakdown is unavailable.")).toBeNull();
    expect(screen.queryByRole("table", { name: "Spend by workload" })).toBeNull();
  });
  it("clears workload attribution during refresh and keeps failed refreshes unavailable", async () => {
    mocks.GET.mockResolvedValueOnce({ data: { ...report, dashboard: { ...report.dashboard, workloads: [{ id: "workload-a", name: "Support worker", requests: 8, tokens: 56, cost: 0.00017, uncosted_requests: 0 }] } } });
    let resolve!: (value: unknown) => void;
    mocks.GET.mockImplementationOnce(() => new Promise((done) => { resolve = done; }));
    render(show());
    await screen.findByRole("table", { name: "Spend by workload" });
    fireEvent.click(screen.getByRole("button", { name: "Refresh usage" }));
    expect(screen.queryByText("Support worker")).toBeNull();
    expect(screen.queryByRole("region", { name: "Workload usage" })).toBeNull();
    await act(async () => resolve({ error: { message: "Unavailable" } }));
    await screen.findByRole("alert");
    expect(screen.queryByRole("region", { name: "Workload usage" })).toBeNull();
    expect(screen.queryByText("No workload usage recorded in this period.")).toBeNull();
  });
});
