import { createElement } from "react";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AIUsageWorkspace } from "../src/components/AIUsageWorkspace";

const mocks = vi.hoisted(() => ({ GET: vi.fn() }));
vi.mock("../src/lib/api", () => ({ api: mocks }));
vi.mock("../src/components/AIUsageDashboard", () => ({
  AIUsageDashboard: (p: { status: string; filters: unknown; totals?: { cost: number }; error?: string; onRetry: () => void }) =>
    createElement("section", null, p.filters as never,
      createElement("p", { "data-testid": "result" }, p.status === "ready" ? `Cost ${p.totals?.cost}` : p.status),
      p.error ? createElement("p", { role: "alert" }, p.error) : null,
      createElement("button", { onClick: p.onRetry }, "Retry dashboard")),
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
});
