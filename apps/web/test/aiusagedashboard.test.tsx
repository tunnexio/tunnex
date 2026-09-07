import { createElement } from "react";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import AIUsageDashboard, { formatAIUsageCost, type AIUsageDashboardProps } from "../src/components/AIUsageDashboard";
afterEach(cleanup);
const report: AIUsageDashboardProps = {
  status: "ready",
  totals: { requests: 5, tokens: 30, inputTokens: 20, outputTokens: 10, cost: 0.00017, uncostedRequests: 1, successfulRequests: 4, failedRequests: 1 },
  daily: [{ date: "2026-09-07", requests: 5, tokens: 30, cost: 0.00017, uncostedRequests: 1 }],
  models: [{ name: "openrouter/example", cost: 0.00017 }],
  teams: [{ id: "team-a", name: "Engineering", requests: 5, tokens: 30, cost: 0.00017, uncostedRequests: 1 }],
  agents: [{ id: "agent-a", name: "Build assistant", requests: 5, tokens: 30, cost: 0.00017, uncostedRequests: 1 }],
};
describe("AI usage dashboard", () => {
  it("preserves small nonzero spend and never claims invalid cost is zero", () => {
    expect(formatAIUsageCost(0.00017)).toBe("$0.000170");
    expect(formatAIUsageCost(0.0000002)).toBe("<$0.000001");
    expect(formatAIUsageCost(0)).toBe("$0.00");
    expect(formatAIUsageCost(NaN)).toBe("Unavailable");
  });
  it("shows incomplete cost and accessible keyboard daily details with a table alternative", () => {
    render(createElement(AIUsageDashboard, report));
    expect(screen.getByText(/Cost is incomplete/)).toBeTruthy();
    expect(screen.getByText(/Provider request outcomes exclude/)).toBeTruthy();
    const day = screen.getByRole("button", { name: /2026-09-07: \$0.000170/ });
    fireEvent.focus(day);
    expect(screen.getByText(/5 requests · 30 tokens · 1 without cost/)).toBeTruthy();
    expect(day.getAttribute("aria-describedby")).toBeTruthy();
    fireEvent.keyDown(day, { key: "Escape" });
    expect(screen.getByText(/Hover or focus a day/)).toBeTruthy();
    fireEvent.click(screen.getByText("View daily data table"));
    const table = screen.getByRole("table", { name: "Daily observed usage in UTC" });
    expect(within(table).getByText("$0.000170")).toBeTruthy();
    expect(within(table).getByRole("columnheader", { name: "Without cost" })).toBeTruthy();
  });
  it("shows average cost only for nonempty completely priced requests", () => {
    const page = render(createElement(AIUsageDashboard, report));
    const metric = () => screen.getByText("Avg. cost / request").parentElement!;
    expect(metric().textContent).toContain("UnavailableIncomplete pricing");
    page.rerender(createElement(AIUsageDashboard, { ...report, totals: { ...report.totals!, uncostedRequests: 0 } }));
    expect(metric().textContent).toContain("$0.000034");
    page.rerender(createElement(AIUsageDashboard, { ...report, totals: { requests: 0, tokens: 0, inputTokens: 0, outputTokens: 0, cost: 0, uncostedRequests: 0, successfulRequests: 0, failedRequests: 0 } }));
    expect(metric().textContent).toContain("UnavailableNo requests");
    expect(metric().textContent).not.toContain("$0.00");
  });
  it("renders model costs without inventing model request counts", () => {
    render(createElement(AIUsageDashboard, report));
    const table = screen.getByRole("table", { name: "Spend by model" });
    expect(within(table).getByText("openrouter/example")).toBeTruthy();
    expect(within(table).queryByRole("columnheader", { name: "Requests" })).toBeNull();
  });
  it("does not display stale totals as current during loading or failure and offers retry", () => {
    const retry = vi.fn();
    const page = render(createElement(AIUsageDashboard, { ...report, status: "loading" }));
    expect(screen.queryByText("ESTIMATED SPEND")).toBeNull();
    expect(screen.getByRole("status").textContent).toContain("Loading usage");
    page.rerender(createElement(AIUsageDashboard, { ...report, status: "error", onRetry: retry }));
    expect(screen.queryByText("ESTIMATED SPEND")).toBeNull();
    expect(screen.getByRole("alert").textContent).toContain("No zero-spend claim");
    fireEvent.click(screen.getByRole("button", { name: "Retry usage" }));
    expect(retry).toHaveBeenCalledOnce();
  });
  it("distinguishes zero activity from missing breakdowns", () => {
    render(createElement(AIUsageDashboard, { status: "ready", totals: { requests: 0, tokens: 0, inputTokens: 0, outputTokens: 0, cost: 0, uncostedRequests: 0, successfulRequests: 0, failedRequests: 0 }, daily: [] }));
    expect(screen.getByText("No requests in this period")).toBeTruthy();
    expect(screen.getByText("No daily usage recorded in this period.")).toBeTruthy();
    expect(screen.getAllByText("Breakdown is unavailable.")).toHaveLength(3);
  });
});
