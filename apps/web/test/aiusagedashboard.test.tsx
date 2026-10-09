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
    expect(screen.getByText(/requests missing cost/)).toBeTruthy();
    fireEvent.click(screen.getByText("About figures", { selector: "summary" }));
    expect(screen.getByText(/Outcomes exclude/)).toBeTruthy();
    const day = screen.getByRole("button", { name: /2026-09-07: \$0.000170/ });
    fireEvent.focus(day);
    expect(screen.getByText(/5 requests · 30 tokens · 1 without cost/)).toBeTruthy();
    expect(day.getAttribute("aria-describedby")).toBeTruthy();
    fireEvent.keyDown(day, { key: "Escape" });
    expect(screen.getByText(/UTC · Requests/)).toBeTruthy();
    fireEvent.click(screen.getByText("View daily data table"));
    const table = screen.getByRole("table", { name: "Daily observed usage in UTC" });
    expect(within(table).getByText("$0.000170")).toBeTruthy();
    expect(within(table).getByRole("columnheader", { name: "Without cost" })).toBeTruthy();
  });
  it("averages priced requests and excludes missing costs", () => {
    const page = render(createElement(AIUsageDashboard, report));
    const metric = () => screen.getByText("Avg. cost / priced request").parentElement!;
    expect(metric().textContent).not.toContain("Unavailable");
    page.rerender(createElement(AIUsageDashboard, { ...report, totals: { ...report.totals!, uncostedRequests: 0 } }));
    expect(metric().textContent).toContain("$0.000034");
    page.rerender(createElement(AIUsageDashboard, { ...report, totals: { requests: 0, tokens: 0, inputTokens: 0, outputTokens: 0, cost: 0, uncostedRequests: 0, successfulRequests: 0, failedRequests: 0 } }));
    expect(metric().textContent).toContain("Unavailable");
    expect(metric().textContent).not.toContain("$0.00");
  });
  it("keeps an unpriced day's cost unavailable in the chart, focused details and table", () => {
    const daily = [
      { date: "2026-10-08", requests: 16, tokens: 464, cost: 0, uncostedRequests: 16 },
      { date: "2026-10-09", requests: 3, tokens: 100, cost: 0.00017, uncostedRequests: 1 },
    ];
    render(createElement(AIUsageDashboard, { ...report, daily }));
    const day = screen.getByRole("button", { name: "2026-10-08: Unavailable, 16 requests, 464 tokens, 16 without cost" });
    fireEvent.focus(day);
    const detail = within(document.getElementById(day.getAttribute("aria-describedby")!)!);
    expect(detail.getByText("Unavailable")).toBeTruthy();
    expect(detail.getByText("16 requests · 464 tokens · 16 without cost")).toBeTruthy();
    expect(detail.queryByText("$0.00")).toBeNull();
    fireEvent.click(screen.getByText("View daily data table"));
    const table = within(screen.getByRole("table", { name: "Daily observed usage in UTC" }));
    const unpriced = within(table.getByRole("rowheader", { name: "2026-10-08" }).closest("tr")!);
    expect(unpriced.getByRole("cell", { name: "Unavailable" })).toBeTruthy();
    expect(unpriced.queryByRole("cell", { name: "$0.00" })).toBeNull();
    const partial = within(table.getByRole("rowheader", { name: "2026-10-09" }).closest("tr")!);
    expect(partial.getByRole("cell", { name: "$0.000170" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "2026-10-09: $0.000170, 3 requests, 100 tokens, 1 without cost" })).toBeTruthy();
  });
  it("renders model costs without inventing model request counts", () => {
    render(createElement(AIUsageDashboard, report));
    fireEvent.click(screen.getByRole("tab", { name: "Models" }));
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
    expect(screen.getAllByText("Breakdown is unavailable.")).toHaveLength(1);
  });
  it("pages ranked model usage without changing the period total or inventing request counts", () => {
    const models = Array.from({ length: 55 }, (_, index) => ({ name: `Model ${String(index + 1).padStart(2, "0")}`, cost: index + 1 }));
    render(createElement(AIUsageDashboard, { ...report, models }));
    fireEvent.click(screen.getByRole("tab", { name: "Models" }));
    const panel = within(screen.getByRole("tabpanel", { name: "Models" }));
    const table = () => panel.getByRole("table", { name: "Spend by model" });
    expect(within(table()).getAllByRole("row")).toHaveLength(21);
    expect(within(table()).getByText("Model 55")).toBeTruthy();
    expect(within(table()).queryByText("Model 01")).toBeNull();
    expect(within(table()).queryByRole("columnheader", { name: "Requests" })).toBeNull();
    fireEvent.click(panel.getByRole("button", { name: "Next page" }));
    fireEvent.click(panel.getByRole("button", { name: "Next page" }));
    expect(within(table()).getAllByRole("row")).toHaveLength(16);
    expect(within(table()).getByText("Model 01")).toBeTruthy();
    expect(panel.getByRole("button", { name: "Next page" })).toHaveProperty("disabled", true);
    expect(panel.getByRole("button", { name: "Previous page" })).toHaveProperty("disabled", false);
    fireEvent.change(panel.getByRole("combobox", { name: "Rows per page" }), { target: { value: "50" } });
    expect(within(table()).getAllByRole("row")).toHaveLength(51);
    expect(within(table()).getByText("Model 55")).toBeTruthy();
    expect(screen.getByTitle("$0.000170")).toBeTruthy();
    expect(models[0].name).toBe("Model 01");
  });
  it("pages the daily table while retaining every day in the keyboard-accessible chart", () => {
    const daily = Array.from({ length: 31 }, (_, index) => ({ ...report.daily![0], date: `2026-10-${String(index + 1).padStart(2, "0")}` }));
    render(createElement(AIUsageDashboard, { ...report, daily }));
    expect(within(screen.getByRole("group", { name: "Daily requests" })).getAllByRole("button")).toHaveLength(31);
    fireEvent.click(screen.getByText("View daily data table"));
    const table = screen.getByRole("table", { name: "Daily observed usage in UTC" });
    expect(within(table).getAllByRole("row")).toHaveLength(21);
    const disclosure = within(table.closest("details")!);
    fireEvent.click(disclosure.getByRole("button", { name: "Next page" }));
    expect(within(table).getAllByRole("row")).toHaveLength(12);
    expect(within(table).getByRole("rowheader", { name: "2026-10-31" })).toBeTruthy();
    expect(disclosure.getByRole("button", { name: "Previous page" })).toHaveProperty("disabled", false);
    fireEvent.change(disclosure.getByRole("combobox", { name: "Rows per page" }), { target: { value: "50" } });
    expect(within(table).getAllByRole("row")).toHaveLength(32);
    expect(disclosure.queryByRole("button", { name: "Previous page" })).toBeNull();
    expect(within(screen.getByRole("group", { name: "Daily requests" })).getAllByRole("button")).toHaveLength(31);
  });
});

it("compacts large metrics while retaining exact accessible values", () => {
  render(createElement(AIUsageDashboard, { ...report, totals: { ...report.totals!, requests: 123456789, tokens: 9876543210, cost: 1234567, uncostedRequests: 0 } }));
  expect(screen.getByText("123.5M").getAttribute("aria-label")).toBe("123,456,789");
  expect(screen.getByText("9.9B").getAttribute("title")).toBe("9,876,543,210");
  expect(screen.getByText("$1.2M").getAttribute("title")).toBe("$1,234,567.00");
});
