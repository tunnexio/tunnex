import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ModelPriceCell, ModelPriceDialog, formatPerMillion } from "../src/components/AIModelPrices";
import { AIGatewaySettings } from "../src/components/AIGatewaySettings";

// AI-READY-1: operator model prices on Models & endpoints, and the unknown-price policy in settings.
const api = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn(), DELETE: vi.fn(), POST: vi.fn() }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api }));
beforeEach(() => { vi.resetAllMocks(); });
afterEach(cleanup);

const saved = { model: "gemini/gemini-3.5-flash", input_cost_per_token: 3e-7, output_cost_per_token: 2.5e-6, removed: false, revision: 2, applied_revision: 2, status: "applied" as const, updated_at: "2026-11-28T00:00:00Z" };

describe("model price cell", () => {
  it("reads per million tokens and names the source", () => {
    render(<ModelPriceCell failed={false} info={{ effective: { model: saved.model, source: "override", input_cost_per_token: 3e-7, output_cost_per_token: 2.5e-6 }, saved }} />);
    expect(screen.getByText("$0.3 / $2.50")).toBeTruthy();
    expect(screen.getByText("Custom")).toBeTruthy();
  });
  it("marks an unknown price", () => {
    render(<ModelPriceCell failed={false} info={{ effective: { model: saved.model, source: "unknown", input_cost_per_token: null, output_cost_per_token: null } }} />);
    expect(screen.getByText("Price unknown")).toBeTruthy();
  });
  it("says when a saved price is not applied yet", () => {
    render(<ModelPriceCell failed={false} info={{ effective: { model: saved.model, source: "catalog", input_cost_per_token: 1e-6, output_cost_per_token: 2e-6 }, saved: { ...saved, status: "pending", applied_revision: 1 } }} />);
    expect(screen.getByText("Catalog · change pending")).toBeTruthy();
  });
  it("formats small and large prices", () => {
    expect(formatPerMillion(0.000015)).toBe("$15.00");
    expect(formatPerMillion(null)).toBe("—");
  });
});

describe("set price dialog", () => {
  it("sends USD per token from per-million input with the current revision", async () => {
    api.PUT.mockResolvedValue({ data: { ...saved, revision: 3 }, response: { status: 200 } });
    const onSaved = vi.fn();
    render(<ModelPriceDialog orgId="org-1" model={saved.model} mode="chat" info={{ saved }} onClose={() => {}} onSaved={onSaved} />);
    fireEvent.change(screen.getByLabelText("Input (USD per 1M tokens)"), { target: { value: "0.5" } });
    fireEvent.change(screen.getByLabelText("Output (USD per 1M tokens)"), { target: { value: "4" } });
    fireEvent.click(screen.getByRole("button", { name: "Save price" }));
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
    const body = api.PUT.mock.calls[0][1].body;
    expect(body.model).toBe(saved.model);
    expect(body.input_cost_per_token).toBeCloseTo(5e-7, 15);
    expect(body.output_cost_per_token).toBeCloseTo(4e-6, 15);
    expect(body.expected_revision).toBe(2);
  });
  it("requires an output price for chat, not for embedding", () => {
    const { unmount } = render(<ModelPriceDialog orgId="org-1" model="openai/x" mode="chat" onClose={() => {}} onSaved={() => {}} />);
    fireEvent.change(screen.getByLabelText("Input (USD per 1M tokens)"), { target: { value: "1" } });
    expect((screen.getByRole("button", { name: "Save price" }) as HTMLButtonElement).disabled).toBe(true);
    unmount();
    render(<ModelPriceDialog orgId="org-1" model="openai/e" mode="embedding" onClose={() => {}} onSaved={() => {}} />);
    fireEvent.change(screen.getByLabelText("Input (USD per 1M tokens)"), { target: { value: "0.02" } });
    expect((screen.getByRole("button", { name: "Save price" }) as HTMLButtonElement).disabled).toBe(false);
  });
  it("removes a saved price with its revision", async () => {
    api.DELETE.mockResolvedValue({ data: { ...saved, removed: true, revision: 3 }, response: { status: 200 } });
    const onSaved = vi.fn();
    render(<ModelPriceDialog orgId="org-1" model={saved.model} mode="chat" info={{ saved }} onClose={() => {}} onSaved={onSaved} />);
    fireEvent.click(screen.getByRole("button", { name: "Remove price" }));
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
    expect(api.DELETE.mock.calls[0][1].params.query).toEqual({ model: saved.model, expected_revision: 2 });
  });
});

describe("cost settings", () => {
  it("saves the unknown-price policy and retention with the revision", async () => {
    api.GET.mockImplementation(async (path: string) => path.endsWith("/cost-settings")
      ? { data: { unknown_price_policy: "block", request_log_retention_days: 30, revision: 0 }, response: { status: 200 } }
      : { data: { enabled: true, available: true, revision: 1, status: { on: true } }, response: { status: 200 } });
    api.PUT.mockResolvedValue({ data: { unknown_price_policy: "allow_and_alert", request_log_retention_days: 14, revision: 1 }, response: { status: 200 } });
    render(<AIGatewaySettings orgId="org-1" canEdit={false} />);
    await screen.findByText("Block (default)");
    expect((screen.getByRole("radio", { name: /Allow and alert/ }) as HTMLInputElement).disabled).toBe(true);
    cleanup();
    render(<AIGatewaySettings orgId="org-1" canEdit />);
    fireEvent.click(await screen.findByRole("radio", { name: /Allow and alert/ }));
    fireEvent.change(screen.getByLabelText("Keep the request log for (days)"), { target: { value: "14" } });
    fireEvent.click(screen.getByRole("button", { name: "Save cost settings" }));
    await waitFor(() => expect(api.PUT).toHaveBeenCalled());
    const call = api.PUT.mock.calls.find((c) => String(c[0]).endsWith("/cost-settings"));
    expect(call?.[1].body).toEqual({ unknown_price_policy: "allow_and_alert", request_log_retention_days: 14, expected_revision: 0 });
    expect(screen.getByText(/Prompts and responses are never stored/)).toBeTruthy();
  });
});
