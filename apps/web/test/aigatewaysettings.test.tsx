import { createElement } from "react";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AIGatewaySettings } from "../src/components/AIGatewaySettings";

const api = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn() }));
vi.mock("../src/lib/api", () => ({ api }));
type Result = { data: { enabled: boolean; available: boolean; revision: number } };
function result(enabled: boolean, available = true): Result {
  return { data: { enabled, available, revision: 1 } };
}
function deferred() {
  let resolve!: (value: Result) => void;
  const promise = new Promise<Result>((done) => { resolve = done; });
  return { promise, resolve };
}
function view(orgId = "org-a", canEdit = true) {
  return createElement(AIGatewaySettings, { orgId, canEdit });
}
async function state(enabled: boolean) {
  await waitFor(() => expect(screen.getByRole("status").textContent).toContain(`Organization access: ${enabled ? "enabled" : "disabled"}.`));
}
beforeEach(() => { vi.resetAllMocks(); });
afterEach(cleanup);

describe("AI gateway organization settings", () => {
  it("retries an initial settings load failure without a browser refresh", async () => {
    api.GET.mockRejectedValueOnce(new Error("offline")).mockResolvedValueOnce(result(false));
    render(view());
    await screen.findByRole("alert");
    fireEvent.click(screen.getByRole("button", { name: "Retry AI gateway settings" }));
    await state(false);
    expect(screen.queryByRole("alert")).toBeNull();
    expect(api.GET).toHaveBeenCalledTimes(2);
    expect(api.PUT).not.toHaveBeenCalled();
  });
  it("prevents enable when the installation is unavailable", async () => {
    api.GET.mockResolvedValue(result(false, false));
    render(view());
    await state(false);
    const button = screen.getByRole("button", { name: "Enable AI gateway" }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fireEvent.click(button);
    expect(api.PUT).not.toHaveBeenCalled();
  });
  it("permits disable even when the installation is unavailable", async () => {
    api.GET.mockResolvedValue(result(true, false));
    api.PUT.mockResolvedValue(result(false, false));
    render(view());
    await state(true);
    const button = screen.getByRole("button", { name: "Disable AI gateway" }) as HTMLButtonElement;
    expect(button.disabled).toBe(false);
    fireEvent.click(button);
    await state(false);
    expect(api.PUT).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/ai-gateway", {
      params: { path: { orgId: "org-a" } }, body: { enabled: false },
    });
  });
  it("waits for server truth rather than optimistic enable", async () => {
    const saving = deferred();
    api.GET.mockResolvedValue(result(false));
    api.PUT.mockReturnValue(saving.promise);
    render(view());
    await state(false);
    fireEvent.click(screen.getByRole("button", { name: "Enable AI gateway" }));
    expect(screen.getByRole("status").textContent).toContain("Organization access: disabled.");
    expect((screen.getByRole("button", { name: "Saving…" }) as HTMLButtonElement).disabled).toBe(true);
    await act(async () => { saving.resolve(result(false)); });
    await state(false);
    expect(screen.getByRole("button", { name: "Enable AI gateway" })).toBeTruthy();
  });
  it("preserves the setting when saving fails over the network", async () => {
    api.GET.mockResolvedValue(result(true));
    api.PUT.mockRejectedValue(new Error("network unavailable"));
    render(view());
    await state(true);
    fireEvent.click(screen.getByRole("button", { name: "Disable AI gateway" }));
    await screen.findByRole("alert");
    expect(screen.getByRole("alert").textContent).toBe("Could not update AI gateway access.");
    await state(true);
    expect((screen.getByRole("button", { name: "Disable AI gateway" }) as HTMLButtonElement).disabled).toBe(false);
  });
  it("ignores stale organization loads", async () => {
    const oldLoad = deferred();
    api.GET.mockReturnValueOnce(oldLoad.promise).mockResolvedValueOnce(result(false, false));
    const page = render(view());
    page.rerender(view("org-b"));
    await state(false);
    await act(async () => { oldLoad.resolve(result(true)); });
    expect(screen.getByRole("status").textContent).toContain("Organization access: disabled. Gateway: not configured.");
    expect((screen.getByRole("button", { name: "Enable AI gateway" }) as HTMLButtonElement).disabled).toBe(true);
    expect(api.GET).toHaveBeenLastCalledWith("/api/v1/organizations/{orgId}/ai-gateway", { params: { path: { orgId: "org-b" } } });
  });
  it("ignores stale organization saves", async () => {
    const oldSave = deferred();
    api.GET.mockResolvedValue(result(false));
    api.PUT.mockReturnValue(oldSave.promise);
    const page = render(view());
    await state(false);
    fireEvent.click(screen.getByRole("button", { name: "Enable AI gateway" }));
    page.rerender(view("org-b"));
    await state(false);
    await act(async () => { oldSave.resolve(result(true)); });
    await state(false);
    expect(screen.getByRole("button", { name: "Enable AI gateway" })).toBeTruthy();
    expect(api.PUT).toHaveBeenCalledTimes(1);
    expect(api.PUT.mock.calls[0][1].params.path.orgId).toBe("org-a");
  });
  it("hides mutation controls when editing is forbidden", async () => {
    api.GET.mockResolvedValue(result(true));
    render(view("org-a", false));
    await state(true);
    expect(screen.queryByRole("button")).toBeNull();
    expect(api.PUT).not.toHaveBeenCalled();
  });
});
