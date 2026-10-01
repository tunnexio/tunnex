import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AITransportSettings } from "../src/components/AITransportSettings";

const api = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn() }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api }));
const endpoint = "/api/v1/admin/ai-transport-settings";
const settings = (allow_http = false, revision = 1) => ({ data: { allow_http, revision } });
const show = (canEdit = true) => render(<AITransportSettings canEdit={canEdit} />);
const toggle = () => screen.getByRole("switch", { name: "Allow AI Gateway over HTTP" }) as HTMLButtonElement;
const save = () => screen.getByRole("button", { name: "Save changes" }) as HTMLButtonElement;
const load = () => screen.findByRole("switch", { name: "Allow AI Gateway over HTTP" });

beforeEach(() => { vi.resetAllMocks(); api.GET.mockResolvedValue(settings()); });
afterEach(cleanup);

describe("server AI transport settings", () => {
  it("reflects default deny without mutating it and explains the public HTTP risk", async () => {
    show(); await load();
    expect(toggle().getAttribute("aria-checked")).toBe("false");
    expect(save().disabled).toBe(true);
    expect(screen.getByText("Saved policy: HTTPS required")).toBeTruthy();
    expect(screen.getByText(/including public endpoints/)).toBeTruthy();
    expect(screen.getByText(/HTTP does not encrypt credentials or requests/)).toBeTruthy();
    expect(api.GET).toHaveBeenCalledWith(endpoint);
    expect(api.PUT).not.toHaveBeenCalled();
  });

  it("saves only explicit opt-in with the loaded revision, waiting for server truth", async () => {
    let complete!: (value: ReturnType<typeof settings>) => void;
    api.PUT.mockImplementation(() => new Promise(resolve => { complete = resolve; }));
    show(); await load();
    fireEvent.click(toggle());
    expect(screen.getByText("Saved policy: HTTPS required")).toBeTruthy();
    expect(api.PUT).not.toHaveBeenCalled();
    const form = save().closest("form")!;
    fireEvent.submit(form); fireEvent.submit(form);
    expect(api.PUT).toHaveBeenCalledTimes(1);
    expect(api.PUT).toHaveBeenCalledWith(endpoint, { body: { allow_http: true, revision: 1 } });
    expect(screen.getByText("Saved policy: HTTPS required")).toBeTruthy();
    expect(toggle().disabled).toBe(true);
    await act(async () => complete(settings(true, 2)));
    expect(await screen.findByText("Saved policy: HTTP allowed")).toBeTruthy();
    expect(screen.getByRole("status").textContent).toContain("HTTPS remains available");
    expect(save().disabled).toBe(true);
  });

  it("can disable the saved exception using its current revision", async () => {
    api.GET.mockResolvedValue(settings(true, 9)); api.PUT.mockResolvedValue(settings(false, 10));
    show(); await load(); fireEvent.click(toggle()); fireEvent.click(save());
    await screen.findByText("Saved policy: HTTPS required");
    expect(api.PUT).toHaveBeenCalledWith(endpoint, { body: { allow_http: false, revision: 9 } });
    expect(toggle().getAttribute("aria-checked")).toBe("false");
    expect(screen.getByRole("status").textContent).toContain("HTTP access is blocked");
  });

  it("does not invent an editable default after a failed load and supports retry", async () => {
    api.GET.mockResolvedValueOnce({ error: { error: { message: "Settings unavailable" } } });
    show(); await screen.findByText("Settings unavailable");
    expect(screen.queryByRole("switch")).toBeNull();
    expect(screen.queryByText(/Saved policy/)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Retry transport settings" }));
    await load(); expect(toggle().getAttribute("aria-checked")).toBe("false");
    expect(api.PUT).not.toHaveBeenCalled();
  });

  it("preserves the confirmed policy when the server rejects saving", async () => {
    api.PUT.mockResolvedValue({ error: { error: { message: "Server administrator required" } }, response: { status: 403 } });
    show(); await load(); fireEvent.click(toggle()); fireEvent.click(save());
    await screen.findByText("Server administrator required");
    expect(screen.getByText("Saved policy: HTTPS required")).toBeTruthy();
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("requires reload after a stale revision rather than overwriting another admin", async () => {
    api.GET.mockResolvedValueOnce(settings()).mockResolvedValueOnce(settings(true, 4));
    api.PUT.mockResolvedValue({ error: { error: { code: "ai_transport_settings_changed" } }, response: { status: 409 } });
    show(); await load(); fireEvent.click(toggle()); fireEvent.click(save());
    await screen.findByText(/These settings changed on the server/);
    expect(save().disabled).toBe(true); expect(toggle().disabled).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Reload saved settings" }));
    await screen.findByText("Saved policy: HTTP allowed");
    expect(screen.queryByRole("alert")).toBeNull();
    expect(api.PUT).toHaveBeenCalledTimes(1);
  });

  it("reloads uncertain network results before permitting another save", async () => {
    api.GET.mockResolvedValueOnce(settings()).mockResolvedValueOnce(settings(true, 2));
    api.PUT.mockRejectedValue(new Error("network interrupted"));
    show(); await load(); fireEvent.click(toggle()); fireEvent.click(save());
    await screen.findByText(/response was interrupted/);
    expect(save().disabled).toBe(true);
    expect(screen.getByText("Saved policy: HTTPS required")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Reload saved settings" }));
    await screen.findByText("Saved policy: HTTP allowed");
    expect(api.PUT).toHaveBeenCalledTimes(1);
  });

  it("requires verified administrator editing even for programmatic form submission", async () => {
    show(false); await load();
    expect(toggle().disabled).toBe(true); expect(save().disabled).toBe(true);
    expect(screen.getByText(/Verify your email and change your initial password/)).toBeTruthy();
    fireEvent.click(toggle()); fireEvent.submit(save().closest("form")!);
    expect(api.PUT).not.toHaveBeenCalled();
  });

  it("reflects persisted policy on a new mount", async () => {
    api.GET.mockResolvedValue(settings(true, 6));
    const page = show(); await load(); page.unmount();
    show(); await load();
    expect(toggle().getAttribute("aria-checked")).toBe("true");
    expect(screen.getByText("Saved policy: HTTP allowed")).toBeTruthy();
    expect(api.GET).toHaveBeenCalledTimes(2); expect(api.PUT).not.toHaveBeenCalled();
  });
});
