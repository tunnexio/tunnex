import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AIModelConnectionDetails } from "../src/components/AIModelConnectionDetails";
const state = vi.hoisted(() => ({ orgs: [{ id: "one", name: "First" }], user: "user-one", get: vi.fn() }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => state }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: state.user } } }) }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api: { GET: state.get } }));
const copy = vi.fn().mockResolvedValue(undefined);
const base = "http://100.96.0.1:8083/api/v1/organizations/one/ai-gateway/inference/v1";
const model = "custom-connection/gpt-5";
const granted = { model, mode: "chat", vpn_base_url: base };
beforeEach(() => {
  state.orgs = [{ id: "one", name: "First" }]; state.user = "user-one";
  state.get.mockReset().mockResolvedValue({ data: [granted] });
  copy.mockClear(); Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: copy } });
});
afterEach(cleanup);
it("uses the granted user's published VPN endpoint instead of the browser origin", async () => {
  render(<AIModelConnectionDetails orgId="one" model={model} />);
  fireEvent.click(await screen.findByRole("button", { name: "Copy Base URL" }));
  await waitFor(() => expect(copy).toHaveBeenCalledWith(base));
  fireEvent.click(screen.getByRole("button", { name: "Copy Python example" }));
  expect(copy).toHaveBeenLastCalledWith(expect.stringContaining(`base_url="${base}"`));
  expect(copy).toHaveBeenLastCalledWith(expect.stringContaining('api_key="unused"'));
  expect(copy).toHaveBeenLastCalledWith(expect.stringContaining(`model="${model}"`));
  expect(copy.mock.calls.at(-1)?.[0]).not.toContain(window.location.origin);
  expect(state.get).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/ai-gateway/my-models", { params: { path: { orgId: "one" } } });
});
it("keeps every language and both Python styles on the VPN with no credential prompt", async () => {
  render(<AIModelConnectionDetails orgId="one" model={model} />);
  await screen.findByRole("tab", { name: "Python" });
  fireEvent.click(screen.getByRole("button", { name: "REST over VPN" }));
  for (const tab of screen.getAllByRole("tab")) {
    fireEvent.click(tab);
    fireEvent.click(screen.getByRole("button", { name: "Copy example" }));
    const source = copy.mock.calls.at(-1)?.[0] as string;
    expect(source).toContain("/api/v1/organizations/one/ai-gateway/inference/v1/chat/completions");
    expect(source).toContain("100.96.0.1:8083");
    expect(source).not.toMatch(/TUNNEX_API_KEY|Authorization|YOUR_TUNNEX_CREDENTIAL|api_key/);
    expect(source).not.toContain(window.location.origin);
  }
  expect(screen.getAllByRole("tab", { name: "Python" })).toHaveLength(1);
});
it.each(["deployment_disabled", "http_disabled", "transport_unavailable", "gateway_not_ready", undefined])("has no copyable fallback when the endpoint is unavailable (%s)", async reason => {
  state.get.mockResolvedValue({ data: [{ model, mode: "chat", vpn_unavailable_reason: reason }] });
  render(<AIModelConnectionDetails orgId="one" model={model} />);
  await waitFor(() => expect((screen.getByRole("button", { name: "Refresh VPN endpoint" }) as HTMLButtonElement).disabled).toBe(false));
  expect(screen.queryByRole("button", { name: "Copy Base URL" })).toBeNull();
  expect(screen.queryByRole("tablist")).toBeNull();
  expect(screen.queryByText(/Checking your VPN endpoint/)).toBeNull();
  state.get.mockResolvedValue({ data: [granted] });
  fireEvent.click(screen.getByRole("button", { name: "Refresh VPN endpoint" }));
  await screen.findByRole("button", { name: "Copy Base URL" });
});
it("does not give an administrator a connection example without their own model grant", async () => {
  state.get.mockResolvedValue({ data: [{ ...granted, model: "a-different-model" }] });
  render(<AIModelConnectionDetails orgId="one" model={model} />);
  await screen.findByText(/Your user needs a model access grant/);
  expect(screen.queryByRole("tablist")).toBeNull();
});
it.each(["embedding", "audio_speech", "audio_transcription", "video_generation", "completion", "image_generation", "rerank"])("does not advertise unsupported VPN operation %s", mode => {
  render(<AIModelConnectionDetails orgId="one" model={model} mode={mode} />);
  expect(screen.getByText(/This model's operation is not supported over VPN yet/)).toBeTruthy();
  expect(screen.queryByRole("button", { name: /Copy/ })).toBeNull();
  expect(state.get).not.toHaveBeenCalled();
});
it.each(["response", "network"])("offers retry after a %s failure without inventing an endpoint", async failure => {
  if (failure === "network") state.get.mockRejectedValue(new Error("offline"));
  else state.get.mockResolvedValue({ error: { error: { message: "Failed" } } });
  render(<AIModelConnectionDetails orgId="one" model={model} />);
  expect(await screen.findByRole("alert")).toBeTruthy();
  expect(screen.queryByRole("tablist")).toBeNull();
});
it("discards in-flight results from the previous organization or user", async () => {
  let resolve!: (value: unknown) => void;
  state.get.mockReturnValueOnce(new Promise(done => { resolve = done; }));
  const { rerender } = render(<AIModelConnectionDetails orgId="one" model={model} />);
  state.get.mockResolvedValue({ data: [] });
  state.user = "user-two";
  rerender(<AIModelConnectionDetails orgId="two" model={model} />);
  await screen.findByText(/Your user needs a model access grant/);
  await act(async () => resolve({ data: [granted] }));
  expect(screen.queryByRole("button", { name: "Copy Base URL" })).toBeNull();
  expect(state.get).toHaveBeenLastCalledWith(expect.any(String), { params: { path: { orgId: "two" } } });
});
it("switches language tabs with arrow keys and copies the selected source", async () => {
  render(<AIModelConnectionDetails orgId="one" model={model} />);
  const python = await screen.findByRole("tab", { name: "Python" });
  fireEvent.keyDown(python, { key: "ArrowRight" });
  const curl = screen.getByRole("tab", { name: "cURL" });
  expect(curl.getAttribute("aria-selected")).toBe("true");
  expect(document.activeElement).toBe(curl);
  fireEvent.click(screen.getByRole("button", { name: "Copy example" }));
  expect(copy).toHaveBeenLastCalledWith(expect.stringContaining("curl --fail-with-body"));
});
