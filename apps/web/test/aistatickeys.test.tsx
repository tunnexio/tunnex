import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AIWorkloads } from "../src/components/AIWorkloads";

const mock = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), success: vi.fn() }));
vi.mock("../src/lib/api", async (importOriginal) => ({ ...await importOriginal<typeof import("../src/lib/api")>(), api: { GET: mock.get, POST: mock.post, PUT: mock.put } }));
vi.mock("../src/components/Toasts", () => ({ toast: { success: mock.success, error: vi.fn() } }));

const DAY = 86400000;
const root = "/api/v1/organizations/{orgId}/ai-gateway/workloads";
const keysPath = `${root}/{workloadId}/static-keys`;
const models = [{ connection_id: "connection", model: "openai/chat", mode: "chat" as const }];
const workload = { id: "workload", name: "Support bot", enabled: true, models, revision: 3, applied_revision: 3, status: "applied" as const, created_at: "2026-09-09T00:00:00Z" };
const provider = { id: "connection", name: "OpenAI production", provider: "openai", models: ["openai/chat"], model_modes: { "openai/chat": "chat" }, enabled: true, status: "applied", revision: 2, applied_revision: 2 };
const iso = (ms: number) => new Date(ms).toISOString();
function staticKey(over: Record<string, unknown> = {}) {
  return { id: "sk-1", workload_id: "workload", name: "lambda-parser", hint: "Ab12", scope: "internal", source_cidrs: ["10.20.0.0/16"], expires_at: iso(Date.now() + 60 * DAY), status: "applied", created_at: "2026-11-01T00:00:00Z", updated_at: "2026-11-02T00:00:00Z", ...over };
}
const gateway = { node_id: "node-1", node_name: "gw-east", tunnel_address: "100.64.0.1", has_site: true, supported: true, ready: true, url: "https://100.64.0.1:9443", endpoint: { id: "ep", enabled: true, listen_addresses: ["100.64.0.1"], port: 9443, source_cidrs: ["10.20.0.0/16"], tls_mode: "tunnex_ca", revision: 2, updated_at: "2026-11-01T00:00:00Z" } };

let keys: ReturnType<typeof staticKey>[] = [];
let endpoints: unknown[] = [gateway];
let publicAllowed = false;
function get(path: string) {
  if (path === root) return Promise.resolve({ data: [workload] });
  if (path.endsWith("providers")) return Promise.resolve({ data: { items: [provider] } });
  if (path === keysPath) return Promise.resolve({ data: { items: keys } });
  if (path.endsWith("internal-endpoints")) return Promise.resolve({ data: { items: endpoints } });
  if (path.endsWith("static-key-settings")) return Promise.resolve({ data: { public_static_keys_allowed: publicAllowed } });
  return Promise.resolve({ data: { items: [] } });
}
beforeEach(() => { vi.clearAllMocks(); keys = []; endpoints = [gateway]; publicAllowed = false; mock.get.mockImplementation(get); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

async function openWorkload(manage = true) {
  render(<AIWorkloads orgId="org" canManage={manage} />);
  fireEvent.click(await screen.findByRole("button", { name: "Open Support bot" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Refresh workload" })).toHaveProperty("disabled", false));
}
async function openKeys(manage = true) {
  await openWorkload(manage);
  fireEvent.click(screen.getByRole("tab", { name: "API keys" }));
  await waitFor(() => expect(screen.queryByText("Loading API keys…")).toBeNull());
  await screen.findByRole("heading", { name: "API keys" });
}
async function openCreate() {
  await openKeys();
  fireEvent.click(screen.getByRole("button", { name: "Create API key" }));
  return within(await screen.findByRole("dialog", { name: "Create API key" }));
}

describe("Workload static API keys", () => {
  it("offers the CLI first and a static key second in Connect application", async () => {
    await openWorkload();
    const group = screen.getByRole("radiogroup", { name: "How the application connects" });
    const radios = within(group).getAllByRole("radio");
    expect(radios.map((r) => r.closest("label")?.textContent)).toEqual([
      "Run with Tunnex CLI (recommended)Each replica gets its own identity and short-lived tokens. Linux and macOS.",
      "Static API key (for serverless, Windows and SaaS tools)One key you paste into the tool. It expires and you rotate it.",
    ]);
    expect((radios[0] as HTMLInputElement).checked).toBe(true);
    expect(screen.getByRole("button", { name: "Manage enrollment keys" })).toBeTruthy();
    fireEvent.click(radios[1]);
    expect(screen.queryByRole("button", { name: "Manage enrollment keys" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Create API key" }));
    expect(await screen.findByRole("dialog", { name: "Create API key" })).toBeTruthy();
    expect(screen.getByRole("tab", { name: "API keys", selected: true, hidden: true })).toBeTruthy();
  });

  it("creates an internal key by default and shows the secret once with how to use it", async () => {
    mock.post.mockResolvedValue({ data: { key: staticKey(), secret: "tnx_sk_secretvalue" }, response: new Response(null, { status: 201 }) });
    const modal = await openCreate();
    expect((modal.getByRole("radio", { name: /Inside your network \(recommended\)/ }) as HTMLInputElement).checked).toBe(true);
    fireEvent.change(modal.getByLabelText("1. Key name"), { target: { value: " lambda-parser " } });
    fireEvent.change(modal.getByLabelText("Requests per minute"), { target: { value: "120" } });
    const before = Date.now();
    fireEvent.click(modal.getByRole("button", { name: "Create key" }));
    await waitFor(() => expect(mock.post).toHaveBeenCalledTimes(1));
    const [path, request] = mock.post.mock.calls[0];
    expect(path).toBe(keysPath);
    expect(request.params.path).toEqual({ orgId: "org", workloadId: "workload" });
    expect(request.body).toMatchObject({ name: "lambda-parser", scope: "internal", source_cidrs: [], daily_usd_threshold: null, rate_limit_per_minute: 120 });
    expect(request.body.allow_any_source).toBeUndefined();
    const span = Date.parse(request.body.expires_at) - before;
    expect(span).toBeGreaterThan(29 * DAY); expect(span).toBeLessThanOrEqual(30 * DAY);
    const secret = await screen.findByRole("dialog", { name: "Save API key" });
    expect(within(secret).getByTestId("ots-secret").textContent).toBe("tnx_sk_secretvalue");
    expect(within(secret).getByText("https://100.64.0.1:9443/v1")).toBeTruthy();
    expect(within(secret).getByRole("button", { name: "Download CA certificate" })).toBeTruthy();
    expect(within(secret).getByText(/4 requests at once/)).toBeTruthy();
    const done = within(secret).getByRole("button", { name: /saved it/ }) as HTMLButtonElement;
    expect(done.disabled).toBe(true);
    fireEvent.click(within(secret).getByTestId("ots-ack"));
    fireEvent.click(done);
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Save API key" })).toBeNull());
    expect(screen.queryByText("tnx_sk_secretvalue")).toBeNull();
  });

  it("disables the public option with the reason when the organization switch is off", async () => {
    const modal = await openCreate();
    const pub = modal.getByRole("radio", { name: /Public internet/ }) as HTMLInputElement;
    expect(pub.disabled).toBe(true);
    expect(modal.getByText(/Public keys are off for this organization/)).toBeTruthy();
  });

  it("says when no gateway serves the internal endpoint and links to settings", async () => {
    endpoints = [{ ...gateway, endpoint: undefined, ready: false, url: null }];
    const modal = await openCreate();
    expect(modal.getByText(/No gateway serves the internal AI endpoint yet/)).toBeTruthy();
    expect(modal.getByRole("link", { name: "Set it up in AI Gateway settings" }).getAttribute("href")).toBe("/ai-gateway/settings#internal-ai-endpoint");
    expect((modal.getByRole("radio", { name: /Inside your network/ }) as HTMLInputElement).disabled).toBe(false);
  });

  it("requires Allow from any address for a public key without ranges", async () => {
    publicAllowed = true;
    mock.post.mockResolvedValue({ data: { key: staticKey({ scope: "public", source_cidrs: [] }), secret: "tnx_sk_public" }, response: new Response(null, { status: 201 }) });
    const modal = await openCreate();
    fireEvent.change(modal.getByLabelText("1. Key name"), { target: { value: "saas" } });
    fireEvent.click(modal.getByRole("radio", { name: /Public internet/ }));
    const create = modal.getByRole("button", { name: "Create key" }) as HTMLButtonElement;
    expect(create.disabled).toBe(true);
    fireEvent.click(modal.getByRole("checkbox", { name: /Allow from any address/ }));
    expect(create.disabled).toBe(false);
    fireEvent.click(create);
    await waitFor(() => expect(mock.post).toHaveBeenCalledTimes(1));
    expect(mock.post.mock.calls[0][1].body).toMatchObject({ scope: "public", source_cidrs: [], allow_any_source: true });
    const secret = await screen.findByRole("dialog", { name: "Save API key" });
    expect(within(secret).getByText(`${window.location.origin}/ai/v1`)).toBeTruthy();
  });

  it("explains a refused create in plain words", async () => {
    mock.post.mockResolvedValue({ error: { error: { code: "static_key_capacity", message: "capacity" } }, response: new Response(null, { status: 400 }) });
    const modal = await openCreate();
    fireEvent.change(modal.getByLabelText("1. Key name"), { target: { value: "one more" } });
    fireEvent.click(modal.getByRole("button", { name: "Create key" }));
    expect((await modal.findByRole("alert")).textContent).toMatch(/A workload can have 8 active keys/);
  });

  it("lists keys with scope, ranges, last 4, where they were used and refused, and the 14-day badge", async () => {
    keys = [
      staticKey({ id: "soon", name: "soon key", expires_at: iso(Date.now() + 14 * DAY - 60000), last_used_at: "2026-11-27T10:00:00Z", last_used_ingress: "internal", last_used_source: "10.20.1.5", last_used_node_id: "node-1", last_refused_at: "2026-11-27T11:00:00Z", last_refused_reason: "wrong_ingress", last_refused_ingress: "public", last_refused_source: "8.8.8.8" }),
      staticKey({ id: "later", name: "later key", hint: "Zz99", scope: "public", source_cidrs: [], expires_at: iso(Date.now() + 15 * DAY), last_used_at: "2026-11-27T10:00:00Z", last_used_ingress: "public", last_used_source: "8.8.8.8", last_refused_at: "2026-11-27T11:00:00Z", last_refused_reason: "rate_limited" }),
      staticKey({ id: "gone", name: "gone key", revoked_at: "2026-11-20T00:00:00Z", status: "revoked", expires_at: iso(Date.now() + 2 * DAY) }),
    ];
    await openKeys();
    const table = screen.getByRole("table", { name: "API keys" });
    const [, soon, later, gone] = within(table).getAllByRole("row");
    expect(within(soon).getByText("Expires soon")).toBeTruthy();
    expect(within(soon).getByText("tnx_sk_…Ab12")).toBeTruthy();
    expect(within(soon).getByText("Internal")).toBeTruthy();
    expect(within(soon).getByText("10.20.0.0/16")).toBeTruthy();
    expect(within(soon).getByText("internal endpoint via gw-east from 10.20.1.5")).toBeTruthy();
    expect(within(soon).getByText("Used on the wrong endpoint")).toBeTruthy();
    expect(within(soon).getByText(/public endpoint from 8\.8\.8\.8/)).toBeTruthy();
    expect(within(later).queryByText("Expires soon")).toBeNull();
    expect(within(later).getByText("Public")).toBeTruthy();
    expect(within(later).getByText("Any address")).toBeTruthy();
    expect(within(later).getByText("public endpoint from 8.8.8.8")).toBeTruthy();
    expect(within(later).getByText("Requests-per-minute limit reached")).toBeTruthy();
    expect(within(gone).getByText("Revoked")).toBeTruthy();
    expect(within(gone).queryByText("Expires soon")).toBeNull();
    expect(within(gone).queryByRole("button", { name: /Actions for API key/ })).toBeNull();
  });

  it("rotates with an overlap and shows the new key once", async () => {
    keys = [staticKey()];
    mock.post.mockResolvedValue({ data: { key: staticKey({ id: "sk-2" }), secret: "tnx_sk_rotated", previous: staticKey({ expires_at: "2026-11-29T10:00:00Z" }) }, response: new Response(null, { status: 201 }) });
    await openKeys();
    fireEvent.click(screen.getByRole("button", { name: "Actions for API key lambda-parser" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Rotate key" }));
    const modal = within(await screen.findByRole("dialog", { name: "Rotate API key" }));
    expect((modal.getByLabelText("Overlap in hours") as HTMLInputElement).value).toBe("24");
    fireEvent.change(modal.getByLabelText("Overlap in hours"), { target: { value: "200" } });
    expect((modal.getByRole("button", { name: "Rotate key" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(modal.getByLabelText("Overlap in hours"), { target: { value: "6" } });
    fireEvent.click(modal.getByRole("radio", { name: "7 days" }));
    fireEvent.click(modal.getByRole("button", { name: "Rotate key" }));
    await waitFor(() => expect(mock.post).toHaveBeenCalledTimes(1));
    const [path, request] = mock.post.mock.calls[0];
    expect(path).toBe(`${keysPath}/{keyId}/rotate`);
    expect(request.params.path).toEqual({ orgId: "org", workloadId: "workload", keyId: "sk-1" });
    expect(request.body.overlap_hours).toBe(6);
    expect(Date.parse(request.body.expires_at) - Date.now()).toBeLessThanOrEqual(7 * DAY);
    const secret = await screen.findByRole("dialog", { name: "Save API key" });
    expect(within(secret).getByTestId("ots-secret").textContent).toBe("tnx_sk_rotated");
    expect(within(secret).getByText(/previous key keeps working until/)).toBeTruthy();
  });

  it("revokes after a confirmation that says the next request is refused", async () => {
    keys = [staticKey()];
    mock.post.mockResolvedValue({ response: new Response(null, { status: 204 }) });
    await openKeys();
    fireEvent.click(screen.getByRole("button", { name: "Actions for API key lambda-parser" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Revoke key" }));
    const modal = within(await screen.findByRole("dialog", { name: "Revoke API key" }));
    expect(modal.getByText(/The next request with this key is refused/)).toBeTruthy();
    fireEvent.click(modal.getByRole("button", { name: "Revoke key" }));
    await waitFor(() => expect(mock.post).toHaveBeenCalledWith(`${keysPath}/{keyId}/revoke`, { params: { path: { orgId: "org", workloadId: "workload", keyId: "sk-1" } } }));
    await waitFor(() => expect(mock.success).toHaveBeenCalledWith("API key revoked"));
  });

  it("edits a key with the observed update time and refreshes on a stale edit", async () => {
    keys = [staticKey()];
    mock.put.mockResolvedValue({ error: { error: { code: "conflict" } }, response: new Response(null, { status: 409 }) });
    await openKeys();
    fireEvent.click(screen.getByRole("button", { name: "Actions for API key lambda-parser" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Edit key" }));
    const modal = within(await screen.findByRole("dialog", { name: "Edit API key" }));
    fireEvent.change(modal.getByLabelText("Allowed source ranges"), { target: { value: "10.20.0.0/16\n10.30.0.0/16" } });
    fireEvent.click(modal.getByRole("button", { name: "Save key" }));
    await waitFor(() => expect(mock.put).toHaveBeenCalledTimes(1));
    expect(mock.put.mock.calls[0][1].body).toMatchObject({ name: "lambda-parser", source_cidrs: ["10.20.0.0/16", "10.30.0.0/16"], expected_updated_at: "2026-11-02T00:00:00Z" });
    expect((await screen.findByRole("alert")).textContent).toMatch(/Someone else changed this key/);
    expect(screen.queryByRole("dialog", { name: "Edit API key" })).toBeNull();
  });

  it("shows view-only users the keys without any create, rotate or revoke control", async () => {
    keys = [staticKey()];
    await openKeys(false);
    expect(screen.getByText("lambda-parser")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Create API key" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Actions for API key/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Edit |Revoke |Rotate / })).toBeNull();
    expect(mock.post).not.toHaveBeenCalled(); expect(mock.put).not.toHaveBeenCalled();
  });
});
