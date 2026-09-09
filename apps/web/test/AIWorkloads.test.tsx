import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { StrictMode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AIWorkloads } from "../src/components/AIWorkloads";

const mock = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), success: vi.fn() }));
vi.mock("../src/lib/api", async (importOriginal) => ({ ...await importOriginal<typeof import("../src/lib/api")>(), api: { GET: mock.get, POST: mock.post, PUT: mock.put } }));
vi.mock("../src/components/Toasts", () => ({ toast: { success: mock.success, error: vi.fn() } }));

const root = "/api/v1/organizations/{orgId}/ai-gateway/workloads";
const models = [{ connection_id: "connection", model: "openai/vision", mode: "image_generation" as const }];
const workload = { id: "workload", name: "Support bot", enabled: true, models, revision: 3, applied_revision: 3, status: "applied" as const, created_at: "2026-09-09T00:00:00Z" };
const key = { id: "key", name: "Production key", reusable: true, ephemeral: true, max_uses: 0, uses: 2, expires_at: "2099-10-09T00:00:00Z", created_at: "2026-09-09T00:00:00Z" };
const instance = { id: "instance", enrollment_key_id: "key", ephemeral: true, state: "active", key_generation: 1, last_contact_at: "2026-09-09T00:00:00Z", created_at: "2026-09-09T00:00:00Z" };
const provider = { id: "connection", name: "OpenAI production", provider: "openai", models: ["openai/vision", "openai/chat"], model_modes: { "openai/vision": "image_generation", "openai/chat": "chat" }, enabled: true, status: "applied", revision: 2, applied_revision: 2 };

function defaultGet(path: string) {
  return Promise.resolve({ data: path === root ? [workload] : path.endsWith("providers") ? { items: [provider] } : path.endsWith("enrollment-keys") ? { items: [key] } : { items: [instance] } });
}
beforeEach(() => { vi.clearAllMocks(); mock.get.mockImplementation(defaultGet); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

async function openWorkload(tab = "Overview") {
  fireEvent.click(await screen.findByRole("button", { name: "Open Support bot" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Refresh workload" })).toHaveProperty("disabled", false));
  if (tab !== "Overview") fireEvent.click(screen.getByRole("tab", { name: tab }));
}

describe("Workload model access", () => {
  it("starts with a searchable list and opens only the selected detail tab", async () => {
    render(<AIWorkloads orgId="org" canManage />);
    await screen.findByRole("button", { name: "Open Support bot" });
    expect(screen.queryByRole("tab", { name: "Overview" })).toBeNull();
    expect(mock.get.mock.calls.some(([path]) => path.endsWith("enrollment-keys"))).toBe(false);
    const search = screen.getByRole("textbox", { name: "Search workloads" });
    fireEvent.change(search, { target: { value: "missing" } });
    expect(screen.queryByRole("button", { name: "Open Support bot" })).toBeNull();
    expect(screen.getByText("No workloads match your search.")).toBeTruthy();
    fireEvent.change(search, { target: { value: "support" } });
    await openWorkload();
    expect(screen.getByRole("tab", { name: "Overview", selected: true })).toBeTruthy();
    expect(screen.queryByRole("table", { name: "Enrollment keys" })).toBeNull();
    fireEvent.click(screen.getByRole("tab", { name: "Instances" }));
    expect(await screen.findByRole("table", { name: "Workload instances" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Connect application" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Back to workloads" }));
    expect(screen.getByRole("textbox", { name: "Search workloads" })).toHaveProperty("value", "support");
  });

  it("shows AI viewers read-only data without enrollment or mutation controls", async () => {
    render(<AIWorkloads orgId="org" canManage={false} />);
    await openWorkload("Enrollment keys");
    await screen.findByText("Production key");
    expect(screen.getByText(/Read-only access/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Create workload" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Create enrollment key" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Edit |Revoke / })).toBeNull();
    expect(mock.post).not.toHaveBeenCalled(); expect(mock.put).not.toHaveBeenCalled();
  });

  it("creates a policy from exact saved models and modes, refusing a zero threshold", async () => {
    mock.post.mockResolvedValue({ data: { ...workload, id: "new-workload", name: "New bot", status: "pending", applied_revision: 0 }, response: new Response(null, { status: 201 }) });
    render(<StrictMode><AIWorkloads orgId="org" canManage /></StrictMode>);
    fireEvent.click(await screen.findByRole("button", { name: "Create workload" }));
    const modal = within(screen.getByRole("dialog", { name: "Create workload" }));
    fireEvent.change(modal.getByLabelText("Workload name"), { target: { value: " New bot " } });
    fireEvent.click(modal.getByRole("checkbox", { name: /^openai\/vision/ }));
    fireEvent.change(modal.getByLabelText("Daily USD soft threshold (optional)"), { target: { value: "0" } });
    expect((modal.getByRole("button", { name: "Create workload" }) as HTMLButtonElement).disabled).toBe(true);
    expect(mock.post).not.toHaveBeenCalled();
    fireEvent.change(modal.getByLabelText("Daily USD soft threshold (optional)"), { target: { value: "12.5" } });
    fireEvent.click(modal.getByRole("button", { name: "Create workload" }));
    await waitFor(() => expect(mock.post).toHaveBeenCalledWith(root, { params: { path: { orgId: "org" } }, body: { name: "New bot", enabled: true, models, daily_usd_threshold: 12.5, expected_revision: 0 } }));
    await waitFor(() => expect(mock.success).toHaveBeenCalledWith("Workload saved; provisioning is pending"));
    expect(screen.getByText(/The saved policy is not applied/)).toBeTruthy();
  });

  it("sends the observed revision and refreshes a conflicting edit", async () => {
    mock.put.mockResolvedValue({ error: { error: { code: "workload_conflict" } }, response: new Response(null, { status: 409 }) });
    render(<AIWorkloads orgId="org" canManage />);
    await openWorkload();
    fireEvent.click(screen.getByRole("button", { name: "Edit access" }));
    fireEvent.click(screen.getByLabelText("Enable workload access"));
    expect(screen.getByText(/permanently revokes every enrollment key/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Save workload" }));
    await waitFor(() => expect(mock.put).toHaveBeenCalledWith(`${root}/{workloadId}`, expect.objectContaining({ body: { name: "Support bot", enabled: false, models, daily_usd_threshold: null, expected_revision: 3 } })));
    expect(await screen.findByText(/Another administrator changed this workload/)).toBeTruthy();
    await waitFor(() => expect(mock.get.mock.calls.filter(([path]) => path === root)).toHaveLength(2));
    expect(screen.queryByRole("dialog")).toBeNull(); expect(mock.success).not.toHaveBeenCalled();
  });

  it.each([[true, 30, 0], [false, 1, 1]] as const)("creates reusable=%s with bounded defaults and discards the one-time secret", async (reusable, days, maxUses) => {
    const saved = vi.spyOn(Storage.prototype, "setItem");
    mock.post.mockResolvedValue({ data: { key: { ...key, reusable, max_uses: maxUses }, secret: "one-time-enrollment-secret" }, response: new Response(null, { status: 201 }) });
    render(<AIWorkloads orgId="org" canManage />);
    await openWorkload("Enrollment keys");
    await screen.findByText("Production key");
    fireEvent.click(screen.getByRole("button", { name: "Create enrollment key" }));
    if (!reusable) fireEvent.change(screen.getByLabelText("Enrollment type"), { target: { value: "single" } });
    const before = Date.now();
    fireEvent.click(screen.getByRole("button", { name: "Create key" }));
    expect(await screen.findByText("one-time-enrollment-secret")).toBeTruthy();
    const [path, request] = mock.post.mock.calls[0];
    expect(path).toBe(`${root}/{workloadId}/enrollment-keys`);
    expect(request.params.path).toEqual({ orgId: "org", workloadId: "workload" });
    expect(request.body).toMatchObject({ reusable, ephemeral: true, max_uses: maxUses });
    expect(new Date(request.body.expires_at).getTime()).toBeGreaterThanOrEqual(before + days * 86400000);
    expect(new Date(request.body.expires_at).getTime()).toBeLessThanOrEqual(Date.now() + days * 86400000);
    expect(saved).not.toHaveBeenCalled();
    fireEvent.click(screen.getByLabelText("I saved this key securely."));
    fireEvent.click(screen.getByRole("button", { name: "I’ve saved it" }));
    expect(screen.queryByText("one-time-enrollment-secret")).toBeNull();
  });

  it.each([false, true])("revokes a key with explicit descendant choice %s", async (revokeInstances) => {
    mock.post.mockResolvedValue({ response: new Response(null, { status: 204 }) });
    render(<AIWorkloads orgId="org" canManage />);
    await openWorkload("Enrollment keys");
    fireEvent.click(await screen.findByRole("button", { name: "Revoke enrollment key Production key" }));
    const checkbox = screen.getByLabelText("Also revoke every instance enrolled with this key") as HTMLInputElement;
    expect(checkbox.checked).toBe(false);
    if (revokeInstances) fireEvent.click(checkbox);
    fireEvent.click(screen.getByRole("button", { name: "Confirm revocation" }));
    await waitFor(() => expect(mock.post).toHaveBeenCalledWith(`${root}/{workloadId}/enrollment-keys/{keyId}/revoke`, { params: { path: { orgId: "org", workloadId: "workload", keyId: "key" } }, body: { revoke_instances: revokeInstances } }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("paginates instance state and revokes only the selected instance", async () => {
    mock.get.mockImplementation((path: string, options: { params: { query?: { after?: string } } }) => path.endsWith("/instances") ? Promise.resolve({ data: options.params.query?.after ? { items: [{ ...instance, id: "instance-2" }] } : { items: [instance], next_cursor: "cursor-instance" } }) : defaultGet(path));
    mock.post.mockResolvedValue({ response: new Response(null, { status: 204 }) });
    render(<AIWorkloads orgId="org" canManage />);
    await openWorkload("Instances");
    expect(await screen.findByRole("columnheader", { name: "Enrollment key" })).toBeTruthy();
    expect(screen.getByRole("cell", { name: "Production key key" })).toBeTruthy();
    fireEvent.click(await screen.findByRole("button", { name: "Load more instances" }));
    fireEvent.click(await screen.findByRole("button", { name: "Revoke instance instance-2" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm revocation" }));
    await waitFor(() => expect(mock.post).toHaveBeenCalledWith(`${root}/{workloadId}/instances/{instanceId}/revoke`, { params: { path: { orgId: "org", workloadId: "workload", instanceId: "instance-2" } } }));
    expect(mock.get).toHaveBeenCalledWith(`${root}/{workloadId}/instances`, { params: { path: { orgId: "org", workloadId: "workload" }, query: { after: "cursor-instance", limit: 50 } } });
  });

  it("does not turn failed inventory reads into an empty state", async () => {
    mock.get.mockResolvedValue({ error: { error: { message: "Unavailable" } } });
    render(<AIWorkloads orgId="org" canManage />);
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.queryByText(/No workloads yet/)).toBeNull();
    expect((screen.getByRole("button", { name: "Create workload" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("discards a late enrollment secret after the organization or role changes", async () => {
    let resolve!: (value: unknown) => void;
    mock.post.mockImplementation(() => new Promise((done) => { resolve = done; }));
    const view = render(<AIWorkloads orgId="org" canManage />);
    await openWorkload("Enrollment keys");
    await screen.findByText("Production key");
    fireEvent.click(screen.getByRole("button", { name: "Create enrollment key" }));
    fireEvent.click(screen.getByRole("button", { name: "Create key" }));
    expect(mock.post).toHaveBeenCalledTimes(1);
    view.rerender(<AIWorkloads orgId="other-org" canManage={false} />);
    await act(async () => resolve({ data: { key, secret: "late-private-enrollment-key" }, response: new Response(null, { status: 201 }) }));
    expect(await screen.findByText(/Read-only access/)).toBeTruthy();
    expect(screen.queryByText("late-private-enrollment-key")).toBeNull();
    expect(screen.queryByText("Save enrollment key")).toBeNull();
  });

  it("can revoke descendants after their enrollment key was revoked alone", async () => {
    let revoked = false;
    mock.get.mockImplementation((path: string) => path.endsWith("enrollment-keys") ? Promise.resolve({ data: { items: [{ ...key, ...(revoked ? { revoked_at: "2026-09-09T01:00:00Z" } : {}) }] } }) : defaultGet(path));
    mock.post.mockImplementation(() => { revoked = true; return Promise.resolve({ response: new Response(null, { status: 204 }) }); });
    render(<AIWorkloads orgId="org" canManage />);
    await openWorkload("Enrollment keys");
    fireEvent.click(await screen.findByRole("button", { name: "Revoke enrollment key Production key" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm revocation" }));
    fireEvent.click(await screen.findByRole("button", { name: "Revoke instances from Production key" }));
    expect(screen.getByText(/This enrollment key is already revoked/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Confirm revocation" }));
    await waitFor(() => expect(mock.post).toHaveBeenNthCalledWith(2, `${root}/{workloadId}/enrollment-keys/{keyId}/revoke`, { params: { path: { orgId: "org", workloadId: "workload", keyId: "key" } }, body: { revoke_instances: true } }));
  });

  it("warns that disabling destroys enrollment keys and refreshes their saved state", async () => {
    let disabled = false;
    mock.get.mockImplementation((path: string) => path.endsWith("enrollment-keys") ? Promise.resolve({ data: { items: [{ ...key, ...(disabled ? { revoked_at: "2026-09-09T01:00:00Z" } : {}) }] } }) : defaultGet(path));
    mock.put.mockImplementation(() => { disabled = true; return Promise.resolve({ data: { ...workload, enabled: false, revision: 4 }, response: new Response(null, { status: 200 }) }); });
    render(<AIWorkloads orgId="org" canManage />);
    await openWorkload("Enrollment keys");
    await screen.findByRole("cell", { name: "Active" });
    fireEvent.click(screen.getByRole("button", { name: "Edit access" }));
    fireEvent.click(screen.getByLabelText("Enable workload access"));
    expect(screen.getByText(/permanently revokes every enrollment key/)).toBeTruthy();
    expect(screen.getByText(/create new enrollment keys after re-enabling/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Save workload" }));
    expect(await screen.findByRole("cell", { name: "Revoked" })).toBeTruthy();
    expect(screen.queryByRole("cell", { name: "Active" })).toBeNull();
    expect(mock.get.mock.calls.filter(([path]) => path.endsWith("enrollment-keys"))).toHaveLength(2);
  });

  it("requires one credential per public model and keeps selections when searching", async () => {
    const backup = { ...provider, id: "backup", name: "OpenAI backup" };
    mock.get.mockImplementation((path: string) => path.endsWith("providers") ? Promise.resolve({ data: { items: [provider, backup] } }) : defaultGet(path));
    render(<AIWorkloads orgId="org" canManage />);
    fireEvent.click(await screen.findByRole("button", { name: "Create workload" }));
    const modal = within(screen.getByRole("dialog", { name: "Create workload" }));
    fireEvent.click(modal.getByRole("checkbox", { name: "openai/vision on OpenAI production" }));
    expect(modal.getByRole("checkbox", { name: "openai/vision on OpenAI backup" })).toHaveProperty("disabled", true);
    fireEvent.change(modal.getByRole("textbox", { name: "Search models" }), { target: { value: "backup" } });
    expect(modal.queryByRole("checkbox", { name: "openai/vision on OpenAI production" })).toBeNull();
    expect(modal.getByRole("checkbox", { name: "openai/vision on OpenAI backup" })).toHaveProperty("disabled", true);
    fireEvent.change(modal.getByRole("textbox", { name: "Search models" }), { target: { value: "" } });
    fireEvent.click(modal.getByRole("checkbox", { name: "openai/vision on OpenAI production" }));
    expect(modal.getByRole("checkbox", { name: "openai/vision on OpenAI backup" })).toHaveProperty("disabled", false);
  });

  it("requires explicit reselection when a disabled workload's saved model mode changed", async () => {
    const changedProvider = { ...provider, model_modes: { ...provider.model_modes, "openai/vision": "chat" } };
    mock.get.mockImplementation((path: string) => path === root ? Promise.resolve({ data: [{ ...workload, enabled: false }] }) : path.endsWith("providers") ? Promise.resolve({ data: { items: [changedProvider] } }) : defaultGet(path));
    mock.put.mockResolvedValue({ data: { ...workload, enabled: false, models: [{ ...models[0], mode: "chat" }], revision: 4 }, response: new Response(null, { status: 200 }) });
    render(<AIWorkloads orgId="org" canManage />);
    await openWorkload();
    fireEvent.click(screen.getByRole("button", { name: "Edit access" }));
    const modal = within(screen.getByRole("dialog", { name: "Edit workload access" }));
    expect(modal.getByText(/Saved mode: image generation. Current mode: chat/)).toBeTruthy();
    expect(modal.getByRole("alert").textContent).toMatch(/Remove and reselect/);
    const save = modal.getByRole("button", { name: "Save workload" });
    expect(save).toHaveProperty("disabled", true);
    fireEvent.submit(modal.getByLabelText("Workload name").closest("form")!);
    expect(mock.put).not.toHaveBeenCalled();
    const choice = modal.getByRole("checkbox", { name: "openai/vision on OpenAI production" });
    expect(choice).toHaveProperty("checked", true);
    fireEvent.click(choice);
    fireEvent.click(choice);
    expect(modal.queryByText(/Saved mode:/)).toBeNull();
    expect(save).toHaveProperty("disabled", false);
    fireEvent.click(save);
    await waitFor(() => expect(mock.put).toHaveBeenCalledWith(`${root}/{workloadId}`, expect.objectContaining({ body: { name: "Support bot", enabled: false, models: [{ ...models[0], mode: "chat" }], daily_usd_threshold: null, expected_revision: 3 } })));
  });

  it.each(["models", "credentials"] as const)("enforces the %s limit before saving", async (limit) => {
    const providers = limit === "models"
      ? [{ ...provider, models: Array.from({ length: 33 }, (_, i) => `openai/model-${i}`) }]
      : Array.from({ length: 9 }, (_, i) => ({ ...provider, id: `connection-${i}`, name: `Credential ${i}`, models: [`openai/model-${i}`] }));
    mock.get.mockImplementation((path: string) => path.endsWith("providers") ? Promise.resolve({ data: { items: providers } }) : defaultGet(path));
    render(<AIWorkloads orgId="org" canManage />);
    fireEvent.click(await screen.findByRole("button", { name: "Create workload" }));
    const modal = within(screen.getByRole("dialog", { name: "Create workload" }));
    const choices = modal.getAllByRole("checkbox", { name: /^openai\/model-/ });
    for (const choice of choices.slice(0, -1)) fireEvent.click(choice);
    expect(choices[choices.length - 1]).toHaveProperty("disabled", true);
    fireEvent.click(choices[0]);
    expect(choices[choices.length - 1]).toHaveProperty("disabled", false);
  });
});
