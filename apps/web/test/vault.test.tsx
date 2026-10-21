import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import Vault from "../src/pages/Vault";

const mock = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), remove: vi.fn(), clipboard: vi.fn(), org: "org-one", user: "user-one", canAssign: false }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api: { GET: mock.get, POST: mock.post, PUT: mock.put, DELETE: mock.remove } }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: mock.org }, failed: false }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: mock.user, email_verified: true } } }) }));

const personal = { configured: true, id: "entry-personal", service_name: "Private console", title: "My console login", kind: "password", username: "rajan", visibility: "personal", owner_user_id: "user-one", current_version: 2, created_at: "2026-10-20T10:00:00Z", updated_at: "2026-10-21T10:00:00Z", can_edit: true, can_delete: true };
const assigned = { ...personal, id: "entry-assigned", service_id: "service-one", title: "Production API", service_name: "Payments", kind: "api_key", visibility: "assigned", subject_kind: "group", subject_id: "group-one", subject_name: "DevOps", can_delete: false };
const unconfigured = { ...personal, id: "entry-quick", configured: false, title: "", service_name: "", username: "", current_version: 1 };
let entries = [personal, assigned];
let services = [{ id: "service-one", name: "Payments" }];
const history = { current_version: 2, total: 2, versions: [{ version: 2, changed_by: "user-one", changed_by_name: "Rajan", created_at: "2026-10-21T10:00:00Z" }, { version: 1, changed_by: "user-two", changed_by_name: "DevOps admin", created_at: "2026-10-20T10:00:00Z" }] };
function show(path = "/vault") { return render(<MemoryRouter initialEntries={[path]}><Vault /></MemoryRouter>); }
beforeEach(() => {
  vi.resetAllMocks(); mock.org = "org-one"; mock.user = "user-one"; mock.canAssign = false;
  entries = [personal, assigned]; services = [{ id: "service-one", name: "Payments" }];
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: mock.clipboard.mockResolvedValue(undefined) } });
  mock.get.mockImplementation(async (path: string) => ({ data: path.endsWith("/services") ? [...services] : path.endsWith("/subjects") ? { users: [{ id: "user-two", name: "Teammate" }], groups: [{ id: "group-one", name: "DevOps" }] } : path.endsWith("/versions") ? history : { entries, total: entries.length, can_assign: mock.canAssign } }));
  mock.post.mockImplementation(async (path: string, options: { body: { version?: number; name?: string; title?: string } }) => {
    if (path.endsWith("/reveal")) return { data: { value: options.body.version === 1 ? "old-secret-value" : "current-secret-value", username: "rajan", version: options.body.version ?? 2 }, response: new Response("{}") };
    if (path.endsWith("/services")) { const service = { id: "service-new", name: options.body.name! }; services.push(service); return { data: service, response: new Response("{}", { status: 201 }) }; }
    if (path.endsWith("/quick")) { entries = [...entries, unconfigured]; return { data: unconfigured, response: new Response("{}") }; }
    if (path.endsWith("/configure")) { entries = entries.map(entry => entry.id === unconfigured.id ? { ...personal, ...options.body, id: unconfigured.id } : entry); return { data: entries.find(entry => entry.id === unconfigured.id), response: new Response("{}") }; }
    return { data: personal, response: new Response("{}", { status: 201 }) };
  });
  mock.put.mockResolvedValue({ data: { ...personal, current_version: 3 }, response: new Response("{}") });
  mock.remove.mockResolvedValue({ response: new Response(null, { status: 204 }) });
});
afterEach(() => { cleanup(); vi.useRealTimers(); Object.defineProperty(document, "visibilityState", { configurable: true, value: "visible" }); });

describe("Tunnex Vault", () => {
  it("opens only a masked password and Copy, then persists before releasing the value", async () => {
    let finish!: (value: unknown) => void;
    mock.post.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    show(); await screen.findByRole("button", { name: personal.title });
    fireEvent.click(screen.getByRole("button", { name: "Quick generate" }));
    const element = screen.getByRole("dialog", { name: "Quick generate" });
    const dialog = within(element);
    expect(element.closest(".tnx-modal-overlay")?.getAttribute("data-placement")).toBe("right");
    const password = dialog.getByLabelText("Generated password") as HTMLInputElement;
    const value = password.value;
    expect(value).toHaveLength(24);
    expect(password.type).toBe("password");
    expect(password.readOnly).toBe(true);
    expect(element.querySelectorAll("input")).toHaveLength(1);
    expect(element.querySelectorAll("select")).toHaveLength(0);
    expect(dialog.queryByLabelText("Title")).toBeNull();
    expect(dialog.queryByLabelText("Credential type")).toBeNull();
    expect(dialog.queryByRole("button", { name: /Save|Generate again|Show/ })).toBeNull();
    expect(mock.clipboard).not.toHaveBeenCalled();
    expect(mock.post).not.toHaveBeenCalled();
    fireEvent.click(dialog.getByRole("button", { name: "Copy" }));
    expect(mock.post).toHaveBeenCalledWith(expect.stringMatching(/\/entries\/quick$/), {
      params: { path: { orgId: mock.org } }, body: { request_id: expect.stringMatching(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/), secret: value },
    });
    expect(mock.clipboard).not.toHaveBeenCalled();
    await act(async () => { entries = [...entries, unconfigured]; finish({ data: unconfigured, response: new Response("{}") }); });
    await waitFor(() => expect(mock.clipboard).toHaveBeenCalledWith(value));
    await screen.findByRole("button", { name: "Configure Unconfigured password" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.queryByDisplayValue(value)).toBeNull();
    expect(screen.getByRole("status").textContent).toContain("copied and saved");
  });

  it("discards a quick password on close and organization change without prefilling manual Add", async () => {
    const view = show(); await screen.findByRole("button", { name: personal.title });
    fireEvent.click(screen.getByRole("button", { name: "Quick generate" }));
    let dialog = within(screen.getByRole("dialog", { name: "Quick generate" }));
    const first = (dialog.getByLabelText("Generated password") as HTMLInputElement).value;
    fireEvent.click(dialog.getByRole("button", { name: "Close" }));
    expect(screen.queryByDisplayValue(first)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Add credential" }));
    dialog = within(screen.getByRole("dialog", { name: "Add credential" }));
    expect((dialog.getByLabelText("Secret") as HTMLInputElement).value).toBe("");
    fireEvent.click(dialog.getByRole("button", { name: "Cancel" }));
    fireEvent.click(screen.getByRole("button", { name: "Quick generate" }));
    const pending = (within(screen.getByRole("dialog", { name: "Quick generate" })).getByLabelText("Generated password") as HTMLInputElement).value;
    mock.org = "org-two"; entries = [];
    view.rerender(<MemoryRouter><Vault /></MemoryRouter>);
    await screen.findByRole("heading", { name: "No credentials yet" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.queryByDisplayValue(pending)).toBeNull();
    expect(mock.post).not.toHaveBeenCalled();
    expect(mock.clipboard).not.toHaveBeenCalled();
  });

  it("retries an uncertain quick save with the same id and never copies an unconfirmed value", async () => {
    mock.post.mockRejectedValueOnce(new Error("private storage diagnostic"));
    show(); await screen.findByRole("button", { name: personal.title });
    fireEvent.click(screen.getByRole("button", { name: "Quick generate" }));
    const dialog = within(screen.getByRole("dialog", { name: "Quick generate" }));
    const value = (dialog.getByLabelText("Generated password") as HTMLInputElement).value;
    fireEvent.click(dialog.getByRole("button", { name: "Copy" }));
    expect((await dialog.findByRole("alert")).textContent).toContain("Nothing was copied");
    const first = mock.post.mock.calls[0];
    expect(mock.clipboard).not.toHaveBeenCalled();
    expect(screen.queryByText("private storage diagnostic")).toBeNull();
    fireEvent.click(dialog.getByRole("button", { name: "Copy" }));
    await waitFor(() => expect(mock.clipboard).toHaveBeenCalledWith(value));
    expect(mock.post.mock.calls[1]).toEqual(first);
  });

  it("uses a fresh request id when a discarded quick password is generated again", async () => {
    mock.post.mockResolvedValue({ error: {}, response: new Response("{}", { status: 503 }) });
    show(); await screen.findByRole("button", { name: personal.title });
    for (let attempt = 0; attempt < 2; attempt++) {
      fireEvent.click(screen.getByRole("button", { name: "Quick generate" }));
      const dialog = within(screen.getByRole("dialog", { name: "Quick generate" }));
      fireEvent.click(dialog.getByRole("button", { name: "Copy" }));
      await dialog.findByRole("alert");
      fireEvent.click(dialog.getByRole("button", { name: "Close" }));
    }
    expect(mock.post.mock.calls[0][1].body.request_id).not.toBe(mock.post.mock.calls[1][1].body.request_id);
    expect(mock.post.mock.calls[0][1].body.secret).not.toBe(mock.post.mock.calls[1][1].body.secret);
    expect(mock.clipboard).not.toHaveBeenCalled();
  });

  it("keeps a confirmed quick entry after clipboard failure and retries without another save", async () => {
    mock.clipboard.mockRejectedValueOnce(new Error("private clipboard diagnostic"));
    show(); await screen.findByRole("button", { name: personal.title });
    fireEvent.click(screen.getByRole("button", { name: "Quick generate" }));
    const dialog = within(screen.getByRole("dialog", { name: "Quick generate" }));
    const value = (dialog.getByLabelText("Generated password") as HTMLInputElement).value;
    fireEvent.click(dialog.getByRole("button", { name: "Copy" }));
    expect((await dialog.findByRole("alert")).textContent).toContain("Saved to Vault, but");
    expect(screen.queryByText("private clipboard diagnostic")).toBeNull();
    expect(mock.post).toHaveBeenCalledTimes(1);
    fireEvent.click(dialog.getByRole("button", { name: "Copy" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(mock.post).toHaveBeenCalledTimes(1);
    expect(mock.clipboard).toHaveBeenNthCalledWith(2, value);
    await screen.findByRole("button", { name: "Configure Unconfigured password" });
  });

  it.each(["close", "organization", "user", "hidden tab"])("does not copy a late quick-save response after %s", async boundary => {
    let finish!: (value: unknown) => void;
    mock.post.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    const view = show(); await screen.findByRole("button", { name: personal.title });
    fireEvent.click(screen.getByRole("button", { name: "Quick generate" }));
    const dialog = within(screen.getByRole("dialog", { name: "Quick generate" }));
    fireEvent.click(dialog.getByRole("button", { name: "Copy" }));
    if (boundary === "close") fireEvent.click(dialog.getByRole("button", { name: "Close" }));
    else if (boundary === "hidden tab") {
      Object.defineProperty(document, "visibilityState", { configurable: true, value: "hidden" });
      fireEvent(document, new Event("visibilitychange"));
    } else {
      if (boundary === "organization") mock.org = "org-two"; else mock.user = "user-two";
      entries = [];
      view.rerender(<MemoryRouter><Vault /></MemoryRouter>);
      await screen.findByRole("heading", { name: "No credentials yet" });
    }
    const callsBeforeLateResponse = mock.get.mock.calls.length;
    await act(async () => { if (boundary === "close") entries = [...entries, unconfigured]; finish({ data: unconfigured, response: new Response("{}") }); });
    expect(mock.clipboard).not.toHaveBeenCalled();
    if (boundary === "close") await screen.findByRole("button", { name: "Configure Unconfigured password" });
    if (boundary === "organization" || boundary === "user") {
      expect(mock.get.mock.calls).toHaveLength(callsBeforeLateResponse);
      expect(screen.queryByRole("button", { name: "Configure Unconfigured password" })).toBeNull();
    }
  });

  it("configures a saved password with assignment metadata without resending or replacing its secret", async () => {
    mock.canAssign = true; entries = [unconfigured];
    show(); fireEvent.click(await screen.findByRole("button", { name: "Configure Unconfigured password" }));
    const element = screen.getByRole("dialog", { name: "Configure credential" });
    const dialog = within(element);
    expect(element.closest(".tnx-modal-overlay")?.getAttribute("data-placement")).toBe("right");
    expect(dialog.queryByLabelText("Secret")).toBeNull();
    expect(dialog.queryByLabelText("New secret")).toBeNull();
    expect(dialog.queryByLabelText("Credential type")).toBeNull();
    expect(dialog.queryByRole("button", { name: /Generate|Show secret/ })).toBeNull();
    fireEvent.change(dialog.getByLabelText("Title"), { target: { value: "On-call account" } });
    fireEvent.change(dialog.getByLabelText("Visibility"), { target: { value: "assigned" } });
    await dialog.findByRole("option", { name: "Teammate" });
    fireEvent.change(dialog.getByLabelText("Service"), { target: { value: "service-one" } });
    fireEvent.change(dialog.getByLabelText("Assign to"), { target: { value: "group" } });
    fireEvent.change(dialog.getByLabelText("Group"), { target: { value: "group-one" } });
    fireEvent.change(dialog.getByLabelText("Username (optional)"), { target: { value: "oncall" } });
    fireEvent.click(dialog.getByRole("button", { name: "Save details" }));
    await waitFor(() => expect(mock.post).toHaveBeenCalledWith(expect.stringMatching(/\/configure$/), { params: { path: { orgId: mock.org, entryId: unconfigured.id } }, body: { expected_version: 1, title: "On-call account", username: "oncall", visibility: "assigned", service_id: "service-one", subject_kind: "group", subject_id: "group-one" } }));
    expect(mock.put).not.toHaveBeenCalled();
    expect(mock.clipboard).not.toHaveBeenCalled();
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("offers members private-only metadata configuration and prevents retrying a stale configure", async () => {
    entries = [unconfigured];
    mock.post.mockResolvedValue({ error: {}, response: new Response("{}", { status: 409 }) });
    show(); fireEvent.click(await screen.findByRole("button", { name: "Configure Unconfigured password" }));
    const dialog = within(screen.getByRole("dialog", { name: "Configure credential" }));
    expect(dialog.queryByRole("option", { name: /Assigned/ })).toBeNull();
    fireEvent.change(dialog.getByLabelText("Title"), { target: { value: "Private login" } });
    fireEvent.change(dialog.getByLabelText("Private service name"), { target: { value: "Private console" } });
    fireEvent.click(dialog.getByRole("button", { name: "Save details" }));
    await dialog.findByRole("alert");
    expect(mock.post).toHaveBeenCalledWith(expect.stringMatching(/\/configure$/), expect.objectContaining({ body: { expected_version: 1, title: "Private login", username: "", visibility: "personal", service_name: "Private console" } }));
    expect((dialog.getByRole("button", { name: "Save details" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(dialog.getByRole("button", { name: "Save details" }));
    expect(mock.post).toHaveBeenCalledTimes(1);
  });

  it("shows metadata only, reveals an explicit historical version, and reauthorizes copying", async () => {
    show();
    fireEvent.click(await screen.findByRole("button", { name: personal.title }));
    expect(screen.getByRole("dialog", { name: personal.title }).closest(".tnx-modal-overlay")?.getAttribute("data-placement")).toBe("right");
    const dialog = within(screen.getByRole("dialog", { name: personal.title }));
    await dialog.findByRole("button", { name: "Reveal version 1" });
    expect(dialog.getByLabelText("Hidden secret").textContent).toBe("••••••••••••••••");
    expect(mock.post).not.toHaveBeenCalled();
    fireEvent.click(dialog.getByRole("button", { name: "Reveal version 1" }));
    expect((await dialog.findByLabelText("Revealed secret")).textContent).toBe("old-secret-value");
    expect(mock.post).toHaveBeenLastCalledWith(expect.stringContaining("/reveal"), { params: { path: { orgId: mock.org, entryId: personal.id } }, body: { version: 1 } });
    fireEvent.click(dialog.getByRole("button", { name: "Copy version 1" }));
    await waitFor(() => expect(mock.clipboard).toHaveBeenCalledWith("old-secret-value"));
    expect(mock.post).toHaveBeenCalledTimes(2);
    expect(dialog.queryByLabelText("Revealed secret")).toBeNull();
    fireEvent.click(dialog.getByRole("button", { name: "Close" }));
    expect(screen.queryByText("old-secret-value")).toBeNull();
  });

  it("lets members save private credentials without offering assignment administration", async () => {
    show(); fireEvent.click(await screen.findByRole("button", { name: "Add credential" }));
    expect(screen.getByRole("dialog", { name: "Add credential" }).closest(".tnx-modal-overlay")?.getAttribute("data-placement")).toBe("right");
    const dialog = within(screen.getByRole("dialog", { name: "Add credential" }));
    await dialog.findByRole("option", { name: "Payments" });
    expect(dialog.queryByRole("option", { name: /Assigned/ })).toBeNull();
    expect(dialog.queryByRole("button", { name: /Add a service to/ })).toBeNull();
    fireEvent.change(dialog.getByLabelText("Title"), { target: { value: "Personal tool" } });
    fireEvent.change(dialog.getByLabelText("Private service name"), { target: { value: "Private tool" } });
    fireEvent.change(dialog.getByLabelText("Secret"), { target: { value: "UserProvidedSecret!" } });
    fireEvent.click(dialog.getByRole("button", { name: "Save credential" }));
    await waitFor(() => expect(mock.post).toHaveBeenCalledWith(expect.stringContaining("/entries"), expect.objectContaining({ body: { title: "Personal tool", kind: "password", username: "", secret: "UserProvidedSecret!", visibility: "personal", service_name: "Private tool" } })));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(mock.get.mock.calls.some(([path]) => path.endsWith("/subjects"))).toBe(false);
    expect(screen.queryByDisplayValue("UserProvidedSecret!")).toBeNull();
  });

  it("creates a reusable service inline and waits for explicit confirmation of a group assignment", async () => {
    mock.canAssign = true;
    show(); fireEvent.click(await screen.findByRole("button", { name: "Add credential" }));
    const dialog = within(screen.getByRole("dialog", { name: "Add credential" }));
    fireEvent.change(dialog.getByLabelText("Visibility"), { target: { value: "assigned" } });
    await dialog.findByRole("option", { name: "Teammate" });
    fireEvent.click(dialog.getByRole("button", { name: "Add a service to the catalog" }));
    fireEvent.change(dialog.getByLabelText("New service name"), { target: { value: " Build server " } });
    fireEvent.click(dialog.getByRole("button", { name: "Add service" }));
    await dialog.findByRole("option", { name: "Build server" });
    expect((dialog.getByLabelText("Service") as HTMLSelectElement).value).toBe("service-new");
    expect(mock.post).toHaveBeenCalledTimes(1);
    expect(dialog.queryByLabelText("Private service name")).toBeNull();
    fireEvent.change(dialog.getByLabelText("Title"), { target: { value: "Build key" } });
    fireEvent.change(dialog.getByLabelText("Credential type"), { target: { value: "api_key" } });
    fireEvent.change(dialog.getByLabelText("Assign to"), { target: { value: "group" } });
    fireEvent.change(dialog.getByLabelText("Group"), { target: { value: "group-one" } });
    fireEvent.change(dialog.getByLabelText("Secret"), { target: { value: "BuildApiSecret" } });
    fireEvent.click(dialog.getByRole("button", { name: "Save credential" }));
    await waitFor(() => expect(mock.post).toHaveBeenLastCalledWith(expect.stringContaining("/entries"), expect.objectContaining({ body: { title: "Build key", kind: "api_key", username: "", secret: "BuildApiSecret", visibility: "assigned", service_id: "service-new", subject_kind: "group", subject_id: "group-one" } })));
  });

  it("clears secret drafts after a version conflict and prevents a blind retry", async () => {
    mock.put.mockResolvedValue({ error: { error: { code: "vault_version_conflict" } }, response: new Response("{}", { status: 409 }) });
    show(); fireEvent.click(await screen.findByRole("button", { name: assigned.title }));
    fireEvent.click(within(screen.getByRole("dialog", { name: assigned.title })).getByRole("button", { name: "Change secret" }));
    const dialog = within(screen.getByRole("dialog", { name: "Change secret" }));
    expect(screen.getByRole("dialog", { name: "Change secret" }).closest(".tnx-modal-overlay")?.getAttribute("data-placement")).toBe("right");
    fireEvent.change(dialog.getByLabelText("New secret"), { target: { value: "next-secret" } });
    fireEvent.click(dialog.getByRole("button", { name: "Save new version" }));
    await dialog.findByRole("alert");
    expect(mock.put).toHaveBeenCalledWith(expect.stringContaining("/entries/{entryId}"), expect.objectContaining({ body: { title: assigned.title, username: assigned.username, secret: "next-secret", expected_version: 2 } }));
    expect((dialog.getByLabelText("New secret") as HTMLInputElement).value).toBe("");
    expect((dialog.getByRole("button", { name: "Save new version" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(dialog.getByRole("button", { name: "Save new version" }));
    expect(mock.put).toHaveBeenCalledTimes(1);
  });

  it("keeps recipients from deleting assigned credentials and confirms deletion of personal history", async () => {
    show(); fireEvent.click(await screen.findByRole("button", { name: assigned.title }));
    const shared = within(screen.getByRole("dialog", { name: assigned.title }));
    expect(shared.queryByRole("button", { name: "Delete credential" })).toBeNull();
    expect(shared.getByRole("button", { name: "Change secret" })).toBeTruthy();
    fireEvent.click(shared.getByRole("button", { name: "Close" }));
    fireEvent.click(screen.getByRole("button", { name: personal.title }));
    fireEvent.click(within(screen.getByRole("dialog", { name: personal.title })).getByRole("button", { name: "Delete credential" }));
    const confirmation = within(screen.getByRole("dialog", { name: "Delete credential" }));
    expect(screen.getByRole("dialog", { name: "Delete credential" }).closest(".tnx-modal-overlay")?.getAttribute("data-placement")).toBe("right");
    expect(confirmation.getByText(/and all 2 saved versions/)).toBeTruthy();
    expect(mock.remove).not.toHaveBeenCalled();
    fireEvent.click(confirmation.getByRole("button", { name: "Confirm deletion" }));
    await waitFor(() => expect(mock.remove).toHaveBeenCalledWith(expect.stringContaining("/entries/{entryId}"), { params: { path: { orgId: mock.org, entryId: personal.id }, query: { expected_version: 2 } } }));
  });

  it("discards a late reveal response when the user changes organizations", async () => {
    let finish!: (value: unknown) => void;
    mock.post.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    const view = show();
    fireEvent.click(await screen.findByRole("button", { name: personal.title }));
    fireEvent.click(within(screen.getByRole("dialog", { name: personal.title })).getByRole("button", { name: "Reveal current secret" }));
    mock.org = "org-two"; entries = [];
    view.rerender(<MemoryRouter><Vault /></MemoryRouter>);
    await screen.findByText(/No credentials yet/);
    await act(async () => { finish({ data: { value: "late-private-secret", username: "rajan", version: 2 }, response: new Response("{}") }); });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.queryByText("late-private-secret")).toBeNull();
    expect(mock.clipboard).not.toHaveBeenCalled();
  });

  it("invalidates an in-flight reveal when history is refreshed", async () => {
    let finish!: (value: unknown) => void;
    mock.post.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    show(); fireEvent.click(await screen.findByRole("button", { name: personal.title }));
    const dialog = within(screen.getByRole("dialog", { name: personal.title }));
    fireEvent.click(dialog.getByRole("button", { name: "Reveal current secret" }));
    fireEvent.click(dialog.getByRole("button", { name: "Refresh version history" }));
    await act(async () => { finish({ data: { value: "outdated-reveal", username: "rajan", version: 2 }, response: new Response("{}") }); });
    expect(dialog.queryByLabelText("Revealed secret")).toBeNull();
    expect(dialog.getByLabelText("Hidden secret")).toBeTruthy();
  });

  it("discards late reveals when moving in either direction through history", async () => {
    const defaultGet = mock.get.getMockImplementation()!;
    mock.get.mockImplementation(async (path: string, options: any) => path.endsWith("/versions")
      ? { data: { ...history, total: 12 } }
      : defaultGet(path, options));
    let finish!: (value: unknown) => void;
    mock.post.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    show(); fireEvent.click(await screen.findByRole("button", { name: personal.title }));
    const dialog = within(screen.getByRole("dialog", { name: personal.title }));
    await dialog.findByRole("button", { name: "Reveal version 1" });
    for (const direction of ["Next versions", "Previous versions"]) {
      fireEvent.click(dialog.getByRole("button", { name: "Reveal current secret" }));
      fireEvent.click(dialog.getByRole("button", { name: direction }));
      await act(async () => { finish({ data: { value: "outdated-page-secret", username: "rajan", version: 2 }, response: new Response("{}") }); });
      await dialog.findByRole("button", { name: "Reveal version 1" });
      expect(dialog.queryByLabelText("Revealed secret")).toBeNull();
      expect(dialog.getByLabelText("Hidden secret")).toBeTruthy();
    }
    expect(mock.clipboard).not.toHaveBeenCalled();
  });

  it("restores search and page controls from the inventory URL", async () => {
    show("/vault?q=Payments&page=2&page_size=10");
    await screen.findByRole("button", { name: personal.title });
    expect((screen.getByLabelText("Search Vault") as HTMLInputElement).value).toBe("Payments");
    expect(mock.get).toHaveBeenCalledWith(expect.stringContaining("/entries"), expect.objectContaining({ params: { path: { orgId: mock.org }, query: { limit: 10, offset: 10, q: "Payments" } } }));
    fireEvent.click(screen.getByRole("button", { name: "Clear search" }));
    await waitFor(() => expect(mock.get).toHaveBeenCalledWith(expect.stringContaining("/entries"), expect.objectContaining({ params: { path: { orgId: mock.org }, query: { limit: 10, offset: 0, q: undefined } } })));
  });

  it("automatically hides a revealed version after thirty seconds", async () => {
    show(); fireEvent.click(await screen.findByRole("button", { name: personal.title }));
    const dialog = within(screen.getByRole("dialog", { name: personal.title }));
    fireEvent.click(dialog.getByRole("button", { name: "Reveal current secret" }));
    await dialog.findByLabelText("Revealed secret");
    vi.useFakeTimers();
    // Re-reveal under the fake clock so the concealment timer belongs to this clock.
    fireEvent.click(dialog.getByRole("button", { name: "Hide secret" }));
    await act(async () => { fireEvent.click(dialog.getByRole("button", { name: "Reveal current secret" })); });
    expect(dialog.getByLabelText("Revealed secret").textContent).toBe("current-secret-value");
    act(() => { vi.advanceTimersByTime(30001); });
    expect(dialog.queryByLabelText("Revealed secret")).toBeNull();
    expect(dialog.getByLabelText("Hidden secret")).toBeTruthy();
  });

  it("keeps load failures distinct from an empty Vault", async () => {
    mock.get.mockImplementation(async (path: string) => path.endsWith("/entries") ? { error: {} } : { data: services });
    show();
    await screen.findByRole("button", { name: "Retry Vault" });
    expect(screen.queryByText(/No credentials yet/)).toBeNull();
    expect((screen.getByRole("button", { name: "Add credential" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it.each([["/vault", "No credentials yet"], ["/vault?q=missing", "No credentials match your search."]])("uses Local Sharing's shared empty state for %s", async (path, title) => {
    entries = [];
    show(path);
    const heading = await screen.findByRole("heading", { name: title });
    expect(heading.closest(".aa-empty-state")).toBeTruthy();
    expect(screen.getByRole("link", { name: "My Vault" }).getAttribute("aria-current")).toBe("page");
    expect(screen.queryByRole("table", { name: "Vault credentials" })).toBeNull();
    if (path.includes("q=")) {
      fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
      await screen.findByRole("heading", { name: "No credentials yet" });
    } else {
      fireEvent.click(screen.getByRole("button", { name: "Add your first credential" }));
      expect(screen.getByRole("dialog", { name: "Add credential" }).closest(".tnx-modal-overlay")?.getAttribute("data-placement")).toBe("right");
    }
  });
});
