import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import Vault from "../src/pages/Vault";
import { auditActionLabel, auditChangeLabel, vaultAuditDetails } from "../src/lib/auditview";

// VAULT-UX-1: the Vault experience findings, one behaviour per test.
const mock = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), patch: vi.fn(), remove: vi.fn(), write: vi.fn(), read: vi.fn(), permission: vi.fn(), canAssign: false, reauth: { password: true, mfa: false, available: true } }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api: { GET: mock.get, POST: mock.post, PUT: mock.put, PATCH: mock.patch, DELETE: mock.remove } }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: "org-one" }, failed: false }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "user-one", email_verified: true } } }), useOptionalAuth: () => null }));
vi.mock("../src/components/AdminOnly", () => ({ AdminOnlyNotice: ({ page }: { page: string }) => <p>{page} is managed by organization admins</p> }));
vi.mock("../src/components/InlineTerminalMfa", () => ({ InlineTerminalMfa: ({ action, onVerified, onCancel }: { action: string; onVerified: () => void; onCancel: () => void }) => <section aria-label={`MFA for ${action}`}><button onClick={() => onVerified()}>Verify and continue</button><button onClick={onCancel}>Cancel verification</button></section> }));

const base = { configured: true, owner_user_id: "user-one", current_version: 2, revision: 3, created_at: "2026-10-20T10:00:00Z", updated_at: "2026-10-21T10:00:00Z" };
const personal = { ...base, id: "entry-personal", service_name: "Private console", title: "My console login", kind: "password", username: "rajan", visibility: "personal", can_edit: true, can_edit_details: true, can_delete: true };
const shared = { ...base, id: "entry-shared", service_id: "service-one", service_name: "Payments", title: "Production API", kind: "api_key", username: "svc", visibility: "assigned", subject_kind: "user", subject_id: "user-one", subject_name: "Rajan", owner_user_id: "admin-one", can_edit: true, can_edit_details: false, can_delete: false };
const quick = { ...personal, id: "entry-quick", configured: false, title: "", service_name: "", username: "", current_version: 1, revision: 1 };
let entries: unknown[] = [];
let listFailure: { status: number; code?: string } | null = null;
const ok = (data: unknown, status = 200) => ({ data, response: new Response("{}", { status }) });
const fail = (status: number, code: string) => ({ error: { error: { code, message: "server text" } }, response: new Response("{}", { status }) });
function show() { return render(<MemoryRouter initialEntries={["/vault"]}><Vault /></MemoryRouter>); }

beforeEach(() => {
  vi.resetAllMocks(); mock.canAssign = false; mock.reauth = { password: true, mfa: false, available: true }; listFailure = null;
  entries = [personal, shared];
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: mock.write.mockResolvedValue(undefined), readText: mock.read } });
  Object.defineProperty(navigator, "permissions", { configurable: true, value: { query: mock.permission.mockResolvedValue({ state: "granted" }) } });
  mock.get.mockImplementation(async (path: string) => {
    if (path.endsWith("/services")) return ok([{ id: "service-one", name: "Payments" }]);
    if (path.endsWith("/subjects")) return ok({ users: [{ id: "user-two", name: "Teammate", email: "teammate@example.test" }], groups: [{ id: "group-one", name: "DevOps", member_count: 3, members_without_access: [{ id: "u9", name: "Ivy Viewer", email: "ivy@example.test" }] }] });
    if (path.endsWith("/versions")) return ok({ current_version: 2, total: 2, versions: [{ version: 2, changed_by: "user-one", changed_by_name: "Rajan", changed_by_email: "rajan@example.test", created_at: "2026-10-21T10:00:00Z" }, { version: 1, changed_by: "admin-one", changed_by_name: "Ada", changed_by_email: "ada@example.test", created_at: "2026-10-20T10:00:00Z" }] });
    if (listFailure) return fail(listFailure.status, listFailure.code ?? "boom");
    return ok({ entries, total: entries.length, can_assign: mock.canAssign, reauthentication: mock.reauth });
  });
  mock.post.mockImplementation(async (path: string) => {
    if (path.endsWith("/reveal")) return ok({ value: "current-secret-value", username: "svc", version: 2 });
    if (path.endsWith("/quick")) { entries = [...entries, quick]; return ok(quick); }
    if (path.endsWith("/configure")) return ok({ ...personal, id: quick.id, current_version: 1 });
    return ok(personal, 201);
  });
  mock.put.mockResolvedValue(ok({ ...shared, current_version: 3 }));
  mock.patch.mockResolvedValue(ok({ ...personal, title: "Renamed" }));
});
afterEach(() => { cleanup(); vi.useRealTimers(); });

describe("VAULT-UX-1", () => {
  it("names the page Vault and offers useful views instead of a lone tab (V10, V13)", async () => {
    show(); await screen.findByRole("button", { name: personal.title });
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Vault");
    expect(screen.queryByText("My Vault")).toBeNull();
    expect(screen.getByText("2 credentials")).toBeTruthy();
    for (const name of ["All", "Personal", "Shared with me"]) expect(screen.getByRole("button", { name })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Organization" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Personal" }));
    await waitFor(() => expect(mock.get).toHaveBeenLastCalledWith(expect.stringMatching(/\/vault\/entries$/), expect.objectContaining({ params: expect.objectContaining({ query: expect.objectContaining({ view: "personal" }) }) })));
  });

  it("shows administrators an Organization view", async () => {
    mock.canAssign = true;
    show(); await screen.findByRole("button", { name: personal.title });
    expect(screen.getByRole("button", { name: "Organization" })).toBeTruthy();
  });

  it("maps a refused list to a calm access notice (V11)", async () => {
    listFailure = { status: 403, code: "forbidden" };
    show();
    expect(await screen.findByText("Vault is managed by organization admins")).toBeTruthy();
  });

  it("tells an unverified person to verify their email (V11)", async () => {
    listFailure = { status: 403, code: "email_not_verified" };
    show();
    expect(await screen.findByText(/Verify your email to use Vault/)).toBeTruthy();
  });

  it("keeps Add credential and Quick generate available when the list fails (V11)", async () => {
    listFailure = { status: 500, code: "internal" };
    show();
    await screen.findByRole("button", { name: "Retry Vault" });
    expect((screen.getByRole("button", { name: "Add credential" }) as HTMLButtonElement).disabled).toBe(false);
    expect((screen.getByRole("button", { name: "Quick generate" }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("labels quick copy as a save, warns before discarding, and names the saved row plainly (V7, V8)", async () => {
    show(); await screen.findByRole("button", { name: personal.title });
    fireEvent.click(screen.getByRole("button", { name: "Quick generate" }));
    let dialog = within(screen.getByRole("dialog", { name: "Quick generate" }));
    expect(dialog.getByText(/Saving keeps this password in your Vault/)).toBeTruthy();
    fireEvent.click(dialog.getByRole("button", { name: "Close" }));
    expect(dialog.getByText(/isn't saved/)).toBeTruthy();
    fireEvent.click(dialog.getByRole("button", { name: "Keep it" }));
    expect(screen.getByRole("dialog", { name: "Quick generate" })).toBeTruthy();
    fireEvent.click(dialog.getByRole("button", { name: "Close" }));
    fireEvent.click(dialog.getByRole("button", { name: "Discard" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Quick generate" }));
    dialog = within(screen.getByRole("dialog", { name: "Quick generate" }));
    fireEvent.click(dialog.getByRole("button", { name: "Save & copy" }));
    await waitFor(() => expect(mock.write).toHaveBeenCalled());
    expect(await screen.findByRole("button", { name: "Generated password · add details" })).toBeTruthy();
    expect(screen.queryByText(/Unconfigured/)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Add details for Generated password" }));
    const details = within(screen.getByRole("dialog", { name: "Add details" }));
    expect(details.queryByText(/version 2/i)).toBeNull();
  });

  it("keeps the title read-only for a recipient rotating a shared secret (V2)", async () => {
    show(); fireEvent.click(await screen.findByRole("button", { name: shared.title }));
    const drawer = within(screen.getByRole("dialog", { name: shared.title }));
    expect(drawer.queryByRole("button", { name: "Edit details" })).toBeNull();
    expect(drawer.queryByRole("button", { name: "Delete credential" })).toBeNull();
    fireEvent.click(drawer.getByRole("button", { name: "Change secret" }));
    const dialog = within(screen.getByRole("dialog", { name: "Change secret" }));
    expect(dialog.queryByLabelText("Title")).toBeNull();
    expect(dialog.getByText(shared.title)).toBeTruthy();
    fireEvent.change(dialog.getByLabelText("New secret"), { target: { value: "rotated-value" } });
    fireEvent.click(dialog.getByRole("button", { name: "Save new version" }));
    await waitFor(() => expect(mock.put).toHaveBeenCalled());
    expect(mock.put.mock.calls[0][1].body).not.toHaveProperty("title");
  });

  it("edits details without a new version (V5)", async () => {
    show(); fireEvent.click(await screen.findByRole("button", { name: personal.title }));
    fireEvent.click(within(screen.getByRole("dialog", { name: personal.title })).getByRole("button", { name: "Edit details" }));
    const dialog = within(screen.getByRole("dialog", { name: "Edit details" }));
    expect(dialog.queryByLabelText(/secret/i)).toBeNull();
    fireEvent.change(dialog.getByLabelText("Title"), { target: { value: "Renamed" } });
    fireEvent.click(dialog.getByRole("button", { name: "Save details" }));
    await waitFor(() => expect(mock.patch).toHaveBeenCalled());
    expect(mock.patch.mock.calls[0][1].body).toMatchObject({ expected_revision: 3, title: "Renamed" });
    expect(mock.patch.mock.calls[0][1].body).not.toHaveProperty("secret");
  });

  it("names people with their email in the picker and history, and flags group members without access (V1, V9)", async () => {
    mock.canAssign = true;
    show(); await screen.findByRole("button", { name: personal.title });
    fireEvent.click(screen.getByRole("button", { name: "Add credential" }));
    const dialog = within(screen.getByRole("dialog", { name: "Add credential" }));
    fireEvent.change(dialog.getByLabelText("Visibility"), { target: { value: "assigned" } });
    expect(await dialog.findByRole("option", { name: "Teammate (teammate@example.test)" })).toBeTruthy();
    fireEvent.change(dialog.getByLabelText("Assign to"), { target: { value: "group" } });
    fireEvent.change(dialog.getByLabelText("Group"), { target: { value: "group-one" } });
    expect(dialog.getByText(/Ivy Viewer \(ivy@example.test\)/)).toBeTruthy();
    fireEvent.click(dialog.getByRole("button", { name: "Cancel" }));
    fireEvent.click(screen.getByRole("button", { name: personal.title }));
    expect(await screen.findByText("Rajan (rajan@example.test)")).toBeTruthy();
  });

  it("asks for the password before revealing a shared secret and continues after MFA (V4)", async () => {
    mock.reauth = { password: true, mfa: true, available: true };
    let calls = 0;
    mock.post.mockImplementation(async (path: string) => {
      if (!path.endsWith("/reveal")) return ok({});
      calls++;
      return calls === 1 ? fail(403, "mfa_step_up_required") : ok({ value: "current-secret-value", username: "svc", version: 2 });
    });
    show(); fireEvent.click(await screen.findByRole("button", { name: shared.title }));
    const dialog = within(screen.getByRole("dialog", { name: shared.title }));
    expect(dialog.getByText(/shared credential/i)).toBeTruthy();
    fireEvent.change(dialog.getByLabelText("Current password"), { target: { value: "test-password" } });
    fireEvent.click(dialog.getByRole("button", { name: "Reveal current secret" }));
    fireEvent.click(await dialog.findByRole("button", { name: "Verify and continue" }));
    expect(await dialog.findByText("current-secret-value")).toBeTruthy();
    expect(mock.post.mock.calls[0][1].body).toMatchObject({ current_password: "test-password", purpose: "reveal" });
    expect(mock.post.mock.calls[1][1].body).toMatchObject({ current_password: "test-password" });
    expect(dialog.queryByText(/mfa_step_up_required/)).toBeNull();
  });

  it("does not ask for re-authentication on personal entries (V4)", async () => {
    show(); fireEvent.click(await screen.findByRole("button", { name: personal.title }));
    const dialog = within(screen.getByRole("dialog", { name: personal.title }));
    expect(dialog.queryByLabelText("Current password")).toBeNull();
  });

  it("explains a wrong password and the rate limit in plain words (V4)", async () => {
    mock.post.mockResolvedValueOnce(fail(403, "invalid_credentials")).mockResolvedValueOnce(fail(429, "vault_reveal_rate_limited"));
    show(); fireEvent.click(await screen.findByRole("button", { name: shared.title }));
    const dialog = within(screen.getByRole("dialog", { name: shared.title }));
    fireEvent.change(dialog.getByLabelText("Current password"), { target: { value: "nope" } });
    fireEvent.click(dialog.getByRole("button", { name: "Reveal current secret" }));
    expect(await dialog.findByText(/password is incorrect/i)).toBeTruthy();
    fireEvent.click(dialog.getByRole("button", { name: "Reveal current secret" }));
    expect(await dialog.findByText(/Wait a minute/i)).toBeTruthy();
  });

  it("marks copies as copies and clears the clipboard after 30 seconds only if unchanged (V3, V15)", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    mock.read.mockResolvedValue("current-secret-value");
    show(); fireEvent.click(await screen.findByRole("button", { name: personal.title }));
    const dialog = within(screen.getByRole("dialog", { name: personal.title }));
    fireEvent.click(dialog.getByRole("button", { name: "Copy current secret" }));
    await waitFor(() => expect(mock.write).toHaveBeenCalledWith("current-secret-value"));
    expect(mock.post.mock.calls[0][1].body).toMatchObject({ purpose: "copy" });
    expect(await dialog.findByText(/clears it after about 30 seconds/)).toBeTruthy();
    await act(async () => { await vi.advanceTimersByTimeAsync(31_000); });
    await waitFor(() => expect(mock.write).toHaveBeenLastCalledWith(""));
  });

  it("never prompts for clipboard access: no grant, no read (V15)", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    mock.permission.mockResolvedValue({ state: "prompt" });
    mock.read.mockResolvedValue("current-secret-value");
    show(); fireEvent.click(await screen.findByRole("button", { name: personal.title }));
    fireEvent.click(within(screen.getByRole("dialog", { name: personal.title })).getByRole("button", { name: "Copy current secret" }));
    await waitFor(() => expect(mock.write).toHaveBeenCalledTimes(1));
    await act(async () => { await vi.advanceTimersByTimeAsync(31_000); });
    expect(mock.read).not.toHaveBeenCalled();
    expect(mock.write).toHaveBeenCalledTimes(1);
  });

  it("leaves the clipboard alone when it no longer holds the secret (V15)", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    mock.read.mockResolvedValue("something the user copied later");
    show(); fireEvent.click(await screen.findByRole("button", { name: personal.title }));
    fireEvent.click(within(screen.getByRole("dialog", { name: personal.title })).getByRole("button", { name: "Copy current secret" }));
    await waitFor(() => expect(mock.write).toHaveBeenCalledTimes(1));
    await act(async () => { await vi.advanceTimersByTimeAsync(31_000); });
    expect(mock.read).toHaveBeenCalled();
    expect(mock.write).toHaveBeenCalledTimes(1);
  });
});

describe("Vault audit labels (V3)", () => {
  it("reads Vault actions as words", () => {
    expect(auditActionLabel("vault.copied")).toBe("Secret copied");
    expect(auditActionLabel("vault.revealed")).toBe("Secret revealed");
    expect(auditActionLabel("vault.details_changed")).toBe("Credential details changed");
    expect(auditActionLabel("vault.personal_entries_purged")).toBe("Personal credentials removed with the membership");
    expect(auditChangeLabel({ action: "vault.copied", details: { title: "Deploy key" } })).toBe("Secret copied · Deploy key");
    expect(auditChangeLabel({ action: "vault.revealed", details: { visibility: "personal" } })).toBe("Secret revealed · personal credential");
  });
  it("shows only allowlisted Vault details", () => {
    expect(vaultAuditDetails({ title: "Deploy key", version: 2, secret: "x", recipient: "DevOps", nested: { a: 1 } })).toEqual([["title", "Deploy key"], ["version", 2], ["recipient", "DevOps"]]);
  });
});
