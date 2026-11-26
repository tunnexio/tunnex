import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { MemoryRouter } from "react-router-dom";
import Vault from "../src/pages/Vault";

// VAULT-UX-2: polish from the v0.1.51 walk (W1–W6) and the full pass (F1–F10).
const mock = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), patch: vi.fn(), remove: vi.fn(), canAssign: false, reauth: { password: true, mfa: false, available: true } as { password: boolean; mfa: boolean; available: boolean } }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api: { GET: mock.get, POST: mock.post, PUT: mock.put, PATCH: mock.patch, DELETE: mock.remove } }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: "org-one" }, failed: false }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "user-one", email_verified: true } } }), useOptionalAuth: () => null }));
vi.mock("../src/components/AdminOnly", () => ({ AdminOnlyNotice: ({ page }: { page: string }) => <p>{page} is managed by organization admins</p> }));
vi.mock("../src/components/InlineTerminalMfa", () => ({ InlineTerminalMfa: () => null }));

const base = { configured: true, current_version: 2, revision: 3, created_at: "2026-10-20T10:00:00Z", updated_at: "2026-10-21T10:00:00Z", kind: "password", username: "svc", service_id: "service-one", service_name: "Payments" };
const personal = { ...base, id: "entry-personal", service_id: undefined, service_name: "Private console", title: "My console login", visibility: "personal", owner_user_id: "user-one", can_edit: true, can_edit_details: true, can_delete: true };
const toPerson = { ...base, id: "entry-person", title: "Reviewer login", visibility: "assigned", owner_user_id: "admin-one", subject_kind: "user", subject_id: "user-two", subject_name: "reviewer", subject_email: "reviewer@tunnex.io", can_edit: true, can_edit_details: false, can_delete: false };
const toGroup = { ...base, id: "entry-group", title: "Ops login", visibility: "assigned", owner_user_id: "admin-one", subject_kind: "group", subject_id: "group-one", subject_name: "DevOps", subject_member_count: 3, can_edit: true, can_edit_details: false, can_delete: false };
let entries: unknown[] = [];
const ok = (data: unknown, status = 200) => ({ data, response: new Response("{}", { status }) });
function show(at = "/vault") { return render(<MemoryRouter initialEntries={[at]}><Vault /></MemoryRouter>); }
function listQueries() { return mock.get.mock.calls.filter(([path]) => String(path).endsWith("/vault/entries")).map(([, init]) => init.params.query); }
const css = readFileSync(join(__dirname, "..", "src", "vault-workspace.css"), "utf8").replace(/\/\*[\s\S]*?\*\//g, "");

beforeEach(() => {
  vi.resetAllMocks(); mock.canAssign = false; mock.reauth = { password: true, mfa: false, available: true };
  entries = [personal, toPerson, toGroup];
  mock.get.mockImplementation(async (path: string, init: { params: { query?: { q?: string; view?: string } } }) => {
    if (path.endsWith("/services")) return ok([{ id: "service-one", name: "Payments" }]);
    if (path.endsWith("/versions")) return ok({ current_version: 2, total: 1, versions: [{ version: 2, changed_by: "admin-one", changed_by_name: "Ada", changed_by_email: "ada@example.test", created_at: "2026-10-21T10:00:00Z" }] });
    const q = init?.params?.query?.q;
    const view = init?.params?.query?.view;
    const rows = (entries as { title: string }[]).filter(entry => !q || entry.title.toLowerCase().includes(q.toLowerCase())).filter(() => view !== "shared" || false);
    return ok({ entries: rows, total: rows.length, can_assign: mock.canAssign, reauthentication: mock.reauth });
  });
  mock.post.mockResolvedValue(ok(personal, 201));
  mock.put.mockResolvedValue(ok({ ...toPerson, current_version: 3 }));
});
afterEach(() => { cleanup(); vi.useRealTimers(); });

describe("W2 — recipients are named with their email or group size", () => {
  it("shows a person as name (email) and a group with its member count in the Access column", async () => {
    show(); await screen.findByRole("button", { name: toPerson.title });
    const table = within(screen.getByRole("table", { name: "Vault credentials" }));
    expect(table.getByText("reviewer (reviewer@tunnex.io)")).toBeTruthy();
    expect(table.getByText("DevOps · 3 members")).toBeTruthy();
    expect(table.getByText("Only you")).toBeTruthy();
  });

  it("uses the same recipient label in the detail drawer and the Change secret summary", async () => {
    show(); fireEvent.click(await screen.findByRole("button", { name: toPerson.title }));
    const drawer = within(screen.getByRole("dialog", { name: toPerson.title }));
    expect(drawer.getByText(/Shared · reviewer \(reviewer@tunnex\.io\) and Vault administrators/)).toBeTruthy();
    fireEvent.click(drawer.getByRole("button", { name: "Change secret" }));
    expect(within(screen.getByRole("dialog", { name: "Change secret" })).getByText(/Shared with reviewer \(reviewer@tunnex\.io\)/)).toBeTruthy();
  });

  it("falls back to the name alone when an older server sends no email", async () => {
    entries = [{ ...toPerson, subject_email: undefined }, { ...toGroup, subject_member_count: undefined }];
    show(); await screen.findByRole("button", { name: toPerson.title });
    const table = within(screen.getByRole("table", { name: "Vault credentials" }));
    expect(table.getByText("reviewer")).toBeTruthy();
    expect(table.getByText("DevOps")).toBeTruthy();
  });
});

describe("W3 — the secret field stays a normal masked input", () => {
  it.each([["Add credential"], ["Change secret"]])("%s: masked secret opts out of password managers and reveals on Show secret", async (form) => {
    show(); await screen.findByRole("button", { name: personal.title });
    if (form === "Add credential") fireEvent.click(screen.getByRole("button", { name: "Add credential" }));
    else { fireEvent.click(screen.getByRole("button", { name: personal.title })); fireEvent.click(within(screen.getByRole("dialog", { name: personal.title })).getByRole("button", { name: "Change secret" })); }
    const dialog = within(screen.getByRole("dialog", { name: form }));
    const input = dialog.getByLabelText(form === "Add credential" ? "Secret" : "New secret") as HTMLInputElement;
    fireEvent.click(dialog.getByRole("button", { name: "Generate password" }));
    expect(input.value).toHaveLength(24);
    expect(input.type).toBe("password");
    expect(input.classList.contains("vault-secret-input")).toBe(true);
    for (const attribute of ["data-1p-ignore", "data-lpignore", "data-bwignore"]) expect(input.hasAttribute(attribute)).toBe(true);
    expect(input.getAttribute("data-form-type")).toBe("other");
    fireEvent.click(dialog.getByRole("button", { name: "Show secret" }));
    expect(input.type).toBe("text");
  });

  it("pins the normal input colours for an autofilled secret, scoped to Vault", () => {
    expect(css).toMatch(/\.vault-secret-input:is\(:autofill,\s*:-webkit-autofill\)/);
    expect(css).toMatch(/-webkit-text-fill-color:\s*var\(--tnx-text-heading\)/);
  });
});

describe("W5 — search filters as you type", () => {
  it("searches 300 ms after typing stops, with no Search button", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    show(); await screen.findByRole("button", { name: personal.title });
    expect(screen.queryByRole("button", { name: "Search" })).toBeNull();
    fireEvent.change(screen.getByLabelText("Search Vault"), { target: { value: "rev" } });
    fireEvent.change(screen.getByLabelText("Search Vault"), { target: { value: "revi" } });
    expect(listQueries().some(query => query.q)).toBe(false);
    await act(async () => { await vi.advanceTimersByTimeAsync(350); });
    await waitFor(() => expect(listQueries().at(-1)?.q).toBe("revi"));
    expect(listQueries().filter(query => query.q === "rev")).toHaveLength(0);
    expect((screen.getByLabelText("Search Vault") as HTMLInputElement).value).toBe("revi");
    expect(await screen.findByRole("button", { name: toPerson.title })).toBeTruthy();
  });

  it("applies the search at once on Enter", async () => {
    show(); await screen.findByRole("button", { name: personal.title });
    const input = screen.getByLabelText("Search Vault");
    fireEvent.change(input, { target: { value: "ops" } });
    fireEvent.submit(input.closest("form")!);
    await waitFor(() => expect(listQueries().at(-1)?.q).toBe("ops"));
  });

  it("keeps the rows on screen while a search loads", async () => {
    show(); await screen.findByRole("button", { name: personal.title });
    let release: () => void = () => {};
    mock.get.mockImplementationOnce(() => new Promise(resolve => { release = () => resolve(ok({ entries: [toGroup], total: 1, can_assign: false, reauthentication: mock.reauth })); }));
    const input = screen.getByLabelText("Search Vault");
    fireEvent.change(input, { target: { value: "ops" } });
    fireEvent.submit(input.closest("form")!);
    await waitFor(() => expect(listQueries().at(-1)?.q).toBe("ops"));
    expect(screen.queryByText("Loading credentials…")).toBeNull();
    expect(screen.getByRole("button", { name: personal.title })).toBeTruthy();
    await act(async () => { release(); });
    await waitFor(() => expect(screen.queryByRole("button", { name: personal.title })).toBeNull());
  });

  it("names the empty-search action Clear search", async () => {
    show("/vault?q=nothing-matches"); await screen.findByText("No credentials match your search.");
    expect(screen.queryByRole("button", { name: "Clear filters" })).toBeNull();
    expect(screen.getAllByRole("button", { name: "Clear search" }).length).toBeGreaterThan(0);
  });
});

describe("W6 — Quick generate is a full-height drawer like the others", () => {
  it("has no Vault-only rule that shortens the Quick generate drawer", () => {
    expect(css).not.toMatch(/:has\(\.vault-quick-password\)/);
  });
});

describe("F1 — the step-up sentence follows what the account will be asked for", () => {
  it.each([
    [{ password: true, mfa: true, available: true }, "your password and a recent two-factor check"],
    [{ password: true, mfa: false, available: true }, "your password"],
    [{ password: false, mfa: true, available: true }, "a recent two-factor check"],
  ])("%j", async (reauth, words) => {
    mock.reauth = reauth;
    show(); fireEvent.click(await screen.findByRole("button", { name: toPerson.title }));
    const drawer = within(screen.getByRole("dialog", { name: toPerson.title }));
    const note = drawer.getByText(/opening or copying it asks you to confirm it is you/);
    expect(note.textContent).toContain(`(${words})`);
    if (!reauth.password) expect(note.textContent).not.toContain("password");
  });

  it("tells an account that cannot re-authenticate what to set up", async () => {
    mock.reauth = { password: false, mfa: true, available: false };
    show(); fireEvent.click(await screen.findByRole("button", { name: toPerson.title }));
    expect(within(screen.getByRole("dialog", { name: toPerson.title })).getByText("Set up an authenticator app before you can open shared credentials.")).toBeTruthy();
  });
});

describe("F2–F4 — empty states and notices", () => {
  it("does not offer to add a personal credential on Shared with me", async () => {
    show("/vault?view=shared"); await screen.findByText("Nothing in Shared with me yet");
    expect(screen.queryByRole("button", { name: /Add your first credential/ })).toBeNull();
  });

  it("offers a personal credential on the empty Personal view", async () => {
    entries = [];
    show("/vault?view=personal"); await screen.findByText("Nothing in Personal yet");
    expect(screen.getByRole("button", { name: /Add a personal credential/ })).toBeTruthy();
  });

  it("clears a success notice when the view changes", async () => {
    show(); await screen.findByRole("button", { name: personal.title });
    fireEvent.click(screen.getByRole("button", { name: "Add credential" }));
    const dialog = within(screen.getByRole("dialog", { name: "Add credential" }));
    fireEvent.change(dialog.getByLabelText("Title"), { target: { value: "New login" } });
    fireEvent.change(dialog.getByLabelText("Private service name"), { target: { value: "Console" } });
    fireEvent.change(dialog.getByLabelText("Secret"), { target: { value: "typed-secret" } });
    fireEvent.click(dialog.getByRole("button", { name: "Save credential" }));
    expect(await screen.findByText("Credential saved.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Personal" }));
    await waitFor(() => expect(screen.queryByText("Credential saved.")).toBeNull());
  });
});
