import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { StrictMode } from "react";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useNavigate } from "react-router-dom";
import AppAccessMyApplications, { AppAccessLaunch } from "../src/pages/AppAccessMyApplications";
import { AuthProvider, useAuth } from "../src/lib/auth";
import { OrgProvider, useOrg } from "../src/lib/useOrg";
import { api } from "../src/lib/api";

const orgId = "00000000-0000-4000-8000-000000000001";
const appId = "00000000-0000-4000-8000-000000000002";
const state = vi.hoisted(() => ({ appsFailed: false, sessionsFailed: false, revokeFailed: false, launchFailed: true, logoutFailed: false, availability: "available", items: [] as unknown[], sessions: [] as unknown[] }));
vi.mock("sonner", () => ({ toast: { error: vi.fn() } }));
vi.mock("../src/lib/api", async importOriginal => {
  const original = await importOriginal<typeof import("../src/lib/api")>();
  return { ...original, api: {
    GET: vi.fn(async (path: string) => {
      if (path.endsWith("/auth/me")) return { data: { id: "user-1", email: "member@test.local", email_verified: true } };
      if (path === "/api/v1/organizations") return { data: [{ id: "00000000-0000-4000-8000-000000000001", name: "Office", slug: "office" }, { id: "00000000-0000-4000-8000-000000000003", name: "Other office", slug: "other-office" }] };
      if (path.endsWith("/my-apps")) return state.appsFailed ? { error: { error: { message: "Catalog unavailable" } } } : { data: { items: state.items, limit: 20, offset: 0, availability: state.availability } };
      if (path.endsWith("/my-sessions")) return state.sessionsFailed ? { error: { error: { message: "Sessions unavailable" } } } : { data: { items: state.sessions, limit: 20, offset: 0 } };
      throw new Error(`Unexpected path ${path}`);
    }),
    POST: vi.fn(async (path: string) => path.endsWith("/logout") ? { ...(state.logoutFailed ? { error: { error: { message: "Retry sign-out" } } } : {}), response: { status: state.logoutFailed ? 503 : 204 } } : { error: { error: { code: "access_denied", message: "Application access denied" } }, response: { status: 403 } }),
    DELETE: vi.fn(async (_path: string, options: { params: { path: { sessionId: string } } }) => { if (state.revokeFailed) return { error: { error: { message: "Revocation unavailable" } } }; state.sessions = state.sessions.filter(item => (item as { id: string }).id !== options.params.path.sessionId); return { response: { status: 204 } }; }),
  } };
});
const originalLocation = Object.getOwnPropertyDescriptor(window, "location")!;
const originalTop = Object.getOwnPropertyDescriptor(window, "top")!;
afterEach(() => { cleanup(); vi.restoreAllMocks(); Object.defineProperty(window, "location", originalLocation); Object.defineProperty(window, "top", originalTop); });
beforeEach(() => {
  Object.assign(state, { appsFailed: false, sessionsFailed: false, revokeFailed: false, launchFailed: true, logoutFailed: false, availability: "available", items: [], sessions: [] });
  window.localStorage.clear(); window.sessionStorage.clear(); vi.clearAllMocks();
  vi.spyOn(window, "open").mockImplementation(() => pendingWindow().window);
});
function show(path = "/app-access/my-applications") {
  return render(<MemoryRouter initialEntries={[path]}><AuthProvider><OrgProvider><Routes><Route path="/app-access/my-applications" element={<AppAccessMyApplications orgId={orgId} />} /><Route path="/app-access/launch" element={<AppAccessLaunch />} /></Routes></OrgProvider></AuthProvider></MemoryRouter>);
}


function pendingWindow() {
  const document = window.document.implementation.createHTMLDocument("Pending");
  const location = { href: "about:blank", replace: vi.fn((href: string) => { location.href = href; }) };
  const stored = new Map<string, string>();
  const sessionStorage = { getItem: vi.fn((key: string) => stored.get(key) ?? null), setItem: vi.fn((key: string, value: string) => { stored.set(key, value); }), removeItem: vi.fn((key: string) => { stored.delete(key); }) };
  const popup = { document, location, sessionStorage, opener: window as Window | null, closed: false, close: vi.fn(() => { popup.closed = true; }) };
  return { window: popup as unknown as Window, popup, location };
}
const launchPath = `/app-access/launch?orgId=${orgId}&appId=${appId}&nonce_hash=${"a".repeat(64)}&target=%2Freports`;
const redeemURL = `https://payroll.apps.example.net/__tunnex_app/redeem?code=${"a".repeat(43)}`;
const catalogIntentKey = "tunnex.appAccess.catalogLaunch";
const automaticLaunchPath = `/app-access/launch?${new URLSearchParams({ orgId, appId, nonce_hash: "a".repeat(64), target: "/" })}`;
const payroll = { id: appId, name: "Payroll", description: "Your payslips", icon: "app", launch_url: "https://payroll.apps.example.net/__tunnex_app/start" };
function seedCatalogIntent(overrides: Record<string, unknown> = {}) {
  window.sessionStorage.setItem(catalogIntentKey, JSON.stringify({ version: 1, orgId, appId, userId: "user-1", origin: "https://payroll.apps.example.net", target: "/", createdAt: Date.now(), ...overrides }));
}
function captureChildNavigation() {
  const replace = vi.fn();
  Object.defineProperty(window, "location", { configurable: true, value: { ...window.location, replace } });
  return replace;
}
function deferredLaunch() {
  let resolve!: (value: unknown) => void;
  const promise = new Promise<unknown>(done => { resolve = done; });
  vi.mocked(api.POST).mockImplementationOnce(() => promise as never);
  return { resolve };
}

describe("member application access", () => {
  it("keeps MFA-protected apps visible and explains setup without exposing admin controls", async () => {
    state.items = [{ ...payroll, require_mfa: true, mfa_required: true, mfa_setup_required: true, mfa_freshness_seconds: 900 }];
    show();
    await screen.findByRole("link", { name: "Open Payroll" });
    expect(screen.getByText("MFA required")).toBeTruthy();
    expect(screen.getByText("Set up MFA when you open this app")).toBeTruthy();
    expect(screen.queryByRole("switch", { name: "Require MFA" })).toBeNull();
    expect(api.POST).not.toHaveBeenCalled();
  });
  it("continues the same automatic handoff only after the server confirms MFA", async () => {
    seedCatalogIntent();
    const navigate = captureChildNavigation();
    vi.mocked(api.POST)
      .mockResolvedValueOnce({ error: { error: { code: "app_mfa_required", message: "Verify MFA" } } } as never)
      .mockResolvedValueOnce({ error: { error: { code: "invalid_code", message: "Invalid authenticator code" } } } as never)
      .mockResolvedValueOnce({ data: { verified_at: "2026-10-04T12:00:00Z" } } as never)
      .mockResolvedValueOnce({ data: { redirect_url: redeemURL } } as never);
    show(automaticLaunchPath);
    const code = await screen.findByLabelText("Authenticator or recovery code");
    expect(navigate).not.toHaveBeenCalled();
    fireEvent.change(code, { target: { value: "111111" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify MFA" }));
    await screen.findByText("Invalid authenticator code");
    expect(api.POST).toHaveBeenCalledTimes(2);
    expect(navigate).not.toHaveBeenCalled();
    fireEvent.change(code, { target: { value: "222222" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify MFA" }));
    await waitFor(() => expect(navigate).toHaveBeenCalledExactlyOnceWith(redeemURL));
    expect(api.POST).toHaveBeenNthCalledWith(3, "/api/v1/auth/mfa/step-up", { body: { code: "222222" } });
    expect(api.POST).toHaveBeenNthCalledWith(4, "/api/v1/organizations/{orgId}/app-access/my-apps/{appId}/launch", { params: { path: { orgId, appId } }, body: { nonce_hash: "a".repeat(64), relative_target: "/" } });
    expect(window.open).not.toHaveBeenCalled();
  });
  it("reuses already-fresh server assurance without prompting or issuing a separate challenge", async () => {
    seedCatalogIntent();
    const navigate = captureChildNavigation();
    vi.mocked(api.POST).mockResolvedValueOnce({ data: { redirect_url: redeemURL } } as never);
    show(automaticLaunchPath);
    await waitFor(() => expect(navigate).toHaveBeenCalledExactlyOnceWith(redeemURL));
    expect(api.POST).toHaveBeenCalledTimes(1);
    expect(screen.queryByLabelText("Authenticator or recovery code")).toBeNull();
    expect(api.POST).not.toHaveBeenCalledWith("/api/v1/auth/mfa/step-up", expect.anything());
  });
  it("offers account factor setup for an explicit server enrollment requirement", async () => {
    seedCatalogIntent();
    vi.mocked(api.POST).mockResolvedValueOnce({ error: { error: { code: "app_mfa_setup_required", message: "Set up MFA" } } } as never);
    show(automaticLaunchPath);
    expect(await screen.findByRole("button", { name: "Set up MFA" })).toBeTruthy();
    expect(api.POST).toHaveBeenCalledTimes(1);
    expect(window.open).not.toHaveBeenCalled();
  });
  it("does not retry an uncertain application handoff as an MFA challenge", async () => {
    seedCatalogIntent();
    vi.mocked(api.POST).mockRejectedValueOnce(new Error("network interrupted"));
    show(automaticLaunchPath);
    await screen.findByText(/Could not complete application handoff/);
    expect(screen.queryByLabelText("Authenticator or recovery code")).toBeNull();
    expect(api.POST).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("button", { name: "Continue to application" })).toBeNull();
  });
  it("keeps own-session withdrawal available after launch permission is lost", async () => {
    state.sessions = [{ id: "session-public-id", app_label: "Payroll", created_at: "2026-10-03T00:00:00Z", expires_at: "2026-10-03T20:00:00Z", current_parent: true }];
    render(<MemoryRouter><AuthProvider><AppAccessMyApplications orgId={orgId} canUse={false} /></AuthProvider></MemoryRouter>);
    expect(screen.queryByRole("button", { name: /^Sign out of Payroll · Session / })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "My sessions" }));
    expect(await screen.findByRole("button", { name: /^Sign out of Payroll · Session / })).toBeTruthy();
    expect(screen.getByText(/You can still revoke your own sessions/)).toBeTruthy();
    expect(api.GET).not.toHaveBeenCalledWith(expect.stringContaining("my-apps"), expect.anything());
    fireEvent.click(screen.getByRole("button", { name: /^Sign out of Payroll · Session / }));
    await screen.findByText("Application session access revoked.");
  });
  it("opens only server-granted published cards through the nonce start route", async () => {
    state.items = [{ id: appId, name: "Payroll", description: "Your payslips", icon: "app", launch_url: "https://payroll.apps.example.net/__tunnex_app/start" }];
    show();
    expect(await screen.findByRole("link", { name: "Open Payroll" })).toHaveProperty("href", "https://payroll.apps.example.net/__tunnex_app/start");
    expect(screen.getByRole("link", { name: "Open Payroll" }).getAttribute("referrerpolicy")).toBe("no-referrer");
    expect(screen.getByText("payroll.apps.example.net")).toBeTruthy();
    expect(screen.getByText("Your payslips")).toBeTruthy();
    expect(screen.queryByText("Only your sessions")).toBeNull();
    expect(screen.getByRole("button", { name: "My sessions" })).toBeTruthy();
    expect(api.GET).not.toHaveBeenCalledWith(expect.stringContaining("/my-sessions"), expect.anything());
    expect(api.POST).not.toHaveBeenCalled();
    expect(api.GET).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/app-access/my-apps", { params: { path: { orgId }, query: { limit: 20, offset: 0, search: "" } } });
  });
  it("starts one-click launch in a detached new tab with child-only bounded intent and leaves the catalog open", async () => {
    state.items = [payroll];
    const tab = pendingWindow();
    vi.mocked(window.open).mockReturnValue(tab.window);
    const parentLocation = window.location.href;
    show();
    const open = await screen.findByRole("link", { name: "Open Payroll" });
    fireEvent.click(open, { detail: 1 });
    fireEvent.click(open, { detail: 2 });
    expect(window.open).toHaveBeenCalledExactlyOnceWith("about:blank", "_blank");
    expect(tab.popup.opener).toBeNull();
    expect(tab.popup.document.querySelector('meta[name="referrer"]')?.getAttribute("content")).toBe("no-referrer");
    const intent = JSON.parse(tab.popup.sessionStorage.getItem(catalogIntentKey)!);
    expect(intent).toEqual({ version: 1, orgId, appId, userId: "user-1", origin: "https://payroll.apps.example.net", target: "/", createdAt: expect.any(Number) });
    expect(Date.now() - intent.createdAt).toBeLessThan(2000);
    expect(tab.location.replace).toHaveBeenCalledExactlyOnceWith(payroll.launch_url);
    expect(tab.popup.sessionStorage.setItem.mock.invocationCallOrder[0]).toBeLessThan(tab.location.replace.mock.invocationCallOrder[0]!);
    expect(window.sessionStorage.getItem(catalogIntentKey)).toBeNull();
    expect(window.location.href).toBe(parentLocation);
    expect(screen.getByRole("link", { name: "Open Payroll" })).toBeTruthy();
    expect(api.POST).not.toHaveBeenCalled();
    cleanup();
    expect(tab.popup.close).not.toHaveBeenCalled();
  });
  it("shows the latest saved custom app icon supplied by the member catalog", async () => {
    const image = "data:image/png;base64,iVBORw0KGgo=";
    state.items = [{ ...payroll, icon_data_url: image }];
    show();
    await screen.findByRole("link", { name: "Open Payroll" });
    expect(screen.getByAltText("")).toHaveProperty("src", image);
  });
  it("keeps the catalog when popups are blocked and does not fall back to navigating the parent", async () => {
    state.items = [payroll];
    vi.mocked(window.open).mockReturnValue(null);
    const navigate = captureChildNavigation();
    show();
    fireEvent.click(await screen.findByRole("link", { name: "Open Payroll" }));
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("browser blocked the new tab"));
    expect(navigate).not.toHaveBeenCalled();
    expect(api.POST).not.toHaveBeenCalled();
    expect(window.sessionStorage.getItem(catalogIntentKey)).toBeNull();
    expect(screen.getByRole("link", { name: "Open Payroll" })).toBeTruthy();
  });
  it("closes only its blank child if intent storage cannot be written", async () => {
    state.items = [payroll];
    const tab = pendingWindow();
    tab.popup.sessionStorage.setItem.mockImplementation(() => { throw new Error("Storage denied"); });
    vi.mocked(window.open).mockReturnValue(tab.window);
    show();
    fireEvent.click(await screen.findByRole("link", { name: "Open Payroll" }));
    await screen.findByText(/Could not open the application in a new tab/);
    expect(tab.popup.close).toHaveBeenCalledTimes(1);
    expect(tab.location.replace).not.toHaveBeenCalled();
    expect(api.POST).not.toHaveBeenCalled();
  });
  it.each([
    "http://payroll.apps.example.net/__tunnex_app/start",
    "https://payroll.apps.example.net/__tunnex_app/start?auto=1",
    "https://payroll.apps.example.net/untrusted",
  ])("refuses an unexpected catalog start URL before opening a tab: %s", async launch_url => {
    state.items = [{ ...payroll, launch_url }];
    show();
    fireEvent.click(await screen.findByRole("link", { name: "Open Payroll" }));
    await screen.findByText(/Could not open the application in a new tab/);
    expect(window.open).not.toHaveBeenCalled();
    expect(api.POST).not.toHaveBeenCalled();
  });
  it("automatically consumes valid child intent once and redeems in that same tab under StrictMode", async () => {
    seedCatalogIntent();
    const navigate = captureChildNavigation();
    const pending = deferredLaunch();
    render(<StrictMode><MemoryRouter initialEntries={[automaticLaunchPath]}><AuthProvider><OrgProvider><AppAccessLaunch /></OrgProvider></AuthProvider></MemoryRouter></StrictMode>);
    await waitFor(() => expect(api.POST).toHaveBeenCalledTimes(1));
    expect(api.POST).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/app-access/my-apps/{appId}/launch", { params: { path: { orgId, appId } }, body: { nonce_hash: "a".repeat(64), relative_target: "/" } });
    expect(window.sessionStorage.getItem(catalogIntentKey)).toBeNull();
    expect(window.open).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "Continue to application" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Opening application…" })).toBeNull();
    expect(screen.getByRole("status")).toHaveProperty("textContent", "Opening application…");
    await act(async () => pending.resolve({ data: { redirect_url: redeemURL } }));
    expect(navigate).toHaveBeenCalledExactlyOnceWith(redeemURL);
    expect(api.POST).toHaveBeenCalledTimes(1);
  });
  it("does not create a child or intent from a framed catalog", async () => {
    Object.defineProperty(window, "top", { configurable: true, value: {} });
    state.items = [payroll];
    show();
    fireEvent.click(await screen.findByRole("link", { name: "Open Payroll" }));
    await screen.findByText(/Open My Applications in its own browser tab/);
    expect(window.open).not.toHaveBeenCalled();
    expect(api.POST).not.toHaveBeenCalled();
    expect(window.sessionStorage.getItem(catalogIntentKey)).toBeNull();
  });
  it("does not consume catalog intent or automatically launch inside a frame", async () => {
    seedCatalogIntent();
    Object.defineProperty(window, "top", { configurable: true, value: {} });
    show(automaticLaunchPath);
    await screen.findByText(/Open this application from a full browser tab/);
    expect(api.POST).not.toHaveBeenCalled();
    expect(window.open).not.toHaveBeenCalled();
    expect(window.sessionStorage.getItem(catalogIntentKey)).not.toBeNull();
    expect(screen.queryByRole("button", { name: "Continue to application" })).toBeNull();
  });
  it.each([
    { userId: "another-user" }, { orgId: "other-org" }, { appId: "other-app" },
    { target: "/reports" }, { version: 2 }, { origin: "http://payroll.apps.example.net" },
    { createdAt: 0 }, { createdAt: Number.MAX_SAFE_INTEGER },
  ])("requires deliberate continuation for mismatched or expired intent: %j", async override => {
    seedCatalogIntent(override);
    show(automaticLaunchPath + "&auto=1");
    expect(await screen.findByRole("button", { name: "Continue to application" })).toBeTruthy();
    expect(window.sessionStorage.getItem(catalogIntentKey)).toBeNull();
    expect(api.POST).not.toHaveBeenCalled();
    expect(window.open).not.toHaveBeenCalled();
  });
  it("does not automatically launch an external callback with only a query flag", async () => {
    show(automaticLaunchPath + "&auto=1");
    await screen.findByRole("button", { name: "Continue to application" });
    expect(api.POST).not.toHaveBeenCalled();
    expect(window.open).not.toHaveBeenCalled();
  });
  it("does not issue a code for invalid or duplicated nonce parameters even with valid intent", async () => {
    seedCatalogIntent();
    show(automaticLaunchPath + "&nonce_hash=" + "b".repeat(64));
    await screen.findByText(/application link is invalid or unavailable/);
    expect(api.POST).not.toHaveBeenCalled();
    expect(window.sessionStorage.getItem(catalogIntentKey)).toBeNull();
  });
  it("refuses a redeem origin that differs from the trusted catalog origin", async () => {
    seedCatalogIntent();
    const navigate = captureChildNavigation();
    vi.mocked(api.POST).mockResolvedValueOnce({ data: { redirect_url: redeemURL.replace("payroll.apps.example.net", "different.apps.example.net") } } as never);
    show(automaticLaunchPath);
    await screen.findByText(/Could not complete application handoff/);
    expect(navigate).not.toHaveBeenCalled();
    expect(window.open).not.toHaveBeenCalled();
    expect(window.sessionStorage.getItem(catalogIntentKey)).toBeNull();
    expect(screen.queryByRole("button", { name: "Continue to application" })).toBeNull();
  });
  it("does not automatically retry a denied handoff after remount", async () => {
    seedCatalogIntent();
    const navigate = captureChildNavigation();
    const first = show(automaticLaunchPath);
    await screen.findByText("Application access denied");
    expect(api.POST).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("button", { name: "Continue to application" })).toBeNull();
    first.unmount();
    show(automaticLaunchPath);
    await screen.findByRole("button", { name: "Continue to application" });
    expect(api.POST).toHaveBeenCalledTimes(1);
    expect(navigate).not.toHaveBeenCalled();
  });
  it("ignores a late automatic handoff after the child launch page unmounts", async () => {
    seedCatalogIntent();
    const navigate = captureChildNavigation();
    const pending = deferredLaunch();
    const view = show(automaticLaunchPath);
    await waitFor(() => expect(api.POST).toHaveBeenCalledTimes(1));
    view.unmount();
    await act(async () => pending.resolve({ data: { redirect_url: redeemURL } }));
    expect(navigate).not.toHaveBeenCalled();
    expect(window.sessionStorage.getItem(catalogIntentKey)).toBeNull();
  });
  it("keeps failed catalog reads distinct from no explicit grants and retries", async () => {
    state.appsFailed = true; show();
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", "Catalog unavailable");
    expect(screen.queryByText(/No published applications/)).toBeNull();
    state.appsFailed = false; fireEvent.click(screen.getByRole("button", { name: "Retry applications" }));
    expect(await screen.findByText(/No published applications are granted/)).toBeTruthy();
  });
  it("retains domain-unavailable and session-read failure states", async () => {
    state.availability = "domain_unavailable"; state.sessionsFailed = true; show();
    expect(await screen.findByText(/setup is not complete/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "My sessions" }));
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", "Sessions unavailable");
    expect(screen.queryByText("No active application sessions.")).toBeNull();
  });
  it("revokes exactly one owned public session UUID and labels parent scope", async () => {
    state.sessions = [{ id: "session-1", app_id: appId, app_label: "Payroll", created_at: "2026-10-03T00:00:00Z", expires_at: "2026-10-04T00:00:00Z", current_parent: true }]; show("/app-access/my-applications?view=sessions");
    expect(await screen.findByText(/This login/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /^Sign out of Payroll · Session / }));
    expect(await screen.findByText("Application session access revoked.")).toBeTruthy();
    expect(api.DELETE).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/app-access/my-sessions/{sessionId}", { params: { path: { orgId, sessionId: "session-1" } } });
  });
  it("distinguishes sessions sharing a login and expiry and preserves the other session", async () => {
    const first = "b85d8296-0000-4000-8000-000000000001";
    const latest = "a871f771-0000-4000-8000-000000000002";
    state.sessions = [
      { id: first, app_id: appId, app_label: "Payroll", created_at: "2026-10-04T01:26:39Z", expires_at: "2026-10-04T12:00:00Z", current_parent: true },
      { id: latest, app_id: appId, app_label: "Payroll", created_at: "2026-10-04T01:30:24Z", expires_at: "2026-10-04T12:00:00Z", current_parent: true },
    ];
    show("/app-access/my-applications?view=sessions");
    const identifier = await screen.findByText(/Session a871f771/);
    expect(identifier.closest("p")?.textContent).toContain("Started");
    const selected = within(identifier.closest("li")!).getByRole("button", { name: "Sign out of Payroll · Session a871f771" });
    fireEvent.click(selected);
    await screen.findByText("Application session access revoked.");
    await waitFor(() => expect(screen.queryByText(/Session a871f771/)).toBeNull());
    expect(screen.getByText(/Session b85d8296/)).toBeTruthy();
    expect(api.DELETE).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/app-access/my-sessions/{sessionId}", { params: { path: { orgId, sessionId: latest } } });
  });
  it("does not report a failed session revocation as confirmed", async () => {
    state.revokeFailed = true;
    state.sessions = [{ id: "session-1", app_id: appId, app_label: "Payroll", created_at: "2026-10-03T00:00:00Z", expires_at: "2026-10-04T00:00:00Z", current_parent: false }]; show("/app-access/my-applications?view=sessions");
    fireEvent.click(await screen.findByRole("button", { name: /^Sign out of Payroll · Session / }));
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", "Revocation unavailable");
    expect(screen.queryByText("Application session access revoked.")).toBeNull();
  });
  it("requires a deliberate launch and posts only nonce hash plus safe relative target", async () => {
    show(`/app-access/launch?orgId=${orgId}&appId=${appId}&nonce_hash=${"a".repeat(64)}&target=%2Freports`);
    const button = await screen.findByRole("button", { name: "Continue to application" });
    expect(api.POST).not.toHaveBeenCalled(); fireEvent.click(button);
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", "Application access denied");
    expect(api.POST).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/app-access/my-apps/{appId}/launch", { params: { path: { orgId, appId } }, body: { nonce_hash: "a".repeat(64), relative_target: "/reports" } });
  });
  it("refuses duplicate nonce or external-target handoffs before issuing a code", async () => {
    show(`/app-access/launch?orgId=${orgId}&appId=${appId}&nonce_hash=${"a".repeat(64)}&nonce_hash=${"b".repeat(64)}&target=https%3A%2F%2Fevil.example`);
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("invalid or unavailable"));
    expect(screen.queryByRole("button", { name: "Continue to application" })).toBeNull(); expect(api.POST).not.toHaveBeenCalled();
  });
  it("loads sessions only after the secondary action and returns to the preserved catalog search", async () => {
    show("/app-access/my-applications?q=Payroll&page=2");
    await screen.findByText("No applications match your search.");
    expect(api.GET).not.toHaveBeenCalledWith(expect.stringContaining("/my-sessions"), expect.anything());
    fireEvent.click(screen.getByRole("button", { name: "My sessions" }));
    await screen.findByText("No active application sessions.");
    expect(screen.queryByLabelText("Search applications")).toBeNull();
    expect(screen.getByRole("heading", { name: "My sessions", level: 1 })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Back to My Applications" }));
    expect(await screen.findByLabelText("Search applications")).toHaveProperty("value", "Payroll");
    expect(screen.getByText("Page 2")).toBeTruthy();
    expect(screen.queryByRole("region", { name: "My application sessions" })).toBeNull();
  });
  it("retains retry and pagination in the secondary sessions view", async () => {
    state.sessionsFailed = true;
    show("/app-access/my-applications?view=sessions");
    await screen.findByText("Sessions unavailable");
    state.sessionsFailed = false;
    state.sessions = Array.from({ length: 20 }, (_, index) => ({ id: `session-${index}`, app_label: "Payroll", created_at: "2026-10-03T00:00:00Z", expires_at: "2026-10-04T00:00:00Z", current_parent: true }));
    fireEvent.click(screen.getByRole("button", { name: "Retry sessions" }));
    await screen.findAllByRole("button", { name: /^Sign out of Payroll/ });
    fireEvent.click(screen.getByRole("button", { name: "More sessions" }));
    await waitFor(() => expect(api.GET).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/app-access/my-sessions", { params: { path: { orgId }, query: { limit: 20, offset: 20 } } }));
    expect(api.GET).not.toHaveBeenCalledWith(expect.stringContaining("/my-apps"), expect.anything());
  });
  it("opens and detaches an empty tab during the click before requesting a code, then navigates only that tab", async () => {
    const tab = pendingWindow();
    vi.mocked(window.open).mockReturnValue(tab.window);
    const pending = deferredLaunch();
    show(launchPath);
    const portalLocation = window.location.href;
    fireEvent.click(await screen.findByRole("button", { name: "Continue to application" }));
    fireEvent.click(screen.getByRole("button", { name: "Opening application…" }));
    expect(window.open).toHaveBeenCalledTimes(1);
    expect(api.POST).toHaveBeenCalledTimes(1);
    expect(window.open).toHaveBeenCalledWith("about:blank", "_blank");
    expect(vi.mocked(window.open).mock.invocationCallOrder[0]).toBeLessThan(vi.mocked(api.POST).mock.invocationCallOrder[0]!);
    expect(tab.popup.opener).toBeNull();
    expect(tab.popup.document.querySelector('meta[name="referrer"]')?.getAttribute("content")).toBe("no-referrer");
    expect(tab.location.replace).not.toHaveBeenCalled();
    await act(async () => pending.resolve({ data: { redirect_url: redeemURL } }));
    expect(tab.location.replace).toHaveBeenCalledExactlyOnceWith(redeemURL);
    expect(window.location.href).toBe(portalLocation);
    expect(await screen.findByRole("status")).toHaveProperty("textContent", expect.stringContaining("Application opened in a new tab"));
    expect(screen.queryByRole("button", { name: "Continue to application" })).toBeNull();
    expect(screen.getByRole("link", { name: "Back to My Applications" })).toBeTruthy();
    cleanup();
    expect(tab.popup.close).not.toHaveBeenCalled();
    expect(api.POST).toHaveBeenCalledTimes(1);
  });
  it("does not issue a code when the browser blocks the tab and permits a fresh click", async () => {
    vi.mocked(window.open).mockReturnValueOnce(null);
    show(launchPath);
    fireEvent.click(await screen.findByRole("button", { name: "Continue to application" }));
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("browser blocked the new tab"));
    expect(api.POST).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Continue to application" }));
    await screen.findByText("Application access denied");
    expect(api.POST).toHaveBeenCalledTimes(1);
  });
  it("closes only its empty pending tab after access denial and does not retry the same handoff", async () => {
    const tab = pendingWindow();
    vi.mocked(window.open).mockReturnValue(tab.window);
    show(launchPath);
    fireEvent.click(await screen.findByRole("button", { name: "Continue to application" }));
    await screen.findByText("Application access denied");
    expect(tab.popup.close).toHaveBeenCalledTimes(1);
    expect(tab.location.replace).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "Continue to application" })).toBeNull();
  });
  it.each([
    "http://payroll.apps.example.net/__tunnex_app/redeem?code=" + "a".repeat(43),
    "https://payroll.apps.example.net:8443/__tunnex_app/redeem?code=" + "a".repeat(43),
    redeemURL + "&code=" + "b".repeat(43),
    "https://payroll.apps.example.net/other?code=" + "a".repeat(43),
  ])("refuses invalid returned handoffs and closes the pending tab: %s", async redirect_url => {
    const tab = pendingWindow();
    vi.mocked(window.open).mockReturnValue(tab.window);
    vi.mocked(api.POST).mockResolvedValueOnce({ data: { redirect_url } } as never);
    show(launchPath);
    fireEvent.click(await screen.findByRole("button", { name: "Continue to application" }));
    await screen.findByText(/Could not complete application handoff/);
    expect(tab.popup.close).toHaveBeenCalledTimes(1);
    expect(tab.location.replace).not.toHaveBeenCalled();
  });
  it("keeps the portal when a requested handoff fails at the network boundary", async () => {
    const tab = pendingWindow();
    vi.mocked(window.open).mockReturnValue(tab.window);
    vi.mocked(api.POST).mockRejectedValueOnce(new Error("network failure"));
    show(launchPath);
    fireEvent.click(await screen.findByRole("button", { name: "Continue to application" }));
    await screen.findByText(/Could not complete application handoff/);
    expect(tab.popup.close).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("button", { name: "Continue to application" })).toBeNull();
    expect(screen.getByRole("link", { name: "Back to My Applications" })).toBeTruthy();
  });
  it.each(["closed", "navigated"])("does not navigate or close a pending tab the user has %s", async disposition => {
    const tab = pendingWindow();
    vi.mocked(window.open).mockReturnValue(tab.window);
    const pending = deferredLaunch();
    show(launchPath);
    fireEvent.click(await screen.findByRole("button", { name: "Continue to application" }));
    if (disposition === "closed") tab.popup.closed = true;
    else tab.location.href = "https://unrelated.example.org/";
    await act(async () => pending.resolve({ data: { redirect_url: redeemURL } }));
    await screen.findByText(/Could not complete application handoff/);
    expect(tab.location.replace).not.toHaveBeenCalled();
    expect(tab.popup.close).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "Continue to application" })).toBeNull();
  });
  it("closes pending owned tabs on unmount and ignores a late handoff", async () => {
    const tab = pendingWindow();
    vi.mocked(window.open).mockReturnValue(tab.window);
    const pending = deferredLaunch();
    const view = show(launchPath);
    fireEvent.click(await screen.findByRole("button", { name: "Continue to application" }));
    view.unmount();
    expect(tab.popup.close).toHaveBeenCalledTimes(1);
    await act(async () => pending.resolve({ data: { redirect_url: redeemURL } }));
    expect(tab.location.replace).not.toHaveBeenCalled();
    expect(tab.popup.close).toHaveBeenCalledTimes(1);
  });
  it("rejects stale responses after a handoff query changes without closing the new pending tab", async () => {
    const first = pendingWindow();
    const second = pendingWindow();
    vi.mocked(window.open).mockReturnValueOnce(first.window).mockReturnValueOnce(second.window);
    const initial = deferredLaunch();
    function ChangeHandoff() {
      const navigate = useNavigate();
      return <button onClick={() => navigate(launchPath.replace("a".repeat(64), "b".repeat(64)))}>Change handoff</button>;
    }
    render(<MemoryRouter initialEntries={[launchPath]}><AuthProvider><OrgProvider><AppAccessLaunch /><ChangeHandoff /></OrgProvider></AuthProvider></MemoryRouter>);
    fireEvent.click(await screen.findByRole("button", { name: "Continue to application" }));
    fireEvent.click(screen.getByRole("button", { name: "Change handoff" }));
    expect(first.popup.close).toHaveBeenCalledTimes(1);
    const next = deferredLaunch();
    fireEvent.click(await screen.findByRole("button", { name: "Continue to application" }));
    await act(async () => initial.resolve({ data: { redirect_url: redeemURL } }));
    expect(first.location.replace).not.toHaveBeenCalled();
    expect(second.popup.close).not.toHaveBeenCalled();
    await act(async () => next.resolve({ data: { redirect_url: redeemURL } }));
    expect(second.location.replace).toHaveBeenCalledExactlyOnceWith(redeemURL);
  });
  it("closes the owned pending tab and ignores the issued handoff after the organization changes", async () => {
    const tab = pendingWindow();
    vi.mocked(window.open).mockReturnValue(tab.window);
    const pending = deferredLaunch();
    function ChangeOrganization() {
      const { setOrg } = useOrg();
      return <button onClick={() => setOrg("00000000-0000-4000-8000-000000000003")}>Change organization</button>;
    }
    render(<MemoryRouter initialEntries={[launchPath]}><AuthProvider><OrgProvider><AppAccessLaunch /><ChangeOrganization /></OrgProvider></AuthProvider></MemoryRouter>);
    fireEvent.click(await screen.findByRole("button", { name: "Continue to application" }));
    fireEvent.click(screen.getByRole("button", { name: "Change organization" }));
    expect(tab.popup.close).toHaveBeenCalledTimes(1);
    await act(async () => pending.resolve({ data: { redirect_url: redeemURL } }));
    expect(tab.location.replace).not.toHaveBeenCalled();
    expect(screen.queryByText(/Application opened in a new tab/)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Switch to Office" }));
    expect(await screen.findByText(/handoff has already been requested/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Continue to application" })).toBeNull();
    expect(window.open).toHaveBeenCalledTimes(1);
    expect(api.POST).toHaveBeenCalledTimes(1);
  });
});

function LogoutProbe() {
  const { state: auth, logout } = useAuth();
  return <><p>{auth.status}</p><button onClick={() => void logout()}>Sign out</button></>;
}
it("keeps an authenticated UI when authoritative logout fails", async () => {
  state.logoutFailed = true;
  render(<AuthProvider><LogoutProbe /></AuthProvider>);
  await screen.findByText("authed"); fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
  await waitFor(() => expect(api.POST).toHaveBeenCalled());
  expect(screen.getByText("authed")).toBeTruthy(); expect(screen.queryByText("anon")).toBeNull();
});
