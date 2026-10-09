import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import Beam, { BeamLaunch } from "../src/pages/Beam";
import { BeamPolicySettings } from "../src/components/BeamPolicySettings";
import { beamRoomsApi } from "../src/lib/beam-rooms";
import { beamApi, type BeamPolicy, type BeamShare } from "../src/lib/beam";

const identity = vi.hoisted(() => ({ org: "11111111-1111-4111-8111-111111111111", user: "22222222-2222-4222-8222-222222222222", preview: false }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: identity.org }, failed: false }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: identity.user, email_verified: true } } }) }));
vi.mock("../src/lib/api", () => ({ api: { GET: vi.fn(), POST: vi.fn() }, apiErrorMessage: (error: { error?: { message: string } } | undefined, fallback: string) => error?.error?.message ?? fallback, apiErrorCode: (error: { error?: { code: string } } | undefined) => error?.error?.code, loadOne: async (call: () => Promise<{ data?: unknown; error?: unknown }>) => { try { const result = await call(); return result.data === undefined || result.error ? { ok: false, error: "Failed directory" } : { ok: true, data: result.data }; } catch { return { ok: false, error: "Failed directory" }; } } }));
vi.mock("../src/lib/beam", async () => { const actual = await vi.importActual<typeof import("../src/lib/beam")>("../src/lib/beam"); return { ...actual, beamApi: Object.fromEntries(Object.keys(actual.beamApi).map(key => [key, vi.fn()])) }; });
vi.mock("../src/lib/beam-rooms", async () => { const actual = await vi.importActual<typeof import("../src/lib/beam-rooms")>("../src/lib/beam-rooms"); return { ...actual, beamRoomsApi: Object.fromEntries(Object.keys(actual.beamRoomsApi).map(key => [key, vi.fn()])) }; });
vi.mock("../src/lib/beam-ui-fixtures", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/beam-ui-fixtures")>("../src/lib/beam-ui-fixtures");
  return { ...actual, beamUIFixtures: (orgId: string) => identity.preview && orgId === initialOrg ? [previewShare] : [], filterBeamUIFixtures: (orgId: string) => identity.preview && orgId === initialOrg ? [previewShare] : [] };
});
const shareId = "33333333-3333-4333-8333-333333333333";
const initialOrg = identity.org;
const policy: BeamPolicy = { version: 3, enabled: true, domain_ready: true, base_domain: "beam.example.net", max_duration_seconds: 86400, max_shares: 5, require_mfa: false, publisher_group_ids: ["group-1"], reviewer_user_ids: [identity.user], reviewer_group_ids: [], can_manage_policy: false, can_publish: true, protocol_version: 1, min_client_version: "0.1.7", capabilities: [] };
const share: BeamShare = { id: shareId, org_id: initialOrg, publisher_id: identity.user, name: "Design review", hostname: "p-1.beam.example.net", url: "https://p-1.beam.example.net/", state: "active", connectivity: "online", version: 8, authority_version: 2, expires_at: "2099-10-06T10:00:00Z", created_at: "2099-10-06T08:00:00Z", can_open: true, can_manage: true, grants: [{ subject_kind: "user", subject_id: identity.user }] };
const previewShare: BeamShare = { ...share, id: "01900000-0000-7000-8000-0000000fd001", name: "Local UI preview", hostname: "preview-1.beam.example.test", url: "https://preview-1.beam.example.test", can_open: false, can_manage: false, target: { protocol: "http", address: "127.0.0.1", port: 5173 } };
function show(path = "/beam/shared-with-me") { return render(<MemoryRouter initialEntries={[path]}><Routes><Route path="/beam/launch" element={<BeamLaunch />} /><Route path="/beam/shares/:shareId" element={<Beam />} /><Route path="*" element={<Beam />} /></Routes></MemoryRouter>); }
beforeEach(() => { vi.clearAllMocks(); identity.preview = false; vi.mocked(beamRoomsApi.feedback).mockResolvedValue({ ok: true, data: { items: [], limit: 20, offset: 0, server_time: "2026-10-06T11:00:00Z" } }); vi.mocked(beamRoomsApi.projects).mockResolvedValue({ ok: true, data: { items: [], limit: 20, offset: 0, server_time: "2026-10-06T11:00:00Z" } }); vi.mocked(beamRoomsApi.notifications).mockResolvedValue({ ok: true, data: { items: [], limit: 20, offset: 0, server_time: "2026-10-06T11:00:00Z" } }); vi.mocked(beamApi.shareEvents).mockResolvedValue({ ok: true, data: { items: [], limit: 20, offset: 0, server_time: "2026-10-06T11:00:00Z" } }); vi.mocked(beamApi.events).mockResolvedValue({ ok: true, data: { items: [], limit: 20, offset: 0, server_time: "2026-10-06T11:00:00Z" } }); vi.mocked(beamApi.diagnostics).mockResolvedValue({ ok: false, error: "Share diagnostics unavailable" }); vi.mocked(beamApi.policyImpact).mockResolvedValue({ ok: true, data: { policy_version: 3, active_share_count: 0, affected_share_count: 0, affected_reviewer_session_count: 0, requires_confirmation: false } }); identity.org = initialOrg; vi.mocked(beamApi.policy).mockResolvedValue({ ok: true, data: { ...policy, can_publish: false } }); vi.mocked(beamApi.shares).mockResolvedValue({ ok: true, data: { items: [share], limit: 20, offset: 0, server_time: "2026-10-06T11:00:00Z" } }); vi.mocked(beamApi.share).mockResolvedValue({ ok: true, data: share }); vi.mocked(beamApi.audience).mockResolvedValue({ ok: true, data: { users: [{ id: identity.user, name: "Reviewer", email: "r@example.com" }], groups: [] } }); });
beforeEach(() => { vi.stubEnv("DEV", true); vi.stubEnv("VITE_BEAM_UI_FIXTURES", "0"); });
afterEach(() => { cleanup(); vi.unstubAllEnvs(); });
describe("Beam open organization mode", () => {
 it("keeps publishing and reviewer workspaces available to the same member", async () => {
  vi.mocked(beamApi.policy).mockResolvedValue({ok:true,data:{...policy,open_for_all_users:true}});
  show();await screen.findByRole("link",{name:"Open Design review"});
  expect(screen.getByRole("link",{name:"My shares"})).toBeTruthy();
  expect(screen.getByRole("link",{name:"Shared with me"}).getAttribute("aria-current")).toBe("page");
 });
 it("lets admins enable open mode without replacing their saved restricted audience", async () => {
  const saved={...policy,can_manage_policy:true};
  vi.mocked(beamApi.policy).mockResolvedValue({ok:true,data:saved});
  vi.mocked(beamApi.audience).mockResolvedValue({ok:true,data:{users:[{id:identity.user,name:"Reviewer",email:"r@example.com"}],groups:[{id:"group-1",name:"Developers"}]}});
  vi.mocked(beamApi.savePolicy).mockResolvedValue({ok:true,data:{...saved,open_for_all_users:true,version:4}});
  render(<MemoryRouter><BeamPolicySettings orgId={initialOrg} canEdit/></MemoryRouter>);
  const toggle=await screen.findByRole("checkbox",{name:/Open for all users/});fireEvent.click(toggle);
  expect(screen.queryByRole("group",{name:"Publisher groups"})).toBeNull();
  expect(screen.queryByRole("group",{name:"Permitted reviewers"})).toBeNull();
  fireEvent.click(screen.getByRole("button",{name:"Review policy changes"}));
  await screen.findByText("Open for all users in this organization");
  fireEvent.click(screen.getByRole("button",{name:"Confirm sharing policy"}));
  await screen.findByText(/Sharing policy saved/);
  expect(beamApi.savePolicy).toHaveBeenCalledWith(initialOrg,expect.objectContaining({open_for_all_users:true,publisher_group_ids:saved.publisher_group_ids,reviewer_user_ids:saved.reviewer_user_ids,version:3}),false);
 });
 it("restores restricted audience controls when the admin switches open mode off", async () => {
  vi.mocked(beamApi.policy).mockResolvedValue({ok:true,data:{...policy,can_manage_policy:true,open_for_all_users:true}});
  vi.mocked(beamApi.audience).mockResolvedValue({ok:true,data:{users:[{id:identity.user,name:"Reviewer",email:"r@example.com"}],groups:[{id:"group-1",name:"Developers"}]}});
  render(<MemoryRouter><BeamPolicySettings orgId={initialOrg} canEdit/></MemoryRouter>);
  fireEvent.click(await screen.findByRole("checkbox",{name:/Open for all users/}));
  expect((screen.getByRole("checkbox",{name:"Developers"}) as HTMLInputElement).checked).toBe(true);
  expect((screen.getByRole("checkbox",{name:/Reviewer/}) as HTMLInputElement).checked).toBe(true);
 });
});
describe("Beam reviewer inventory", () => {
  it("shows active and paused shares while omitting ended cards and terminal state filters", async () => {
    const items = [share, { ...share, id: "paused", name: "Paused review", state: "paused" as const, can_open: false }, ...(["stopped", "expired", "revoked"] as const).map(state => ({ ...share, id: state, name: `${state} review`, state, can_open: false })), { ...share, id: "elapsed", name: "Elapsed review", expires_at: "2026-10-06T10:00:00Z" }];
    vi.mocked(beamApi.shares).mockResolvedValue({ ok: true, data: { items, limit: 20, offset: 0, server_time: "2026-10-06T11:00:00Z" } });
    show(); await screen.findByRole("link", { name: "Open Design review" });
    expect(screen.getByText("Paused review")).toBeTruthy();
    for (const name of ["stopped review", "expired review", "revoked review", "Elapsed review"]) expect(screen.queryByText(name)).toBeNull();
    expect(screen.queryByLabelText("Share state")).toBeNull();
  });
  it("keeps ended shares in the publisher's own history", async () => {
    vi.mocked(beamApi.policy).mockResolvedValue({ ok: true, data: policy });
    vi.mocked(beamApi.shares).mockResolvedValue({ ok: true, data: { items: [{ ...share, state: "stopped", can_open: false }], limit: 20, offset: 0, server_time: "2026-10-06T11:00:00Z" } });
    show("/beam/my-shares"); await screen.findByRole("heading", { name: "No active shares" });
    expect(screen.queryByText("Stopped")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "History" }));
    await screen.findByText("Stopped");
    expect(beamApi.shares).toHaveBeenLastCalledWith(initialOrg, false, 0, undefined, { scope: "history" }, 20);
    expect(screen.getByRole("link", { name: "View Design review" })).toBeTruthy();
  });
});
describe("Beam role-focused navigation", () => {
  it("opens My shares for a publisher and offers the CLI workflow without a reviewer tab", async () => {
    vi.mocked(beamApi.policy).mockResolvedValue({ ok: true, data: policy }); show("/beam");
    await screen.findByRole("button", { name: "Share a local app" });
    expect(screen.getByRole("link", { name: "My shares" }).getAttribute("aria-current")).toBe("page");
    expect(screen.queryByRole("link", { name: "Shared with me" })).toBeNull();
    expect(beamApi.audience).not.toHaveBeenCalled();
  });
  it("keeps a consumer in Shared with me without publisher tabs or command generation", async () => {
    vi.mocked(beamApi.shares).mockResolvedValue({ ok: true, data: { items: [], limit: 20, offset: 0, server_time: "2026-10-06T11:00:00Z" } }); show("/beam/my-shares");
    await screen.findByText("No apps are currently shared with you.");
    expect(screen.getByRole("link", { name: "Shared with me" }).getAttribute("aria-current")).toBe("page");
    expect(screen.queryByRole("link", { name: "My shares" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Share a local app" })).toBeNull();
  });
  it("preserves a former publisher's owned history after delegation is removed", async () => {
    show("/beam/my-shares"); await screen.findByRole("link", { name: "Manage Design review" });
    expect(screen.getByRole("link", { name: "My shares" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Share a local app" })).toBeNull();
  });
  it("preserves saved projects for a former publisher even before their first session", async () => {
    vi.mocked(beamApi.shares).mockResolvedValue({ ok: true, data: { items: [], limit: 20, offset: 0, server_time: "2026-10-06T11:00:00Z" } });
    vi.mocked(beamRoomsApi.projects).mockResolvedValue({ ok: true, data: { items: [{ id: "44444444-4444-4444-8444-444444444444", org_id: initialOrg, owner_id: identity.user, name: "Saved checkout", target: { protocol: "http", address: "127.0.0.1", port: 3000 }, grants: [], duration_seconds: 1800, version: 1, created_at: "2026-10-06T08:00:00Z", updated_at: "2026-10-06T08:00:00Z" }], limit: 20, offset: 0, server_time: "2026-10-06T11:00:00Z" } });
    vi.mocked(beamRoomsApi.sessions).mockResolvedValue({ ok: true, data: { items: [], limit: 20, offset: 0, server_time: "2026-10-06T11:00:00Z" } });
    show("/beam/my-shares"); fireEvent.click(await screen.findByRole("button", { name: "Saved projects" }));
    await screen.findByRole("heading", { name: "Saved checkout" });
    expect(screen.queryByRole("button", { name: "Publish Saved checkout" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Actions for Saved checkout" }));
    expect(screen.getByRole("menuitem", { name: "Edit Saved checkout" })).toHaveProperty("disabled", true);
  });
  it("does not treat failed owner-history lookup as an empty inventory", async () => {
    vi.mocked(beamApi.shares).mockResolvedValue({ ok: false, error: "Inventory unavailable" }); show("/beam/my-shares");
    await screen.findByText("Could not check your share history."); expect(screen.queryByText("No apps are currently shared with you.")).toBeNull();
  });
  it("brands even an invalid launch link without attempting app admission", async () => {
    show("/beam/launch"); expect(screen.getByRole("img", { name: "tunnex" })).toBeTruthy();
    expect(screen.getByText("This sharing link is invalid. Reopen the original shared URL.")).toBeTruthy(); expect(beamApi.launch).not.toHaveBeenCalled();
  });
});
describe("Beam console authority", () => {
  it("loads only organization-scoped permitted reviewer inventory without exposing owner controls", async () => { show(); await screen.findByRole("link", { name: "Open Design review" }); expect(beamApi.shares).toHaveBeenCalledWith(initialOrg, true, 0, undefined, {}, 20); expect(screen.queryByRole("button", { name: "Pause share" })).toBeNull(); expect(screen.queryByRole("link", { name: "Sharing policy" })).toBeNull(); expect(beamApi.audience).not.toHaveBeenCalled(); });
  it("distinguishes failed inventory reads from an empty permitted inventory", async () => { vi.mocked(beamApi.shares).mockResolvedValue({ ok: false, error: "Current access could not be checked" }); show(); await screen.findByText("Current access could not be checked"); expect(screen.queryByText("No apps are currently shared with you.")).toBeNull(); expect(screen.queryByRole("link", { name: "Open Design review" })).toBeNull(); });
  it.each([{ state: "paused" }, { connectivity: "offline" }, { can_open: false }, { expires_at: "2000-01-01T00:00:00Z" }])("withholds app launch for current denied or unavailable projection %o", async patch => { vi.mocked(beamApi.shares).mockResolvedValue({ ok: true, data: { items: [{ ...share, ...patch } as BeamShare], limit: 20, offset: 0, server_time: "2026-10-06T11:00:00Z" } }); show(); if (patch.expires_at) await screen.findByText("No apps are currently shared with you."); else await screen.findByRole("heading", { name: "Design review" }); expect(screen.queryByRole("link", { name: "Open Design review" })).toBeNull(); });
  it("requires explicit Stop confirmation and sends the exact saved version", async () => { vi.mocked(beamApi.action).mockResolvedValue({ ok: true, data: { ...share, state: "stopped", version: 9 } }); show(`/beam/shares/${shareId}`); fireEvent.click(await screen.findByRole("button", { name: "Stop share" })); expect(beamApi.action).not.toHaveBeenCalled(); fireEvent.click(screen.getByRole("button", { name: "Confirm stop" })); await screen.findByText("Share stopped permanently."); expect(beamApi.action).toHaveBeenCalledWith(initialOrg, share, "stop"); expect(screen.queryByRole("button", { name: "Resume share" })).toBeNull(); });
  it("keeps Stop available after serving setup is withdrawn while refusing Resume", async () => { vi.mocked(beamApi.policy).mockResolvedValue({ ok: true, data: { ...policy, domain_ready: false } }); vi.mocked(beamApi.share).mockResolvedValue({ ok: true, data: { ...share, state: "paused" } }); show(`/beam/shares/${shareId}`); const stop = await screen.findByRole("button", { name: "Stop share" }); expect((stop as HTMLButtonElement).disabled).toBe(false); expect((screen.getByRole("button", { name: "Resume share" }) as HTMLButtonElement).disabled).toBe(true); });
  it("returns focus to the lifecycle trigger when Stop confirmation is cancelled", async () => { show(`/beam/shares/${shareId}`); const stop = await screen.findByRole("button", { name: "Stop share" }); stop.focus(); fireEvent.click(stop); const dialog = await screen.findByRole("dialog", { name: "Stop this share" }); expect(dialog).toBeTruthy(); fireEvent.click(screen.getByRole("button", { name: "Keep sharing" })); await waitFor(() => expect(screen.queryByRole("dialog", { name: "Stop this share" })).toBeNull()); expect(document.activeElement).toBe(stop); expect(beamApi.action).not.toHaveBeenCalled(); });
  it("keeps an uncertain versioned change from allowing another mutation", async () => { vi.mocked(beamApi.action).mockResolvedValue({ ok: false, code: "beam_changed", error: "Share changed" }); show(`/beam/shares/${shareId}`); fireEvent.click(await screen.findByRole("button", { name: "Pause share" })); await screen.findByText(/Share changed.*Refresh the share/); expect((screen.getByRole("button", { name: "Pause share" }) as HTMLButtonElement).disabled).toBe(true); expect(screen.queryByText("Share paused. Reviewer access is ending.")).toBeNull(); });
  it("does not fetch reviewer directory or show management for non-owner content access", async () => { vi.mocked(beamApi.share).mockResolvedValue({ ok: true, data: { ...share, can_manage: false, grants: undefined } }); show(`/beam/shares/${shareId}`); await screen.findByText("You do not have permission to manage this share."); expect(beamApi.audience).not.toHaveBeenCalled(); expect(screen.queryByRole("button", { name: "Review reviewer access" })).toBeNull(); });
  it("discards a previous organization's delayed policy response", async () => { let resolve!: (value: { ok: true; data: BeamPolicy }) => void; vi.mocked(beamApi.policy).mockImplementationOnce(() => new Promise(done => { resolve = done; })); const rendered = show(); identity.org = "44444444-4444-4444-8444-444444444444"; rendered.rerender(<MemoryRouter initialEntries={["/beam/shared-with-me"]}><Beam /></MemoryRouter>); await screen.findByRole("link", { name: "Open Design review" }); resolve({ ok: true, data: { ...policy, can_manage_policy: true } }); await waitFor(() => expect(screen.queryByRole("link", { name: "Sharing policy" })).toBeNull()); });
  it("ends owner launch and lifecycle controls at expiry without navigation", async () => {
    vi.useFakeTimers();
    try {
      vi.mocked(beamApi.share).mockResolvedValue({ ok: true, data: { ...share, expires_at: new Date(Date.now() + 1500).toISOString() } });
      await act(async () => { show(`/beam/shares/${shareId}`); });
      expect(screen.getByRole("link", { name: "Open Design review" })).toBeTruthy();
      await act(async () => { await vi.advanceTimersByTimeAsync(2000); });
      expect(screen.queryByRole("link", { name: "Open Design review" })).toBeNull();
      expect(screen.queryByRole("button", { name: "Stop share" })).toBeNull();
      expect(screen.getByText(/This share has ended/)).toBeTruthy();
    } finally { cleanup(); vi.useRealTimers(); }
  });
  it("preserves reviewer edits and requires refresh when a newer server version is observed", async () => {
    vi.useFakeTimers();
    try {
      await act(async () => { show(`/beam/shares/${shareId}`); });
      fireEvent.click(screen.getByRole("checkbox", { name: /Reviewer/ }));
      vi.mocked(beamApi.share).mockResolvedValue({ ok: true, data: { ...share, version: 9, state: "paused", can_open: false } });
      await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
      expect(screen.getByText(/This share changed on the server/)).toBeTruthy();
      expect((screen.getByRole("checkbox", { name: /Reviewer/ }) as HTMLInputElement).checked).toBe(false);
      expect((screen.getByRole("button", { name: "Review reviewer access" }) as HTMLButtonElement).disabled).toBe(true);
      expect(screen.queryByRole("link", { name: "Open Design review" })).toBeNull();
      expect(beamApi.grants).not.toHaveBeenCalled();
    } finally { cleanup(); vi.useRealTimers(); }
  });
});
describe("Beam reviewer handoff", () => {
  const path = `/beam/launch?orgId=${initialOrg}&shareId=${shareId}&nonce_hash=${"a".repeat(64)}&target=%2F`;
  it("refuses invalid and cross-organization handoffs before any launch request", async () => { show(path.replace(initialOrg, "55555555-5555-4555-8555-555555555555")); await screen.findByText(/different organization/); expect(beamApi.launch).not.toHaveBeenCalled(); expect(beamApi.share).not.toHaveBeenCalled(); });
  it("recovers an expired mobile sign-in through a fresh browser-bound entry with the original app path", async () => {
    vi.mocked(beamApi.launch).mockResolvedValue({ ok: false, code: "beam_launch_expired", error: "This sign-in link expired or was already used. Open a fresh link to continue." });
    show(path.replace("target=%2F", "target=%2Fdesign%3Fmobile%3D1"));
    fireEvent.click(await screen.findByRole("button", { name: "Continue to Design review" }));
    const link = await screen.findByRole("link", { name: "Open fresh link" });
    expect(link.getAttribute("href")).toBe("https://p-1.beam.example.net/_beam/start?target=%2Fdesign%3Fmobile%3D1");
    expect(link.getAttribute("referrerpolicy")).toBe("no-referrer");
    expect(link.getAttribute("href")).not.toContain("nonce_hash");
    expect((screen.getByRole("button", { name: "Continue to Design review" }) as HTMLButtonElement).disabled).toBe(true);
    expect(beamApi.launch).toHaveBeenCalledTimes(1);
  });
  it("does not offer expiry recovery for a reviewer authority denial", async () => {
    vi.mocked(beamApi.launch).mockResolvedValue({ ok: false, code: "beam_authority_unavailable", error: "Beam authority is unavailable" });
    show(path); fireEvent.click(await screen.findByRole("button", { name: "Continue to Design review" }));
    await screen.findByText(/Beam authority is unavailable/);
    expect(screen.queryByRole("link", { name: "Open fresh link" })).toBeNull();
  });
  it("keeps nonce handoff explicit and rejects a foreign redirect returned by the server", async () => { vi.mocked(beamApi.launch).mockResolvedValue({ ok: true, data: { redirect_url: "https://attacker.example/", expires_at: share.expires_at } }); show(path); fireEvent.click(await screen.findByRole("button", { name: "Continue to Design review" })); await screen.findByText(/invalid sharing destination/); expect(beamApi.launch).toHaveBeenCalledWith(initialOrg, shareId, "a".repeat(64), "/"); expect((screen.getByRole("button", { name: "Continue to Design review" }) as HTMLButtonElement).disabled).toBe(true); });
});
describe("Beam policy editing", () => {
  it("renders the saved opt-in state and blocks a failed directory from becoming empty authority", async () => { vi.mocked(beamApi.policy).mockResolvedValue({ ok: true, data: { ...policy, enabled: false, can_manage_policy: true } }); vi.mocked(beamApi.audience).mockResolvedValue({ ok: false, error: "directory unavailable" }); render(<MemoryRouter><BeamPolicySettings orgId={initialOrg} canEdit /></MemoryRouter>); await screen.findByText(/Could not load the organization directory/); expect(screen.getByText("Local Sharing: Disabled")).toBeTruthy(); expect(screen.queryByRole("checkbox", { name: "Enable Local Sharing for this organization" })).toBeNull(); expect(screen.getByRole("button", { name: "Review policy changes" })).toHaveProperty("disabled", true); expect(beamApi.savePolicy).not.toHaveBeenCalled(); });
  it("explains operator attestation and refuses enablement while domain setup is incomplete", async () => { vi.mocked(beamApi.policy).mockResolvedValue({ ok: true, data: { ...policy, enabled: false, domain_ready: false, can_manage_policy: true } }); render(<MemoryRouter><BeamPolicySettings orgId={initialOrg} canEdit /></MemoryRouter>); await screen.findByText("Local Sharing: Disabled"); expect(screen.getByRole("link", { name: "Manage feature" }).getAttribute("href")).toBe("/settings?section=features&feature=local-sharing"); expect(screen.queryByRole("checkbox", { name: "Enable Local Sharing for this organization" })).toBeNull(); expect(screen.getByText(/this organization screen does not run DNS or certificate probes/)).toBeTruthy(); expect(screen.getByText(/Environment readiness assertions cannot bypass these checks/)).toBeTruthy(); expect(beamApi.savePolicy).not.toHaveBeenCalled(); });
  it("saves only current policy fields using its committed expected version", async () => { const managed = { ...policy, can_manage_policy: true }; vi.mocked(beamApi.policy).mockResolvedValue({ ok: true, data: managed }); vi.mocked(beamApi.audience).mockResolvedValue({ ok: true, data: { users: [{ id: identity.user, name: "Reviewer", email: "r@example.com" }], groups: [{ id: "group-1", name: "Developers" }] } }); vi.mocked(beamApi.savePolicy).mockResolvedValue({ ok: true, data: { ...managed, max_shares: 2, version: 4 } }); render(<MemoryRouter><BeamPolicySettings orgId={initialOrg} canEdit /></MemoryRouter>); fireEvent.change(await screen.findByRole("spinbutton", { name: "Shares per publisher" }), { target: { value: "2" } }); fireEvent.click(screen.getByRole("button", { name: "Review policy changes" })); fireEvent.click(await screen.findByRole("button", { name: "Confirm sharing policy" })); await screen.findByText(/Sharing policy saved/); expect(beamApi.savePolicy).toHaveBeenCalledWith(initialOrg, expect.objectContaining({ version: 3, enabled: policy.enabled, max_shares: 2 }), false); });
});

describe("Beam functional acceptance controls", () => {
  it("searches the scoped server inventory instead of filtering only a loaded page", async () => {
    show(); await screen.findByRole("heading", { name: share.name });
    vi.mocked(beamApi.shares).mockResolvedValue({ ok: true, data: { items: [], limit: 20, offset: 0, server_time: "2026-10-06T11:00:00Z" } });
    fireEvent.change(screen.getByRole("searchbox", { name: "Search shares" }), { target: { value: " unseen%_app " } });
    fireEvent.click(screen.getByRole("button", { name: "Search shares" }));
    await screen.findByText("No shares match this search.");
    expect(beamApi.shares).toHaveBeenLastCalledWith(initialOrg, true, 0, "unseen%_app", {}, 20);
    fireEvent.click(screen.getByRole("button", { name: "Clear share search" }));
    await waitFor(() => expect(beamApi.shares).toHaveBeenLastCalledWith(initialOrg, true, 0, undefined, {}, 20));
  });
  it("uses server time and elapsed time despite a workstation clock in the future", async () => {
    vi.useFakeTimers(); vi.setSystemTime("2099-01-01T00:00:00Z");
    try {
      vi.mocked(beamApi.shares).mockResolvedValue({ ok: true, data: { items: [{ ...share, expires_at: "2026-10-06T11:00:02Z" }], limit: 20, offset: 0, server_time: "2026-10-06T11:00:00Z" } });
      await act(async () => { show(); });
      expect(screen.getByRole("link", { name: "Open Design review" })).toBeTruthy();
      expect(screen.getByText("0m 2s remaining")).toBeTruthy();
      await act(async () => { await vi.advanceTimersByTimeAsync(2000); });
      expect(screen.queryByRole("link", { name: "Open Design review" })).toBeNull();
      expect(screen.getByText("No apps are currently shared with you.")).toBeTruthy();
    } finally { cleanup(); vi.useRealTimers(); }
  });
  it("does not expose owner history or diagnostic projections to a content-only reviewer", async () => {
    vi.mocked(beamApi.share).mockResolvedValue({ ok: true, data: { ...share, can_manage: false, grants: undefined } });
    show(`/beam/shares/${shareId}`); await screen.findByText("You do not have permission to manage this share.");
    expect(beamApi.shareEvents).not.toHaveBeenCalled(); expect(beamApi.diagnostics).not.toHaveBeenCalled();
    expect(screen.queryByText("Audience")).toBeNull();
  });
  it("requires checked impact and confirmation before removing the final reviewer grant", async () => {
    vi.mocked(beamApi.grantsImpact).mockResolvedValue({ ok: true, data: { share_version: 8, removed_grant_count: 1, affected_reviewer_count: 1, affected_reviewer_session_count: 2, requires_confirmation: true } });
    vi.mocked(beamApi.grants).mockResolvedValue({ ok: true, data: { ...share, version: 9, grants: [] } });
    show(`/beam/shares/${shareId}`); fireEvent.click(await screen.findByRole("checkbox", { name: /Reviewer/ }));
    fireEvent.click(screen.getByRole("button", { name: "Review reviewer access" }));
    await screen.findByRole("dialog", { name: "Review reviewer access" });
    expect(beamApi.grants).not.toHaveBeenCalled();
    expect((screen.getByRole("button", { name: "Confirm reviewer access" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole("checkbox", { name: "Confirm removal of these reviewer grants" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm reviewer access" }));
    await screen.findByText("Reviewer access saved.");
    expect(beamApi.grantsImpact).toHaveBeenCalledWith(initialOrg, share, []);
    expect(beamApi.grants).toHaveBeenCalledWith(initialOrg, share, [], true);
  });
  it("preserves reviewer edits when impact cannot be checked, without applying a grant mutation", async () => {
    vi.mocked(beamApi.grantsImpact).mockResolvedValue({ ok: false, error: "Impact unavailable" });
    show(`/beam/shares/${shareId}`); fireEvent.click(await screen.findByRole("checkbox", { name: /Reviewer/ }));
    fireEvent.click(screen.getByRole("button", { name: "Review reviewer access" })); await screen.findByText(/Impact unavailable.*not changed/);
    expect((screen.getByRole("checkbox", { name: /Reviewer/ }) as HTMLInputElement).checked).toBe(false);
    expect(beamApi.grants).not.toHaveBeenCalled();
  });
  it("requires impact confirmation before reducing organization policy", async () => {
    vi.mocked(beamApi.policy).mockResolvedValue({ ok: true, data: { ...policy, can_manage_policy: true } });
    vi.mocked(beamApi.policyImpact).mockResolvedValue({ ok: true, data: { policy_version: 3, active_share_count: 4, affected_share_count: 3, affected_reviewer_session_count: 6, requires_confirmation: true } });
    vi.mocked(beamApi.savePolicy).mockResolvedValue({ ok: true, data: { ...policy, version: 4, max_shares: 2 } });
    render(<MemoryRouter><BeamPolicySettings orgId={initialOrg} canEdit /></MemoryRouter>);
    fireEvent.change(await screen.findByRole("spinbutton", { name: "Shares per publisher" }), { target: { value: "2" } });
    fireEvent.click(screen.getByRole("button", { name: "Review policy changes" }));
    await screen.findByRole("dialog", { name: "Review sharing policy change" });
    expect(beamApi.savePolicy).not.toHaveBeenCalled();
    expect((screen.getByRole("button", { name: "Confirm sharing policy" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole("checkbox", { name: "End active shares affected by this policy change" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm sharing policy" }));
    await screen.findByText(/Sharing policy saved/);
    expect(beamApi.savePolicy).toHaveBeenCalledWith(initialOrg, expect.objectContaining({ version: 3, enabled: policy.enabled, max_shares: 2 }), true);
  });
  it("filters the owner share history without requiring organization audit rights", async () => {
    show(`/beam/shares/${shareId}`);
    fireEvent.click(await screen.findByText("Diagnostics & event history", { selector: "summary" }));
    await screen.findByRole("heading", { name: "Share history" });
    fireEvent.change(screen.getByRole("combobox", { name: "Event outcome" }), { target: { value: "denied" } });
    fireEvent.change(screen.getByRole("searchbox", { name: "Search events" }), { target: { value: "authority_unavailable" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply event filters" }));
    await waitFor(() => expect(beamApi.shareEvents).toHaveBeenLastCalledWith(initialOrg, shareId, 0, { outcome: "denied", q: "authority_unavailable" }, 20));
    expect(beamApi.events).not.toHaveBeenCalled();
  });
});
  it("applies health filters on the server and labels selected grants without guessing group size", async () => {
    show("/beam/my-shares"); await screen.findByText("1 selection");
    fireEvent.change(screen.getByRole("combobox", { name: "Share connectivity" }), { target: { value: "offline" } });
    fireEvent.click(screen.getByRole("button", { name: "Search shares" }));
    await waitFor(() => expect(beamApi.shares).toHaveBeenLastCalledWith(initialOrg, false, 0, undefined, { connectivity: "offline", scope: "active" }, 20));
  });
  it("shows exact-host Vite compatibility help to owners", async () => {
    show(`/beam/shares/${shareId}`); await screen.findByText("Web app compatibility help");
    const configuration = screen.getByLabelText("Vite configuration").textContent;
    expect(configuration).toContain(`allowedHosts: ["${share.hostname}"]`);
    expect(configuration).toContain('protocol: "wss"'); expect(configuration).toContain('clientPort: 443');
    expect(configuration).not.toContain("allowedHosts: true");
  });
  it("refreshes owner diagnostics and history when a changed server authority is observed", async () => {
    vi.useFakeTimers();
    try {
      await act(async () => { show(`/beam/shares/${shareId}`); });
      expect(beamApi.diagnostics).toHaveBeenCalledTimes(1);
      expect(beamApi.shareEvents).toHaveBeenCalledTimes(1);
      vi.mocked(beamApi.share).mockResolvedValue({ ok: true, data: { ...share, version: 9, authority_version: 3, state: "paused", can_open: false } });
      await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
      expect(beamApi.diagnostics).toHaveBeenCalledTimes(2);
      expect(beamApi.shareEvents).toHaveBeenCalledTimes(2);
      expect(screen.getByText(/This share changed on the server/)).toBeTruthy();
    } finally { cleanup(); vi.useRealTimers(); }
  });
  it("blocks an impact result for another policy version without saving or losing edits", async () => {
    vi.mocked(beamApi.policy).mockResolvedValue({ ok: true, data: { ...policy, can_manage_policy: true } });
    vi.mocked(beamApi.policyImpact).mockResolvedValue({ ok: true, data: { policy_version: 4, active_share_count: 0, affected_share_count: 0, affected_reviewer_session_count: 0, requires_confirmation: false } });
    render(<MemoryRouter><BeamPolicySettings orgId={initialOrg} canEdit /></MemoryRouter>);
    fireEvent.change(await screen.findByRole("spinbutton", { name: "Shares per publisher" }), { target: { value: "2" } });
    fireEvent.click(screen.getByRole("button", { name: "Review policy changes" }));
    await screen.findByText(/Sharing policy changed.*edits are still shown/);
    expect(screen.getByRole("spinbutton", { name: "Shares per publisher" })).toHaveProperty("value", "2");
    expect(screen.queryByRole("dialog")).toBeNull(); expect(beamApi.savePolicy).not.toHaveBeenCalled();
  });
  it("returns policy preview focus to the trigger disabled during asynchronous impact loading", async () => {
    vi.mocked(beamApi.policy).mockResolvedValue({ ok: true, data: { ...policy, can_manage_policy: true } });
    let complete!: (value: Awaited<ReturnType<typeof beamApi.policyImpact>>) => void;
    vi.mocked(beamApi.policyImpact).mockImplementationOnce(() => new Promise(resolve => { complete = resolve; }));
    render(<MemoryRouter><BeamPolicySettings orgId={initialOrg} canEdit /></MemoryRouter>);
    const review = await screen.findByRole("button", { name: "Review policy changes" }); review.focus(); fireEvent.click(review);
    expect((review as HTMLButtonElement).disabled).toBe(true); document.body.focus();
    await act(async () => { complete({ ok: true, data: { policy_version: 3, active_share_count: 0, affected_share_count: 0, affected_reviewer_session_count: 0, requires_confirmation: false } }); });
    fireEvent.click(screen.getByRole("button", { name: "Keep editing policy" }));
    await waitFor(() => expect(document.activeElement).toBe(review));
    expect(beamApi.savePolicy).not.toHaveBeenCalled();
  });
  it("blocks reviewer editing after a server version conflict during impact checking", async () => {
    vi.mocked(beamApi.grantsImpact).mockResolvedValue({ ok: false, code: "beam_version_conflict", error: "Share changed" });
    show(`/beam/shares/${shareId}`); const review = await screen.findByRole("button", { name: "Review reviewer access" });
    fireEvent.click(review); await screen.findByText(/Reviewer access was not changed.*Refresh before another change/);
    expect((review as HTMLButtonElement).disabled).toBe(true); expect(beamApi.grants).not.toHaveBeenCalled();
  });
  it("shows authoritative quota independently of a filtered empty owner inventory", async () => {
    vi.mocked(beamApi.shares).mockResolvedValue({ ok: true, data: { items: [], limit: 20, offset: 0, server_time: "2026-10-06T11:00:00Z", quota: { active_shares: 4, max_shares: 5 } } });
    show("/beam/my-shares"); await screen.findByText(/4 of 5 share slots in use/);
    fireEvent.change(screen.getByRole("searchbox", { name: "Search shares" }), { target: { value: "unmatched" } });
    fireEvent.click(screen.getByRole("button", { name: "Search shares" })); await screen.findByText("No shares match this search.");
    expect(screen.getByText(/4 of 5 share slots in use/)).toBeTruthy();
  });

describe("Minimal Local Sharing workspace", () => {
  it("pages the selected backend limit and resets the offset while retaining submitted search and health filters", async () => {
    vi.mocked(beamApi.policy).mockResolvedValue({ ok: true, data: policy });
    vi.mocked(beamApi.shares).mockImplementation(async (_org, _shared, offset = 0, _query, _filters, limit = 20) => ({ ok: true, data: { items: Array.from({ length: limit }, (_, index) => ({ ...share, id: `share-${offset + index}`, name: `Share ${offset + index}` })), limit, offset, server_time: "2026-10-06T11:00:00Z" } }));
    show("/beam/my-shares");
    await screen.findByRole("table", { name: "Active shares" });
    fireEvent.change(screen.getByRole("searchbox", { name: "Search shares" }), { target: { value: " design " } });
    fireEvent.change(screen.getByRole("combobox", { name: "Share connectivity" }), { target: { value: "offline" } });
    fireEvent.click(screen.getByRole("button", { name: "Search shares" }));
    await screen.findByRole("table", { name: "Active shares" });
    fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "10" } });
    await screen.findByRole("table", { name: "Active shares" });
    expect(beamApi.shares).toHaveBeenLastCalledWith(initialOrg, false, 0, "design", { connectivity: "offline", scope: "active" }, 10);
    expect(screen.getAllByRole("row")).toHaveLength(11);
    fireEvent.click(screen.getByRole("button", { name: "Next shares" }));
    await screen.findByRole("table", { name: "Active shares" });
    expect(beamApi.shares).toHaveBeenLastCalledWith(initialOrg, false, 10, "design", { connectivity: "offline", scope: "active" }, 10);
    fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "50" } });
    await screen.findByRole("table", { name: "Active shares" });
    expect(beamApi.shares).toHaveBeenLastCalledWith(initialOrg, false, 0, "design", { connectivity: "offline", scope: "active" }, 50);
    expect(screen.getAllByRole("row")).toHaveLength(51);
    expect(screen.getByRole("button", { name: "Previous shares" })).toHaveProperty("disabled", true);
    expect(beamApi.action).not.toHaveBeenCalled();
  });
  it("preserves next-page availability when current-authority filtering hides expired rows", async () => {
    const items = [share, ...Array.from({ length: 19 }, (_, index) => ({ ...share, id: `expired-${index}`, expires_at: "2000-01-01T00:00:00Z" }))];
    vi.mocked(beamApi.shares).mockResolvedValue({ ok: true, data: { items, limit: 20, offset: 0, server_time: "2026-10-06T11:00:00Z" } });
    show();
    await screen.findByRole("table", { name: "Apps shared with me" });
    expect(screen.getAllByRole("row")).toHaveLength(2);
    expect(screen.getByRole("button", { name: "Next shares" })).toHaveProperty("disabled", false);
    fireEvent.click(screen.getByRole("button", { name: "Next shares" }));
    await screen.findByRole("table", { name: "Apps shared with me" });
    expect(beamApi.shares).toHaveBeenLastCalledWith(initialOrg, true, 20, undefined, {}, 20);
  });
  it("keeps navigation when all rows in a full backend page are hidden by current authority", async () => {
    const items = Array.from({ length: 20 }, (_, index) => ({ ...share, id: `expired-${index}`, expires_at: "2000-01-01T00:00:00Z" }));
    vi.mocked(beamApi.shares).mockImplementation(async (_org, _shared, offset = 0) => ({ ok: true, data: { items: offset === 0 ? items : [], limit: 20, offset, server_time: "2026-10-06T11:00:00Z" } }));
    show();
    await screen.findByRole("heading", { name: "No apps are currently shared with you." });
    expect(screen.queryByRole("table", { name: "Apps shared with me" })).toBeNull();
    expect(screen.getByText("0 results")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Next shares" })).toHaveProperty("disabled", false);
    fireEvent.click(screen.getByRole("button", { name: "Next shares" }));
    await screen.findByText("Page 2");
    expect(beamApi.shares).toHaveBeenLastCalledWith(initialOrg, true, 20, undefined, {}, 20);
    await waitFor(() => expect(screen.getByRole("button", { name: "Next shares" })).toHaveProperty("disabled", true));
    expect(screen.getByRole("button", { name: "Previous shares" })).toHaveProperty("disabled", false);
    expect(beamApi.action).not.toHaveBeenCalled();
    expect(beamApi.launch).not.toHaveBeenCalled();
  });
  it("retains a way back from an empty later backend page", async () => {
    vi.mocked(beamApi.policy).mockResolvedValue({ ok: true, data: policy });
    vi.mocked(beamApi.shares).mockImplementation(async (_org, _shared, offset = 0) => ({ ok: true, data: { items: offset === 0 ? Array.from({ length: 20 }, (_, index) => ({ ...share, id: `share-${index}`, name: `Share ${index}` })) : [], limit: 20, offset, server_time: "2026-10-06T11:00:00Z" } }));
    show("/beam/my-shares");
    await screen.findByRole("link", { name: "Manage Share 0" });
    fireEvent.click(screen.getByRole("button", { name: "Next shares" }));
    await screen.findByRole("heading", { name: "No active shares" });
    expect(beamApi.shares).toHaveBeenLastCalledWith(initialOrg, false, 20, undefined, { scope: "active" }, 20);
    expect(screen.getByRole("navigation", { name: "Table pagination" })).toBeTruthy();
    expect(screen.getByText("Page 2")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Next shares" })).toHaveProperty("disabled", true);
    expect(screen.getByRole("button", { name: "Previous shares" })).toHaveProperty("disabled", false);
    fireEvent.click(screen.getByRole("button", { name: "Previous shares" }));
    await screen.findByRole("link", { name: "Manage Share 0" });
    expect(beamApi.shares).toHaveBeenLastCalledWith(initialOrg, false, 0, undefined, { scope: "active" }, 20);
    expect(screen.getByRole("button", { name: "Previous shares" })).toHaveProperty("disabled", true);
    expect(beamApi.action).not.toHaveBeenCalled();
    expect(beamApi.launch).not.toHaveBeenCalled();
  });
  it("keeps local fixtures separate from empty backend results and opens a read-only fixture without authority calls", async () => {
    identity.preview = true;
    vi.stubEnv("VITE_BEAM_UI_FIXTURES", "1");
    vi.mocked(beamApi.policy).mockResolvedValue({ ok: true, data: policy });
    vi.mocked(beamApi.shares).mockResolvedValue({ ok: true, data: { items: [], limit: 20, offset: 0, server_time: "2026-10-06T11:00:00Z" } });
    show("/beam/my-shares");
    await screen.findByText("No active shares", { selector: "p[role='status']" });
    expect(screen.queryByRole("table", { name: "Active shares" })).toBeNull();
    expect(screen.queryByRole("navigation", { name: "Table pagination" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Next shares" })).toBeNull();
    expect(screen.queryByRole("combobox", { name: "Rows per page" })).toBeNull();
    const previews = screen.getByRole("region", { name: "Local UI previews" });
    expect(within(previews).getByText("Read only · sample states")).toBeTruthy();
    const selectedSample = within(within(previews).getByRole("tablist", { name: "Sample shares" })).getByRole("tab", { selected: true });
    expect(selectedSample.textContent).toContain(previewShare.name);
    const samplePanel = within(previews).getByRole("tabpanel", { name: previewShare.name });
    expect(within(previews).queryByRole("link", { name: /Open/ })).toBeNull();
    expect(within(previews).queryByRole("button", { name: /Pause|Stop|Copy|Extend|Review reviewer/ })).toBeNull();
    const detail = within(samplePanel).getByRole("link", { name: "View fixture Local UI preview" });
    expect(detail.getAttribute("href")).toBe(`/beam/my-shares?sample=${previewShare.id}`);
    fireEvent.click(detail);
    await screen.findByText("Read-only sample. Nothing is published.");
    expect(screen.queryByRole("button", { name: /Pause|Stop|Copy|Extend|Review reviewer/ })).toBeNull();
    expect(beamApi.share).not.toHaveBeenCalled();
    expect(beamApi.audience).not.toHaveBeenCalled();
    expect(beamApi.diagnostics).not.toHaveBeenCalled();
    expect(beamApi.shareEvents).not.toHaveBeenCalled();
    expect(beamApi.action).not.toHaveBeenCalled();
    expect(beamApi.grants).not.toHaveBeenCalled();
    expect(beamApi.launch).not.toHaveBeenCalled();
  });
  it.each(["development without opt-in", "production with opt-in"])("withholds local samples in %s and keeps backend results authoritative", async mode => {
    identity.preview = true;
    vi.stubEnv("DEV", mode !== "production with opt-in");
    vi.stubEnv("VITE_BEAM_UI_FIXTURES", mode === "production with opt-in" ? "1" : "0");
    vi.mocked(beamApi.policy).mockResolvedValue({ ok: true, data: policy });
    vi.mocked(beamApi.shares).mockResolvedValue({ ok: true, data: { items: [], limit: 20, offset: 0, server_time: "2026-10-06T11:00:00Z" } });
    show(`/beam/my-shares?sample=${previewShare.id}`);
    await screen.findByText("No active shares");
    expect(screen.queryByRole("region", { name: "Local UI previews" })).toBeNull();
    expect(screen.queryByText("Read-only sample. Nothing is published.")).toBeNull();
    expect(screen.queryByRole("link", { name: "View fixture Local UI preview" })).toBeNull();
    expect(beamApi.shares).toHaveBeenCalledWith(initialOrg, false, 0, undefined, { scope: "active" }, 20);
    expect(beamApi.share).not.toHaveBeenCalled();
    expect(beamApi.action).not.toHaveBeenCalled();
    expect(beamApi.launch).not.toHaveBeenCalled();
  });
  it("never replaces a real share route with sample data even when its ID matches a local preview", async () => {
    identity.preview = true;
    vi.stubEnv("VITE_BEAM_UI_FIXTURES", "1");
    const backendShare = { ...share, id: previewShare.id, name: "Backend record", can_manage: false, can_open: false };
    vi.mocked(beamApi.share).mockResolvedValue({ ok: true, data: backendShare });
    show(`/beam/shares/${previewShare.id}?sample=${previewShare.id}`);
    await screen.findByRole("heading", { name: backendShare.name });
    expect(beamApi.share).toHaveBeenCalledWith(initialOrg, previewShare.id);
    expect(screen.queryByText("Read-only sample. Nothing is published.")).toBeNull();
    expect(screen.queryByRole("region", { name: "Local UI previews" })).toBeNull();
    expect(screen.queryByRole("link", { name: /Open Backend record/ })).toBeNull();
    expect(beamApi.action).not.toHaveBeenCalled();
    expect(beamApi.launch).not.toHaveBeenCalled();
  });
  it("submits a pending lifecycle action only once while keeping uncertain results visible", async () => {
    let resolve!: (value: Awaited<ReturnType<typeof beamApi.action>>) => void;
    vi.mocked(beamApi.action).mockImplementationOnce(() => new Promise(done => { resolve = done; }));
    show(`/beam/shares/${shareId}`);
    const pause = await screen.findByRole("button", { name: "Pause share" });
    fireEvent.click(pause); fireEvent.click(pause);
    expect(beamApi.action).toHaveBeenCalledTimes(1);
    expect(pause).toHaveProperty("disabled", true);
    await act(async () => { resolve({ ok: false, error: "Outcome unknown" }); });
    expect(screen.getByText(/Outcome unknown.*Refresh the share/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Pause share" })).toHaveProperty("disabled", true);
    expect(screen.getByRole("button", { name: "Refresh share" })).toHaveProperty("disabled", false);
    expect(beamApi.action).toHaveBeenCalledTimes(1);
  });
  it("consumes an explicit pending reviewer handoff only once", async () => {
    vi.mocked(beamApi.launch).mockImplementationOnce(() => new Promise(() => {}));
    show(`/beam/launch?orgId=${initialOrg}&shareId=${shareId}&nonce_hash=${"a".repeat(64)}&target=%2F`);
    const launch = await screen.findByRole("button", { name: "Continue to Design review" });
    fireEvent.click(launch); fireEvent.click(launch);
    expect(beamApi.launch).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("button", { name: "Opening…" })).toHaveProperty("disabled", true);
  });
});
