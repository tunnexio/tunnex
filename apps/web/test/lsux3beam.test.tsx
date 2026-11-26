import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import Beam, { BeamLaunch } from "../src/pages/Beam";
import { BeamFeedback, BeamNotifications } from "../src/components/BeamFeedback";
import { AudiencePicker, beamGroupDetail } from "../src/components/BeamAudiencePicker";
import { beamRoomsApi } from "../src/lib/beam-rooms";
import { api } from "../src/lib/api";
import { BEAM_SHARE_UNAVAILABLE, beamApi, type BeamPolicy, type BeamShare } from "../src/lib/beam";

// LS-UX-3: reviewer page polish. A policy MFA check is explained and offered inline, never shown
// as a red error; the share card actions are one button group.
const identity = vi.hoisted(() => ({ org: "11111111-1111-4111-8111-111111111111", user: "22222222-2222-4222-8222-222222222222" }));
const authValue = vi.hoisted(() => ({ state: { status: "authed", user: { id: "22222222-2222-4222-8222-222222222222", email: "rae@example.com", email_verified: true, recovery_codes_remaining: 2 } }, logout: async () => true }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: identity.org, name: "Acme" }, orgs: [{ id: identity.org, name: "Acme" }], setOrg: vi.fn(), failed: false }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => authValue, useOptionalAuth: () => authValue }));
vi.mock("../src/lib/api", () => ({ api: { GET: vi.fn(), POST: vi.fn() }, apiErrorMessage: (error: { error?: { message: string } } | undefined, fallback: string) => error?.error?.message ?? fallback, apiErrorCode: (error: { error?: { code: string } } | undefined) => error?.error?.code, loadOne: async () => ({ ok: false, error: "unused" }) }));
vi.mock("../src/lib/beam", async () => { const actual = await vi.importActual<typeof import("../src/lib/beam")>("../src/lib/beam"); return { ...actual, beamApi: Object.fromEntries(Object.keys(actual.beamApi).map(key => [key, vi.fn()])) }; });
vi.mock("../src/lib/beam-rooms", async () => { const actual = await vi.importActual<typeof import("../src/lib/beam-rooms")>("../src/lib/beam-rooms"); return { ...actual, beamRoomsApi: Object.fromEntries(Object.keys(actual.beamRoomsApi).map(key => [key, vi.fn()])) }; });

const shareId = "33333333-3333-4333-8333-333333333333";
const publisherId = "44444444-4444-4444-8444-444444444444";
const policy: BeamPolicy = { version: 3, enabled: true, domain_ready: true, base_domain: "beam.example.net", max_duration_seconds: 86400, max_shares: 5, require_mfa: true, publisher_group_ids: [], reviewer_user_ids: [identity.user], reviewer_group_ids: [], can_manage_policy: false, can_publish: false, protocol_version: 1, min_client_version: "0.1.7", capabilities: [] };
const reviewed: BeamShare = { id: shareId, org_id: identity.org, publisher_id: publisherId, publisher_name: "Pat Publisher", publisher_email: "pat@example.com", name: "Checkout preview", hostname: "p-1.beam.example.net", url: "https://p-1.beam.example.net/", state: "active", connectivity: "online", version: 8, authority_version: 2, expires_at: "2099-10-06T10:00:00Z", created_at: "2099-10-06T08:00:00Z", can_open: true, can_manage: false } as BeamShare;
const empty = { items: [], limit: 20, offset: 0, server_time: "2026-10-06T11:00:00Z" };
const mfaRefusal = { ok: false as const, code: "mfa_step_up_required", error: "Verify MFA to open this share" };
const PRIMARY = "bg-ink-heading";
const SECONDARY = "border-line";
function show(path: string) { return render(<MemoryRouter initialEntries={[path]}><Routes><Route path="/beam/launch" element={<BeamLaunch />} /><Route path="/beam/shares/:shareId" element={<Beam />} /><Route path="*" element={<Beam />} /></Routes></MemoryRouter>); }
async function verifyInline() {
  fireEvent.change(await screen.findByRole("textbox", { name: "Authenticator or recovery code" }), { target: { value: "123456" } });
  fireEvent.click(screen.getByRole("button", { name: "Verify and continue" }));
}
beforeEach(() => {
  vi.clearAllMocks();
  Element.prototype.scrollIntoView = vi.fn();
  vi.mocked(beamApi.policy).mockResolvedValue({ ok: true, data: policy });
  vi.mocked(beamApi.share).mockResolvedValue({ ok: true, data: reviewed });
  vi.mocked(beamApi.shares).mockResolvedValue({ ok: true, data: { ...empty, items: [reviewed] } });
  vi.mocked(beamApi.audience).mockResolvedValue({ ok: true, data: { users: [], groups: [] } });
  vi.mocked(beamApi.shareEvents).mockResolvedValue({ ok: true, data: empty });
  vi.mocked(beamApi.diagnostics).mockResolvedValue({ ok: false, error: "unused" });
  vi.mocked(beamRoomsApi.feedback).mockResolvedValue({ ok: true, data: empty });
  vi.mocked(beamRoomsApi.notifications).mockResolvedValue({ ok: true, data: empty });
  vi.mocked(beamRoomsApi.projects).mockResolvedValue({ ok: true, data: empty });
  vi.mocked(api.POST).mockResolvedValue({ data: { mfa_verified_at: "2026-10-06T11:00:00Z" } } as never);
});
afterEach(cleanup);

describe("LS-UX-3 review feedback behind the MFA policy", () => {
  it("explains the policy without red text and opens the form in place after inline MFA (U1)", async () => {
    vi.mocked(beamRoomsApi.feedback).mockResolvedValueOnce(mfaRefusal).mockResolvedValue({ ok: true, data: empty });
    render(<MemoryRouter><BeamFeedback orgId={identity.org} share={reviewed} viewer="reviewer" /></MemoryRouter>);
    await screen.findByText("Your organization requires a recent MFA check to read and send review feedback.");
    expect(screen.queryByText("Verify MFA to open this share")).toBeNull();
    expect(screen.queryByText(/Feedback can be added while/)).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Verify MFA" }));
    expect(await screen.findByText(/reused for up to 5 minutes/)).toBeTruthy();
    await verifyInline();
    await screen.findByRole("form", { name: "Send review feedback" });
    expect(api.POST).toHaveBeenCalledWith("/api/v1/auth/mfa/step-up", { body: { code: "123456" } });
    expect(beamRoomsApi.feedback).toHaveBeenCalledTimes(2);
    expect(screen.queryByText(/requires a recent MFA check/)).toBeNull();
  });
  it("returns to the Verify MFA button when the step-up is cancelled (U1)", async () => {
    vi.mocked(beamRoomsApi.feedback).mockResolvedValue(mfaRefusal);
    render(<MemoryRouter><BeamFeedback orgId={identity.org} share={reviewed} viewer="publisher" /></MemoryRouter>);
    fireEvent.click(await screen.findByRole("button", { name: "Verify MFA" }));
    fireEvent.click(await screen.findByRole("button", { name: "Cancel verification" }));
    expect(screen.getByRole("button", { name: "Verify MFA" })).toBeTruthy();
    expect(screen.queryByRole("textbox", { name: "Authenticator or recovery code" })).toBeNull();
  });
  it("keeps the draft when MFA lapses on send, verifies inline and sends it (U2)", async () => {
    vi.mocked(beamRoomsApi.addFeedback).mockResolvedValueOnce(mfaRefusal).mockResolvedValue({ ok: true, data: { id: "f2", share_id: shareId, author_id: identity.user, author_name: "Rae", body: "Looks good", status: "comment", created_at: "2026-10-06T10:01:00Z" } });
    render(<MemoryRouter><BeamFeedback orgId={identity.org} share={reviewed} viewer="reviewer" /></MemoryRouter>);
    await screen.findByRole("form", { name: "Send review feedback" });
    fireEvent.change(screen.getByRole("textbox", { name: "Your feedback" }), { target: { value: "Looks good" } });
    fireEvent.click(screen.getByRole("button", { name: "Send feedback" }));
    await screen.findByRole("textbox", { name: "Authenticator or recovery code" });
    expect((screen.getByRole("textbox", { name: "Your feedback" }) as HTMLTextAreaElement).value).toBe("Looks good");
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.queryByText(/Refresh feedback before submitting again/)).toBeNull();
    await verifyInline();
    await screen.findByText("Feedback sent. The publisher sees it on this page and in Sharing updates.");
    expect(beamRoomsApi.addFeedback).toHaveBeenCalledTimes(2);
    expect(vi.mocked(beamRoomsApi.addFeedback).mock.calls[1][2]).toMatchObject({ body: "Looks good", status: "comment" });
  });
});

describe("LS-UX-3 review screenshots behind the MFA policy", () => {
  const withShot = { id: "f1", share_id: shareId, author_id: publisherId, author_name: "Sam Reviewer", author_email: "sam@example.com", body: "Button overlaps", status: "changes_requested", created_at: "2026-10-06T10:00:00Z", screenshot_url: `/api/v1/organizations/${identity.org}/beam/shares/${shareId}/feedback/f1/screenshot` };
  beforeEach(() => {
    vi.mocked(beamRoomsApi.feedback).mockResolvedValue({ ok: true, data: { ...empty, items: [withShot] } } as never);
    URL.createObjectURL = vi.fn(() => "blob:http://localhost/shot-1"); URL.revokeObjectURL = vi.fn();
  });
  it("opens the screenshot in the console, verifies MFA inline and never links a new tab to the API (U11)", async () => {
    vi.mocked(beamRoomsApi.screenshot).mockResolvedValueOnce(mfaRefusal).mockResolvedValue({ ok: true, data: new Blob(["png"], { type: "image/png" }) });
    render(<MemoryRouter><BeamFeedback orgId={identity.org} share={reviewed} viewer="reviewer" /></MemoryRouter>);
    const view = await screen.findByRole("button", { name: "View screenshot from Sam Reviewer (sam@example.com)" });
    expect(document.querySelector('a[href*="/screenshot"]')).toBeNull();
    fireEvent.click(view);
    await screen.findByText("Your organization requires a recent MFA check to view review screenshots.");
    expect(screen.queryByText("Verify MFA to open this share")).toBeNull();
    await verifyInline();
    const image = await screen.findByRole("img", { name: "Screenshot from Sam Reviewer (sam@example.com)" });
    expect(image.getAttribute("src")).toBe("blob:http://localhost/shot-1");
    expect(beamRoomsApi.screenshot).toHaveBeenCalledTimes(2);
    expect(beamRoomsApi.screenshot).toHaveBeenLastCalledWith(identity.org, shareId, "f1");
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    await waitFor(() => expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:http://localhost/shot-1"));
  });
  it("shows a plain sentence when the screenshot is no longer available (U11)", async () => {
    vi.mocked(beamRoomsApi.screenshot).mockResolvedValue({ ok: false, code: "beam_share_not_found", error: "Share not found" });
    render(<MemoryRouter><BeamFeedback orgId={identity.org} share={reviewed} viewer="reviewer" /></MemoryRouter>);
    fireEvent.click(await screen.findByRole("button", { name: /View screenshot from/ }));
    await screen.findByText("This screenshot is no longer available to your account. Refresh feedback to check.");
    expect(screen.queryByText("Share not found")).toBeNull();
  });
});

describe("LS-UX-3 Sharing updates behind the MFA policy", () => {
  it("offers inline MFA instead of a red error and a Retry that cannot help (U3)", async () => {
    vi.mocked(beamRoomsApi.notifications).mockResolvedValueOnce(mfaRefusal).mockResolvedValue({ ok: true, data: empty });
    render(<MemoryRouter><BeamNotifications orgId={identity.org} /></MemoryRouter>);
    fireEvent.click(screen.getByRole("button", { name: "Sharing updates" }));
    await screen.findByText("Your organization requires a recent MFA check to show sharing updates.");
    expect(screen.queryByText("Verify MFA to open this share")).toBeNull();
    expect(screen.queryByRole("button", { name: "Retry sharing updates" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Verify MFA" }));
    await verifyInline();
    await screen.findByText("No sharing updates right now.");
  });
});

describe("LS-UX-3 open shared app behind the MFA policy", () => {
  it("says why a code is needed before the existing MFA step (U4)", async () => {
    vi.mocked(beamApi.launch).mockResolvedValue(mfaRefusal);
    show(`/beam/launch?orgId=${identity.org}&shareId=${shareId}&nonce_hash=${"a".repeat(64)}&target=%2F`);
    fireEvent.click(await screen.findByRole("button", { name: "Continue to Checkout preview" }));
    await screen.findByText("Your organization requires a recent MFA check before you open shared apps.");
    expect(screen.getByRole("button", { name: "Verify MFA" })).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });
});

describe("LS-UX-3 share card actions", () => {
  it("renders Open app as the primary button and the other actions as secondary buttons (U5)", async () => {
    show(`/beam/shares/${shareId}`);
    const open = await screen.findByRole("link", { name: "Open Checkout preview" });
    expect(open.className).toContain(PRIMARY);
    for (const name of ["Open on phone", "Copy link"]) expect(screen.getByRole("button", { name }).className).toContain(SECONDARY);
    const review = screen.getByRole("link", { name: "Review feedback" });
    expect(review.getAttribute("href")).toBe("#beam-review-feedback");
    expect(review.className).toContain(SECONDARY);
    expect(review.className).not.toContain("beam-inline-link");
  });
  it("moves focus to the feedback form from Review feedback (U5)", async () => {
    show(`/beam/shares/${shareId}`);
    await screen.findByRole("form", { name: "Send review feedback" });
    fireEvent.click(screen.getByRole("link", { name: "Review feedback" }));
    expect(document.activeElement).toBe(screen.getByRole("radio", { name: /Comment/ }));
    expect(Element.prototype.scrollIntoView).toHaveBeenCalled();
  });
  it("moves focus to Verify MFA from Review feedback when the policy check is pending (U5)", async () => {
    vi.mocked(beamRoomsApi.feedback).mockResolvedValue(mfaRefusal);
    show(`/beam/shares/${shareId}`);
    await screen.findByRole("button", { name: "Verify MFA" });
    fireEvent.click(screen.getByRole("link", { name: "Review feedback" }));
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Verify MFA" }));
  });
  it("keeps the compact Open app link in the list rows (U5)", async () => {
    show("/beam/shared-with-me");
    const open = await screen.findByRole("link", { name: "Open Checkout preview" });
    expect(open.className).toContain("beam-open-link");
    expect(open.className).not.toContain(PRIMARY);
  });
  it("makes Pause secondary and keeps Resume primary on the manage card (U6)", async () => {
    vi.mocked(beamApi.share).mockResolvedValue({ ok: true, data: { ...reviewed, publisher_id: identity.user, can_manage: true, grants: [] } });
    show(`/beam/shares/${shareId}`);
    expect((await screen.findByRole("button", { name: "Pause share" })).className).toContain(SECONDARY);
    expect(screen.getByRole("button", { name: "Pause share" }).className).not.toContain(PRIMARY);
    cleanup();
    vi.mocked(beamApi.share).mockResolvedValue({ ok: true, data: { ...reviewed, publisher_id: identity.user, can_manage: true, grants: [], state: "paused", can_open: false } });
    show(`/beam/shares/${shareId}`);
    expect((await screen.findByRole("button", { name: "Resume share" })).className).toContain(PRIMARY);
  });
});

describe("LS-UX-3 unavailable share is a status, not an error", () => {
  it("shows the uniform unavailable sentence neutrally on the share page (U7)", async () => {
    vi.mocked(beamApi.share).mockResolvedValue({ ok: false, code: "beam_share_not_found", error: "Share not found" });
    show(`/beam/shares/${shareId}`);
    const sentence = await screen.findByText(new RegExp(BEAM_SHARE_UNAVAILABLE.slice(0, 30).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    expect(sentence.getAttribute("role")).toBe("status");
    expect(screen.queryByRole("alert")).toBeNull();
  });
  it("shows the uniform unavailable sentence neutrally on the open page (U7)", async () => {
    vi.mocked(beamApi.share).mockResolvedValue({ ok: false, code: "beam_share_not_found", error: "Share not found" });
    show(`/beam/launch?orgId=${identity.org}&shareId=${shareId}&nonce_hash=${"a".repeat(64)}&target=%2F`);
    const sentence = await screen.findByText(`${BEAM_SHARE_UNAVAILABLE} You're signed in as rae@example.com.`);
    expect(sentence.getAttribute("role")).toBe("status");
    expect(screen.queryByRole("alert")).toBeNull();
    await waitFor(() => expect(screen.getByRole("button", { name: "Check again" })).toBeTruthy());
  });
});

describe("LS-UX-3 reviewer group sizes", () => {
  it("shows how many current members each reviewer group has, and only the word Group from older servers (U12)", async () => {
    expect(beamGroupDetail(3)).toBe("Group · 3 members");
    expect(beamGroupDetail(1)).toBe("Group · 1 member");
    expect(beamGroupDetail(0)).toBe("Group · 0 members");
    expect(beamGroupDetail(undefined)).toBe("Group");
    render(<AudiencePicker audience={{ users: [], groups: [{ id: "g1", name: "Developers", member_count: 4 }, { id: "g2", name: "Design" }] }} grants={[]} onChange={() => undefined} disabled={false} />);
    expect(screen.getByText("Group · 4 members")).toBeTruthy();
    expect(screen.getByText("Group")).toBeTruthy();
  });
});
