import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import Beam, { BeamLaunch } from "../src/pages/Beam";
import { BeamFeedback, BeamNotifications } from "../src/components/BeamFeedback";
import { BeamPolicySettings } from "../src/components/BeamPolicySettings";
import { BeamCompatibilityHelp } from "../src/components/BeamCompatibilityHelp";
import { BeamAccessEvidence } from "../src/components/BeamAccessEvidence";
import { BeamRooms } from "../src/components/BeamRooms";
import { BeamCliPublisher } from "../src/components/BeamCliPublisher";
import { InlineTerminalMfa } from "../src/components/InlineTerminalMfa";
import { beamRoomsApi, type BeamFeedback as Feedback, type BeamProject } from "../src/lib/beam-rooms";
import { api } from "../src/lib/api";
import { announceMfaVerified, onMfaVerified } from "../src/lib/mfa-events";
import { beamApi, beamCount, beamDuration, beamReviewerCount, beamReviewerSummary, type BeamAudience, type BeamPolicy, type BeamShare } from "../src/lib/beam";

// LS-UX-4: publisher and admin polish (docs/LS-UX-4-publisher-polish.md).
const identity = vi.hoisted(() => ({ org: "11111111-1111-4111-8111-111111111111", user: "22222222-2222-4222-8222-222222222222" }));
const authValue = vi.hoisted(() => ({ state: { status: "authed", user: { id: "22222222-2222-4222-8222-222222222222", email: "pat@tunnex.io", email_verified: true, cp_admin: false, recovery_codes_remaining: 2 } }, logout: async () => true }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: identity.org, name: "Acme" }, orgs: [{ id: identity.org, name: "Acme" }], setOrg: vi.fn(), failed: false }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => authValue, useOptionalAuth: () => authValue }));
vi.mock("../src/lib/api", () => ({ api: { GET: vi.fn(), POST: vi.fn() }, apiErrorMessage: (error: { error?: { message: string } } | undefined, fallback: string) => error?.error?.message ?? fallback, apiErrorCode: (error: { error?: { code: string } } | undefined) => error?.error?.code, loadOne: async () => ({ ok: false, error: "unused" }) }));
vi.mock("../src/lib/beam", async () => { const actual = await vi.importActual<typeof import("../src/lib/beam")>("../src/lib/beam"); return { ...actual, beamApi: Object.fromEntries(Object.keys(actual.beamApi).map(key => [key, vi.fn()])) }; });
vi.mock("../src/lib/beam-rooms", async () => { const actual = await vi.importActual<typeof import("../src/lib/beam-rooms")>("../src/lib/beam-rooms"); return { ...actual, beamRoomsApi: Object.fromEntries(Object.keys(actual.beamRoomsApi).map(key => [key, vi.fn()])) }; });

const shareId = "33333333-3333-4333-8333-333333333333";
const reviewerId = "44444444-4444-4444-8444-444444444444";
const groupId = "55555555-5555-4555-8555-555555555555";
const self = { subject_kind: "user" as const, subject_id: identity.user };
const reviewerGrant = { subject_kind: "user" as const, subject_id: reviewerId };
const groupGrant = { subject_kind: "group" as const, subject_id: groupId };
const audience: BeamAudience = { users: [{ id: identity.user, name: "Pat Publisher", email: "pat@tunnex.io" }, { id: reviewerId, name: "reviewer", email: "reviewer@tunnex.io" }], groups: [{ id: groupId, name: "Developers", member_count: 1 }] };
// The publisher is also the organization admin, as in the v0.1.51 walk.
const policy: BeamPolicy = { version: 3, enabled: true, domain_ready: true, base_domain: "beam.example.net", max_duration_seconds: 3600, max_shares: 5, require_mfa: true, publisher_group_ids: [], reviewer_user_ids: [], reviewer_group_ids: [], open_for_all_users: true, can_manage_policy: true, can_publish: true, protocol_version: 1, min_client_version: "0.1.7", capabilities: [] };
// Created 08:00, expiring 09:00: already at a 1-hour maximum.
const owned: BeamShare = { id: shareId, org_id: identity.org, publisher_id: identity.user, publisher_name: "Pat Publisher", publisher_email: "pat@tunnex.io", name: "Checkout preview", hostname: "p-1.beam.example.net", url: "https://p-1.beam.example.net/", state: "active", connectivity: "online", version: 8, authority_version: 2, created_at: "2099-10-06T08:00:00Z", expires_at: "2099-10-06T09:00:00Z", can_open: true, can_manage: true, grants: [self, reviewerGrant, groupGrant] } as BeamShare;
const empty = { items: [], limit: 20, offset: 0, server_time: "2026-10-06T11:00:00Z" };
const mfaRefusal = { ok: false as const, code: "mfa_step_up_required", error: "Verify MFA to open this share" };
const fromReviewer = (id: string, status: Feedback["status"], body: string): Feedback => ({ id, share_id: shareId, author_id: reviewerId, author_name: "reviewer", author_email: "reviewer@tunnex.io", body, status, created_at: "2026-10-06T10:00:00Z" });
function show(path: string) { return render(<MemoryRouter initialEntries={[path]}><Routes><Route path="/beam/launch" element={<BeamLaunch />} /><Route path="/beam/shares/:shareId" element={<Beam />} /><Route path="*" element={<Beam />} /></Routes></MemoryRouter>); }
function reason(button: HTMLElement) { const id = button.getAttribute("aria-describedby"); return id ? document.getElementById(id)?.textContent ?? "" : ""; }
async function verifyInline() {
  fireEvent.change(await screen.findByRole("textbox", { name: "Authenticator or recovery code" }), { target: { value: "123456" } });
  fireEvent.click(screen.getByRole("button", { name: "Verify and continue" }));
}
beforeEach(() => {
  vi.clearAllMocks();
  Element.prototype.scrollIntoView = vi.fn();
  vi.mocked(beamApi.policy).mockResolvedValue({ ok: true, data: policy });
  vi.mocked(beamApi.share).mockResolvedValue({ ok: true, data: owned });
  vi.mocked(beamApi.shares).mockResolvedValue({ ok: true, data: { ...empty, items: [owned] } });
  vi.mocked(beamApi.audience).mockResolvedValue({ ok: true, data: audience });
  vi.mocked(beamApi.shareEvents).mockResolvedValue({ ok: true, data: empty });
  vi.mocked(beamApi.events).mockResolvedValue({ ok: true, data: empty });
  vi.mocked(beamApi.diagnostics).mockResolvedValue({ ok: true, data: { share_id: shareId, hostname: owned.hostname, state: "active", connectivity: "online", version: 8, authority_version: 2, generation: "g", expires_at: owned.expires_at, domain_ready: true, status: "ready", reason: "ready" } as never });
  vi.mocked(beamRoomsApi.feedback).mockResolvedValue({ ok: true, data: empty });
  vi.mocked(beamRoomsApi.notifications).mockResolvedValue({ ok: true, data: empty });
  vi.mocked(beamRoomsApi.projects).mockResolvedValue({ ok: true, data: empty });
  vi.mocked(api.POST).mockResolvedValue({ data: { mfa_verified_at: "2026-10-06T11:00:00Z" } } as never);
});
afterEach(cleanup);

describe("LS-UX-4 durations and counts (P1, P2)", () => {
  it("formats lifetimes in whole hours and minutes with correct plurals", () => {
    expect(beamDuration(60)).toBe("1 minute");
    expect(beamDuration(2700)).toBe("45 minutes");
    expect(beamDuration(3600)).toBe("1 hour");
    expect(beamDuration(3660)).toBe("1 hour 1 minute");
    expect(beamDuration(5400)).toBe("1 hour 30 minutes");
    expect(beamDuration(7200)).toBe("2 hours");
    expect(beamDuration(86400)).toBe("24 hours");
  });
  it("pluralizes counts", () => {
    expect(beamCount(1, "share")).toBe("1 share");
    expect(beamCount(0, "share")).toBe("0 shares");
    expect(beamCount(2, "person", "people")).toBe("2 people");
  });
  it("says 1 hour, not 1 hours, on the manage card (P1)", async () => {
    vi.mocked(beamApi.share).mockResolvedValue({ ok: true, data: { ...owned, expires_at: "2099-10-06T08:30:00Z" } });
    show(`/beam/shares/${shareId}`);
    await screen.findByText("Your organization allows a share to last up to 1 hour from when it was created. Reconnecting never extends it.");
    expect(screen.queryByText(/1 hours/)).toBeNull();
  });
});

describe("LS-UX-4 reviewers shown plainly (P3, P4, P5)", () => {
  it("summarizes reviewers by name without the publisher's own grant", () => {
    expect(beamReviewerSummary(owned, audience)).toBe("reviewer (reviewer@tunnex.io), Developers group · 1 member");
    expect(beamReviewerSummary({ ...owned, grants: [self] }, audience)).toBe("No reviewers yet");
    expect(beamReviewerSummary(owned, null)).toBe("1 person and 1 group");
    const many = { users: [...audience.users, ...["a", "b", "c"].map((name, index) => ({ id: `6666666${index}-6666-4666-8666-666666666666`, name, email: `${name}@tunnex.io` }))], groups: audience.groups };
    const grants = [self, reviewerGrant, groupGrant, ...many.users.slice(2).map(user => ({ subject_kind: "user" as const, subject_id: user.id }))];
    expect(beamReviewerSummary({ ...owned, grants }, many)).toBe("reviewer (reviewer@tunnex.io), Developers group · 1 member, a (a@tunnex.io) +2 more");
  });
  it("counts reviewers for the list without the publisher", () => {
    expect(beamReviewerCount(owned)).toBe("1 person and 1 group");
    expect(beamReviewerCount({ ...owned, grants: [self] })).toBe("None yet");
    expect(beamReviewerCount({ ...owned, grants: [self, reviewerGrant, { subject_kind: "user", subject_id: groupId }] })).toBe("2 people");
    expect(beamReviewerCount({ ...owned, grants: undefined })).toBe("Not reported");
  });
  it("shows Reviewers by name on the share settings card instead of an Audience count (P3)", async () => {
    show(`/beam/shares/${shareId}`);
    await screen.findByText("reviewer (reviewer@tunnex.io), Developers group · 1 member");
    expect(screen.queryByText("Audience")).toBeNull();
    expect(screen.queryByText(/selected users or groups/)).toBeNull();
  });
  it("shows reviewer counts in the My shares list (P4)", async () => {
    show("/beam/my-shares");
    await screen.findByText("1 person and 1 group");
    expect(screen.queryByText(/selection/)).toBeNull();
  });
  it("hides the publisher from the reviewer picker and always keeps their own grant (P5)", async () => {
    vi.mocked(beamApi.grantsImpact).mockResolvedValue({ ok: true, data: { share_version: 8, removed_grant_count: 1, affected_reviewer_count: 1, affected_reviewer_session_count: 2, requires_confirmation: true } });
    vi.mocked(beamApi.grants).mockResolvedValue({ ok: true, data: { ...owned, version: 9, grants: [self, groupGrant] } });
    show(`/beam/shares/${shareId}`);
    const picker = await screen.findByRole("group", { name: "Permitted reviewers" });
    expect(within(picker).queryByRole("checkbox", { name: /Pat Publisher/ })).toBeNull();
    const save = screen.getByRole("button", { name: "Save reviewer changes" });
    expect((save as HTMLButtonElement).disabled).toBe(true);
    expect(reason(save)).toBe("Select or clear a reviewer to make a change.");
    fireEvent.click(within(picker).getByRole("checkbox", { name: /reviewer@tunnex.io/ }));
    expect((save as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(save);
    const dialog = await screen.findByRole("dialog", { name: "Confirm reviewer changes" });
    expect(within(dialog).getByText("1 reviewer choice removed. 1 person loses access. 2 open sessions end.")).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("checkbox", { name: "Remove these reviewers and end their access" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Save reviewers" }));
    await screen.findByText("Reviewers saved.");
    expect(beamApi.grants).toHaveBeenCalledWith(identity.org, owned, [self, groupGrant], true);
    expect(screen.queryByText(/last matching grant/)).toBeNull();
  });
});

describe("LS-UX-4 disabled buttons say why (P6, P7, P16, P17)", () => {
  it("replaces the expiry picker with the maximum-lifetime reason (P6)", async () => {
    show(`/beam/shares/${shareId}`);
    await screen.findByText("Already at your organization's maximum lifetime of 1 hour.");
    expect(screen.queryByLabelText("New expiry")).toBeNull();
    expect(screen.queryByRole("button", { name: "Extend expiry" })).toBeNull();
  });
  it("explains a disabled Extend expiry when there is room left (P6)", async () => {
    vi.mocked(beamApi.share).mockResolvedValue({ ok: true, data: { ...owned, expires_at: "2099-10-06T08:30:00Z" } });
    show(`/beam/shares/${shareId}`);
    const extend = await screen.findByRole("button", { name: "Extend expiry" });
    expect((extend as HTMLButtonElement).disabled).toBe(true);
    expect(reason(extend)).toBe("Choose a new expiry first.");
    expect(screen.getByLabelText("New expiry")).toBeTruthy();
  });
  it("explains a disabled Resume share when the feature is off (P7)", async () => {
    vi.mocked(beamApi.policy).mockResolvedValue({ ok: true, data: { ...policy, enabled: false } });
    vi.mocked(beamApi.share).mockResolvedValue({ ok: true, data: { ...owned, state: "paused", can_open: false } });
    show(`/beam/shares/${shareId}`);
    const resume = await screen.findByRole("button", { name: "Resume share" });
    expect((resume as HTMLButtonElement).disabled).toBe(true);
    expect(reason(resume)).toBe("Local Sharing is turned off for this organization.");
  });
  it("explains a disabled Share a local app (P16)", async () => {
    vi.mocked(beamApi.policy).mockResolvedValue({ ok: true, data: { ...policy, domain_ready: false } });
    show("/beam/my-shares");
    const publish = await screen.findByRole("button", { name: "Share a local app" });
    expect((publish as HTMLButtonElement).disabled).toBe(true);
    expect(reason(publish)).toBe("Local Sharing isn't available on this server right now.");
  });
  it("explains a disabled Generate command and hides the publisher from the CLI reviewer list (P17, P5)", async () => {
    render(<MemoryRouter><BeamCliPublisher orgId={identity.org} policy={policy} selfId={identity.user} /></MemoryRouter>);
    fireEvent.click(screen.getByRole("button", { name: "Publish using CLI" }));
    const generate = await screen.findByRole("button", { name: "Generate command" });
    expect((generate as HTMLButtonElement).disabled).toBe(true);
    expect(reason(generate)).toBe("Select at least one reviewer to generate the command.");
    expect(screen.queryByRole("checkbox", { name: /Pat Publisher/ })).toBeNull();
    expect(screen.getByText(/Maximum lifetime: 1 hour\./)).toBeTruthy();
  });
});

describe("LS-UX-4 publisher review feedback (P8, P9)", () => {
  it("puts reviewers' feedback first with decision badges and offers a comment-only reply (P8)", async () => {
    vi.mocked(beamRoomsApi.feedback).mockResolvedValue({ ok: true, data: { ...empty, items: [fromReviewer("f1", "approved", "Ship it"), fromReviewer("f2", "changes_requested", "Fix the footer")] } });
    vi.mocked(beamRoomsApi.addFeedback).mockResolvedValue({ ok: true, data: { ...fromReviewer("f3", "comment", "Fixed"), author_id: identity.user } });
    render(<MemoryRouter><BeamFeedback orgId={identity.org} share={owned} viewer="publisher" /></MemoryRouter>);
    const heading = await screen.findByRole("heading", { name: "Feedback from reviewers" });
    expect(screen.queryByRole("heading", { name: "Earlier feedback" })).toBeNull();
    expect(screen.queryByRole("radio")).toBeNull();
    expect(screen.queryByRole("form", { name: "Send review feedback" })).toBeNull();
    expect(screen.getByText("Approved").getAttribute("data-tone")).toBe("live");
    expect(screen.getByText("Changes requested").getAttribute("data-tone")).toBe("warning");
    const reply = screen.getByRole("button", { name: "Reply to reviewers" });
    expect(heading.compareDocumentPosition(reply) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    fireEvent.click(reply);
    const form = await screen.findByRole("form", { name: "Reply to reviewers" });
    expect(within(form).queryByRole("radio")).toBeNull();
    fireEvent.change(within(form).getByRole("textbox", { name: "Your reply" }), { target: { value: "Fixed" } });
    fireEvent.click(within(form).getByRole("button", { name: "Send reply" }));
    await screen.findByText("Reply sent. Reviewers see it on this page.");
    expect(beamRoomsApi.addFeedback).toHaveBeenCalledWith(identity.org, shareId, { body: "Fixed", status: "comment" });
    expect(screen.queryByRole("form", { name: "Reply to reviewers" })).toBeNull();
  });
  it("marks the publisher's replies for reviewers and keeps the reviewer form first (P8)", async () => {
    const reviewing = { ...owned, publisher_id: reviewerId, can_manage: false };
    vi.mocked(beamRoomsApi.feedback).mockResolvedValue({ ok: true, data: { ...empty, items: [fromReviewer("f1", "comment", "Fixed")] } });
    render(<MemoryRouter><BeamFeedback orgId={identity.org} share={reviewing} viewer="reviewer" /></MemoryRouter>);
    const form = await screen.findByRole("form", { name: "Send review feedback" });
    const heading = screen.getByRole("heading", { name: "Feedback so far" });
    expect(form.compareDocumentPosition(heading) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getByText("· Publisher")).toBeTruthy();
  });
  it("does not flash the access sentence while feedback loads (P9)", async () => {
    vi.mocked(beamRoomsApi.feedback).mockImplementation(() => new Promise(() => undefined));
    render(<MemoryRouter><BeamFeedback orgId={identity.org} share={owned} viewer="publisher" /></MemoryRouter>);
    await screen.findByText("Loading review feedback…");
    expect(screen.queryByText(/Feedback can be added while/)).toBeNull();
  });
});

describe("LS-UX-4 MFA panels recover without a manual refresh (P10)", () => {
  it("announces every successful inline step-up", async () => {
    const heard = vi.fn(); const stop = onMfaVerified(heard);
    try {
      render(<MemoryRouter><InlineTerminalMfa action="Test" onVerified={() => undefined} onCancel={() => undefined} /></MemoryRouter>);
      await verifyInline();
      await waitFor(() => expect(heard).toHaveBeenCalledTimes(1));
    } finally { stop(); }
  });
  it("re-reads feedback after MFA is verified elsewhere in the console", async () => {
    vi.mocked(beamRoomsApi.feedback).mockResolvedValueOnce(mfaRefusal).mockResolvedValue({ ok: true, data: empty });
    render(<MemoryRouter><BeamFeedback orgId={identity.org} share={owned} viewer="publisher" /></MemoryRouter>);
    await screen.findByRole("button", { name: "Verify MFA" });
    act(() => announceMfaVerified());
    await screen.findByText("No feedback yet. Reviewers' comments appear here.");
    expect(screen.queryByRole("button", { name: "Verify MFA" })).toBeNull();
    expect(beamRoomsApi.feedback).toHaveBeenCalledTimes(2);
  });
  it("re-checks on window focus and when the tab becomes visible, only while MFA is pending", async () => {
    vi.mocked(beamRoomsApi.feedback).mockResolvedValueOnce(mfaRefusal).mockResolvedValueOnce(mfaRefusal).mockResolvedValue({ ok: true, data: empty });
    render(<MemoryRouter><BeamFeedback orgId={identity.org} share={owned} viewer="publisher" /></MemoryRouter>);
    await screen.findByRole("button", { name: "Verify MFA" });
    act(() => { window.dispatchEvent(new Event("focus")); });
    await waitFor(() => expect(beamRoomsApi.feedback).toHaveBeenCalledTimes(2));
    expect(await screen.findByRole("button", { name: "Verify MFA" })).toBeTruthy();
    act(() => { document.dispatchEvent(new Event("visibilitychange")); });
    await screen.findByText("No feedback yet. Reviewers' comments appear here.");
    expect(beamRoomsApi.feedback).toHaveBeenCalledTimes(3);
    act(() => { window.dispatchEvent(new Event("focus")); });
    await new Promise(resolve => setTimeout(resolve, 20));
    expect(beamRoomsApi.feedback).toHaveBeenCalledTimes(3);
  });
  it.skipIf(typeof BroadcastChannel === "undefined")("re-reads after MFA is verified in another tab", async () => {
    vi.mocked(beamRoomsApi.feedback).mockResolvedValueOnce(mfaRefusal).mockResolvedValue({ ok: true, data: empty });
    render(<MemoryRouter><BeamFeedback orgId={identity.org} share={owned} viewer="publisher" /></MemoryRouter>);
    await screen.findByRole("button", { name: "Verify MFA" });
    const otherTab = new BroadcastChannel("tnx-mfa");
    try { otherTab.postMessage("verified"); await screen.findByText("No feedback yet. Reviewers' comments appear here.", {}, { timeout: 2000 }); }
    finally { otherTab.close(); }
  });
  it("never sends a waiting draft on its own; Send works again after MFA elsewhere", async () => {
    const reviewing = { ...owned, publisher_id: reviewerId, can_manage: false };
    vi.mocked(beamRoomsApi.addFeedback).mockResolvedValueOnce(mfaRefusal);
    render(<MemoryRouter><BeamFeedback orgId={identity.org} share={reviewing} viewer="reviewer" /></MemoryRouter>);
    await screen.findByRole("form", { name: "Send review feedback" });
    fireEvent.change(screen.getByRole("textbox", { name: "Your feedback" }), { target: { value: "Draft" } });
    fireEvent.click(screen.getByRole("button", { name: "Send feedback" }));
    await screen.findByRole("textbox", { name: "Authenticator or recovery code" });
    act(() => announceMfaVerified());
    await waitFor(() => expect(screen.queryByRole("textbox", { name: "Authenticator or recovery code" })).toBeNull());
    expect(beamRoomsApi.addFeedback).toHaveBeenCalledTimes(1);
    expect((screen.getByRole("textbox", { name: "Your feedback" }) as HTMLTextAreaElement).value).toBe("Draft");
  });
  it("re-reads Sharing updates after MFA is verified elsewhere", async () => {
    vi.mocked(beamRoomsApi.notifications).mockResolvedValueOnce(mfaRefusal).mockResolvedValue({ ok: true, data: empty });
    render(<MemoryRouter><BeamNotifications orgId={identity.org} /></MemoryRouter>);
    fireEvent.click(screen.getByRole("button", { name: "Sharing updates" }));
    await screen.findByRole("button", { name: "Verify MFA" });
    act(() => announceMfaVerified());
    await screen.findByText("No sharing updates right now.");
  });
  it("offers Continue again on the open page after MFA is verified elsewhere, without launching", async () => {
    vi.mocked(beamApi.share).mockResolvedValue({ ok: true, data: { ...owned, publisher_id: reviewerId, can_manage: false } });
    vi.mocked(beamApi.launch).mockResolvedValue(mfaRefusal);
    show(`/beam/launch?orgId=${identity.org}&shareId=${shareId}&nonce_hash=${"a".repeat(64)}&target=%2F`);
    fireEvent.click(await screen.findByRole("button", { name: "Continue to Checkout preview" }));
    await screen.findByText("Your organization requires a recent MFA check before you open shared apps.");
    act(() => announceMfaVerified());
    await screen.findByRole("button", { name: "Continue to Checkout preview" });
    expect(beamApi.launch).toHaveBeenCalledTimes(1);
  });
});

describe("LS-UX-4 wording (P11-P16)", () => {
  it("names the support section and its facts in plain words (P11)", async () => {
    show(`/beam/shares/${shareId}`);
    fireEvent.click(await screen.findByText("Share health and history", { selector: "summary" }));
    await screen.findByRole("heading", { name: "Share health" });
    for (const term of ["Status", "Connection", "Server checks", "Revision"]) expect(screen.getByText(term, { selector: "dt" })).toBeTruthy();
    expect(screen.getByText("Passing")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Download support file" })).toBeTruthy();
    expect(screen.queryByText(/Diagnostics &/)).toBeNull();
    expect(screen.queryByText(/authority/)).toBeNull();
    expect(screen.queryByText("Connectivity")).toBeNull();
  });
  it("titles compatibility help by the problem it solves and drops jargon (P12)", () => {
    render(<BeamCompatibilityHelp />);
    expect(screen.getByText("If your app doesn't load for reviewers", { selector: "summary" })).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/numeric loopback|unavailable authority|connector credentials/);
    expect(document.body.textContent).toMatch(/127\.0\.0\.1 or ::1/);
  });
  it("links events to their share and says when there are none yet (P13)", async () => {
    show("/beam/events");
    await screen.findByText("No Local Sharing events yet.");
    cleanup();
    vi.mocked(beamApi.events).mockResolvedValue({ ok: true, data: { ...empty, items: [{ id: "e1", share_id: shareId, action: "beam.share.pause", outcome: "success", reason: "", actor_id: identity.user, created_at: "2026-10-06T10:00:00Z" }] } });
    show("/beam/events");
    const link = await screen.findByRole("link", { name: `Open share ${shareId}` });
    expect(link.getAttribute("href")).toBe(`/beam/shares/${shareId}`);
    expect(screen.getByText("None")).toBeTruthy();
    expect(screen.queryByText("None recorded")).toBeNull();
  });
  it("labels Local Sharing access evidence in words (P14)", () => {
    render(<MemoryRouter><BeamAccessEvidence event={{ id: "a1", created_at: "2026-10-06T10:00:00Z", decision: "allow", src_user_id: reviewerId, beam: { share_id: shareId, action: "beam.access.allowed", reason: "admission" } } as never} /></MemoryRouter>);
    expect(screen.getByText("Reviewer opened the app")).toBeTruthy();
    expect(screen.queryByText("Safe reason")).toBeNull();
    expect(screen.getByText("Reason")).toBeTruthy();
  });
  it("explains the MFA requirement and lifetime on the sharing policy (P15)", async () => {
    render(<MemoryRouter><BeamPolicySettings orgId={identity.org} canEdit /></MemoryRouter>);
    await screen.findByRole("checkbox", { name: /Require a recent MFA check/ });
    expect(screen.getByText(/verify MFA within the last 5 minutes/)).toBeTruthy();
    expect(screen.getByText("Shares can last up to 1 hour.")).toBeTruthy();
    fireEvent.click(screen.getByRole("checkbox", { name: /Open for all users/ }));
    expect(screen.getByRole("heading", { name: "Who publishers can choose as reviewers" })).toBeTruthy();
    fireEvent.change(screen.getByRole("spinbutton", { name: "Shares per publisher" }), { target: { value: "40" } });
    const review = screen.getByRole("button", { name: "Review policy changes" });
    expect((review as HTMLButtonElement).disabled).toBe(true);
    expect(reason(review)).toBe("Lifetime must be 1 to 1440 minutes and shares per publisher 1 to 25.");
  });
  it("pluralizes the policy change dialog (P2)", async () => {
    vi.mocked(beamApi.policyImpact).mockResolvedValue({ ok: true, data: { policy_version: 3, active_share_count: 1, affected_share_count: 1, affected_reviewer_session_count: 1, requires_confirmation: false } });
    render(<MemoryRouter><BeamPolicySettings orgId={identity.org} canEdit /></MemoryRouter>);
    fireEvent.click(await screen.findByRole("button", { name: "Review policy changes" }));
    await screen.findByText("1 active share now. This change affects 1 share and 1 open reviewer session.");
  });
  it("uses one noun for ended shares in History (P16)", async () => {
    vi.mocked(beamApi.shares).mockResolvedValue({ ok: true, data: empty });
    show("/beam/my-shares");
    fireEvent.click(await screen.findByRole("button", { name: "History" }));
    await screen.findByText("No ended shares yet.");
  });
  it("describes a saved project with a formatted lifetime and reviewer count (P2, P16)", async () => {
    const project: BeamProject = { id: "77777777-7777-4777-8777-777777777777", org_id: identity.org, owner_id: identity.user, name: "Checkout", target: { protocol: "http", address: "127.0.0.1", port: 3000 }, duration_seconds: 3600, grants: [self, reviewerGrant, groupGrant], version: 1, created_at: "2026-10-07T10:00:00Z", updated_at: "2026-10-07T10:00:00Z" };
    vi.mocked(beamRoomsApi.projects).mockResolvedValue({ ok: true, data: { ...empty, items: [project] } });
    render(<MemoryRouter><BeamRooms orgId={identity.org} policy={policy} selfId={identity.user} /></MemoryRouter>);
    await screen.findByText("Local port 3000 · Lasts 1 hour · 1 person and 1 group");
  });
});
