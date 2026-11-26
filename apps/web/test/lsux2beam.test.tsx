import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import Beam, { BeamLaunch } from "../src/pages/Beam";
import { BeamFeedback } from "../src/components/BeamFeedback";
import { beamRoomsApi } from "../src/lib/beam-rooms";
import { BEAM_SHARE_UNAVAILABLE, beamApi, beamStatusHint, type BeamPolicy, type BeamShare } from "../src/lib/beam";

// LS-UX-2: the Local Sharing pages speak to the person looking at them (publisher, organization
// manager or invited reviewer) and never tell "not invited" apart from "does not exist".
const identity = vi.hoisted(() => ({ org: "11111111-1111-4111-8111-111111111111", user: "22222222-2222-4222-8222-222222222222" }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: identity.org, name: "Acme" }, orgs: [{ id: identity.org, name: "Acme" }], setOrg: vi.fn(), failed: false }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: identity.user, email: "rae@example.com", email_verified: true } }, logout: vi.fn(async () => true) }) }));
vi.mock("../src/lib/api", () => ({ api: { GET: vi.fn(), POST: vi.fn() }, apiErrorMessage: (error: { error?: { message: string } } | undefined, fallback: string) => error?.error?.message ?? fallback, apiErrorCode: (error: { error?: { code: string } } | undefined) => error?.error?.code, loadOne: async () => ({ ok: false, error: "unused" }) }));
vi.mock("../src/lib/beam", async () => { const actual = await vi.importActual<typeof import("../src/lib/beam")>("../src/lib/beam"); return { ...actual, beamApi: Object.fromEntries(Object.keys(actual.beamApi).map(key => [key, vi.fn()])) }; });
vi.mock("../src/lib/beam-rooms", async () => { const actual = await vi.importActual<typeof import("../src/lib/beam-rooms")>("../src/lib/beam-rooms"); return { ...actual, beamRoomsApi: Object.fromEntries(Object.keys(actual.beamRoomsApi).map(key => [key, vi.fn()])) }; });

const shareId = "33333333-3333-4333-8333-333333333333";
const publisherId = "44444444-4444-4444-8444-444444444444";
const policy: BeamPolicy = { version: 3, enabled: true, domain_ready: true, base_domain: "beam.example.net", max_duration_seconds: 86400, max_shares: 5, require_mfa: false, publisher_group_ids: [], reviewer_user_ids: [identity.user], reviewer_group_ids: [], can_manage_policy: false, can_publish: false, protocol_version: 1, min_client_version: "0.1.7", capabilities: [] };
const reviewed: BeamShare = { id: shareId, org_id: identity.org, publisher_id: publisherId, publisher_name: "Pat Publisher", publisher_email: "pat@example.com", name: "Checkout preview", hostname: "p-1.beam.example.net", url: "https://p-1.beam.example.net/", state: "active", connectivity: "online", version: 8, authority_version: 2, expires_at: "2099-10-06T10:00:00Z", created_at: "2099-10-06T08:00:00Z", can_open: true, can_manage: false };
const empty = { items: [], limit: 20, offset: 0, server_time: "2026-10-06T11:00:00Z" };
function show(path: string) { return render(<MemoryRouter initialEntries={[path]}><Routes><Route path="/beam/launch" element={<BeamLaunch />} /><Route path="/beam/shares/:shareId" element={<Beam />} /><Route path="*" element={<Beam />} /></Routes></MemoryRouter>); }
beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(beamApi.policy).mockResolvedValue({ ok: true, data: policy });
  vi.mocked(beamApi.share).mockResolvedValue({ ok: true, data: reviewed });
  vi.mocked(beamApi.shares).mockResolvedValue({ ok: true, data: { ...empty, items: [reviewed] } });
  vi.mocked(beamApi.audience).mockResolvedValue({ ok: true, data: { users: [], groups: [] } });
  vi.mocked(beamApi.shareEvents).mockResolvedValue({ ok: true, data: empty });
  vi.mocked(beamApi.diagnostics).mockResolvedValue({ ok: false, error: "unused" });
  vi.mocked(beamRoomsApi.feedback).mockResolvedValue({ ok: true, data: empty });
  vi.mocked(beamRoomsApi.notifications).mockResolvedValue({ ok: true, data: empty });
  vi.mocked(beamRoomsApi.projects).mockResolvedValue({ ok: true, data: empty });
});
afterEach(cleanup);

describe("LS-UX-2 reviewer share detail", () => {
  it("names who shared it, routes back to Shared with me and offers reviewer actions only (L1-L3)", async () => {
    show(`/beam/shares/${shareId}`);
    await screen.findByRole("heading", { name: "Shared app" });
    const crumb = screen.getByRole("navigation", { name: "Breadcrumb" });
    expect(within(crumb).getByRole("link", { name: "Shared with me" }).getAttribute("href")).toBe("/beam/shared-with-me");
    expect(within(crumb).queryByText("My shares")).toBeNull();
    expect(screen.getByText("Shared with you by")).toBeTruthy();
    expect(screen.getByText("Pat Publisher (pat@example.com)")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Open Checkout preview" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Copy link" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Open on phone" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Review feedback" }).getAttribute("href")).toBe("#beam-review-feedback");
    expect(screen.queryByText(/permission to manage/)).toBeNull();
    expect(screen.queryByRole("heading", { name: "Manage sharing" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Pause share" })).toBeNull();
  });
  it("keeps My shares and the manage controls for the publisher (L1)", async () => {
    vi.mocked(beamApi.share).mockResolvedValue({ ok: true, data: { ...reviewed, publisher_id: identity.user, can_manage: true, grants: [] } });
    show(`/beam/shares/${shareId}`);
    await screen.findByRole("heading", { name: "Manage sharing" });
    expect(within(screen.getByRole("navigation", { name: "Breadcrumb" })).getByRole("link", { name: "My shares" })).toBeTruthy();
    expect(screen.queryByText("Shared with you by")).toBeNull();
  });
  it("tells an organization manager whose share it is (L4)", async () => {
    vi.mocked(beamApi.share).mockResolvedValue({ ok: true, data: { ...reviewed, can_manage: true, can_open: false, grants: [] } });
    vi.mocked(beamRoomsApi.feedback).mockResolvedValue({ ok: false, code: "beam_share_not_found", error: "Share not found" });
    show(`/beam/shares/${shareId}`);
    await screen.findByRole("heading", { name: "Manage sharing" });
    expect(within(screen.getByRole("navigation", { name: "Breadcrumb" })).getByRole("link", { name: "Local Sharing" })).toBeTruthy();
    expect(screen.getByText("Published by")).toBeTruthy();
    expect(screen.getByText(/not one of its reviewers/)).toBeTruthy();
    await screen.findByText("Feedback is visible to the publisher and the share's reviewers."); // L8
    expect(screen.queryByText("Share not found")).toBeNull();
  });
  it("explains a paused share in terms of the publisher (L5)", async () => {
    vi.mocked(beamApi.share).mockResolvedValue({ ok: true, data: { ...reviewed, state: "paused", can_open: false } });
    show(`/beam/shares/${shareId}`);
    await screen.findByText("Pat Publisher (pat@example.com) has paused this share. You can open it again when they resume it.");
  });
  it("closes an ended share for a reviewer without dead links or raw errors (L6, L7)", async () => {
    vi.mocked(beamApi.share).mockResolvedValue({ ok: true, data: { ...reviewed, state: "stopped", can_open: false } });
    show(`/beam/shares/${shareId}`);
    await screen.findByText(/This share has ended. Ask Pat Publisher \(pat@example.com\) for a new link/);
    expect(screen.queryByRole("button", { name: "Copy link" })).toBeNull();
    expect(screen.queryByText(/Create a new share using the CLI/)).toBeNull();
    // The feedback panel sets its closed state in an effect after the share renders; wait for it.
    expect(await screen.findByText("Feedback closed when this share ended.")).toBeTruthy();
    expect(beamRoomsApi.feedback).not.toHaveBeenCalled();
  });
  it("answers not invited, withdrawn and missing with one sentence and a way forward (L9)", async () => {
    vi.mocked(beamApi.share).mockResolvedValue({ ok: false, code: "beam_share_not_found", error: "Share not found" });
    show(`/beam/shares/${shareId}`);
    await screen.findByText(BEAM_SHARE_UNAVAILABLE);
    expect(screen.queryByText("Share not found")).toBeNull();
    expect(within(screen.getByRole("navigation", { name: "Breadcrumb" })).queryByText("My shares")).toBeNull();
    expect(screen.getByRole("link", { name: "Go to Shared with me" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Check again" })).toBeTruthy();
  });
  it("writes reviewer copy for Copy link (L11)", async () => {
    const writeText = vi.fn(async () => undefined); Object.assign(navigator, { clipboard: { writeText } });
    show(`/beam/shares/${shareId}`);
    fireEvent.click(await screen.findByRole("button", { name: "Copy link" }));
    await screen.findByText("Link copied. Anyone you send it to needs their own access and sign-in.");
  });
});

describe("LS-UX-2 Shared with me", () => {
  it("shows the publisher as Name (email), no connection jargon and no separate Search button (L3, L12, L13)", async () => {
    show("/beam/shared-with-me");
    await screen.findByRole("link", { name: "Open Checkout preview" });
    expect(screen.getByText("Pat Publisher (pat@example.com)")).toBeTruthy();
    expect(screen.queryByRole("combobox", { name: "Connection" })).toBeNull();
    expect(screen.queryByText("All connectivity")).toBeNull();
    expect(screen.queryByRole("button", { name: "Search shares" })).toBeNull();
    fireEvent.change(screen.getByRole("searchbox", { name: "Search shares" }), { target: { value: "check" } });
    await waitFor(() => expect(beamApi.shares).toHaveBeenLastCalledWith(identity.org, true, 0, "check", {}, 20));
    expect(screen.getByRole("button", { name: "Sharing updates" })).toBeTruthy(); // L14
  });
  it("keeps a renamed connection filter for publishers that applies on change (L12)", async () => {
    vi.mocked(beamApi.policy).mockResolvedValue({ ok: true, data: { ...policy, can_publish: true } });
    vi.mocked(beamApi.shares).mockResolvedValue({ ok: true, data: { ...empty, items: [{ ...reviewed, publisher_id: identity.user, can_manage: true, grants: [] }] } });
    show("/beam/my-shares");
    const filter = await screen.findByRole("combobox", { name: "Connection" });
    expect(within(filter).getByRole("option", { name: "Any connection" })).toBeTruthy();
    fireEvent.change(filter, { target: { value: "origin_unavailable" } });
    await waitFor(() => expect(beamApi.shares).toHaveBeenLastCalledWith(identity.org, false, 0, undefined, { connectivity: "origin_unavailable", scope: "active" }, 20));
  });
});

describe("LS-UX-2 open shared app", () => {
  const path = `/beam/launch?orgId=${identity.org}&shareId=${shareId}&nonce_hash=${"a".repeat(64)}&target=%2F`;
  it("gives a not-invited account the uniform sentence with its own email and a way to switch (L24, L26)", async () => {
    vi.mocked(beamApi.share).mockResolvedValue({ ok: false, code: "beam_share_not_found", error: "Share not found" });
    show(path);
    await screen.findByText(`${BEAM_SHARE_UNAVAILABLE} You're signed in as rae@example.com.`);
    expect(screen.getByRole("button", { name: "Sign out and use another account" })).toBeTruthy();
    expect(screen.queryByRole("link", { name: /review feedback/i })).toBeNull();
    expect(beamApi.launch).not.toHaveBeenCalled();
  });
  it("explains a share that cannot be opened yet and offers Check again (L25)", async () => {
    vi.mocked(beamApi.share).mockResolvedValue({ ok: true, data: { ...reviewed, connectivity: "offline", can_open: true } });
    show(path);
    await screen.findByText(/Pat Publisher \(pat@example.com\)'s computer is offline or reconnecting/);
    expect(screen.getByText("Shared with you by Pat Publisher (pat@example.com)")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Check again" }));
    await waitFor(() => expect(beamApi.share).toHaveBeenCalledTimes(2));
  });
});

describe("LS-UX-2 review feedback", () => {
  it("puts the form first, explains the decision and why Send is disabled (L16, L17, L19, L20)", async () => {
    render(<MemoryRouter><BeamFeedback orgId={identity.org} share={reviewed} viewer="reviewer" /></MemoryRouter>);
    const form = await screen.findByRole("form", { name: "Send review feedback" });
    const empty = await screen.findByText("No feedback yet. Yours will be the first.");
    expect(form.compareDocumentPosition(empty) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.queryByRole("combobox", { name: "Review decision" })).toBeNull();
    for (const [name, meaning] of [["Comment", "A note without a decision."], ["Approve", "Tell the publisher it looks good."], ["Request changes", "Ask the publisher to change something."]]) {
      expect(screen.getByRole("radio", { name: new RegExp(name) })).toBeTruthy(); expect(screen.getByText(meaning)).toBeTruthy();
    }
    expect((screen.getByRole("button", { name: "Send feedback" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText("Write feedback, attach a screenshot or choose Approve or Request changes to send.")).toBeTruthy();
    expect(screen.getByText(/see your name, email, decision, comment and screenshot/)).toBeTruthy();
    fireEvent.click(screen.getByRole("radio", { name: /Approve/ }));
    expect((screen.getByRole("button", { name: "Send feedback" }) as HTMLButtonElement).disabled).toBe(false);
    expect(screen.queryByText(/choose Approve or Request changes to send/)).toBeNull();
  });
  it("uses a console button for the screenshot instead of the native control (L18)", async () => {
    render(<MemoryRouter><BeamFeedback orgId={identity.org} share={reviewed} viewer="reviewer" /></MemoryRouter>);
    await screen.findByRole("form", { name: "Send review feedback" });
    expect(screen.getByRole("button", { name: "Attach screenshot" })).toBeTruthy();
    expect(screen.getByLabelText("Screenshot (optional)").className).toContain("sr-only");
    expect(screen.getByText(/PNG or JPEG, up to 10 MB/)).toBeTruthy();
  });
  it("names authors as Name (email) and confirms what happens after sending (L21)", async () => {
    vi.mocked(beamRoomsApi.feedback).mockResolvedValue({ ok: true, data: { ...empty, items: [{ id: "f1", share_id: shareId, author_id: publisherId, author_name: "Sam Reviewer", author_email: "sam@example.com", body: "Button overlaps", status: "changes_requested", created_at: "2026-10-06T10:00:00Z" }] } });
    vi.mocked(beamRoomsApi.addFeedback).mockResolvedValue({ ok: true, data: { id: "f2", share_id: shareId, author_id: identity.user, author_name: "Rae", body: "ok", status: "comment", created_at: "2026-10-06T10:01:00Z" } });
    render(<MemoryRouter><BeamFeedback orgId={identity.org} share={reviewed} viewer="reviewer" /></MemoryRouter>);
    await screen.findByText("Sam Reviewer (sam@example.com)");
    expect(screen.getByRole("heading", { name: "Earlier feedback" })).toBeTruthy();
    fireEvent.change(screen.getByRole("textbox", { name: "Your feedback" }), { target: { value: "ok" } });
    fireEvent.click(screen.getByRole("button", { name: "Send feedback" }));
    await screen.findByText("Feedback sent. The publisher sees it on this page and in Sharing updates.");
    await waitFor(() => expect(beamRoomsApi.feedback).toHaveBeenCalledTimes(2));
  });
});

describe("LS-UX-2 status sentences", () => {
  it("tells reviewers who can act and publishers what to do", () => {
    const now = Date.parse("2026-10-06T11:00:00Z");
    expect(beamStatusHint(reviewed, "reviewer", now)).toBeNull();
    expect(beamStatusHint({ ...reviewed, can_open: false }, "publisher", now)).toBeNull();
    expect(beamStatusHint({ ...reviewed, can_open: false }, "manager", now)).toMatch(/not one of its reviewers/);
    expect(beamStatusHint({ ...reviewed, connectivity: "origin_unavailable" }, "reviewer", now)).toMatch(/^Pat Publisher \(pat@example.com\)'s local app is not responding/);
    expect(beamStatusHint({ ...reviewed, connectivity: "origin_unavailable" }, "publisher", now)).toMatch(/^Your local app is not responding/);
    expect(beamStatusHint({ ...reviewed, state: "revoked" }, "reviewer", now)).toMatch(/sharing policy or server change\. Ask Pat Publisher/);
    expect(beamStatusHint({ ...reviewed, state: "stopped" }, "manager", now)).toBe("This share has ended. Only its publisher can share the app again.");
    expect(beamStatusHint({ ...reviewed, publisher_name: undefined, publisher_email: undefined, state: "paused" }, "reviewer", now)).toMatch(/^The publisher has paused/);
  });
});
