import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { BeamRooms } from "../src/components/BeamRooms";
import { BeamFeedback, BeamNotifications } from "../src/components/BeamFeedback";
import { prepareBeamScreenshot } from "../src/lib/beam-screenshot";
import { beamRoomsApi, beamScreenshotURL, type BeamFeedback as Feedback, type BeamProject } from "../src/lib/beam-rooms";
import { beamApi, type BeamPolicy, type BeamShare } from "../src/lib/beam";
vi.mock("../src/lib/beam", async () => { const actual = await vi.importActual<typeof import("../src/lib/beam")>("../src/lib/beam"); return { ...actual, beamApi: Object.fromEntries(Object.keys(actual.beamApi).map(key => [key, vi.fn()])) }; });
vi.mock("../src/lib/beam-rooms", async () => { const actual = await vi.importActual<typeof import("../src/lib/beam-rooms")>("../src/lib/beam-rooms"); return { ...actual, beamRoomsApi: Object.fromEntries(Object.keys(actual.beamRoomsApi).map(key => [key, vi.fn()])) }; });
vi.mock("../src/lib/beam-screenshot", () => ({ prepareBeamScreenshot: vi.fn() }));
const org = "11111111-1111-4111-8111-111111111111", user = "22222222-2222-4222-8222-222222222222", group = "33333333-3333-4333-8333-333333333333";
const audience = { users: [{ id: user, name: "Alice", email: "alice@example.com" }], groups: [{ id: group, name: "Design team" }] };
const policy: BeamPolicy = { enabled: true, domain_ready: true, can_publish: true, can_manage_policy: false, version: 1, base_domain: "beam.example.com", max_duration_seconds: 3600, max_shares: 5, publisher_group_ids: [], reviewer_user_ids: [user], reviewer_group_ids: [group], require_mfa: false, protocol_version: 1, min_client_version: "0.1.7", capabilities: ["path_routes_v1"] };
const project: BeamProject = { id: "44444444-4444-4444-8444-444444444444", org_id: org, owner_id: user, name: "Checkout", target: { protocol: "http", address: "127.0.0.1", port: 3000 }, duration_seconds: 1800, grants: [{ subject_kind: "group", subject_id: group }], version: 4, created_at: "2026-10-07T10:00:00Z", updated_at: "2026-10-07T11:00:00Z" };
const share: BeamShare = { id: "55555555-5555-4555-8555-555555555555", org_id: org, publisher_id: user, project_id: project.id, name: "Checkout", hostname: "p-test.beam.example.com", url: "https://p-test.beam.example.com", created_at: "2026-10-07T11:00:00Z", expires_at: "2099-10-07T12:00:00Z", state: "active", connectivity: "online", version: 1, authority_version: 1, can_manage: true, can_open: true };
const feedback: Feedback = { id: "66666666-6666-4666-8666-666666666666", share_id: share.id, author_id: user, author_name: "Alice", body: "Button overlaps on mobile", status: "changes_requested", created_at: "2026-10-07T11:10:00Z" };
const empty = { items: [], limit: 20, offset: 0, server_time: "2026-10-07T11:00:00Z" };
function show(element: React.ReactNode) { return render(<MemoryRouter>{element}</MemoryRouter>); }
beforeEach(() => { vi.clearAllMocks(); vi.mocked(prepareBeamScreenshot).mockResolvedValue("aW1hZ2U="); vi.mocked(beamRoomsApi.projects).mockResolvedValue({ ok: true, data: empty }); vi.mocked(beamRoomsApi.sessions).mockResolvedValue({ ok: true, data: empty }); vi.mocked(beamRoomsApi.feedback).mockResolvedValue({ ok: true, data: empty }); vi.mocked(beamRoomsApi.notifications).mockResolvedValue({ ok: true, data: empty }); vi.mocked(beamApi.audience).mockResolvedValue({ ok: true, data: audience }); vi.mocked(beamRoomsApi.saveProject).mockResolvedValue({ ok: true, data: project }); vi.mocked(beamRoomsApi.addFeedback).mockResolvedValue({ ok: true, data: feedback }); });
afterEach(cleanup);
describe("Saved Beam projects", () => {
  it("saves reusable named reviewer defaults without publishing or changing grants", async () => {
    show(<BeamRooms orgId={org} policy={policy} />); fireEvent.click(screen.getByRole("button", { name: "Save a project" })); await screen.findByRole("checkbox", { name: /Alice/ });
    fireEvent.change(screen.getByRole("textbox", { name: "Project name" }), { target: { value: "Checkout" } }); fireEvent.change(screen.getByRole("spinbutton", { name: "Local app port" }), { target: { value: "5173" } }); fireEvent.change(screen.getByRole("spinbutton", { name: "Default lifetime (minutes)" }), { target: { value: "30" } }); fireEvent.click(screen.getByRole("checkbox", { name: /Design team/ })); fireEvent.click(screen.getByRole("button", { name: "Save project" }));
    await waitFor(() => expect(beamRoomsApi.saveProject).toHaveBeenCalledWith(org, { name: "Checkout", target: { protocol: "http", address: "127.0.0.1", port: 5173, routes: [] }, duration_seconds: 1800, grants: [{ subject_kind: "group", subject_id: group }] }, undefined));
    expect(beamApi.grants).not.toHaveBeenCalled(); expect(beamApi.launch).not.toHaveBeenCalled(); expect(beamApi.action).not.toHaveBeenCalled();
  });
  it("keeps project sessions beneath one card and requests history before pagination", async () => {
    vi.mocked(beamRoomsApi.projects).mockResolvedValue({ ok: true, data: { ...empty, items: [project] } }); vi.mocked(beamRoomsApi.sessions).mockImplementation(async (_org, _id, offset, scope) => ({ ok: true, data: { ...empty, offset: offset ?? 0, items: scope === "history" ? [{ ...share, state: "stopped", can_open: false }] : [share] } }));
    show(<BeamRooms orgId={org} policy={policy} />); await screen.findByRole("link", { name: "Open Checkout" }); expect(screen.getAllByRole("heading", { name: "Checkout" })).toHaveLength(1); expect(beamRoomsApi.sessions).toHaveBeenCalledWith(org, project.id, 0, "active");
    fireEvent.click(screen.getByRole("button", { name: "Session history" })); await screen.findByText("Stopped"); expect(screen.queryByRole("link", { name: "Open Checkout" })).toBeNull(); expect(beamRoomsApi.sessions).toHaveBeenLastCalledWith(org, project.id, 0, "history");
    expect(screen.getAllByRole("heading", { name: "Checkout" })).toHaveLength(1);
  });
  it("prefills the CLI form from the project without granting stale reviewers", async () => {
    vi.mocked(beamRoomsApi.projects).mockResolvedValue({ ok: true, data: { ...empty, items: [project] } }); show(<BeamRooms orgId={org} policy={policy} />); fireEvent.click(await screen.findByRole("button", { name: "Publish Checkout" })); await screen.findByRole("checkbox", { name: /Design team/ }); expect((screen.getByRole("textbox", { name: "App name" }) as HTMLInputElement).value).toBe("Checkout"); expect((screen.getByRole("spinbutton", { name: "Link lifetime (minutes)" }) as HTMLInputElement).value).toBe("30"); expect((screen.getByRole("checkbox", { name: /Design team/ }) as HTMLInputElement).checked).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Generate command" })); expect((screen.getByRole("textbox", { name: "Publish command" }) as HTMLTextAreaElement).value).toContain(`--project ${project.id}`); expect(beamRoomsApi.saveProject).not.toHaveBeenCalled();
  });
  it("requires explicitly discarding saved reviewers no longer permitted", async () => {
    vi.mocked(beamRoomsApi.projects).mockResolvedValue({ ok: true, data: { ...empty, items: [project] } }); vi.mocked(beamApi.audience).mockResolvedValue({ ok: true, data: { users: audience.users, groups: [] } }); show(<BeamRooms orgId={org} policy={policy} />); fireEvent.click(await screen.findByRole("button", { name: "Edit Checkout" })); await screen.findByText(/saved reviewer choices are no longer permitted/); expect((screen.getByRole("button", { name: "Save project defaults" }) as HTMLButtonElement).disabled).toBe(true); fireEvent.click(screen.getByRole("button", { name: "Remove unavailable reviewer choices" })); fireEvent.click(screen.getByRole("checkbox", { name: /Alice/ })); fireEvent.click(screen.getByRole("button", { name: "Save project defaults" })); await waitFor(() => expect(beamRoomsApi.saveProject).toHaveBeenCalledWith(org, expect.objectContaining({ grants: [{ subject_kind: "user", subject_id: user }] }), project));
  });
  it("preserves edits on version conflict and prevents blind retry", async () => {
    vi.mocked(beamRoomsApi.projects).mockResolvedValue({ ok: true, data: { ...empty, items: [project] } }); vi.mocked(beamRoomsApi.saveProject).mockResolvedValue({ ok: false, error: "Version changed", code: "beam_version_conflict" }); show(<BeamRooms orgId={org} policy={policy} />); fireEvent.click(await screen.findByRole("button", { name: "Edit Checkout" })); await screen.findByRole("checkbox", { name: /Design team/ }); fireEvent.change(screen.getByRole("textbox", { name: "Project name" }), { target: { value: "Edited checkout" } }); fireEvent.click(screen.getByRole("button", { name: "Save project defaults" })); await screen.findByText(/This project changed elsewhere/); expect((screen.getByRole("textbox", { name: "Project name" }) as HTMLInputElement).value).toBe("Edited checkout"); expect((screen.getByRole("button", { name: "Save project defaults" }) as HTMLButtonElement).disabled).toBe(true);
  });
  it("makes saved project read failures retryable without claiming an empty list", async () => {
    vi.mocked(beamRoomsApi.projects).mockResolvedValue({ ok: false, error: "Current projects could not be checked" }); show(<BeamRooms orgId={org} policy={policy} />); await screen.findByText("Current projects could not be checked"); expect(screen.queryByText(/No saved projects yet/)).toBeNull(); vi.mocked(beamRoomsApi.projects).mockResolvedValue({ ok: true, data: empty }); fireEvent.click(screen.getByRole("button", { name: "Retry projects" })); await screen.findByText(/No saved projects yet/);
  });
});
describe("Beam review feedback", () => {
  it("records a review decision and clears the successful draft", async () => {
    show(<BeamFeedback orgId={org} share={share} />); await screen.findByText(/No feedback yet/); fireEvent.change(screen.getByRole("combobox", { name: "Review decision" }), { target: { value: "changes_requested" } }); fireEvent.change(screen.getByRole("textbox", { name: "Your feedback" }), { target: { value: feedback.body } }); fireEvent.click(screen.getByRole("button", { name: "Send feedback" })); await screen.findByText(/Feedback shared/); expect(beamRoomsApi.addFeedback).toHaveBeenCalledWith(org, share.id, { body: feedback.body, status: "changes_requested" }); expect((screen.getByRole("textbox", { name: "Your feedback" }) as HTMLTextAreaElement).value).toBe("");
  });
  it("allows status-only approval and escapes comment text", async () => {
    vi.mocked(beamRoomsApi.feedback).mockResolvedValue({ ok: true, data: { ...empty, items: [{ ...feedback, body: "<script>bad()</script>" }] } }); show(<BeamFeedback orgId={org} share={share} />); await screen.findByText("<script>bad()</script>"); expect(document.querySelector("script")).toBeNull(); fireEvent.change(screen.getByRole("combobox", { name: "Review decision" }), { target: { value: "approved" } }); fireEvent.click(screen.getByRole("button", { name: "Send feedback" })); await waitFor(() => expect(beamRoomsApi.addFeedback).toHaveBeenCalledWith(org, share.id, { body: "", status: "approved" }));
  });
  it("retains failed submission drafts and blocks retry until authority is refreshed", async () => {
    vi.mocked(beamRoomsApi.addFeedback).mockResolvedValue({ ok: false, error: "Reviewer access changed" }); show(<BeamFeedback orgId={org} share={share} />); await screen.findByText(/No feedback yet/); fireEvent.change(screen.getByRole("textbox", { name: "Your feedback" }), { target: { value: "Keep my draft" } }); fireEvent.click(screen.getByRole("button", { name: "Send feedback" })); await screen.findByText(/Reviewer access changed/); expect(screen.queryByRole("button", { name: "Send feedback" })).toBeNull(); fireEvent.click(screen.getByRole("button", { name: "Refresh feedback" })); await waitFor(() => expect((screen.getByRole("textbox", { name: "Your feedback" }) as HTMLTextAreaElement).value).toBe("Keep my draft")); expect(beamRoomsApi.addFeedback).toHaveBeenCalledTimes(1);
  });
  it("rejects oversized or unsupported screenshots without sending them", async () => {
    vi.mocked(prepareBeamScreenshot).mockRejectedValue(new Error("Choose a PNG or JPEG screenshot no larger than 10 MB.")); show(<BeamFeedback orgId={org} share={share} />); await screen.findByText(/No feedback yet/); const file = new File([new Uint8Array(10 * 1024 * 1024 + 1)], "large.png", { type: "image/png" }); fireEvent.change(screen.getByLabelText("Screenshot (optional)"), { target: { files: [file] } }); await screen.findByText(/Choose a PNG or JPEG screenshot no larger than 10 MB/); expect(beamRoomsApi.addFeedback).not.toHaveBeenCalled(); expect((screen.getByRole("button", { name: "Send feedback" }) as HTMLButtonElement).disabled).toBe(true);
  });
  it("uploads the prepared screenshot as raw base64 and ignores a replaced in-flight image", async () => {
    let finishFirst!: (value: string) => void;
    vi.mocked(prepareBeamScreenshot).mockImplementationOnce(() => new Promise(resolve => { finishFirst = resolve; })).mockResolvedValueOnce("c2Vjb25k");
    show(<BeamFeedback orgId={org} share={share} />); await screen.findByText(/No feedback yet/);
    const input = screen.getByLabelText("Screenshot (optional)");
    fireEvent.change(input, { target: { files: [new File(["first"], "first.png", { type: "image/png" })] } });
    fireEvent.change(input, { target: { files: [new File(["second"], "second.png", { type: "image/png" })] } });
    await screen.findByRole("button", { name: "Remove screenshot" });
    await act(async () => { finishFirst("Zmlyc3Q="); });
    fireEvent.click(screen.getByRole("button", { name: "Send feedback" }));
    await waitFor(() => expect(beamRoomsApi.addFeedback).toHaveBeenCalledWith(org, share.id, { body: "", status: "comment", screenshot_base64: "c2Vjb25k" }));
  });
  it("uses only the current share's authenticated screenshot endpoint", async () => {
    const path = `/api/v1/organizations/${org}/beam/shares/${share.id}/feedback/${feedback.id}/screenshot`; expect(beamScreenshotURL(org, share.id, { ...feedback, screenshot_url: path })).toBe(path); for (const screenshot_url of ["https://other.example/screenshot.png", "//other.example/file", path + "?token=anything", path.replace(share.id, project.id)]) expect(beamScreenshotURL(org, share.id, { ...feedback, screenshot_url })).toBeNull();
  });
  it("withdraws feedback and attachment links when the parent share access is uncertain", async () => {
    vi.mocked(beamRoomsApi.feedback).mockResolvedValue({ ok: true, data: { ...empty, items: [feedback] } }); const rendered = show(<BeamFeedback orgId={org} share={share} />); await screen.findByText(feedback.body); rendered.rerender(<MemoryRouter><BeamFeedback orgId={org} share={share} uncertain /></MemoryRouter>); await screen.findByText("Refresh the share to check current feedback access."); expect(screen.queryByText(feedback.body)).toBeNull(); expect(screen.queryByRole("button", { name: "Send feedback" })).toBeNull();
  });
  it("lets a currently authorized reviewer comment while the preview is paused", async () => {
    show(<BeamFeedback orgId={org} share={{ ...share, state: "paused", can_open: false, can_manage: false }} />);
    await screen.findByText(/No feedback yet/); fireEvent.change(screen.getByRole("textbox", { name: "Your feedback" }), { target: { value: "Ready to recheck when resumed" } }); fireEvent.click(screen.getByRole("button", { name: "Send feedback" }));
    await waitFor(() => expect(beamRoomsApi.addFeedback).toHaveBeenCalledWith(org, share.id, { body: "Ready to recheck when resumed", status: "comment" }));
  });
  it("keeps ended sessions read-only", async () => { show(<BeamFeedback orgId={org} share={{ ...share, state: "stopped", can_open: false }} />); await screen.findByText(/No feedback yet/); expect(screen.queryByRole("textbox", { name: "Your feedback" })).toBeNull(); });
});
describe("Beam preview updates", () => {
  it("loads current-authority notifications on demand and links into feedback", async () => {
    vi.mocked(beamRoomsApi.notifications).mockResolvedValue({ ok: true, data: { ...empty, items: [{ id: "feedback-1", kind: "feedback", share_id: share.id, title: "Checkout: review feedback received", created_at: feedback.created_at }] } }); show(<BeamNotifications orgId={org} />); expect(beamRoomsApi.notifications).not.toHaveBeenCalled(); fireEvent.click(screen.getByRole("button", { name: "Preview updates" })); const link = await screen.findByRole("link", { name: "Checkout: review feedback received" }); expect(link.getAttribute("href")).toBe(`/beam/shares/${share.id}`); expect(beamRoomsApi.notifications).toHaveBeenCalledWith(org, 0);
  });
});
