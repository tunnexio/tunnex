import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), delete: vi.fn(), put: vi.fn(), copy: vi.fn(), change: vi.fn(), confirmation: vi.fn() }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: "org-a" }, loading: false, failed: false }) }));
vi.mock("../src/lib/api", () => ({
  api: { GET: mocks.get, POST: mocks.post, DELETE: mocks.delete, PUT: mocks.put },
  apiErrorMessage: (error: { error?: { message?: string } } | undefined, fallback: string) => error?.error?.message ?? fallback,
  loadOne: async (call: () => Promise<{ data?: unknown; error?: { error?: { message?: string } } }>) => {
    try { const result = await call(); return result.error || result.data === undefined ? { ok: false, error: result.error?.error?.message ?? "Could not load." } : { ok: true, data: result.data }; }
    catch { return { ok: false, error: "Could not reach the API." }; }
  },
}));
import { SandboxRunnerEnrollment } from "../src/components/SandboxRunnerEnrollment";
import { SandboxSetupPage } from "../src/pages/SandboxSetup";

const command = "sudo python3 /tmp/tunnex-enroll.py --server=https://controller.example.invalid --enrollment-id=11111111-1111-4111-8111-111111111111";
const profile = { id: "profile-a", name: "Approved Ubuntu runner", architecture: "amd64", prerequisites: ["systemd 254 or later and unified cgroup v2", "Preloaded, pinned Ubuntu image and a co-located approved gateway"], blocked_reasons: [], bootstrap_script: { url: "https://controller.example.invalid/public/enroll.py", sha256: "1".repeat(64) }, install: { version: 1, edition: "open", source_sha: "1".repeat(40), bundle: { url: "https://controller.example.invalid/public/bundle.tar.gz", sha256: "2".repeat(64) }, org_id: "org-a", gateway: { node_id: "gateway-a", container_id: "3".repeat(64), image_digest: `sha256:${"4".repeat(64)}`, interface: "wg0" }, controller: { url: "https://controller.example.invalid:8444", server_name: "controller.example.invalid", uri: "spiffe://example.invalid/controller", api_url: "https://controller.example.invalid" }, images: [{ template_id: "template-a", url: "https://controller.example.invalid/public/image.tar", sha256: "5".repeat(64), config_digest: `sha256:${"6".repeat(64)}`, architecture: "amd64", qualification_evidence: "Synthetic profile fixture; does not qualify a host." }] } };
const enrollment = { id: "runner-a", name: "Team runner", profile_id: profile.id, state: "awaiting_install", created_at: "2026-10-05T00:00:00Z", expires_at: "2030-01-01T00:00:00Z", blocked_reasons: [], install_command: command };
const list = { profiles: [profile], enrollments: [], blocked_reasons: [] };
const qualification = { report_sha256: "7".repeat(64), runner_spki_sha256: "8".repeat(64), submitted_at: "2026-10-05T00:02:00Z", decision: "pending", approvable: true, blocked_reasons: [], report: { version: 1, enrollment_id: enrollment.id, profile_id: profile.id, binding_sha256: "9".repeat(64), source_sha: "1".repeat(40), platform: { os: "linux", version: "Ubuntu 26.04", architecture: "amd64" }, image_config_digests: [`sha256:${"6".repeat(64)}`], started_at: "2026-10-05T00:01:00Z", finished_at: "2026-10-05T00:02:00Z", checks: [{ code: "native_expiry_cleanup", result: "passed", evidence: "Synthetic signed control-plane trial fixture; no live host qualification." }] } };
const template = { id: "template-a", name: "Ubuntu terminal", image_digest: "sha256:fixture", maximum_scope: [], memory_mib: 128, max_ttl_seconds: 900, allowed_skill_revision_ids: [] };
const setup = { settings: { enabled: false, max_per_user: 1, max_total: 1 }, policy_mode: "enforcing", creation_status: { can_admin: true, can_manage_catalog: true, runtime_ready: false, blocked_reasons: ["runtime_not_ready", "organization_disabled"] }, catalog: [{ template, enabled: true, runtime_compatible: true }] };
beforeEach(() => {
  for (const mock of Object.values(mocks)) mock.mockReset();
  mocks.get.mockResolvedValue({ data: list });
  mocks.post.mockResolvedValue({ data: { enrollment, bootstrap_token: "synthetic-one-time-token" } });
  mocks.delete.mockResolvedValue({ data: { ...enrollment, state: "revoked", blocked_reasons: ["enrollment_revoked"] } });
  mocks.copy.mockResolvedValue(undefined);
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: mocks.copy } });
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });
function page(canManage = true) {
  render(<MemoryRouter><SandboxRunnerEnrollment orgId="org-a" canManage={canManage} onRunnerChange={mocks.change} onReadinessConfirmed={mocks.confirmation} /></MemoryRouter>);
}
async function review() {
  const add = await screen.findByRole("button", { name: "Add sandbox runner" });
  await waitFor(() => expect((add as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(add);
  const modal = within(screen.getByRole("dialog", { name: "Add sandbox runner" }));
  fireEvent.change(modal.getByLabelText("Runner name"), { target: { value: "Team runner" } });
  fireEvent.click(modal.getByRole("button", { name: "Review enrollment" }));
  return within(screen.getByRole("dialog", { name: "Review runner enrollment" }));
}
async function issue() {
  const modal = await review();
  fireEvent.click(modal.getByRole("checkbox"));
  fireEvent.click(modal.getByRole("button", { name: "Issue enrollment token" }));
  return await screen.findByRole("dialog", { name: "Save the runner enrollment token" });
}
async function saveToken() {
  const modal = within(await screen.findByRole("dialog", { name: "Save the runner enrollment token" }));
  fireEvent.click(modal.getByRole("checkbox"));
  fireEvent.click(modal.getByRole("button", { name: /saved it/i }));
  return within(await screen.findByRole("dialog", { name: "Runner: Team runner" }));
}

it("does not call administrator enrollment APIs for a member", () => {
  page(false);
  expect(mocks.get).not.toHaveBeenCalled();
  expect(screen.getByText(/owner or administrator can enroll/)).toBeTruthy();
  expect((screen.getByRole("button", { name: "Add sandbox runner" }) as HTMLButtonElement).disabled).toBe(true);
});
it("distinguishes a failed server read from an empty enrollment inventory", async () => {
  mocks.get.mockRejectedValue(new Error("offline")); page();
  expect(await screen.findByText(/connection and readiness are unconfirmed/)).toBeTruthy();
  expect(screen.queryByText("No runner enrollments yet.")).toBeNull();
  expect((screen.getByRole("button", { name: "Add sandbox runner" }) as HTMLButtonElement).disabled).toBe(true);
  expect(mocks.confirmation).toHaveBeenLastCalledWith(false);
});
it("explains missing approved deployment inputs instead of producing a placeholder command", async () => {
  mocks.get.mockResolvedValue({ data: { profiles: [], enrollments: [], blocked_reasons: ["runner_profile_unavailable"] } }); page();
  expect(await screen.findByText(/provide a verified public bundle, qualified image/)).toBeTruthy();
  expect(screen.queryByLabelText("Public runner install command")).toBeNull();
  expect((screen.getByRole("button", { name: "Add sandbox runner" }) as HTMLButtonElement).disabled).toBe(true);
});
it("refuses profile blockers and exposes enforcing-policy and cleanup requirements", async () => {
  mocks.get.mockResolvedValue({ data: { ...list, profiles: [{ ...profile, blocked_reasons: ["runner_profile_unavailable"] }], blocked_reasons: ["policy_not_enforcing", "cleanup_pending"] } }); page();
  expect(await screen.findByText(/Enable enforcing network policy/)).toBeTruthy();
  expect(screen.getByText(/retained slot cannot be reused/)).toBeTruthy();
  expect(screen.getByText(/Deployment profiles need attention/)).toBeTruthy();
  expect((screen.getByRole("button", { name: "Add sandbox runner" }) as HTMLButtonElement).disabled).toBe(true);
});
it("reviews server prerequisites and explicit machine-admin consent before issuing a scoped enrollment", async () => {
  page(); const modal = await review();
  expect(modal.getByText(/systemd 254 or later/)).toBeTruthy();
  expect(modal.getByText(/machine administrator permission/)).toBeTruthy();
  expect((modal.getByRole("button", { name: "Issue enrollment token" }) as HTMLButtonElement).disabled).toBe(true);
  expect(mocks.post).not.toHaveBeenCalled();
  fireEvent.click(modal.getByRole("checkbox")); fireEvent.click(modal.getByRole("button", { name: "Issue enrollment token" }));
  await screen.findByRole("dialog", { name: "Save the runner enrollment token" });
  expect(mocks.post).toHaveBeenCalledTimes(1);
  expect(mocks.post.mock.calls[0]).toEqual(["/api/v1/organizations/{orgId}/sandbox-runner-enrollments", { params: { path: { orgId: "org-a" } }, body: { name: "Team runner", profile_id: "profile-a", idempotency_key: expect.any(String) } }]);
  expect(mocks.change).not.toHaveBeenCalled();
});
it("copies a public command and a separately shown token without URL, browser-store or inline-command secret leakage", async () => {
  const stored = vi.spyOn(Storage.prototype, "setItem"); page();
  const tokenModal = within(await issue());
  expect(tokenModal.getByLabelText("Public runner install command").textContent).toBe(command);
  fireEvent.click(tokenModal.getByRole("button", { name: "Copy install command" }));
  await waitFor(() => expect(mocks.copy).toHaveBeenCalledWith(command));
  expect(mocks.copy.mock.calls[0][0]).not.toContain("synthetic-one-time-token");
  fireEvent.click(tokenModal.getByRole("button", { name: "Copy enrollment token" }));
  await waitFor(() => expect(mocks.copy).toHaveBeenCalledWith("synthetic-one-time-token"));
  expect(window.location.href).not.toContain("synthetic-one-time-token");
  expect(stored).not.toHaveBeenCalled();
  const progress = await saveToken();
  expect(screen.queryByText("synthetic-one-time-token")).toBeNull();
  expect(progress.getByRole("status").textContent).toBe("Waiting for installation");
  expect(progress.queryByRole("link", { name: /Review Sandbox setup/ })).toBeNull();
});
it("retries an unconfirmed issuance with the same idempotency key and handles a metadata-only replay", async () => {
  mocks.post.mockRejectedValueOnce(new Error("lost response")).mockResolvedValueOnce({ data: { enrollment } }); page();
  const modal = await review(); fireEvent.click(modal.getByRole("checkbox")); fireEvent.click(modal.getByRole("button", { name: "Issue enrollment token" }));
  await screen.findByText(/Enrollment could not be confirmed/);
  fireEvent.click(modal.getByRole("button", { name: "Issue enrollment token" }));
  const progress = within(await screen.findByRole("dialog", { name: "Runner: Team runner" }));
  expect(mocks.post.mock.calls[0][1].body.idempotency_key).toBe(mocks.post.mock.calls[1][1].body.idempotency_key);
  expect(progress.getByText(/one-time token cannot be shown again/)).toBeTruthy();
  expect(screen.queryByRole("dialog", { name: "Save the runner enrollment token" })).toBeNull();
  expect(progress.getByRole("button", { name: "Cancel enrollment" })).toBeTruthy();
});
it("does not duplicate a token request on double submission", async () => {
  let resolve!: (value: unknown) => void;
  mocks.post.mockReturnValue(new Promise(done => { resolve = done; })); page();
  const modal = await review(); fireEvent.click(modal.getByRole("checkbox"));
  const button = modal.getByRole("button", { name: "Issue enrollment token" }); fireEvent.click(button); fireEvent.click(button);
  expect(mocks.post).toHaveBeenCalledTimes(1);
  await act(async () => resolve({ data: { enrollment, bootstrap_token: "synthetic-one-time-token" } }));
});
it("keeps connection separate from reviewed native qualification", async () => {
  mocks.get.mockResolvedValue({ data: { ...list, enrollments: [{ ...enrollment, state: "awaiting_connection", last_seen_at: "2026-10-05T00:01:00Z", blocked_reasons: ["native_qualification_required"] }] } }); page();
  fireEvent.click(await screen.findByRole("button", { name: "View Team runner" }));
  const modal = within(screen.getByRole("dialog", { name: "Runner: Team runner" }));
  expect(modal.getByRole("status").textContent).toBe("Connected · qualification required");
  expect(modal.getByText(/review the host proof/)).toBeTruthy();
  expect(modal.queryByRole("link", { name: /Review Sandbox setup/ })).toBeNull();
});
it("removes stale Ready and setup handoff after a failed status poll", async () => {
  vi.useFakeTimers();
  mocks.get.mockResolvedValueOnce({ data: { ...list, enrollments: [{ ...enrollment, state: "ready" }] } }).mockRejectedValue(new Error("lost control plane"));
  page(); await act(async () => {});
  fireEvent.click(screen.getByRole("button", { name: "View Team runner" }));
  await act(async () => {});
  const modal = within(screen.getByRole("dialog", { name: "Runner: Team runner" }));
  expect(modal.getByRole("status").textContent).toBe("Status unconfirmed");
  expect(modal.queryByRole("link", { name: /Review Sandbox setup/ })).toBeNull();
  expect(mocks.confirmation).toHaveBeenLastCalledWith(false);
  await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
  expect(mocks.get.mock.calls.length).toBeGreaterThanOrEqual(3);
});
it("requires a fresh server Ready response before offering setup handoff", async () => {
  mocks.get.mockResolvedValue({ data: { ...list, enrollments: [{ ...enrollment, state: "ready" }] } }); page();
  fireEvent.click(await screen.findByRole("button", { name: "View Team runner" }));
  const modal = within(screen.getByRole("dialog", { name: "Runner: Team runner" }));
  expect(modal.getByRole("status").textContent).toBe("Ready");
  expect(modal.getByRole("link", { name: /Review Sandbox setup/ }).getAttribute("href")).toBe("/sandboxes/setup");
  expect(modal.getByText(/terminal device, saved SSH public key and optional skills/)).toBeTruthy();
  expect(mocks.put).not.toHaveBeenCalled();
});
it("confirms revocation and keeps observed cleanup pending distinct from completed deletion", async () => {
  mocks.get.mockResolvedValue({ data: { ...list, enrollments: [{ ...enrollment, state: "ready" }] } }); page();
  fireEvent.click(await screen.findByRole("button", { name: "View Team runner" }));
  fireEvent.click(screen.getByRole("button", { name: "Revoke runner" }));
  let modal = within(screen.getByRole("dialog", { name: "Withdraw runner access?" }));
  expect(modal.getByText(/runtime and network cleanup are confirmed/)).toBeTruthy();
  expect(mocks.delete).not.toHaveBeenCalled();
  fireEvent.click(modal.getByRole("button", { name: "Keep enrollment" }));
  fireEvent.click(screen.getByRole("button", { name: "Revoke runner" }));
  const pendingCleanup = { ...enrollment, state: "pending_cleanup", blocked_reasons: ["cleanup_pending"] };
  mocks.delete.mockResolvedValue({ data: pendingCleanup }); mocks.get.mockResolvedValue({ data: { ...list, enrollments: [pendingCleanup], blocked_reasons: ["cleanup_pending"] } });
  modal = within(screen.getByRole("dialog", { name: "Withdraw runner access?" })); fireEvent.click(modal.getByRole("button", { name: "Withdraw runner access" }));
  await waitFor(() => expect(mocks.delete).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/sandbox-runner-enrollments/{enrollmentId}", { params: { path: { orgId: "org-a", enrollmentId: "runner-a" } } }));
  expect(await screen.findByText("Access withdrawn · cleanup pending", { selector: "[role=status]" })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Close" }));
  expect((screen.getByRole("button", { name: "Add sandbox runner" }) as HTMLButtonElement).disabled).toBe(true);
});
it("keeps an offline machine's same identity recovery instructions and hides Ready", async () => {
  mocks.get.mockResolvedValue({ data: { ...list, enrollments: [{ ...enrollment, state: "offline", last_seen_at: "2026-10-05T00:01:00Z", blocked_reasons: ["runner_offline"] }] } }); page();
  fireEvent.click(await screen.findByRole("button", { name: "View Team runner" }));
  const modal = within(screen.getByRole("dialog", { name: "Runner: Team runner" }));
  expect(modal.getByRole("status").textContent).toBe("Offline");
  expect(modal.getByText(/rerun the public command on the same machine/)).toBeTruthy();
  expect(modal.queryByRole("link", { name: /Review Sandbox setup/ })).toBeNull();
});
it("expires old enrollment intent and uses a fresh idempotency key for an explicit new attempt", async () => {
  page(); await issue(); await saveToken();
  mocks.get.mockResolvedValue({ data: { ...list, enrollments: [{ ...enrollment, state: "expired", blocked_reasons: ["bootstrap_expired"] }] } });
  fireEvent.click(screen.getByRole("button", { name: "Refresh status" }));
  fireEvent.click(await screen.findByRole("button", { name: "Start new enrollment" }));
  const draft = within(screen.getByRole("dialog", { name: "Add sandbox runner" })); fireEvent.click(draft.getByRole("button", { name: "Review enrollment" }));
  const modal = within(screen.getByRole("dialog", { name: "Review runner enrollment" })); fireEvent.click(modal.getByRole("checkbox")); fireEvent.click(modal.getByRole("button", { name: "Issue enrollment token" }));
  await screen.findByRole("dialog", { name: "Save the runner enrollment token" });
  expect(mocks.post.mock.calls[0][1].body.idempotency_key).not.toBe(mocks.post.mock.calls[1][1].body.idempotency_key);
});
it("refreshes existing setup authority after observed Ready without enabling creation automatically", async () => {
  let ready = false;
  mocks.get.mockImplementation(async (path: string) => path.endsWith("/sandbox-setup") ? { data: { ...setup, creation_status: { ...setup.creation_status, runtime_ready: ready, blocked_reasons: ready ? ["organization_disabled"] : setup.creation_status.blocked_reasons } } } : { data: { ...list, enrollments: [{ ...enrollment, state: ready ? "ready" : "awaiting_connection" }] } });
  mocks.put.mockResolvedValue({ data: setup });
  render(<MemoryRouter><SandboxSetupPage /></MemoryRouter>);
  const enable = await screen.findByRole("checkbox", { name: "Enable sandbox creation" });
  expect((enable as HTMLInputElement).disabled).toBe(true);
  await screen.findByRole("button", { name: "View Team runner" }); ready = true;
  fireEvent.click(screen.getByRole("button", { name: "Refresh runners" }));
  await waitFor(() => expect((screen.getByRole("checkbox", { name: "Enable sandbox creation" }) as HTMLInputElement).disabled).toBe(false));
  expect((screen.getByRole("checkbox", { name: "Enable sandbox creation" }) as HTMLInputElement).checked).toBe(false);
  expect(mocks.put).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("checkbox", { name: "Enable sandbox creation" })); fireEvent.click(screen.getByRole("button", { name: "Save settings" }));
  await waitFor(() => expect(mocks.put).toHaveBeenCalledTimes(1));
  expect(mocks.put.mock.calls[0][1].body).toEqual({ expected: setup.settings, settings: { enabled: true, max_per_user: 1, max_total: 1 } });
});

it("exposes missing native report as a real qualification requirement without an approval control", async () => {
  mocks.get.mockResolvedValue({ data: { ...list, enrollments: [{ ...enrollment, state: "awaiting_connection", blocked_reasons: ["native_qualification_required"] }] } }); page();
  fireEvent.click(await screen.findByRole("button", { name: "View Team runner" }));
  expect(screen.getByText(/No qualification report has been submitted/)).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Review approval" })).toBeNull();
});
it("shows exact report pins and blocks approval for failed or unrun native checks", async () => {
  const failed = { ...qualification, approvable: false, blocked_reasons: ["qualification_checks_incomplete", "native_proof_required"], report: { ...qualification.report, checks: [{ code: "native_expiry_cleanup", result: "failed", evidence: "Cleanup did not converge in the synthetic fixture." }, { code: "private_ssh", result: "unrun", evidence: "Not attempted." }] } };
  mocks.get.mockResolvedValue({ data: { ...list, enrollments: [{ ...enrollment, state: "awaiting_connection", qualification: failed }] } }); page();
  fireEvent.click(await screen.findByRole("button", { name: "View Team runner" }));
  const region = within(screen.getByRole("region", { name: "Native qualification review" }));
  expect(region.getByText(qualification.runner_spki_sha256)).toBeTruthy();
  expect(region.getByText(qualification.report_sha256)).toBeTruthy();
  const table = within(region.getByRole("table", { name: "Runner qualification checks" }));
  expect(table.getByRole("row", { name: /native expiry cleanup failed/ })).toBeTruthy();
  expect(table.getByRole("row", { name: /private ssh unrun/ })).toBeTruthy();
  expect((region.getByRole("button", { name: "Review approval" }) as HTMLButtonElement).disabled).toBe(true);
  expect(region.getByText(/host report alone cannot approve/)).toBeTruthy();
  expect(mocks.post).not.toHaveBeenCalled();
});
it("requires an explicit report review and note, sends the exact report CAS, and waits for fresh Ready", async () => {
  const connected = { ...enrollment, state: "awaiting_connection", qualification };
  mocks.get.mockResolvedValue({ data: { ...list, enrollments: [connected] } }); page();
  fireEvent.click(await screen.findByRole("button", { name: "View Team runner" }));
  fireEvent.click(screen.getByRole("button", { name: "Review approval" }));
  const submit = screen.getByRole("button", { name: "Approve qualified runner" });
  expect((submit as HTMLButtonElement).disabled).toBe(true);
  fireEvent.change(screen.getByLabelText("Qualification review note"), { target: { value: "  Reviewed exact SPKI and complete native trial evidence.  " } });
  expect((submit as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(screen.getByRole("checkbox"));
  const approved = { ...connected, qualification: { ...qualification, decision: "approved", reviewed_at: "2026-10-05T00:03:00Z", reviewed_by: "admin-a", review_note: "Reviewed exact SPKI and complete native trial evidence." } };
  mocks.post.mockResolvedValue({ data: approved }); mocks.get.mockResolvedValue({ data: { ...list, enrollments: [approved] } });
  fireEvent.click(submit);
  await waitFor(() => expect(mocks.post).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/sandbox-runner-enrollments/{enrollmentId}/qualification-review", { params: { path: { orgId: "org-a", enrollmentId: "runner-a" } }, body: { expected_report_sha256: qualification.report_sha256, decision: "approve", review_note: "Reviewed exact SPKI and complete native trial evidence." } }));
  expect(await screen.findByText("Report approved")).toBeTruthy();
  expect(screen.getByText(/Waiting for fresh runner health/)).toBeTruthy();
  expect(screen.queryByRole("link", { name: /Review Sandbox setup/ })).toBeNull();
  expect(mocks.put).not.toHaveBeenCalled();
});
it("supports a scoped rejection of an incomplete report without authorizing Ready", async () => {
  const connected = { ...enrollment, state: "awaiting_connection", qualification: { ...qualification, approvable: false, blocked_reasons: ["native_proof_required"] } };
  mocks.get.mockResolvedValue({ data: { ...list, enrollments: [connected] } }); page();
  fireEvent.click(await screen.findByRole("button", { name: "View Team runner" }));
  fireEvent.click(screen.getByRole("button", { name: "Reject report" }));
  fireEvent.change(screen.getByLabelText("Qualification review note"), { target: { value: "Missing complete native expiry and cleanup evidence." } });
  fireEvent.click(screen.getByRole("checkbox"));
  const rejected = { ...connected, qualification: { ...connected.qualification, decision: "rejected" } };
  mocks.post.mockResolvedValue({ data: rejected }); mocks.get.mockResolvedValue({ data: { ...list, enrollments: [rejected] } });
  fireEvent.click(screen.getByRole("button", { name: "Reject qualification report" }));
  expect(await screen.findByText("Report rejected")).toBeTruthy();
  expect(mocks.post.mock.calls[0][1].body).toEqual({ expected_report_sha256: qualification.report_sha256, decision: "reject", review_note: "Missing complete native expiry and cleanup evidence." });
  expect(screen.queryByRole("link", { name: /Review Sandbox setup/ })).toBeNull();
});
it("invalidates approval and preserves actionable review failure on stale report conflict", async () => {
  const connected = { ...enrollment, state: "awaiting_connection", qualification };
  mocks.get.mockResolvedValue({ data: { ...list, enrollments: [connected] } }); page();
  fireEvent.click(await screen.findByRole("button", { name: "View Team runner" }));
  fireEvent.click(screen.getByRole("button", { name: "Review approval" }));
  fireEvent.change(screen.getByLabelText("Qualification review note"), { target: { value: "Reviewed exact machine and native trial evidence." } });
  fireEvent.click(screen.getByRole("checkbox"));
  mocks.post.mockResolvedValue({ error: { error: { message: "Report changed. Refresh before reviewing the replacement." } } });
  fireEvent.click(screen.getByRole("button", { name: "Approve qualified runner" }));
  expect(await screen.findByText(/Report changed. Refresh/)).toBeTruthy();
  mocks.get.mockRejectedValue(new Error("offline")); fireEvent.click(screen.getByRole("button", { name: "Refresh status" }));
  await waitFor(() => expect((screen.getByRole("button", { name: "Approve qualified runner" }) as HTMLButtonElement).disabled).toBe(true));
  expect(mocks.confirmation).toHaveBeenLastCalledWith(false);
});
it.each(["failed", "unrun", "missing"])("never exposes an approval for %s checks even if an inconsistent server flag says approvable", async result => {
  const checks = result === "missing" ? [] : [{ ...qualification.report.checks[0], result }];
  mocks.get.mockResolvedValue({ data: { ...list, enrollments: [{ ...enrollment, state: "awaiting_connection", qualification: { ...qualification, report: { ...qualification.report, checks } } }] } }); page();
  fireEvent.click(await screen.findByRole("button", { name: "View Team runner" }));
  expect((screen.getByRole("button", { name: "Review approval" }) as HTMLButtonElement).disabled).toBe(true);
  expect(mocks.post).not.toHaveBeenCalled();
});
it("does not overwrite a fresh replacement report with a late response to the old review", async () => {
  const connected = { ...enrollment, state: "awaiting_connection", qualification };
  mocks.get.mockResolvedValue({ data: { ...list, enrollments: [connected] } }); page();
  fireEvent.click(await screen.findByRole("button", { name: "View Team runner" }));
  fireEvent.click(screen.getByRole("button", { name: "Review approval" }));
  fireEvent.change(screen.getByLabelText("Qualification review note"), { target: { value: "Reviewed exact machine and native trial evidence." } });
  fireEvent.click(screen.getByRole("checkbox"));
  let resolve!: (value: unknown) => void;
  mocks.post.mockReturnValue(new Promise(done => { resolve = done; }));
  fireEvent.click(screen.getByRole("button", { name: "Approve qualified runner" }));
  const replacement = { ...connected, qualification: { ...qualification, report_sha256: "a".repeat(64) } };
  mocks.get.mockResolvedValue({ data: { ...list, enrollments: [replacement] } });
  await waitFor(() => expect((screen.getByRole("button", { name: "Refresh status" }) as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(screen.getByRole("button", { name: "Refresh status" }));
  await screen.findByText(replacement.qualification.report_sha256);
  await act(async () => resolve({ data: { ...connected, qualification: { ...qualification, decision: "approved" } } }));
  expect(screen.getByText(/report changed while review was pending/)).toBeTruthy();
  expect(screen.queryByText("Report approved")).toBeNull();
  expect(screen.getByText(replacement.qualification.report_sha256)).toBeTruthy();
});
