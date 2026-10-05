import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ComponentProps } from "react";
const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), changed: vi.fn(), copy: vi.fn() }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "owner-a" } } }) }));
vi.mock("../src/lib/api", () => ({ api: { GET: mocks.get, POST: mocks.post }, apiErrorMessage: (_: unknown, fallback: string) => fallback, loadOne: async (call: () => Promise<{ data?: unknown; error?: unknown }>) => { try { const result = await call(); return result.error || result.data === undefined ? { ok: false, error: "Trial could not be loaded." } : { ok: true, data: result.data }; } catch { return { ok: false, error: "Could not reach the API." }; } } }));
import { SandboxRunnerQualificationTrial } from "../src/components/SandboxRunnerQualificationTrial";
import type { SandboxRunnerQualificationTrial as Trial } from "../src/lib/api";
const publicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const ownTerminal = { id: "terminal-a", name: "My laptop", user_id: "owner-a", node_id: "gateway-a", kind: "human", status: "active", health_blocked: false };
const saved = { id: "key-a", name: "Laptop", public_key: `${publicKey} local-comment`, fingerprint: "SHA256:fixture", is_default: true };
const trial: Trial = { id: "trial-a", enrollment_id: "enrollment-a", profile_id: "profile-a", sandbox_id: "sandbox-a", terminal_device_id: "terminal-a", state: "pending", phase: "initial_ready", observed_state: "pending", desired_state: "started", generation: 1, created_at: "2030-01-01T00:00:00Z", expires_at: "2030-01-01T00:15:00Z", phases: [{ code: "initial_ready", state: "pending" }, { code: "stopped", state: "pending" }, { code: "resume_ready", state: "pending" }, { code: "offline_expiry", state: "pending" }, { code: "retired", state: "pending" }], blocked_reasons: [], qualification_command: "sudo python3 /var/lib/tunnex-sandbox/qualify.py --enrollment-id=enrollment-a --trial-id=trial-a" };
const connection: NonNullable<Trial["connection"]> = { address: "10.254.242.2", username: "sandbox", port: 22, host_public_key: publicKey, host_key_fingerprint: "SHA256:fixture" };
let currentTrial = trial;
beforeEach(() => {
  for (const mock of Object.values(mocks)) mock.mockReset();
  currentTrial = trial;
  mocks.get.mockImplementation(async (path: string) => path.endsWith("/devices") ? { data: [ownTerminal, { ...ownTerminal, id: "someone-else", user_id: "other" }, { ...ownTerminal, id: "other-gateway", node_id: "another-gateway" }] } : path.endsWith("/saved-ssh-keys") ? { data: { items: [saved] } } : { data: currentTrial });
  mocks.post.mockResolvedValue({ data: trial }); mocks.copy.mockResolvedValue(undefined);
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: mocks.copy } });
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });
function page(props: Partial<ComponentProps<typeof SandboxRunnerQualificationTrial>> = {}) {
  return render(<SandboxRunnerQualificationTrial orgId="org-a" enrollmentId="enrollment-a" terminalGatewayId="gateway-a" enrollmentState="awaiting_connection" lastSeenAt={new Date().toISOString()} confirmed onTrialChange={mocks.changed} {...props} />);
}
async function form() {
  fireEvent.click(screen.getByRole("button", { name: "Start qualification trial" }));
  await screen.findByRole("option", { name: "My laptop" });
  await screen.findByText("Laptop · Default");
  fireEvent.change(screen.getByLabelText("Your terminal device"), { target: { value: "terminal-a" } });
  fireEvent.click(screen.getByRole("checkbox", { name: /I authorize this bounded verification/ }));
}

it("requires the profile's exact terminal gateway and confirmed runner status", () => {
  page({ terminalGatewayId: undefined });
  expect(screen.getByText(/operator must configure its terminal binding/)).toBeTruthy();
  expect((screen.getByRole("button", { name: "Start qualification trial" }) as HTMLButtonElement).disabled).toBe(true);
  cleanup(); page({ confirmed: false });
  expect(screen.getByText(/Refresh runner status before starting/)).toBeTruthy();
  expect((screen.getByRole("button", { name: "Start qualification trial" }) as HTMLButtonElement).disabled).toBe(true);
});
it.each([undefined, "2000-01-01T00:00:00Z"])("waits for actual fresh authenticated connection before starting (%s)", lastSeenAt => {
  page({ lastSeenAt });
  expect(screen.getByText(/Wait for a fresh authenticated runner connection/)).toBeTruthy();
  expect((screen.getByRole("button", { name: "Start qualification trial" }) as HTMLButtonElement).disabled).toBe(true);
});
it("uses the caller's eligible terminal and saved public key with explicit consent and no scope, skills or cap overrides", async () => {
  page(); await form();
  expect(screen.queryByRole("option", { name: /someone else/ })).toBeNull();
  expect(screen.getAllByRole("option")).toHaveLength(2);
  expect(screen.getByText(/no optional skills or additional outbound access/)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Create verification trial" }));
  expect(await screen.findByText("Trial queued")).toBeTruthy();
  expect(mocks.post).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/sandbox-runner-enrollments/{enrollmentId}/qualification-trials", { params: { path: { orgId: "org-a", enrollmentId: "enrollment-a" } }, body: { terminal_device_id: "terminal-a", ssh_public_keys: [publicKey], idempotency_key: expect.any(String) } });
  expect(Object.keys(mocks.post.mock.calls[0][1].body).sort()).toEqual(["idempotency_key", "ssh_public_keys", "terminal_device_id"]);
  expect(mocks.get).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/sandbox-runner-enrollments/{enrollmentId}/qualification-trials/{trialId}", { params: { path: { orgId: "org-a", enrollmentId: "enrollment-a", trialId: "trial-a" } } });
  expect(screen.getByText(/Stop, resume, disconnecting and closing this screen do not extend/)).toBeTruthy();
});
it("rejects a pasted private key before the trial request", async () => {
  page(); await form();
  fireEvent.change(screen.getByLabelText("SSH public keys"), { target: { value: "-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic-fixture-only\n-----END OPENSSH PRIVATE KEY-----" } });
  fireEvent.click(screen.getByRole("button", { name: "Create verification trial" }));
  expect(await screen.findByText(/Paste valid SSH public keys from your .pub files/)).toBeTruthy();
  expect(mocks.post).not.toHaveBeenCalled();
});
it("requires exactly one public key for the bounded trial", async () => {
  page(); await form();
  fireEvent.change(screen.getByLabelText("SSH public keys"), { target: { value: "ssh-rsa AAAAC3NzaC1yc2EAAAADAQABAAABAQDummy" } });
  fireEvent.click(screen.getByRole("button", { name: "Create verification trial" }));
  expect(await screen.findByText("Use exactly one SSH public key for this verification trial.")).toBeTruthy();
  expect(mocks.post).not.toHaveBeenCalled();
});
it("keeps the same trial intent key after a lost creation response", async () => {
  mocks.post.mockRejectedValueOnce(new Error("lost response")).mockResolvedValueOnce({ data: trial }); page(); await form();
  fireEvent.click(screen.getByRole("button", { name: "Create verification trial" }));
  await screen.findByText(/Trial creation could not be confirmed/);
  fireEvent.click(screen.getByRole("button", { name: "Create verification trial" }));
  await screen.findByText("Trial queued");
  expect(mocks.post.mock.calls[0][1].body.idempotency_key).toBe(mocks.post.mock.calls[1][1].body.idempotency_key);
});
it("rejects a trial response for a different enrollment or terminal", async () => {
  mocks.post.mockResolvedValue({ data: { ...trial, enrollment_id: "other-enrollment" } }); page(); await form();
  fireEvent.click(screen.getByRole("button", { name: "Create verification trial" }));
  expect(await screen.findByText(/Trial identity did not match the request/)).toBeTruthy();
  expect(screen.queryByText("Trial queued")).toBeNull();
});
it("does not create duplicate trials on double submission", async () => {
  let resolve!: (value: unknown) => void; mocks.post.mockReturnValue(new Promise(done => { resolve = done; })); page(); await form();
  const button = screen.getByRole("button", { name: "Create verification trial" }); fireEvent.click(button); fireEvent.click(button);
  expect(mocks.post).toHaveBeenCalledTimes(1);
  await act(async () => resolve({ data: trial }));
});
it("recovers durable trial phases and copies the real public qualification command", async () => {
  currentTrial = { ...trial, state: "running", phases: [{ ...trial.phases[0], state: "passed", observed_at: "2030-01-01T00:00:10Z" }, ...trial.phases.slice(1)] }; page({ initialTrial: currentTrial });
  const phases = within(screen.getByRole("list", { name: "Qualification phases" }));
  expect(phases.getByText("Initial private SSH readiness")).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Start qualification trial" })).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Copy qualification command" }));
  await waitFor(() => expect(mocks.copy).toHaveBeenCalledWith(trial.qualification_command));
  expect(mocks.copy.mock.calls[0][0]).not.toContain("bootstrap_token");
  expect(screen.queryByText(/Trial complete/)).toBeNull();
});
it("hides stale trial SSH instructions and phase claims after a failed status poll", async () => {
  vi.useFakeTimers(); const ready = { ...trial, state: "pending" as const, observed_state: "ready", connection };
  mocks.get.mockResolvedValueOnce({ data: ready }).mockRejectedValue(new Error("offline")); page({ initialTrial: ready });
  await act(async () => {}); expect(screen.getByRole("button", { name: "Copy trial SSH command" })).toBeTruthy();
  expect(screen.getByText("Native verification in progress")).toBeTruthy();
  await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
  expect(screen.getByText("Trial status unconfirmed")).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Copy trial SSH command" })).toBeNull();
  expect((screen.getByRole("button", { name: "Copy qualification command" }) as HTMLButtonElement).disabled).toBe(true);
});
it.each(["offline", "revoked", "pending_cleanup"] as const)("does not offer private SSH after runner status becomes %s", state => {
  currentTrial = { ...trial, state: "running", observed_state: "ready", connection }; page({ enrollmentState: state, initialTrial: currentTrial });
  expect(screen.queryByRole("button", { name: "Copy trial SSH command" })).toBeNull();
});
it("does not renew an expired trial deadline or show SSH from old Ready metadata", () => {
  currentTrial = { ...trial, state: "awaiting_expiry", observed_state: "ready", expires_at: "2000-01-01T00:15:00Z", connection }; page({ initialTrial: currentTrial });
  expect(screen.queryByRole("button", { name: "Copy trial SSH command" })).toBeNull();
  expect(screen.getByText("Waiting for the original expiry")).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Start new qualification trial" })).toBeNull();
});
it("hides private SSH at the original deadline without waiting for another poll", async () => {
  vi.useFakeTimers(); vi.setSystemTime(new Date("2030-01-01T00:14:59Z"));
  currentTrial = { ...trial, state: "awaiting_expiry", observed_state: "ready", connection };
  page({ initialTrial: currentTrial });
  await act(async () => {});
  expect(screen.getByRole("button", { name: "Copy trial SSH command" })).toBeTruthy();
  await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
  expect(screen.queryByRole("button", { name: "Copy trial SSH command" })).toBeNull();
  expect(mocks.get).toHaveBeenCalledTimes(1);
});
it("requires actual retirement before displaying completion or reusing the slot", () => {
  currentTrial = { ...trial, state: "complete", generation: 4, desired_state: "deleted", observed_state: "deleted", phases: trial.phases.map(phase => ({ ...phase, state: "passed" })) }; page({ initialTrial: currentTrial });
  expect(screen.getByText("Retirement unconfirmed")).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Start new qualification trial" })).toBeNull();
  cleanup(); currentTrial = { ...currentTrial, retired_at: "2030-01-01T00:15:10Z" }; page({ initialTrial: currentTrial });
  expect(screen.getByText("Trial complete · retirement confirmed")).toBeTruthy();
  expect(screen.getByText(/Approval and fresh runner health are still required/)).toBeTruthy();
  expect(screen.queryByRole("link", { name: /Create sandbox/ })).toBeNull();
});
it("keeps failed cleanup occupied and supports a new attempt only after retirement", () => {
  currentTrial = { ...trial, state: "failed", blocked_reasons: ["native_verification_failed"] }; page({ initialTrial: currentTrial });
  expect(screen.getByText("Trial failed · cleanup pending")).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Start new qualification trial" })).toBeNull();
  cleanup(); currentTrial = { ...currentTrial, retired_at: "2030-01-01T00:15:10Z" }; page({ initialTrial: currentTrial });
  expect(screen.getByRole("button", { name: "Start new qualification trial" })).toBeTruthy();
});
it("keeps confirmed retirement when an older enrollment snapshot arrives late", () => {
  const retired: Trial = { ...trial, state: "complete", generation: 4, retired_at: "2030-01-01T00:15:10Z" };
  currentTrial = retired; const view = page({ initialTrial: retired });
  view.rerender(<SandboxRunnerQualificationTrial orgId="org-a" enrollmentId="enrollment-a" terminalGatewayId="gateway-a" enrollmentState="awaiting_connection" confirmed initialTrial={{ ...trial, generation: 3 }} />);
  expect(screen.getByText("Trial complete · retirement confirmed")).toBeTruthy();
});
it("keeps a new trial when an older completed trial arrives in enrollment metadata", () => {
  const newer: Trial = { ...trial, id: "new-trial", created_at: "2030-01-02T00:00:00Z", expires_at: "2030-01-02T00:15:00Z", qualification_command: "public-new-trial-command" };
  currentTrial = newer; const view = page({ initialTrial: newer });
  view.rerender(<SandboxRunnerQualificationTrial orgId="org-a" enrollmentId="enrollment-a" terminalGatewayId="gateway-a" enrollmentState="awaiting_connection" confirmed initialTrial={{ ...trial, state: "complete", generation: 4, retired_at: "2030-01-01T00:15:10Z" }} />);
  expect(screen.getByLabelText("Public qualification command").textContent).toBe("public-new-trial-command");
  expect(screen.queryByText("Trial complete · retirement confirmed")).toBeNull();
});
