import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const { get, post, org } = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), org: { id: "org-a", name: "Acme", managed_agent_runtime_enabled: true } }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "user-a", email: "owner@example.test", email_verified: true } } }) }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { GET: get, POST: post, PUT: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() } };
});

import AgentDetail from "../src/pages/AgentDetail";
import { agentRuntimeUpdateCommand } from "../src/lib/agentview";
import type { BootstrapRelease } from "../src/lib/api";

const asset = (name: string, digit: string) => ({ name, sha256: digit.repeat(64), source_sha: "a".repeat(40) });
const release: BootstrapRelease = {
  tag: "v0.5.0", source_sha: "a".repeat(40), manifest_url: "https://release.example/v0.5.0/release.json",
  verifier_key_id: "release-2026-01", verifier_public_key: "tI_5mSPEMFKt5YDNymOVJpDwfwg3LDWBS6pEy4TWdKA",
  runtime: { binary: "tunnex-agent-runtime", version: "v0.5.0", linux_amd64: asset("tunnex-agent-runtime-linux-amd64", "3"), linux_arm64: asset("tunnex-agent-runtime-linux-arm64", "4"), unit: asset("tunnex-agent-runtime.service", "5") },
  verifier: { linux_amd64: asset("releaseverify-linux-amd64", "6"), linux_arm64: asset("releaseverify-linux-arm64", "7") },
};
const releasePath = "/api/v1/organizations/{orgId}/agents/runtime-release";
const sentence = "Replaces the Tunnex runtime on this agent's host with the current release. The agent keeps its identity, access and MCP settings, and no install token is needed.";
let role = "owner";
let status = "active";
let releaseResult: () => Promise<unknown> = async () => ({ data: release });
const writeText = vi.fn();

beforeEach(() => {
  role = "owner"; status = "active"; releaseResult = async () => ({ data: release });
  writeText.mockResolvedValue(undefined);
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
  get.mockImplementation(async (path: string) => {
    if (path === releasePath) return releaseResult();
    if (path.endsWith("/agents/{deviceId}")) return { data: { device_id: "agent-a", name: "builder", environment: "prod", runtime: "python", labels: {}, owner_id: "user-a", owner_email: "owner@example.test", managing_group_id: null, managing_group_name: null, status, last_handshake_at: null, permissions: { view_privileged: true, manage: true, assign: true, grant_access: true, revoke: true, rotate_credentials: true } } };
    if (path.endsWith("/runtime-status")) return { data: { connectivity: "connected", health: "ready", stale: false, last_seen_at: "2026-11-27T10:00:00Z", desired_revision: 2, applied_revision: 2, client_version: "v0.4.0" } };
    if (path.endsWith("/credential-rotation")) return { data: { device_id: "agent-a", current_revision: 1, state: "current", requested_revision: null, deadline: null, wireguard_current_revision: 1, wireguard_state: "current", wireguard_requested_revision: null } };
    if (path.endsWith("/effective-mcp-profile")) return { data: { assigned: false } };
    if (path.endsWith("/members")) return { data: [{ user_id: "user-a", email: "owner@example.test", role, status: "active" }] };
    if (path === "/api/v1/license") return { data: { state: "unlicensed", tier: "community", features: [] } };
    return { data: [] };
  });
});
afterEach(() => { cleanup(); get.mockReset(); post.mockReset(); writeText.mockReset(); });

const open = () => render(<MemoryRouter initialEntries={["/agents/agent-a?tab=runtime"]}><AgentDetail agentIdOverride="agent-a" /></MemoryRouter>);
const panel = async () => within((await screen.findByRole("heading", { name: "Update runtime" })).closest("section") as HTMLElement);
const releaseCalls = () => get.mock.calls.filter(([path]) => path === releasePath);

describe("Update runtime on the agent Runtime tab", () => {
  it("sits with the runtime status and credential rotation, and says what it keeps", async () => {
    open();
    const update = await panel();
    expect(update.getByText(sentence)).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Managed runtime" })).toBeTruthy();
    expect(await screen.findByRole("heading", { name: "Credential rotation" })).toBeTruthy();
    // Nothing is fetched and no command is shown until it is asked for.
    expect(releaseCalls()).toHaveLength(0);
    expect(screen.queryByTestId("runtime-update-command")).toBeNull();
  });

  it("shows the update command for the served release without issuing an install token, and copies it", async () => {
    open();
    const update = await panel();
    fireEvent.click(update.getByRole("button", { name: "Show update command" }));
    const shown = await screen.findByTestId("runtime-update-command");
    const command = agentRuntimeUpdateCommand(release);
    expect(shown.textContent).toBe(command);
    expect(command).toContain(release.verifier_public_key);
    expect(command).not.toMatch(/bootstrap_token|tnx_agent_|install token/);
    expect(releaseCalls()).toEqual([[releasePath, { params: { path: { orgId: "org-a" } } }]]);
    expect(post).not.toHaveBeenCalled();
    expect(update.getByText("Run it on the agent's host as root or with sudo. It installs runtime v0.5.0 and restarts the agent service; if the service does not start, the previous runtime is put back.")).toBeTruthy();
    fireEvent.click(update.getByRole("button", { name: "Copy command" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(command));
    expect(await update.findByRole("button", { name: "Copied" })).toBeTruthy();
  });

  it("says so when the command cannot be copied", async () => {
    writeText.mockRejectedValue(new Error("denied"));
    open();
    const update = await panel();
    fireEvent.click(update.getByRole("button", { name: "Show update command" }));
    fireEvent.click(await update.findByRole("button", { name: "Copy command" }));
    expect(await update.findByText("Could not copy. Select the command and copy it by hand.")).toBeTruthy();
  });

  it("explains an older release that needs a verifier already on the host", async () => {
    const legacy = { ...release }; delete legacy.verifier;
    releaseResult = async () => ({ data: legacy });
    open();
    const update = await panel();
    fireEvent.click(update.getByRole("button", { name: "Show update command" }));
    expect(await update.findByText("This older release needs the signed release verifier to be installed on the host already; the command stops without changing anything if it is missing.")).toBeTruthy();
  });

  it("says when no signed release is available, shows no command, and can be retried", async () => {
    releaseResult = async () => ({ error: { error: { code: "bootstrap_unavailable", message: "managed agent enrollment is temporarily unavailable" } } });
    open();
    const update = await panel();
    fireEvent.click(update.getByRole("button", { name: "Show update command" }));
    expect((await update.findByRole("alert")).textContent).toBe("The runtime release is not available from this Tunnex server right now, so there is no update command to run. Nothing was changed on the agent. Try again later.");
    expect(screen.queryByTestId("runtime-update-command")).toBeNull();
    releaseResult = async () => ({ data: release });
    fireEvent.click(update.getByRole("button", { name: "Try again" }));
    expect(await screen.findByTestId("runtime-update-command")).toBeTruthy();
    expect(update.queryByRole("alert")).toBeNull();
  });

  it("reports a failed request plainly", async () => {
    releaseResult = async () => { throw new Error("network"); };
    open();
    const update = await panel();
    fireEvent.click(update.getByRole("button", { name: "Show update command" }));
    expect((await update.findByRole("alert")).textContent).toBe("Could not load the update command. Nothing was changed on the agent.");
  });

  it("is not offered to a member who cannot enrol agents", async () => {
    role = "member";
    open();
    expect(await screen.findByRole("heading", { name: "Credential rotation" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Update runtime" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Show update command" })).toBeNull();
    expect(releaseCalls()).toHaveLength(0);
  });

  it("is not offered for a revoked agent", async () => {
    status = "revoked";
    open();
    expect(await screen.findByRole("heading", { name: "Credential rotation" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Update runtime" })).toBeNull();
  });
});
