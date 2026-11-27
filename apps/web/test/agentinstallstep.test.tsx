import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const { get } = vi.hoisted(() => ({ get: vi.fn() }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { GET: get, POST: vi.fn(), PUT: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() } };
});

import { AgentInstallStep, INSTALL_SLOW_AFTER_MS, INSTALL_STATUS_POLL_MS } from "../src/components/AgentInstallStep";
import { agentBootstrapCommand } from "../src/lib/agentview";
import type { BootstrapRelease } from "../src/lib/api";

const TOKEN = "tnx_agent_fixture-only_TOKEN";
const START = new Date("2026-11-27T10:00:00Z").getTime();
const sha = (c: string) => c.repeat(64);
const release: BootstrapRelease = {
  tag: "v1.0.0", source_sha: "a".repeat(40), manifest_url: "https://release.example/v1.0.0/release.json", verifier_key_id: "k", verifier_public_key: "key",
  runtime: { binary: "tunnex-agent-runtime", version: "v1.0.0", linux_amd64: { name: "rt-amd64", sha256: sha("b"), source_sha: "a".repeat(40) }, linux_arm64: { name: "rt-arm64", sha256: sha("c"), source_sha: "a".repeat(40) }, unit: { name: "rt.service", sha256: sha("d"), source_sha: "a".repeat(40) } },
};
const command = agentBootstrapCommand(release, "https://cp.example");
const tokenFileCommand = agentBootstrapCommand(release, "https://cp.example", { tokenFile: true });
const base = { id: "token-1", agent_name: "billing-runner", expires_at: "2026-11-27T11:00:00Z" };
const pending = { ...base, state: "pending", enrolled_at: null, device_id: null, tunnel: null };
const enrolled = (tunnel: Record<string, unknown>) => ({ ...base, state: "enrolled", enrolled_at: "2026-11-27T10:02:11Z", device_id: "device-1", tunnel });
const at = (iso: string) => new Date(iso).toLocaleTimeString();

let answer: () => unknown = () => ({ data: pending });
const dismiss = vi.fn();
function show(props: { tokenId?: string | null } = {}) {
  return render(<MemoryRouter><AgentInstallStep orgId="org-a" command={command} tokenFileCommand={tokenFileCommand} token={TOKEN} tokenId={props.tokenId === null ? undefined : props.tokenId ?? "token-1"} origin="https://cp.example" issuedAt={START} onDismiss={dismiss} /></MemoryRouter>);
}
const status = () => within(screen.getByRole("region", { name: "Install status" }));
const tick = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });

beforeEach(() => {
  vi.useFakeTimers({ now: START });
  answer = () => ({ data: pending });
  get.mockImplementation(async () => answer());
  dismiss.mockReset();
});
afterEach(() => { cleanup(); vi.useRealTimers(); get.mockReset(); });

describe("add-agent install step", () => {
  it("keeps the command and the token on screen and reads the status for this token every 3 seconds", async () => {
    show();
    await tick(0);
    expect(get).toHaveBeenCalledTimes(1);
    expect(get).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/agents/bootstrap-tokens/{tokenId}", { params: { path: { orgId: "org-a", tokenId: "token-1" } } });
    expect(INSTALL_STATUS_POLL_MS).toBe(3000);
    expect(status().getByText("Waiting for the agent to enroll. Run the command on the host.")).toBeTruthy();
    expect(status().getByText("The tunnel connects after the agent enrolls.")).toBeTruthy();
    await tick(3000);
    expect(get).toHaveBeenCalledTimes(2);
    await tick(6000);
    expect(get).toHaveBeenCalledTimes(4);
    expect(screen.getByTestId("ots-secret").textContent).toBe(command);
    expect(screen.getByTestId("ots-extra-secret").textContent).toBe(TOKEN);
    expect(screen.queryByRole("region", { name: "What to check on the host" })).toBeNull();
  });

  it("shows enrolled with its time while the tunnel is still coming up", async () => {
    answer = () => ({ data: enrolled({ connected: false, last_handshake_at: null, gateway_reporting: true }) });
    show(); await tick(0);
    expect(status().getByText(`Enrolled at ${at("2026-11-27T10:02:11Z")}`)).toBeTruthy();
    expect(status().getByText("Waiting for the tunnel to connect.")).toBeTruthy();
    expect(screen.queryByRole("link", { name: /Open billing-runner/ })).toBeNull();
    await tick(3000);
    expect(get).toHaveBeenCalledTimes(2);
  });

  it("shows the tunnel connected with its time, links to the agent and stops reading", async () => {
    answer = () => ({ data: enrolled({ connected: true, last_handshake_at: "2026-11-27T10:02:40Z", gateway_reporting: true }) });
    show(); await tick(0);
    expect(status().getByText(`Enrolled at ${at("2026-11-27T10:02:11Z")}`)).toBeTruthy();
    expect(status().getByText(`Tunnel connected at ${at("2026-11-27T10:02:40Z")}`)).toBeTruthy();
    expect(screen.getByRole("link", { name: "Open billing-runner" }).getAttribute("href")).toBe("/agents/device-1");
    await tick(30_000);
    expect(get).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    expect(dismiss).toHaveBeenCalledOnce();
    // The token is still there to copy until the panel is closed.
    expect(screen.getByTestId("ots-extra-secret").textContent).toBe(TOKEN);
  });

  it("says unknown, never offline, when the agent's gateway is not reporting", async () => {
    answer = () => ({ data: enrolled({ connected: false, last_handshake_at: null, gateway_reporting: false }) });
    show(); await tick(0);
    expect(status().getByText("Tunnel status unknown: this agent's gateway is not reporting connections right now.")).toBeTruthy();
    expect(status().queryByText(/offline|not connected|Waiting for the tunnel/i)).toBeNull();
  });

  it.each([["revoked", /install token was revoked/], ["expired", /install token expired before an agent used it/]])("says a %s token can no longer be used and stops reading", async (state, message) => {
    answer = () => ({ data: { ...pending, state } });
    show(); await tick(0);
    expect(status().getByText(message)).toBeTruthy();
    await tick(30_000);
    expect(get).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("region", { name: "What to check on the host" })).toBeNull();
  });

  it("does not turn a failed status read into a claim, and keeps trying", async () => {
    answer = () => ({ error: { error: { code: "agent_ux_not_implemented" } } });
    show(); await tick(0);
    expect(status().getByText("Could not read the install status. Trying again.")).toBeTruthy();
    expect(status().queryByText(/Enrolled|Waiting for the agent/)).toBeNull();
    answer = () => ({ data: pending });
    await tick(3000);
    expect(status().getByText("Waiting for the agent to enroll. Run the command on the host.")).toBeTruthy();
    expect(status().queryByText(/Could not/)).toBeNull();
  });

  it("makes no status claim when the server gave no token id", async () => {
    show({ tokenId: null }); await tick(9000);
    expect(get).not.toHaveBeenCalled();
    expect(status().getByText(/does not report install progress here/)).toBeTruthy();
  });

  it("after ten minutes shows the three likely causes, each with a check to run on the host", async () => {
    show(); await tick(0);
    await tick(INSTALL_SLOW_AFTER_MS - 3000);
    expect(screen.queryByRole("region", { name: "What to check on the host" })).toBeNull();
    await tick(3000);
    const help = within(screen.getByRole("region", { name: "What to check on the host" }));
    expect(help.getByRole("heading", { name: "Nothing has connected after ten minutes" })).toBeTruthy();
    const causes = help.getAllByRole("listitem");
    expect(causes).toHaveLength(3);
    expect(causes[0].textContent).toContain("The command was not run, or the wrong token was entered.");
    expect(causes[0].textContent).toContain("sudo systemctl status tunnex-agent-runtime");
    expect(causes[1].textContent).toContain("The host cannot reach Tunnex over HTTPS.");
    expect(causes[1].textContent).toContain("curl -sI https://cp.example");
    expect(causes[2].textContent).toContain("WireGuard traffic (UDP) to the gateway is blocked.");
    expect(causes[2].textContent).toContain("sudo wg show");
    // The command and token are still there to use.
    expect(screen.getByTestId("ots-extra-secret").textContent).toBe(TOKEN);
  });

  it("still shows the checks when the agent enrolled but its tunnel never connected", async () => {
    answer = () => ({ data: enrolled({ connected: false, last_handshake_at: null, gateway_reporting: true }) });
    show(); await tick(INSTALL_SLOW_AFTER_MS);
    expect(screen.getByRole("region", { name: "What to check on the host" })).toBeTruthy();
  });

  it("never shows the checks for an agent that connected", async () => {
    answer = () => ({ data: enrolled({ connected: true, last_handshake_at: "2026-11-27T10:02:40Z", gateway_reporting: true }) });
    show(); await tick(INSTALL_SLOW_AFTER_MS + 60_000);
    expect(screen.queryByRole("region", { name: "What to check on the host" })).toBeNull();
  });

  it("offers a host with no terminal a command that reads the token from a root-only file, and never puts the token in it", async () => {
    show(); await tick(0);
    expect(screen.queryByRole("group", { name: "Supply the token from a file" })).toBeNull();
    fireEvent.click(screen.getByRole("checkbox", { name: "This host has no terminal" }));
    const shown = screen.getByTestId("ots-secret").textContent ?? "";
    expect(shown).toBe(tokenFileCommand);
    expect(shown).not.toContain(TOKEN);
    // Only the shape check names the prefix; no token value follows it anywhere.
    expect(shown).not.toMatch(/tnx_agent_[A-Za-z0-9]/);
    expect(shown).toContain("token_file=/root/tunnex-install-token;");
    expect(shown).not.toContain("/dev/tty");
    const how = screen.getByRole("group", { name: "Supply the token from a file" });
    expect(how.textContent).toContain("/root/tunnex-install-token");
    expect(how.textContent).toContain("owned by root with mode 600");
    expect(how.textContent).toContain("configuration management tool, or an editor");
    expect(how.textContent).toContain("sudoedit /root/tunnex-install-token");
    expect(how.textContent).toContain("It reads the file once and deletes it before it contacts anything.");
    // The instructions never show a command line that carries the token.
    expect(how.textContent).not.toContain(TOKEN);
    expect(how.textContent).not.toMatch(/echo\s+\S*tnx_|echo .*>/);
    expect(how.textContent).toContain("Do not write the token with echo");
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    fireEvent.click(screen.getByRole("button", { name: "Copy command" }));
    await tick(0);
    expect(writeText).toHaveBeenLastCalledWith(tokenFileCommand);
    fireEvent.click(screen.getByRole("checkbox", { name: "This host has no terminal" }));
    expect(screen.getByTestId("ots-secret").textContent).toBe(command);
  });

  it("closes only through its own button", async () => {
    show(); await tick(0);
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    expect(dismiss).not.toHaveBeenCalled();
    expect(screen.getByTestId("ots-extra-secret").textContent).toBe(TOKEN);
    fireEvent.click(screen.getByRole("button", { name: /I.ve saved it/ }));
    expect(dismiss).toHaveBeenCalledOnce();
  });
});
