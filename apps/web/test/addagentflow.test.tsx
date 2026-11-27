import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

const { get, post } = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { GET: get, POST: post, PATCH: vi.fn(), PUT: vi.fn(), DELETE: vi.fn() } };
});

import { MemoryRouter } from "react-router-dom";
import type { ComponentProps } from "react";
import { AddAgentFlow as Flow } from "../src/components/AddAgentFlow";

const AddAgentFlow = (props: ComponentProps<typeof Flow>) => <MemoryRouter><Flow {...props} /></MemoryRouter>;
const features = (runtime: boolean, available = true) => ({ data: { items: [{ key: "runtime_sync", enabled: runtime, available, required_plan: available ? null : "starter" }] } });

beforeEach(() => {
  get.mockReset(); post.mockReset();
  get.mockImplementation(async (path: string) => path.endsWith("/nodes") ? { data: [{ id: "gateway-a", name: "Gateway A", status: "active" }] } : features(true));
  post.mockResolvedValue({ data: { bootstrap_token: "tnx_test_once", release: { tag: "v1.0.0", source_sha: "a".repeat(40), manifest_url: "https://example.test/release.json", verifier_key_id: "test", verifier_public_key: "key", runtime: { binary: "tunnex-agent-runtime", version: "v1.0.0", linux_amd64: { name: "runtime-amd64", sha256: "b".repeat(64), source_sha: "a".repeat(40) }, linux_arm64: { name: "runtime-arm64", sha256: "c".repeat(64), source_sha: "a".repeat(40) }, unit: { name: "runtime.service", sha256: "d".repeat(64), source_sha: "a".repeat(40) } } } } });
});
afterEach(() => cleanup());

describe("Add Agent flow", () => {
  it("validates only on continue, reviews before the token mutation, and shows the command once", async () => {
    const dismiss = vi.fn();
    render(<AddAgentFlow orgId="org-a" enabled onDismiss={dismiss} />);
    await screen.findByRole("heading", { name: /Step 1 of 3/ });
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByText(/Enter an agent name and choose a gateway/)).toBeTruthy();
    expect(post).not.toHaveBeenCalled();

    fireEvent.change(screen.getByLabelText("Agent name"), { target: { value: "jira-runner" } });
    fireEvent.change(screen.getByLabelText("Gateway"), { target: { value: "gateway-a" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    await screen.findByRole("heading", { name: /Step 2 of 3/ });
    expect(screen.getByText("jira-runner")).toBeTruthy();
    expect(screen.getByText("Gateway A")).toBeTruthy();
    expect(post).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Issue one-time command" }));
    await waitFor(() => expect(post).toHaveBeenCalledWith(
      "/api/v1/organizations/{orgId}/agents/bootstrap-token",
      { params: { path: { orgId: "org-a" } }, body: { name: "jira-runner", gateway_id: "gateway-a" } },
    ));
    await screen.findByText(/Step 3 of 3/);
    expect(screen.getByText(/no agent is claimed as enrolled/i)).toBeTruthy();

    // The command and the token are separate. The command is what gets pasted
    // into a shell (and its history), so it must not carry the token.
    const command = screen.getByTestId("ots-secret");
    expect(command.textContent).toContain("sh <<'TUNNEX_BOOTSTRAP'");
    expect(command.textContent).not.toContain("tnx_test_once");
    expect(screen.getByTestId("ots-extra-secret").textContent).toBe("tnx_test_once");
    expect(screen.getAllByText("tnx_test_once")).toHaveLength(1);
    expect(screen.getByText("Install token")).toBeTruthy();
    expect(screen.getByText("The command asks for this token when it runs, so the token stays out of your shell history.")).toBeTruthy();
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    fireEvent.click(screen.getByRole("button", { name: "Copy token" }));
    await waitFor(() => expect(writeText).toHaveBeenLastCalledWith("tnx_test_once"));
    fireEvent.click(screen.getByRole("button", { name: "Copy command" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(2));
    expect(writeText.mock.calls[1][0]).toContain("sh <<'TUNNEX_BOOTSTRAP'");
    expect(writeText.mock.calls[1][0]).not.toContain("tnx_test_once");
    fireEvent.click(screen.getByText("Host requirements", { selector: "summary" }));
    expect(screen.getByText(/Missing host dependencies are installed automatically/i)).toBeTruthy();
    expect(screen.getByText(/older release requires a preinstalled release verifier/i)).toBeTruthy();
    fireEvent.click(within(screen.getByText(/Step 3 of 3/).closest("div.fixed")!).getByRole("button", { name: /I.ve saved it/ }));
    expect(dismiss).toHaveBeenCalledOnce();
  });

  it("reports a truthful issuance failure and never claims enrollment", async () => {
    post.mockResolvedValue({ error: { error: { code: "bootstrap_unavailable", message: "Verified release is unavailable." } } });
    render(<AddAgentFlow orgId="org-a" enabled onDismiss={vi.fn()} />);
    await screen.findByRole("heading", { name: /Step 1 of 3/ });
    fireEvent.change(screen.getByLabelText("Agent name"), { target: { value: "jira-runner" } });
    fireEvent.change(screen.getByLabelText("Gateway"), { target: { value: "gateway-a" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    await screen.findByRole("heading", { name: /Step 2 of 3/ });
    fireEvent.click(screen.getByRole("button", { name: "Issue one-time command" }));
    expect(await screen.findByText(/Verified release is unavailable.*has not enrolled/i)).toBeTruthy();
    expect(screen.queryByText(/Agent connected/i)).toBeNull();
  });

  it("shows a token-free specimen command in the design gallery", () => {
    render(<AddAgentFlow orgId="org-a" enabled visualStage="token" onDismiss={vi.fn()} />);
    expect(screen.getByTestId("ots-secret").textContent).not.toMatch(/tnx_|--token/);
    expect(screen.getByTestId("ots-extra-secret").textContent).toMatch(/^tnx_agent_/);
  });

  it("keeps the waiting specimen pending until a server-owned status contract exists", () => {
    render(<AddAgentFlow orgId="org-a" enabled visualStage="waiting" onDismiss={vi.fn()} />);
    expect(screen.getByText(/Enrollment remains pending until a future server-owned status contract/i)).toBeTruthy();
    expect(screen.queryByText(/Agent connected/i)).toBeNull();
  });
});

it("uses fresh runtime settings instead of a stale disabled organization snapshot", async () => {
  render(<AddAgentFlow orgId="org-a" enabled runtimeEnabled={false} onDismiss={vi.fn()} />);
  expect(await screen.findByRole("heading", {name:/Step 1 of 3/})).toBeTruthy();
  expect(screen.getByLabelText("Agent name")).toBeTruthy();
  expect(get).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/agent-features", {params:{path:{orgId:"org-a"}}});
});

it("turns runtime synchronization on inside the flow instead of sending the administrator to Settings", async () => {
  const put = vi.fn(async () => ({ data: { enabled: true } }));
  const { api } = await import("../src/lib/api");
  (api as unknown as { PUT: typeof put }).PUT = put;
  get.mockImplementation(async (path: string) => path.endsWith("/nodes") ? {data:[{id:"gateway-a",name:"Gateway A",status:"active"}]} : features(false));
  render(<AddAgentFlow orgId="org-a" enabled runtimeEnabled onDismiss={vi.fn()} />);
  const toggle = await screen.findByRole("switch", {name:"Runtime synchronization"});
  expect(screen.queryByRole("heading", {name:"Enable the agent runtime first"})).toBeNull();
  expect(screen.queryByRole("link", {name:/Settings/})).toBeNull();
  expect(screen.queryByLabelText("Agent name")).toBeNull();
  expect(post).not.toHaveBeenCalled();
  fireEvent.click(toggle);
  await waitFor(() => expect(put).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/agent-runtime-settings", {params:{path:{orgId:"org-a"}},body:{enabled:true}}));
  expect(await screen.findByLabelText("Agent name")).toBeTruthy();
});

it("names the plan and offers no working switch when this edition cannot add agents", async () => {
  get.mockImplementation(async (path: string) => path.endsWith("/nodes") ? {data:[]} : features(true, false));
  render(<AddAgentFlow orgId="org-a" enabled onDismiss={vi.fn()} />);
  const toggle = await screen.findByRole("switch", {name:"Runtime synchronization"}) as HTMLButtonElement;
  expect(toggle.disabled).toBe(true);
  expect(screen.getByText(/Included in the Starter plan\./)).toBeTruthy();
  expect(screen.queryByLabelText("Agent name")).toBeNull();
});

it("keeps unreadable runtime state unavailable and retries the read", async () => {
  get.mockResolvedValue({error:{error:{code:"unavailable"}}});
  render(<AddAgentFlow orgId="org-a" enabled onDismiss={vi.fn()} />);
  expect(await screen.findByText("Could not verify runtime synchronization. Retry before installing an agent.")).toBeTruthy();
  expect(screen.queryByRole("switch")).toBeNull();
  expect(post).not.toHaveBeenCalled();
  get.mockImplementation(async (path: string) => path.endsWith("/nodes") ? {data:[]} : features(true));
  fireEvent.click(screen.getByRole("button",{name:"Retry"}));
  expect(await screen.findByRole("heading",{name:/Step 1 of 3/})).toBeTruthy();
  expect(screen.queryByText(/Could not load gateways/)).toBeNull();
});
