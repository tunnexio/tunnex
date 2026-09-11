import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

const { get, post } = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { GET: get, POST: post, PATCH: vi.fn(), PUT: vi.fn(), DELETE: vi.fn() } };
});

import { AddAgentFlow } from "../src/components/AddAgentFlow";

beforeEach(() => {
  get.mockReset(); post.mockReset();
  get.mockImplementation(async (path: string) => path.endsWith("/nodes") ? { data: [{ id: "gateway-a", name: "Gateway A", status: "active" }] } : { data: { managed_agent_runtime_enabled: true } });
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

  it("keeps the waiting specimen pending until a server-owned status contract exists", () => {
    render(<AddAgentFlow orgId="org-a" enabled visualStage="waiting" onDismiss={vi.fn()} />);
    expect(screen.getByText(/Enrollment remains pending until a future server-owned status contract/i)).toBeTruthy();
    expect(screen.queryByText(/Agent connected/i)).toBeNull();
  });
});

it("uses fresh runtime settings instead of a stale disabled organization snapshot", async () => {
  get.mockImplementation(async (path: string) => path.endsWith("/nodes") ? {data:[{id:"gateway-a",name:"Gateway A",status:"active"}]} : {data:{managed_agent_runtime_enabled:true}});
  render(<AddAgentFlow orgId="org-a" enabled runtimeEnabled={false} onDismiss={vi.fn()} />);
  expect(await screen.findByRole("heading", {name:/Step 1 of 3/})).toBeTruthy();
  expect(get).toHaveBeenCalledWith("/api/v1/organizations/{orgId}", {params:{path:{orgId:"org-a"}}});
});

it("refuses a stale enabled snapshot when the server runtime opt-in is off", async () => {
  get.mockResolvedValue({data:{managed_agent_runtime_enabled:false}});
  render(<AddAgentFlow orgId="org-a" enabled runtimeEnabled onDismiss={vi.fn()} />);
  expect(await screen.findByRole("heading", {name:"Enable the agent runtime first"})).toBeTruthy();
  expect(post).not.toHaveBeenCalled();
});

it("keeps unreadable runtime state unavailable and retries the read", async () => {
  get.mockResolvedValue({error:{error:{code:"unavailable"}}});
  render(<AddAgentFlow orgId="org-a" enabled onDismiss={vi.fn()} />);
  expect(await screen.findByText("Could not verify runtime synchronization. Retry before installing an agent.")).toBeTruthy();
  expect(screen.queryByText(/It is currently off/)).toBeNull();
  expect(post).not.toHaveBeenCalled();
  get.mockImplementation(async (path: string) => path.endsWith("/nodes") ? {data:[]} : {data:{managed_agent_runtime_enabled:true}});
  fireEvent.click(screen.getByRole("button",{name:"Retry"}));
  expect(await screen.findByRole("heading",{name:/Step 1 of 3/})).toBeTruthy();
  expect(screen.queryByText(/Could not load gateways/)).toBeNull();
});
