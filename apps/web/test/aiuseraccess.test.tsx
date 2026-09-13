import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AIAccessGate, AIGroupAccess, AIUseModel } from "../src/components/AIUserAccess";
import { AIProviderWorkspace } from "../src/components/AIProviderWorkspace";
const mock = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), success: vi.fn() }));
vi.mock("../src/lib/api", () => ({ api: { GET: mock.get, POST: mock.post } }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "user" } } }) }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: "org" }, orgs: [{ id: "org", name: "Demo" }], loading: false, failed: false }) }));
vi.mock("../src/components/Toasts", () => ({ toast: { success: mock.success, error: vi.fn() } }));
afterEach(cleanup);beforeEach(() => vi.clearAllMocks());
const provider = { id: "connection", name: "azure", provider: "azure_ai", models: ["custom-connection/gpt-5"], model_modes: { "custom-connection/gpt-5": "chat" }, status: "applied", enabled: true, revision: 1, applied_revision: 1, last_test_status: "success" };
describe("AI user access", () => {
  it.each([["ai-admin", true], ["ai-view", false]] as const)("scopes %s to AI", async (role, manage) => {
    mock.get.mockResolvedValue({ data: [{ user_id: "user", role, roles: ["member", role] }] });
    render(<AIAccessGate>{(_, access) => <p>{JSON.stringify(access)}</p>}</AIAccessGate>);
    expect(await screen.findByText(JSON.stringify({ view: true, manage, agents: false, workloadsView: true, workloadsManage: manage }))).toBeTruthy();
  });
  it("grants Engineering a configured model", async () => {
    mock.get.mockImplementation((path: string) => Promise.resolve({ data: path.endsWith("user-groups") ? [{ id: "engineering", name: "Engineering", members: 4 }] : path.endsWith("user-model-grants") ? [] : { items: [provider] } }));
    mock.post.mockResolvedValue({ data: { id: "grant", group_id: "engineering", group_name: "Engineering", connection_id: provider.id, model: provider.models[0], enabled: true, status: "applied", revision: 1 } });
    render(<AIGroupAccess orgId="org" canManage />);
    fireEvent.click(await screen.findByRole("button", { name: "Grant access" }));
    await screen.findByRole("option", { name: "Engineering (4)" });
    fireEvent.change(screen.getByLabelText("User group"), { target: { value: "engineering" } });
    fireEvent.change(screen.getByLabelText("Model"), { target: { value: JSON.stringify([provider.id, provider.models[0]]) } });
    fireEvent.click(screen.getByRole("button", { name: "Grant model access" }));
    await waitFor(() => expect(mock.post).toHaveBeenCalledWith(expect.stringContaining("user-model-grants"), expect.objectContaining({ body: { group_id: "engineering", connection_id: provider.id, model: provider.models[0], enabled: true, expected_revision: 0 } })));
    expect(await screen.findByRole("button", { name: "Revoke access" })).toBeTruthy();
  });
  it("uses the login endpoint with conversation history and no provider key input", async () => {
    mock.get.mockResolvedValue({ data: [{ model: provider.models[0], mode: "chat" }] });
    mock.post.mockResolvedValue({ data: { choices: [{ message: { content: "Hello Engineering" } }] }, response: new Response("{}", { status: 200 }) });
    render(<AIUseModel orgId="org" />);
    await screen.findByRole("button", { name: "Send message" });
    fireEvent.change(screen.getByLabelText("Message"), { target: { value: "Hello" } });
    fireEvent.click(screen.getByRole("button", { name: "Send message" }));
    await screen.findByText("Hello Engineering");
    expect(mock.post).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/ai-gateway/inference/v1/chat/completions", expect.objectContaining({ params: { path: { orgId: "org" } } }));
    expect(screen.queryByLabelText(/API key/i)).toBeNull();
    expect(screen.getByText("Hello Engineering")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Message"), { target: { value: "Tell me more" } });
    fireEvent.click(screen.getByRole("button", { name: "Send message" }));
    await waitFor(() => expect(mock.post).toHaveBeenCalledTimes(2));
    expect(mock.post.mock.calls[1][1].body.messages).toEqual([{role:"user",content:"Hello"},{role:"assistant",content:"Hello Engineering"},{role:"user",content:"Tell me more"}]);
  });
  it("disables provider mutations for an AI viewer", async () => {
    mock.get.mockResolvedValue({ data: { items: [provider], definitions: [{ id: "azure_ai", name: "Azure AI Foundry" }], management_available: true, legacy_key_ids: [] } });
    render(<AIProviderWorkspace orgId="org" canManage={false} />);
    expect((await screen.findByRole("tab", { name: "Add Model" }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Edit credentials" }) as HTMLButtonElement).disabled).toBe(true);
  });
});
