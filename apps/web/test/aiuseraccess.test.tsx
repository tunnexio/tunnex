import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AIAccessGate, AIGroupAccess, AIUseModel } from "../src/components/AIUserAccess";
import { AIProviderWorkspace } from "../src/components/AIProviderWorkspace";
const mock = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), success: vi.fn(), roles: ["owner"], emailVerified: true }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api: { GET: mock.get, POST: mock.post } }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "user", email_verified: mock.emailVerified } } }) }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: "org" }, orgs: [{ id: "org", name: "Demo" }], loading: false, failed: false }) }));
vi.mock("../src/components/Toasts", () => ({ toast: { success: mock.success, error: vi.fn() } }));
afterEach(cleanup);beforeEach(() => { vi.resetAllMocks(); mock.roles = ["owner"]; mock.emailVerified = true; });
const provider = { id: "connection", name: "azure", provider: "azure_ai", models: ["custom-connection/gpt-5"], model_modes: { "custom-connection/gpt-5": "chat" }, status: "applied", enabled: true, revision: 1, applied_revision: 1, last_test_status: "success" };
const createdGroup = { id: "new-group", org_id: "org", name: "Research", description: "", member_count: 0, created_at: "2026-09-30T00:00:00Z", updated_at: "2026-09-30T00:00:00Z" };
function grantInventory(groups: Array<{ id: string; name: string; members: number }> = []) {
  mock.get.mockImplementation(async (path: string) => ({ data: path.endsWith("/members") ? [{ user_id: "user", role: "member", roles: mock.roles }] : path.endsWith("user-groups") ? groups : path.endsWith("user-model-grants") ? [] : { items: [provider] } }));
  mock.post.mockImplementation(async (path: string) => {
    if (path.endsWith("/groups")) { groups.push({ id: createdGroup.id, name: createdGroup.name, members: createdGroup.member_count }); return { data: createdGroup }; }
    return { data: { id: "grant", group_id: createdGroup.id, group_name: createdGroup.name, connection_id: provider.id, model: provider.models[0], enabled: true, status: "applied", revision: 1 } };
  });
}
function inlineGrant(onDone = vi.fn()) {
  render(<AIGroupAccess orgId="org" canManage dialogOnly initialConnection={provider.id} initialModel={provider.models[0]} onDone={onDone} />);
  return onDone;
}
async function openGroupCreation() {
  const button = await screen.findByRole("button", { name: "Create user group" });
  await waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(button);
  fireEvent.change(screen.getByLabelText("New group name"), { target: { value: " Research " } });
}
describe("AI user access", () => {
  it.each([["ai-admin", true], ["ai-view", false]] as const)("scopes %s to AI", async (role, manage) => {
    mock.get.mockResolvedValue({ data: [{ user_id: "user", role, roles: ["member", role] }] });
    render(<AIAccessGate>{(_, access) => <p>{JSON.stringify(access)}</p>}</AIAccessGate>);
    expect(await screen.findByText(JSON.stringify({ view: true, manage, agents: false, workloadsView: true, workloadsManage: manage }))).toBeTruthy();
  });
  it("grants Engineering a configured model", async () => {
    mock.get.mockImplementation((path: string) => Promise.resolve({ data: path.endsWith("/members") ? [{ user_id: "user", role: "owner" }] : path.endsWith("user-groups") ? [{ id: "engineering", name: "Engineering", members: 4 }] : path.endsWith("user-model-grants") ? [] : { items: [provider] } }));
    mock.post.mockResolvedValue({ data: { id: "grant", group_id: "engineering", group_name: "Engineering", connection_id: provider.id, model: provider.models[0], enabled: true, status: "applied", revision: 1 } });
    render(<AIGroupAccess orgId="org" canManage />);
    fireEvent.click(await screen.findByRole("button", { name: "Grant access" }));
    await screen.findByRole("option", { name: "Engineering (4)" });
    fireEvent.change(screen.getByLabelText("User group"), { target: { value: "engineering" } });
    fireEvent.change(screen.getByLabelText("Model"), { target: { value: JSON.stringify([provider.id, provider.models[0]]) } });
    fireEvent.click(screen.getByRole("button", { name: "Grant model access" }));
    await waitFor(() => expect(mock.post).toHaveBeenCalledWith(expect.stringContaining("user-model-grants"), expect.objectContaining({ body: { group_id: "engineering", connection_id: provider.id, model: provider.models[0], enabled: true, expected_revision: 0 } })));
    fireEvent.click(await screen.findByRole("radio"));
    expect(await screen.findByRole("button", { name: "Revoke access" })).toBeTruthy();
  });
  it.each([false, true])("creates a group inline with existing groups=%s and waits for an explicit grant", async (hasExisting) => {
    grantInventory(hasExisting ? [{ id: "engineering", name: "Engineering", members: 4 }] : []);
    const done = inlineGrant();
    await openGroupCreation();
    fireEvent.click(screen.getByRole("button", { name: "Create user group" }));
    await screen.findByRole("option", { name: "Research (0)" });
    await waitFor(() => expect((screen.getByRole("button", { name: "Grant model access" }) as HTMLButtonElement).disabled).toBe(false));
    expect((screen.getByLabelText("User group") as HTMLSelectElement).value).toBe(createdGroup.id);
    expect((screen.getByLabelText("Model") as HTMLSelectElement).value).toBe(JSON.stringify([provider.id, provider.models[0]]));
    expect(mock.post).toHaveBeenCalledExactlyOnceWith("/api/v1/organizations/{orgId}/groups", { params: { path: { orgId: "org" } }, body: { name: "Research" } });
    expect(mock.get.mock.calls.filter(([path]) => path.endsWith("user-groups"))).toHaveLength(2);
    expect(done).not.toHaveBeenCalled();
    if (hasExisting) expect(screen.getByRole("option", { name: "Engineering (4)" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Grant model access" }));
    await waitFor(() => expect(mock.post).toHaveBeenCalledWith(expect.stringContaining("user-model-grants"), expect.objectContaining({ body: { group_id: createdGroup.id, connection_id: provider.id, model: provider.models[0], enabled: true, expected_revision: 0 } })));
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
  });
  it.each(["ai-admin", "unverified"])("does not offer group creation to %s", async (role) => {
    grantInventory();
    if (role === "unverified") mock.emailVerified = false;
    else mock.roles = [role];
    inlineGrant();
    const button = await screen.findByRole("button", { name: "Create user group" });
    await screen.findByText(role === "unverified" ? "Verify your email to create a user group." : "An owner or administrator must create user groups.");
    expect((button as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(button);
    expect(screen.queryByLabelText("New group name")).toBeNull();
    expect(mock.post).not.toHaveBeenCalled();
  });
  it("retries a failed permission check without losing the selected model", async () => {
    grantInventory();
    const normalGet = mock.get.getMockImplementation()!;
    let failed = true;
    mock.get.mockImplementation((path: string) => path.endsWith("/members") && failed ? Promise.reject(Error("offline")) : normalGet(path));
    inlineGrant();
    const retry = await screen.findByRole("button", { name: "Retry group permissions" });
    failed = false;
    fireEvent.click(retry);
    await openGroupCreation();
    expect((screen.getByLabelText("Model") as HTMLSelectElement).value).toBe(JSON.stringify([provider.id, provider.models[0]]));
    expect(mock.post).not.toHaveBeenCalled();
  });
  it("keeps a duplicate-name error in the dialog without granting access", async () => {
    grantInventory();
    mock.post.mockResolvedValue({ error: { error: { code: "conflict", message: "A group with that name already exists." } }, response: new Response("{}", { status: 409 }) });
    const done = inlineGrant();
    await openGroupCreation();
    fireEvent.click(screen.getByRole("button", { name: "Create user group" }));
    expect((await screen.findByRole("alert")).textContent).toContain("A group with that name already exists.");
    expect((screen.getByLabelText("New group name") as HTMLInputElement).value).toBe(" Research ");
    expect((screen.getByLabelText("Model") as HTMLSelectElement).value).toBe(JSON.stringify([provider.id, provider.models[0]]));
    expect(mock.post).toHaveBeenCalledTimes(1);
    expect(done).not.toHaveBeenCalled();
  });
  it("refreshes after an uncertain create instead of submitting another group", async () => {
    grantInventory();
    mock.post.mockRejectedValue(Error("offline"));
    inlineGrant();
    await openGroupCreation();
    fireEvent.click(screen.getByRole("button", { name: "Create user group" }));
    await screen.findByRole("button", { name: "Refresh groups" });
    expect((screen.getByRole("button", { name: "Create user group" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Create user group" }));
    expect(mock.post).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: "Refresh groups" }));
    await waitFor(() => expect((screen.getByRole("button", { name: "Create user group" }) as HTMLButtonElement).disabled).toBe(false));
    expect((screen.getByLabelText("Model") as HTMLSelectElement).value).toBe(JSON.stringify([provider.id, provider.models[0]]));
    expect(mock.post).toHaveBeenCalledTimes(1);
  });
  it("keeps the new group selected when inventory refresh needs retry", async () => {
    grantInventory();
    const normalGet = mock.get.getMockImplementation()!;
    let groupReads = 0, failed = true;
    mock.get.mockImplementation((path: string) => path.endsWith("user-groups") && ++groupReads > 1 && failed ? Promise.resolve({ error: {} }) : normalGet(path));
    inlineGrant();
    await openGroupCreation();
    fireEvent.click(screen.getByRole("button", { name: "Create user group" }));
    await screen.findByRole("button", { name: "Refresh groups" });
    expect((screen.getByLabelText("User group") as HTMLSelectElement).value).toBe(createdGroup.id);
    expect((screen.getByRole("button", { name: "Grant model access" }) as HTMLButtonElement).disabled).toBe(true);
    expect(mock.post).toHaveBeenCalledTimes(1);
    failed = false;
    fireEvent.click(screen.getByRole("button", { name: "Refresh groups" }));
    await waitFor(() => expect((screen.getByRole("button", { name: "Grant model access" }) as HTMLButtonElement).disabled).toBe(false));
    expect(mock.post).toHaveBeenCalledTimes(1);
  });
  it("checks inventory after a server error that follows committed creation", async () => {
    const groups: Array<{ id: string; name: string; members: number }> = [];
    grantInventory(groups);
    mock.post.mockImplementation(async () => {
      groups.push({ id: createdGroup.id, name: createdGroup.name, members: 0 });
      return { error: { error: { message: "Could not read group membership." } }, response: new Response("{}", { status: 500 }) };
    });
    inlineGrant();
    await openGroupCreation();
    fireEvent.click(screen.getByRole("button", { name: "Create user group" }));
    await screen.findByRole("button", { name: "Refresh groups" });
    expect((screen.getByRole("button", { name: "Create user group" }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByLabelText("New group name") as HTMLInputElement).value).toBe(" Research ");
    fireEvent.click(screen.getByRole("button", { name: "Refresh groups" }));
    await screen.findByRole("option", { name: "Research (0)" });
    expect(mock.post).toHaveBeenCalledTimes(1);
    expect((screen.getByLabelText("Model") as HTMLSelectElement).value).toBe(JSON.stringify([provider.id, provider.models[0]]));
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
