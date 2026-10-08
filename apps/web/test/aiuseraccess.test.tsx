import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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
    fireEvent.click(await screen.findByRole("button", { name: /^Actions for Engineering · / }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Revoke access" }));
    const confirmation = within(screen.getByRole("dialog", { name: "Revoke model access?" }));
    expect(confirmation.getByText(/Other grants remain in effect/)).toBeTruthy();
    expect(mock.post).toHaveBeenCalledTimes(1);
    fireEvent.click(confirmation.getByRole("button", { name: "Confirm revoke" }));
    await waitFor(() => expect(mock.post).toHaveBeenLastCalledWith("/api/v1/organizations/{orgId}/ai-gateway/user-model-grants", {
      params: { path: { orgId: "org" } },
      body: { group_id: "engineering", connection_id: provider.id, model: provider.models[0], enabled: false, expected_revision: 1 },
    }));
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
  it("pages loaded grants, resets search and page size, and restores only the chosen revision", async () => {
    const grants = Array.from({ length: 55 }, (_, index) => ({ id: `grant-${index + 1}`, group_id: `group-${index + 1}`, group_name: `Group ${String(index + 1).padStart(2, "0")}`, connection_id: provider.id, model: provider.models[0], enabled: false, status: "revoked", revision: index + 7 }));
    mock.get.mockImplementation(async (path: string) => ({ data: path.endsWith("user-groups") ? [] : path.endsWith("user-model-grants") ? grants : { items: [provider] } }));
    mock.post.mockResolvedValue({ data: { ...grants[54], enabled: true, status: "applied" } });
    render(<AIGroupAccess orgId="org" canManage />);
    const table = await screen.findByRole("table", { name: "User group model grants" });
    expect(within(table).getAllByRole("row")).toHaveLength(21);
    expect(screen.queryByText("Group 21")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    expect(screen.getByText("Group 21")).toBeTruthy();
    expect(screen.queryByText("Group 01")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    expect(within(table).getAllByRole("row")).toHaveLength(16);
    expect(screen.getByRole("button", { name: "Next page" })).toHaveProperty("disabled", true);
    expect(screen.getByRole("button", { name: "Previous page" })).toHaveProperty("disabled", false);
    fireEvent.click(screen.getByRole("button", { name: /^Actions for Group 55 · / }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Restore access" }));
    await waitFor(() => expect(mock.post).toHaveBeenCalledExactlyOnceWith("/api/v1/organizations/{orgId}/ai-gateway/user-model-grants", {
      params: { path: { orgId: "org" } },
      body: { group_id: "group-55", connection_id: provider.id, model: provider.models[0], enabled: true, expected_revision: 61 },
    }));
    fireEvent.change(screen.getByRole("textbox", { name: "Search model access" }), { target: { value: "Group 01" } });
    expect(screen.getByText("Group 01")).toBeTruthy();
    expect(screen.queryByRole("navigation", { name: "Table pagination" })).toBeNull();
    fireEvent.change(screen.getByRole("textbox", { name: "Search model access" }), { target: { value: "" } });
    expect(within(table).getAllByRole("row")).toHaveLength(21);
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "50" } });
    expect(within(table).getAllByRole("row")).toHaveLength(51);
    expect(screen.getByText("Group 01")).toBeTruthy();
    expect(screen.queryByText("Group 55")).toBeNull();
    expect(screen.getByRole("button", { name: "Previous page" })).toHaveProperty("disabled", true);
  });
  it("keeps saved grants readable for a viewer without a mutation menu or pointless pager", async () => {
    mock.get.mockImplementation(async (path: string) => ({ data: path.endsWith("user-groups") ? [] : path.endsWith("user-model-grants") ? [{ id: "grant", group_id: "engineering", group_name: "Engineering", connection_id: provider.id, model: provider.models[0], enabled: true, status: "applied", revision: 8 }] : { items: [provider] } }));
    render(<AIGroupAccess orgId="org" canManage={false} />);
    const table = await screen.findByRole("table", { name: "User group model grants" });
    expect(within(table).getByText("Engineering")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Grant access" })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Actions for / })).toBeNull();
    expect(screen.queryByRole("navigation", { name: "Table pagination" })).toBeNull();
    expect(mock.post).not.toHaveBeenCalled();
  });
  it("withdraws old organization grants immediately and ignores late reads", async () => {
    let complete!: (value: unknown) => void;
    mock.get.mockImplementation((path: string, options: { params: { path: { orgId: string } } }) => {
      if (path.endsWith("user-model-grants")) return options.params.path.orgId === "org" ? new Promise((resolve) => { complete = resolve; }) : Promise.resolve({ data: [] });
      return Promise.resolve({ data: path.endsWith("user-groups") ? [] : { items: [provider] } });
    });
    const page = render(<AIGroupAccess orgId="org" canManage />);
    await waitFor(() => expect(complete).toBeDefined());
    page.rerender(<AIGroupAccess orgId="other-org" canManage={false} />);
    await screen.findByText("No model access granted.");
    await act(async () => complete({ data: [{ id: "private", group_id: "private-group", group_name: "Private old group", connection_id: provider.id, model: provider.models[0], enabled: true, status: "applied", revision: 9 }] }));
    expect(screen.queryByText("Private old group")).toBeNull();
    expect(screen.queryByRole("button", { name: /^Actions for / })).toBeNull();
    expect(mock.post).not.toHaveBeenCalled();
  });
  it("does not show or complete a late grant after management permission is removed", async () => {
    grantInventory([{ id: "engineering", name: "Engineering", members: 4 }]);
    const done = vi.fn();
    let complete!: (value: unknown) => void;
    mock.post.mockImplementation(() => new Promise((resolve) => { complete = resolve; }));
    const page = render(<AIGroupAccess orgId="org" canManage dialogOnly initialConnection={provider.id} initialModel={provider.models[0]} onDone={done} />);
    await screen.findByRole("option", { name: "Engineering (4)" });
    fireEvent.change(screen.getByLabelText("User group"), { target: { value: "engineering" } });
    fireEvent.click(screen.getByRole("button", { name: "Grant model access" }));
    expect(mock.post).toHaveBeenCalledTimes(1);
    page.rerender(<AIGroupAccess orgId="org" canManage={false} onDone={done} />);
    expect(screen.queryByRole("dialog")).toBeNull();
    await act(async () => complete({ data: { id: "late", group_id: "engineering", group_name: "Private late grant", connection_id: provider.id, model: provider.models[0], enabled: true, status: "applied", revision: 1 } }));
    await screen.findByText("No model access granted.");
    expect(screen.queryByText("Private late grant")).toBeNull();
    expect(done).not.toHaveBeenCalled(); expect(mock.success).not.toHaveBeenCalled();
    expect(mock.post).toHaveBeenCalledTimes(1);
  });
  it("disables provider mutations for an AI viewer", async () => {
    mock.get.mockResolvedValue({ data: { items: [provider], definitions: [{ id: "azure_ai", name: "Azure AI Foundry" }], management_available: true, legacy_key_ids: [] } });
    render(<AIProviderWorkspace orgId="org" canManage={false} />);
    await screen.findByRole("table", { name: "Configured models" });
    expect(screen.queryByRole("button", { name: "Add Model" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: `Model actions for ${provider.models[0]} · ${provider.name}` }));
    expect(screen.queryByRole("menuitem", { name: "Edit credentials" })).toBeNull();
    expect(screen.queryByRole("menuitem", { name: "Check catalog" })).toBeNull();
    expect(screen.getByRole("menuitem", { name: "View model" })).toBeTruthy();
    expect(mock.post).not.toHaveBeenCalled();
  });
});
