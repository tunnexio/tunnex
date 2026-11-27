import { MemoryRouter } from "react-router-dom";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AIProviderWorkspace } from "../src/components/AIProviderWorkspace";

// Deleting a provider credential that is still used: the 409 `ai_provider_in_use` lists what uses it,
// and the console shows that list with links instead of a bare refusal.
const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PUT: vi.fn(), DELETE: vi.fn() }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "user", email_verified: true } } }) }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ orgs: [{ id: "org", name: "Demo" }], loading: false, failed: false }) }));
vi.mock("../src/components/Toasts", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

const response = (status = 200) => new Response(null, { status });
const c = { id: "c-a", key_id: "tnx-managed-a", provider: "openrouter", name: "Engineering", models: ["openrouter/openai/gpt-4o-mini"], enabled: true, revision: 3, applied_revision: 3, status: "applied", last_test_status: "untested" };
const inventory = { management_available: true, test_available: true, definitions: [{ id: "openrouter", name: "OpenRouter", credential_label: "OpenRouter API key", model_placeholder: "openrouter/openai/gpt-4o-mini" }], items: [c], legacy_key_ids: [] };
const inUse = (lists: object) => ({ error: { error: { code: "ai_provider_in_use", message: "Provider connection is in use" }, in_use: { models: [], policies: [], agents: [], ...lists } }, response: response(409) });
async function askToDelete() {
  render(<MemoryRouter><AIProviderWorkspace orgId="org-a" view="connections" canManage /></MemoryRouter>);
  fireEvent.click(await screen.findByRole("button", { name: "Credential actions for Engineering" }));
  fireEvent.click(screen.getByRole("menuitem", { name: "Delete credentials" }));
  const dialog = screen.getByRole("dialog", { name: "Delete Engineering?" });
  await waitFor(() => expect((within(dialog).getByRole("button", { name: "Confirm deletion" }) as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(within(dialog).getByRole("button", { name: "Confirm deletion" }));
  return within(dialog);
}
beforeEach(() => {
  vi.resetAllMocks();
  api.GET.mockImplementation(async (path: string) => ({ data: path.endsWith("/ai-gateway") ? { enabled: true, available: true, revision: 1 } : inventory, response: response() }));
});
afterEach(cleanup);

describe("deleting provider credentials that are in use", () => {
  it("lists the models, agent groups and agents that use them, each with a link", async () => {
    api.DELETE.mockResolvedValue(inUse({
      models: ["openrouter/openai/gpt-4o-mini"],
      policies: [{ team_id: "11111111-1111-4111-8111-111111111111", name: "Build agents" }],
      agents: [{ device_id: "22222222-2222-4222-8222-222222222222", name: "builder-01" }],
    }));
    const dialog = await askToDelete();
    expect((await dialog.findByRole("alert")).textContent).toContain("These credentials are still in use, so they were not deleted.");
    expect(dialog.getByRole("link", { name: "openai/gpt-4o-mini" }).getAttribute("href")).toBe("/ai-gateway/access");
    expect(dialog.getByRole("link", { name: "Build agents" }).getAttribute("href")).toBe("/ai-gateway/access?subject=agents");
    expect(dialog.getByRole("link", { name: "builder-01" }).getAttribute("href")).toBe("/agents/22222222-2222-4222-8222-222222222222");
    expect(dialog.getByRole("heading", { name: "Agent groups that may use them" })).toBeTruthy();
    // Nothing more to confirm: the only way out is to close and remove those uses.
    expect(dialog.queryByRole("button", { name: "Confirm deletion" })).toBeNull();
    expect(dialog.queryByText(/This connection changed or is referenced/)).toBeNull();
    expect(api.DELETE).toHaveBeenCalledExactlyOnceWith("/api/v1/organizations/{orgId}/ai-gateway/providers/{connectionId}", { params: { path: { orgId: "org-a", connectionId: "c-a" } }, body: { expected_revision: 3 } });
    fireEvent.click(dialog.getByRole("button", { name: "Close" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    // The credentials are still there.
    expect(screen.getByRole("button", { name: "Credential actions for Engineering" })).toBeTruthy();
  });

  it("shows only the kinds of use that exist", async () => {
    api.DELETE.mockResolvedValue(inUse({ agents: [{ device_id: "22222222-2222-4222-8222-222222222222", name: "builder-01" }] }));
    const dialog = await askToDelete();
    await dialog.findByRole("link", { name: "builder-01" });
    expect(dialog.queryByRole("heading", { name: "Models with access granted" })).toBeNull();
    expect(dialog.queryByRole("heading", { name: "Agent groups that may use them" })).toBeNull();
  });

  it("starts clean the next time the dialog is opened", async () => {
    api.DELETE.mockResolvedValueOnce(inUse({ models: ["openrouter/openai/gpt-4o-mini"] }));
    const dialog = await askToDelete();
    await dialog.findByRole("alert");
    fireEvent.click(dialog.getByRole("button", { name: "Close" }));
    fireEvent.click(screen.getByRole("button", { name: "Credential actions for Engineering" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Delete credentials" }));
    const again = within(screen.getByRole("dialog", { name: "Delete Engineering?" }));
    expect(again.queryByRole("alert")).toBeNull();
    expect(again.getByRole("button", { name: "Confirm deletion" })).toBeTruthy();
  });

  it("keeps the ordinary message for a conflict that is not about use", async () => {
    api.DELETE.mockResolvedValue({ error: { error: { code: "ai_provider_conflict", message: "changed" } }, response: response(409) });
    const dialog = await askToDelete();
    expect((await dialog.findByRole("alert")).textContent).toContain("This connection changed");
    expect(dialog.getByRole("button", { name: "Confirm deletion" })).toBeTruthy();
  });
});
