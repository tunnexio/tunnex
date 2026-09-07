import { createElement } from "react";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AIProviderWorkspace } from "../src/components/AIProviderWorkspace";
const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PUT: vi.fn(), DELETE: vi.fn() }));
vi.mock("../src/lib/api", () => ({ api }));
const c = { id: "c-a", key_id: "tnx-managed-a", provider: "openrouter", name: "Engineering", models: ["openrouter/openai/gpt-4o-mini"], enabled: true, revision: 3, applied_revision: 3, status: "applied", last_test_status: "untested" };
const inventory = { management_available: true, items: [c], legacy_key_ids: ["operator-key"] };
const response = (status = 200) => new Response(null, { status });
const show = (orgId = "org-a") => createElement(AIProviderWorkspace, { orgId });
beforeEach(() => {
  vi.resetAllMocks();
  api.GET.mockImplementation((path: string) => Promise.resolve({ data: path.endsWith("/models") ? { items: [{ id: c.models[0], name: "GPT-4o mini" }], total: 1, limit: 50, offset: 0 } : inventory, response: response() }));
  api.POST.mockResolvedValue({ data: c, response: response() }); api.PUT.mockResolvedValue({ data: c, response: response() }); api.DELETE.mockResolvedValue({ response: response(204) });
});
afterEach(cleanup);
describe("AI provider onboarding", () => {
  it("requires deployment setup and preserves legacy references", async () => {
    api.GET.mockResolvedValue({ data: { ...inventory, management_available: false }, response: response() }); render(show());
    await screen.findByText("Provider management requires installation setup");
    expect((screen.getByRole("button", { name: "Add provider" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText("operator-key")).toBeTruthy(); expect(api.POST).not.toHaveBeenCalled();
  });
  it("creates from catalog suggestions and clears the write-only key before response", async () => {
    let finish!: (v: unknown) => void; api.POST.mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }));
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("button", { name: "Add provider" }));
    fireEvent.change(screen.getByLabelText("Connection name"), { target: { value: "Team B" } });
    const key = screen.getByLabelText("OpenRouter API key") as HTMLInputElement; expect(key.type).toBe("password");
    fireEvent.change(key, { target: { value: "fixture-key-not-real" } }); fireEvent.click(screen.getByRole("button", { name: "Search models" }));
    await screen.findByLabelText(/GPT-4o mini/); fireEvent.click(screen.getByLabelText(/GPT-4o mini/)); fireEvent.click(screen.getByRole("button", { name: "Create connection" }));
    expect(screen.queryByLabelText("OpenRouter API key")).toBeNull(); expect(document.body.textContent).not.toContain("fixture-key-not-real");
    expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/providers$/), expect.objectContaining({ body: { provider: "openrouter", name: "Team B", models: c.models, enabled: true, api_key: "fixture-key-not-real" } }));
    await act(async () => finish({ data: c, response: response() }));
    expect(api.POST.mock.calls.every(([path]) => !path.includes("/chat/completions"))).toBe(true);
  });
  it("uses revisions for credential tests, disable and rotation without secret readback", async () => {
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("button", { name: "Test Engineering" }));
    await waitFor(() => expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/test$/), expect.objectContaining({ body: { expected_revision: 3 } })));
    await waitFor(() => expect((screen.getByRole("button", { name: "Disable Engineering" }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByRole("button", { name: "Disable Engineering" }));
    await waitFor(() => expect(api.PUT).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ body: { provider: "openrouter", name: "Engineering", models: c.models, enabled: false, expected_revision: 3 } })));
    await waitFor(() => expect((screen.getByRole("button", { name: "Edit Engineering" }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByRole("button", { name: "Edit Engineering" })); const key = screen.getByLabelText("Replacement API key (optional)") as HTMLInputElement; expect(key.value).toBe("");
    fireEvent.change(key, { target: { value: "fixture-rotated-key" } }); fireEvent.click(screen.getByRole("button", { name: "Save connection" }));
    await waitFor(() => expect(api.PUT).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({ body: expect.objectContaining({ expected_revision: 3, api_key: "fixture-rotated-key" }) })));
    expect(screen.queryByLabelText("Replacement API key (optional)")).toBeNull();
  });
  it("explains referenced delete refusal without leaking raw errors", async () => {
    api.DELETE.mockResolvedValue({ error: { unsafe: "DO_NOT_DISPLAY" }, response: response(409) }); render(show()); await screen.findByText("Engineering");
    fireEvent.click(screen.getByRole("button", { name: "Delete Engineering" })); expect(screen.getByText(/Usage history is preserved/)).toBeTruthy(); fireEvent.click(screen.getByRole("button", { name: "Confirm deletion" }));
    await screen.findByRole("alert"); expect(screen.getByRole("alert").textContent).toContain("referenced by a team policy"); expect(document.body.textContent).not.toContain("DO_NOT_DISPLAY");
    expect(api.DELETE).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ body: { expected_revision: 3 } }));
  });
  it("clears unsent secrets on organization switch", async () => {
    const page = render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("button", { name: "Add provider" })); fireEvent.change(screen.getByLabelText("OpenRouter API key"), { target: { value: "fixture-unsent-key" } });
    page.rerender(show("org-b")); await screen.findByText("Engineering"); expect(screen.queryByLabelText("OpenRouter API key")).toBeNull(); fireEvent.click(screen.getByRole("button", { name: "Add provider" }));
    expect((screen.getByLabelText("OpenRouter API key") as HTMLInputElement).value).toBe(""); expect(api.POST).not.toHaveBeenCalled();
  });
  it("keeps exact model entry when suggestions fail", async () => {
    api.GET.mockImplementation((path: string) => path.endsWith("/models") ? Promise.reject(Error()) : Promise.resolve({ data: inventory })); render(show()); await screen.findByText("Engineering");
    fireEvent.click(screen.getByRole("button", { name: "Add provider" })); fireEvent.click(screen.getByRole("button", { name: "Search models" })); await screen.findByText(/Model suggestions are unavailable/); expect(screen.getByLabelText("Exact model IDs (one per line)")).toBeTruthy();
  });
});
