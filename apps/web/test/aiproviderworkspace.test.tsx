import { createElement } from "react";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AIProviderWorkspace } from "../src/components/AIProviderWorkspace";
const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PUT: vi.fn(), DELETE: vi.fn() }));
vi.mock("../src/lib/api", () => ({ api }));
const c = { id: "c-a", key_id: "tnx-managed-a", provider: "openrouter", name: "Engineering", models: ["openrouter/openai/gpt-4o-mini"], enabled: true, revision: 3, applied_revision: 3, status: "applied", last_test_status: "untested" };
const definitions = [
  { id: "openrouter", name: "OpenRouter", credential_label: "OpenRouter API key", model_placeholder: "openrouter/openai/gpt-4o-mini" },
  { id: "openai", name: "OpenAI", credential_label: "OpenAI API key", model_placeholder: "openai/gpt-4o-mini" },
  { id: "anthropic", name: "Anthropic", credential_label: "Anthropic API key", model_placeholder: "anthropic/claude-sonnet-4" },
  { id: "gemini", name: "Gemini", credential_label: "Gemini API key", model_placeholder: "gemini/gemini-2.5-flash" },
];
const inventory = { management_available: true, definitions, items: [c], legacy_key_ids: ["operator-key"] };
const response = (status = 200) => new Response(null, { status });
const show = (orgId = "org-a") => createElement(AIProviderWorkspace, { orgId });
beforeEach(() => {
  vi.resetAllMocks();
  api.GET.mockImplementation((path: string) => Promise.resolve({ data: path.endsWith("/models") ? { items: [{ id: c.models[0], name: "GPT-4o mini" }], total: 1, limit: 50, offset: 0 } : inventory, response: response() }));
  api.POST.mockResolvedValue({ data: c, response: response() }); api.PUT.mockResolvedValue({ data: c, response: response() }); api.DELETE.mockResolvedValue({ response: response(204) });
});
afterEach(cleanup);
describe("AI provider onboarding", () => {
  it("opens a portalled drawer and clears drafts on Escape with focus returned", async () => {
    render(show()); await screen.findByText("Engineering");
    const opener = screen.getByRole("button", { name: "Add provider" });
    opener.focus(); fireEvent.click(opener);
    const dialog = screen.getByRole("dialog", { name: "Add provider" });
    expect(dialog.parentElement).toBe(document.body);
    expect(dialog.getAttribute("data-placement")).toBe("right");
    expect(dialog.contains(screen.getByLabelText("OpenRouter API key"))).toBe(true);
    expect(dialog.contains(document.activeElement)).toBe(true);
    fireEvent.change(screen.getByLabelText("OpenRouter API key"), { target: { value: "discarded-fixture-key" } });
    fireEvent.keyDown(document.activeElement!, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(opener);
    fireEvent.click(opener);
    expect((screen.getByLabelText("OpenRouter API key") as HTMLInputElement).value).toBe("");
    fireEvent.click(screen.getByRole("button", { name: "Close Add provider" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(api.POST).not.toHaveBeenCalled();
  });

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
  it("uses backend provider definitions and clears secret/model drafts and stale catalog on provider changes", async () => {
    let finish!: (v: unknown) => void;
    api.GET.mockImplementation((path: string) => path.endsWith("/models") ? new Promise((resolve) => { finish = resolve; }) : Promise.resolve({ data: inventory, response: response() }));
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("button", { name: "Add provider" }));
    fireEvent.change(screen.getByLabelText("OpenRouter API key"), { target: { value: "discard-me" } });
    fireEvent.change(screen.getByLabelText("Exact model IDs (one per line)"), { target: { value: c.models[0] } });
    fireEvent.click(screen.getByRole("button", { name: /OpenRouter API key/ }));
    expect((screen.getByLabelText("OpenRouter API key") as HTMLInputElement).value).toBe("discard-me");
    fireEvent.click(screen.getByRole("button", { name: "Search models" }));
    expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/models$/), expect.objectContaining({ params: expect.objectContaining({ query: expect.objectContaining({ provider: "openrouter" }) }) }));
    fireEvent.change(screen.getByLabelText("Search providers"), { target: { value: "Anthropic" } });
    expect(screen.queryByRole("button", { name: /Gemini API key/ })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /Anthropic API key/ }));
    expect((screen.getByLabelText("Anthropic API key") as HTMLInputElement).value).toBe("");
    expect((screen.getByLabelText("Exact model IDs (one per line)") as HTMLTextAreaElement).value).toBe("");
    await act(async () => finish({ data: { items: [{ id: c.models[0], name: "Stale OpenRouter model" }], total: 1, offset: 0, limit: 50 } }));
    expect(screen.queryByText("Stale OpenRouter model")).toBeNull();
    fireEvent.change(screen.getByLabelText("Connection name"), { target: { value: "Research" } });
    fireEvent.change(screen.getByLabelText("Anthropic API key"), { target: { value: "synthetic-key" } });
    fireEvent.change(screen.getByLabelText("Exact model IDs (one per line)"), { target: { value: "anthropic/claude-sonnet-4" } });
    fireEvent.click(screen.getByRole("button", { name: "Create connection" }));
    await waitFor(() => expect(api.POST).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ body: expect.objectContaining({ provider: "anthropic", models: ["anthropic/claude-sonnet-4"] }) })));
  });
  it("reuses a same-provider connection for new models with its revision and preserves existing models without a secret", async () => {
    const other = { ...c, id: "c-b", name: "Direct OpenAI", provider: "openai", models: ["openai/gpt-4o-mini"] };
    api.GET.mockResolvedValue({ data: { ...inventory, items: [c, other, { ...c, id: "pending", name: "Pending key", status: "pending" }, { ...c, id: "failed", name: "Failed key", status: "error" }] }, response: response() });
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: /Models/ }));
    expect(screen.getByRole("table", { name: "Configured models" })).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Filter models by provider"), { target: { value: "openai" } });
    expect(screen.queryByText(c.models[0])).toBeNull(); expect(screen.getByText("openai/gpt-4o-mini")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Search configured models"), { target: { value: "does not exist" } });
    expect(screen.getByText(/No configured models match/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Add model" }));
    expect(screen.queryByRole("option", { name: /Direct OpenAI/ })).toBeNull();
    expect(screen.queryByRole("option", { name: /Pending key|Failed key/ })).toBeNull();
    fireEvent.change(screen.getByLabelText("Credential connection"), { target: { value: c.id } });
    expect(screen.queryByLabelText("OpenRouter API key")).toBeNull();
    fireEvent.change(screen.getByLabelText("Exact model IDs (one per line)"), { target: { value: "openrouter/anthropic/claude-sonnet-4" } });
    fireEvent.click(screen.getByRole("button", { name: "Add models to connection" }));
    await waitFor(() => expect(api.PUT).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ body: { provider: "openrouter", name: c.name, models: [...c.models, "openrouter/anthropic/claude-sonnet-4"], enabled: true, expected_revision: 3 } })));
    expect(api.POST).not.toHaveBeenCalled();
  });
  it("does not invent new provider options on an older API and keeps connection provider immutable", async () => {
    api.GET.mockResolvedValue({ data: { management_available: true, items: [c], legacy_key_ids: [] }, response: response() });
    render(show()); await screen.findByText("Engineering");
    expect((screen.getByRole("button", { name: "Add provider" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Edit Engineering" }));
    expect(screen.queryByLabelText("Search providers")).toBeNull();
    expect(screen.getByText(/provider cannot be changed/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Save connection" }) as HTMLButtonElement).disabled).toBe(false);
  });

});
