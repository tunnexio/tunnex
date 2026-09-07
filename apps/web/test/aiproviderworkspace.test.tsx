import { createElement } from "react";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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
const inventory = { management_available: true, test_available: true, definitions, items: [c], legacy_key_ids: ["operator-key"] };
const response = (status = 200) => new Response(null, { status });
const selectProvider = (name = "OpenRouter") => {
  const input = screen.getByRole("combobox", { name: "Provider" });
  fireEvent.focus(input); fireEvent.change(input, { target: { value: name } });
  fireEvent.keyDown(input, { key: "Enter" });
};
const passTest = async () => {
  const button = screen.queryByRole("button", { name: "Test Connect" });
  if (button && !(button as HTMLButtonElement).disabled) {
    fireEvent.click(button); await screen.findByText(/Test succeeded for/);
  }
};
const saveModel = () => within(screen.getByRole("dialog")).getByRole("button", { name: "Add Model" });
const show = (orgId = "org-a") => createElement(AIProviderWorkspace, { orgId });
beforeEach(() => {
  vi.resetAllMocks();
  api.GET.mockImplementation((path: string) => Promise.resolve({ data: path.endsWith("/models") ? { items: [{ id: c.models[0], name: "GPT-4o mini" }], total: 1, limit: 50, offset: 0 } : inventory, response: response() }));
  api.POST.mockImplementation((path: string) => Promise.resolve({ data: path.endsWith("/test-connection") ? { status: "success", duration_ms: 20 } : c, response: response() })); api.PUT.mockResolvedValue({ data: c, response: response() }); api.DELETE.mockResolvedValue({ response: response(204) });
});
afterEach(cleanup);
describe("AI provider onboarding", () => {
  it("starts without a provider and uses searchable logo options with standard API key caption", async () => {
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("button", { name: "Add Model" }));
    const picker = screen.getByRole("combobox", { name: "Provider" }) as HTMLInputElement;
    expect(picker.value).toBe(""); expect(screen.getByLabelText("API key")).toBeTruthy();
    expect((screen.getByRole("button", { name: "Search models" }) as HTMLButtonElement).disabled).toBe(true);
    expect((saveModel() as HTMLButtonElement).disabled).toBe(true);
    fireEvent.focus(picker); expect(within(screen.getByRole("listbox")).getAllByRole("option")).toHaveLength(4);
    expect(screen.getByRole("listbox").querySelectorAll("img")).toHaveLength(4);
    fireEvent.keyDown(picker, { key: "Escape" }); expect(screen.getByRole("dialog")).toBeTruthy();
    selectProvider("Gemini"); expect(picker.value).toBe("Gemini");
    expect((screen.getByLabelText("Exact model name") as HTMLTextAreaElement).placeholder).toBe("gemini/gemini-2.5-flash");
  });
  it("renders approved expanded provider definitions with actual logos and submits their exact provider", async () => {
    const extras = ["groq", "mistral", "cerebras", "xai", "deepseek"].map((id) => ({ id, name: id, credential_label: "API key", model_placeholder: `${id}/model` }));
    api.GET.mockResolvedValue({ data: { ...inventory, definitions: [...definitions, ...extras] }, response: response() });
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("button", { name: "Add Model" }));
    expect((screen.getByLabelText("Credential name (optional)") as HTMLInputElement).placeholder).toBe("Generated from provider and model");
    fireEvent.focus(screen.getByRole("combobox", { name: "Provider" }));
    expect(screen.getByRole("listbox").querySelectorAll("img")).toHaveLength(9);
    for (const provider of extras) {
      selectProvider(provider.name);
      expect((screen.getByLabelText("Exact model name") as HTMLTextAreaElement).placeholder).toBe(provider.model_placeholder);
    }
    fireEvent.change(screen.getByLabelText("Credential name (optional)"), { target: { value: "Research" } });
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "synthetic-fixture" } });
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "deepseek/deepseek-chat" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    await passTest(); fireEvent.click(saveModel());
    await waitFor(() => expect(api.POST).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ body: expect.objectContaining({ provider: "deepseek", models: ["deepseek/deepseek-chat"] }) })));
  });
  it("adds and removes model chips and closes the compact catalog without dismissing the drawer", async () => {
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("button", { name: "Add Model" })); selectProvider();
    expect(document.querySelector("textarea")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Search models" }));
    await screen.findByRole("region", { name: "Model suggestions" });
    fireEvent.click(screen.getByLabelText(/GPT-4o mini/));
    expect(screen.getByRole("button", { name: `Remove model ${c.models[0]}` })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Done selecting models" }));
    expect(screen.queryByRole("region", { name: "Model suggestions" })).toBeNull();
    expect(screen.getByRole("dialog")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: `Remove model ${c.models[0]}` }));
    expect(screen.queryByRole("button", { name: `Remove model ${c.models[0]}` })).toBeNull();
  });
  it("opens a portalled drawer and clears drafts on Escape with focus returned", async () => {
    render(show()); await screen.findByText("Engineering");
    const opener = screen.getByRole("button", { name: "Add Model" });
    opener.focus(); fireEvent.click(opener); selectProvider();
    const dialog = screen.getByRole("dialog", { name: "Add Model" });
    expect(dialog.parentElement).toBe(document.body);
    expect(dialog.getAttribute("data-placement")).toBe("right");
    expect(dialog.contains(screen.getByLabelText("API key"))).toBe(true);
    expect(dialog.contains(document.activeElement)).toBe(true);
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "discarded-fixture-key" } });
    fireEvent.keyDown(document.activeElement!, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(opener);
    fireEvent.click(opener); selectProvider();
    expect((screen.getByLabelText("API key") as HTMLInputElement).value).toBe("");
    fireEvent.click(screen.getByRole("button", { name: "Close Add Model" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(api.POST).not.toHaveBeenCalled();
  });

  it("requires deployment setup and preserves legacy references", async () => {
    api.GET.mockResolvedValue({ data: { ...inventory, management_available: false }, response: response() }); render(show());
    await screen.findByText("Provider management requires installation setup");
    expect((screen.getByRole("button", { name: "Add Model" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText("operator-key")).toBeTruthy(); expect(api.POST).not.toHaveBeenCalled();
  });
  it("creates from catalog suggestions and clears the write-only key before response", async () => {
    let finish!: (v: unknown) => void; api.POST.mockImplementation((path: string) => path.endsWith("/test-connection") ? Promise.resolve({ data: { status: "success", duration_ms: 20 }, response: response() }) : new Promise((resolve) => { finish = resolve; }));
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("button", { name: "Add Model" })); selectProvider();
    expect(screen.getByRole("tab", { name: /All Models/ }).getAttribute("aria-selected")).toBe("true");
    expect(screen.queryByLabelText("Connection name")).toBeNull();
    expect((screen.getByLabelText("API base URL") as HTMLInputElement).value).toBe("https://openrouter.ai/api/v1");
    expect((screen.getByLabelText("API base URL") as HTMLInputElement).readOnly).toBe(true);
    const key = screen.getByLabelText("API key") as HTMLInputElement; expect(key.type).toBe("password");
    fireEvent.change(key, { target: { value: "fixture-key-not-real" } }); fireEvent.click(screen.getByRole("button", { name: "Search models" }));
    await screen.findByLabelText(/GPT-4o mini/); fireEvent.click(screen.getByLabelText(/GPT-4o mini/)); await passTest(); fireEvent.click(saveModel());
    expect(screen.queryByLabelText("API key")).toBeNull(); expect(document.body.textContent).not.toContain("fixture-key-not-real");
    expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/providers$/), expect.objectContaining({ body: { provider: "openrouter", name: "OpenRouter · openrouter/openai/gpt-4o-mini", models: c.models, enabled: true, api_key: "fixture-key-not-real" } }));
    await act(async () => finish({ data: c, response: response() }));
    expect(api.POST.mock.calls.every(([path]) => !path.includes("/chat/completions"))).toBe(true);
  });
  it("automatically bounds new credential names and recomputes them for the chosen provider and model", async () => {
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("button", { name: "Add Model" }));
    selectProvider("OpenRouter"); selectProvider("OpenAI");
    const model = `openai/${"long-model".repeat(12)}`;
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: model } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    const label = screen.getByLabelText("Credential name (optional)") as HTMLInputElement;
    expect(label.value).toBe(""); expect(label.placeholder).toHaveLength(80); expect(label.placeholder).toMatch(/^OpenAI · openai\//);
    expect((screen.getByLabelText("API base URL") as HTMLInputElement).value).toBe("https://api.openai.com/v1");
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "fixture-key" } }); await passTest(); fireEvent.click(saveModel());
    expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/providers$/), expect.objectContaining({ body: expect.objectContaining({ name: label.placeholder, models: [model], provider: "openai" }) }));
  });
  it("uses revisions for connection tests, disable and rotation without secret readback", async () => {
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: /LLM Credentials/ })); fireEvent.click(screen.getByRole("button", { name: "Check catalog Engineering" }));
    await waitFor(() => expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/test$/), expect.objectContaining({ body: { expected_revision: 3 } })));
    expect(screen.getByRole("columnheader", { name: "Catalog check" })).toBeTruthy();
    expect(screen.getAllByText(/Public catalogs may not validate API keys/).length).toBeGreaterThan(0);
    await waitFor(() => expect((screen.getByRole("button", { name: "Disable Engineering" }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByRole("button", { name: "Disable Engineering" }));
    await waitFor(() => expect(api.PUT).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ body: { provider: "openrouter", name: "Engineering", models: c.models, enabled: false, expected_revision: 3 } })));
    await waitFor(() => expect((screen.getByRole("button", { name: "Edit Engineering" }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByRole("button", { name: "Edit Engineering" })); const key = screen.getByLabelText("Replacement API key (optional)") as HTMLInputElement; expect(key.value).toBe("");
    fireEvent.change(key, { target: { value: "fixture-rotated-key" } }); await passTest(); fireEvent.click(screen.getByRole("button", { name: "Save credentials" }));
    await waitFor(() => expect(api.PUT).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({ body: expect.objectContaining({ expected_revision: 3, api_key: "fixture-rotated-key" }) })));
    expect(screen.queryByLabelText("Replacement API key (optional)")).toBeNull();
  });
  it("explains referenced delete refusal without leaking raw errors", async () => {
    api.DELETE.mockResolvedValue({ error: { unsafe: "DO_NOT_DISPLAY" }, response: response(409) }); render(show()); await screen.findByText("Engineering");
    fireEvent.click(screen.getByRole("tab", { name: /LLM Credentials/ })); fireEvent.click(screen.getByRole("button", { name: "Delete Engineering" })); expect(screen.getByText(/Usage history is preserved/)).toBeTruthy(); fireEvent.click(screen.getByRole("button", { name: "Confirm deletion" }));
    await screen.findByRole("alert"); expect(screen.getByRole("alert").textContent).toContain("referenced by a team policy"); expect(document.body.textContent).not.toContain("DO_NOT_DISPLAY");
    expect(api.DELETE).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ body: { expected_revision: 3 } }));
  });
  it("clears unsent secrets on organization switch", async () => {
    const page = render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("button", { name: "Add Model" })); selectProvider(); fireEvent.change(screen.getByLabelText("API key"), { target: { value: "fixture-unsent-key" } });
    page.rerender(show("org-b")); await screen.findByText("Engineering"); expect(screen.queryByLabelText("API key")).toBeNull(); fireEvent.click(screen.getByRole("button", { name: "Add Model" })); selectProvider();
    expect((screen.getByLabelText("API key") as HTMLInputElement).value).toBe(""); expect(api.POST).not.toHaveBeenCalled();
  });
  it("keeps exact model entry when suggestions fail", async () => {
    api.GET.mockImplementation((path: string) => path.endsWith("/models") ? Promise.reject(Error()) : Promise.resolve({ data: inventory })); render(show()); await screen.findByText("Engineering");
    fireEvent.click(screen.getByRole("button", { name: "Add Model" })); selectProvider(); fireEvent.click(screen.getByRole("button", { name: "Search models" })); await screen.findByText(/Model suggestions are unavailable/); expect(screen.getByLabelText("Exact model name")).toBeTruthy();
  });
  it("uses backend provider definitions and clears secret/model drafts and stale catalog on provider changes", async () => {
    let finish!: (v: unknown) => void;
    api.GET.mockImplementation((path: string) => path.endsWith("/models") ? new Promise((resolve) => { finish = resolve; }) : Promise.resolve({ data: inventory, response: response() }));
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("button", { name: "Add Model" })); selectProvider();
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "discard-me" } });
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: c.models[0] } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    selectProvider();
    expect((screen.getByLabelText("API key") as HTMLInputElement).value).toBe("discard-me");
    fireEvent.click(screen.getByRole("button", { name: "Search models" }));
    expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/models$/), expect.objectContaining({ params: expect.objectContaining({ query: expect.objectContaining({ provider: "openrouter" }) }) }));
    selectProvider("Anthropic");
    expect((screen.getByLabelText("API key") as HTMLInputElement).value).toBe("");
    expect((screen.getByLabelText("Exact model name") as HTMLTextAreaElement).value).toBe("");
    await act(async () => finish({ data: { items: [{ id: c.models[0], name: "Stale OpenRouter model" }], total: 1, offset: 0, limit: 50 } }));
    expect(screen.queryByText("Stale OpenRouter model")).toBeNull();
    fireEvent.change(screen.getByLabelText("Credential name (optional)"), { target: { value: "Research" } });
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "synthetic-key" } });
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "anthropic/claude-sonnet-4" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    await passTest(); fireEvent.click(saveModel());
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
    fireEvent.click(screen.getByRole("button", { name: "Add Model" })); selectProvider();
    expect(screen.queryByRole("option", { name: /Direct OpenAI/ })).toBeNull();
    expect(screen.queryByRole("option", { name: /Pending key|Failed key/ })).toBeNull();
    fireEvent.change(screen.getByLabelText("Existing Credentials"), { target: { value: c.id } });
    expect(screen.queryByLabelText("API key")).toBeNull();
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "openrouter/anthropic/claude-sonnet-4" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    fireEvent.click(saveModel());
    await waitFor(() => expect(api.PUT).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ body: { provider: "openrouter", name: c.name, models: [...c.models, "openrouter/anthropic/claude-sonnet-4"], enabled: true, expected_revision: 3 } })));
    expect(api.POST).not.toHaveBeenCalled();
  });
  it("does not invent new provider options on an older API and keeps connection provider immutable", async () => {
    api.GET.mockResolvedValue({ data: { management_available: true, items: [c], legacy_key_ids: [] }, response: response() });
    render(show()); await screen.findByText("Engineering");
    expect((screen.getByRole("button", { name: "Add Model" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole("tab", { name: /LLM Credentials/ })); fireEvent.click(screen.getByRole("button", { name: "Edit Engineering" }));
    expect(screen.queryByRole("combobox", { name: "Provider" })).toBeNull();
    expect(screen.getByText(/provider cannot be changed/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Save credentials" }) as HTMLButtonElement).disabled).toBe(false);
  });

});

describe("custom provider approved endpoints", () => {
  const custom = { id: "12345678-1234-1234-1234-123456789abc", key_id: "tnx-managed-custom", provider: "custom", name: "Private inference", models: ["custom-12345678-1234-1234-1234-123456789abc/model-a"], enabled: true, revision: 4, applied_revision: 4, status: "applied", last_test_status: "untested", endpoint_url: "https://inference.internal/v1" };
  const customInventory = { ...inventory, custom_available: true, custom_endpoints: [{ name: "Internal inference", url: custom.endpoint_url }], definitions: [...definitions, { id: "custom", name: "Custom", credential_label: "API key", model_placeholder: "model-name" }], items: [custom] };
  it("shows unavailable custom setup and refuses selection without approved egress", async () => {
    api.GET.mockResolvedValue({ data: { ...customInventory, custom_available: false } }); render(show()); await screen.findByText(custom.name);
    fireEvent.click(screen.getByRole("button", { name: "Add Model" })); selectProvider("Custom");
    expect((screen.getByRole("combobox", { name: "Provider" }) as HTMLInputElement).value).toBe("Custom");
    expect(screen.getByText(/Installation setup required: approve this endpoint/)).toBeTruthy();
    expect(screen.getByLabelText("API base URL")).toBeTruthy(); expect((screen.getByRole("button", { name: "Test Connect" }) as HTMLButtonElement).disabled).toBe(true); expect(api.POST).not.toHaveBeenCalled();
  });
  it("creates only an approved custom endpoint using raw names and no precreation catalog request", async () => {
    api.GET.mockResolvedValue({ data: customInventory }); render(show()); await screen.findByText(custom.name);
    fireEvent.click(screen.getByRole("button", { name: "Add Model" })); selectProvider("Custom");
    fireEvent.change(screen.getByLabelText("Credential name (optional)"), { target: { value: "New private" } });
    expect(screen.getByLabelText("Approved upstream endpoint").compareDocumentPosition(screen.getByLabelText("API key")) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Approved upstream endpoint"), { target: { value: custom.endpoint_url } });
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "synthetic-custom-key" } });
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "custom-00000000-0000-4000-8000-000000000001/model" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    expect((saveModel() as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "custom-model" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    expect((screen.getByRole("button", { name: "Search models" }) as HTMLButtonElement).disabled).toBe(true);
    await passTest(); fireEvent.click(saveModel());
    await waitFor(() => expect(api.POST).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ body: { provider: "custom", endpoint_url: custom.endpoint_url, name: "New private", enabled: true, models: ["custom-model"], api_key: "synthetic-custom-key" } })));
    expect(api.GET.mock.calls.some(([path]) => path.endsWith("/models"))).toBe(false);
  });
  it("tests a typed API base URL, invalidates edits and refuses unapproved destinations", async () => {
    const base = "https://inference.internal";
    api.GET.mockResolvedValue({ data: { ...customInventory, custom_endpoints: [{ name: "Internal inference", url: base }] } });
    render(show()); await screen.findByText(custom.name); fireEvent.click(screen.getByRole("button", { name: "Add Model" })); selectProvider("Custom");
    fireEvent.change(screen.getByLabelText("Credential name (optional)"), { target: { value: "Typed endpoint" } });
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "model-a" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    fireEvent.change(screen.getByLabelText("API base URL"), { target: { value: base + "/v1/" } });
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "synthetic-custom-key" } });
    expect(screen.getByText(base + "/v1/chat/completions")).toBeTruthy(); await passTest();
    expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/test-connection$/), expect.objectContaining({ body: { provider: "custom", model: "model-a", api_key: "synthetic-custom-key", endpoint_url: base } }));
    fireEvent.change(screen.getByLabelText("API base URL"), { target: { value: "https://unapproved.internal" } });
    expect(screen.getByText(/This endpoint is not approved/)).toBeTruthy(); expect((screen.getByLabelText("API key") as HTMLInputElement).value).toBe("");
    expect(screen.queryByText(/Test succeeded/)).toBeNull(); expect((saveModel() as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "new-secret" } }); fireEvent.click(screen.getByRole("button", { name: "Test Connect" })); expect(api.POST).toHaveBeenCalledTimes(1);
    fireEvent.change(screen.getByLabelText("API base URL"), { target: { value: "https://user:secret@inference.internal" } }); expect(screen.getByText(/without embedded credentials/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText("API base URL"), { target: { value: base } }); fireEvent.change(screen.getByLabelText("API key"), { target: { value: "synthetic-custom-key" } }); await passTest();
    fireEvent.click(saveModel()); await waitFor(() => expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/providers$/), expect.objectContaining({ body: expect.objectContaining({ endpoint_url: base }) })));
  });
  it("reuses custom credentials with immutable endpoint and scopes catalog to the connection", async () => {
    api.GET.mockImplementation((path: string) => Promise.resolve({ data: path.endsWith("/models") ? { items: [], total: 0, limit: 50, offset: 0 } : customInventory }));
    render(show()); await screen.findByText(custom.name); fireEvent.click(screen.getByRole("tab", { name: /Models/ })); fireEvent.click(screen.getByRole("button", { name: "Add Model" })); selectProvider("Custom");
    fireEvent.change(screen.getByLabelText("Existing Credentials"), { target: { value: custom.id } });
    expect((screen.getByLabelText("Upstream endpoint") as HTMLInputElement).readOnly).toBe(true);
    expect(screen.queryByLabelText("API key")).toBeNull(); fireEvent.click(screen.getByRole("button", { name: "Search models" }));
    await waitFor(() => expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/models$/), expect.objectContaining({ params: expect.objectContaining({ query: expect.objectContaining({ provider: "custom", connection_id: custom.id }) }) })));
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "model-b" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" })); fireEvent.click(saveModel());
    await waitFor(() => expect(api.PUT).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ body: { provider: "custom", endpoint_url: custom.endpoint_url, name: custom.name, enabled: true, models: [...custom.models, "model-b"], expected_revision: 4 } })));
  });
});

describe("pre-save inference check", () => {
  const prepare = async () => {
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("button", { name: "Add Model" })); selectProvider();
    fireEvent.change(screen.getByLabelText("Credential name (optional)"), { target: { value: "Tested connection" } });
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "synthetic-key" } });
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: c.models[0] } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
  };
  it("requires result success, rejects HTTP200 error and invalidates changed credentials", async () => {
    await prepare(); const save = saveModel() as HTMLButtonElement; expect(save.disabled).toBe(true);
    api.POST.mockResolvedValueOnce({ data: { status: "error", duration_ms: 20 }, response: response() });
    fireEvent.click(screen.getByRole("button", { name: "Test Connect" })); await screen.findByText(/Connection test failed/); expect(save.disabled).toBe(true);
    await passTest(); expect(save.disabled).toBe(false);
    expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/test-connection$/), expect.objectContaining({ body: { provider: "openrouter", model: c.models[0], api_key: "synthetic-key" } }));
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "changed-key" } }); expect(save.disabled).toBe(true); expect(screen.queryByText(/Test succeeded for/)).toBeNull();
  });
  it("ignores late success after model changes", async () => {
    await prepare(); let finish!: (v: unknown) => void; api.POST.mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }));
    fireEvent.click(screen.getByRole("button", { name: "Test Connect" }));
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "openrouter/another-model" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    await act(async () => finish({ data: { status: "success", duration_ms: 20 }, response: response() }));
    expect(screen.queryByText(/Test succeeded for/)).toBeNull(); expect((saveModel() as HTMLButtonElement).disabled).toBe(true);
  });
  it("expires success at five minutes and explains missing bridge setup", async () => {
    await prepare(); await passTest(); const now = Date.now(); const clock = vi.spyOn(Date, "now").mockReturnValue(now + 300001);
    fireEvent.change(screen.getByLabelText("Credential name (optional)"), { target: { value: "Same settings" } });
    expect((saveModel() as HTMLButtonElement).disabled).toBe(true); clock.mockRestore(); cleanup();
    api.GET.mockResolvedValue({ data: { ...inventory, test_available: false } }); await prepare();
    expect((screen.getByRole("button", { name: "Test Connect" }) as HTMLButtonElement).disabled).toBe(true); expect(screen.getByText(/Test Connect requires installation setup/)).toBeTruthy();
  });
  it("tests and creates SageMaker with an approved bridge, gateway key and raw alias", async () => {
    api.GET.mockResolvedValue({ data: { ...inventory, sagemaker_available: true, sagemaker_endpoints: [{ name: "AWS bridge", url: "https://aws-bridge.internal" }], definitions: [...definitions, { id: "sagemaker", name: "AWS SageMaker", credential_label: "Gateway API key", model_placeholder: "production-model" }] } });
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("button", { name: "Add Model" })); selectProvider("AWS SageMaker");
    fireEvent.change(screen.getByLabelText("Approved upstream endpoint"), { target: { value: "https://aws-bridge.internal" } });
    fireEvent.change(screen.getByLabelText("Credential name (optional)"), { target: { value: "AWS models" } }); fireEvent.change(screen.getByLabelText("Gateway API key"), { target: { value: "synthetic-gateway-key" } });
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "production-model" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    await passTest(); expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/test-connection$/), expect.objectContaining({ body: { provider: "sagemaker", model: "production-model", api_key: "synthetic-gateway-key", endpoint_url: "https://aws-bridge.internal" } }));
    fireEvent.click(saveModel());
    await waitFor(() => expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/providers$/), expect.objectContaining({ body: expect.objectContaining({ provider: "sagemaker", models: ["production-model"], endpoint_url: "https://aws-bridge.internal" }) })));
    expect(screen.queryByLabelText("AWS Secret Access Key")).toBeNull();
  });
});
