import { createElement } from "react";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AIProviderWorkspace } from "../src/components/AIProviderWorkspace";
const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PUT: vi.fn(), DELETE: vi.fn() }));
vi.mock("../src/lib/api", () => ({ api }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ orgs: [{ id: "org", name: "Demo" }], loading: false, failed: false }) }));
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
vi.mock("../src/components/Toasts", () => ({ toast }));
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
const saveModel = () => within(screen.getByRole("tabpanel", { name: "Add Model" })).getByRole("button", { name: "Add Model" });
const show = (orgId = "org-a") => createElement(AIProviderWorkspace, { orgId });
beforeEach(() => {
  vi.resetAllMocks();
  api.GET.mockImplementation((path: string) => Promise.resolve({ data: path.endsWith("/models") ? { items: [{ id: c.models[0], name: "GPT-4o mini" }], total: 1, limit: 50, offset: 0 } : inventory, response: response() }));
  api.POST.mockImplementation((path: string) => Promise.resolve({ data: path.endsWith("/test-connection") ? { status: "success", duration_ms: 20 } : c, response: response() })); api.PUT.mockResolvedValue({ data: c, response: response() }); api.DELETE.mockResolvedValue({ response: response(204) });
});
afterEach(() => { cleanup(); vi.useRealTimers(); });
describe("AI provider onboarding", () => {
  it.each([
    { failure: { kind: "http_error", source: "provider", http_status: 403 }, title: "Connection test failed · Provider HTTP 403", detail: /Access denied/ },
    { failure: { kind: "http_error", source: "proxy", http_status: 403 }, title: "Connection test failed · Network proxy HTTP 403", detail: /network proxy rejected/i },
    { failure: { kind: "network_error", source: "provider" }, title: "Connection test failed · Network unreachable", detail: /No HTTP response/ },
    { failure: { kind: "timeout", source: "provider" }, title: "Connection test failed · Timeout", detail: /No complete response/ },
    { failure: { kind: "invalid_response", source: "provider" }, title: "Connection test failed · Incomplete or invalid response", detail: /response was interrupted/i },
    { failure: { kind: "http_error", source: "gateway", http_status: 503 }, title: "Connection test failed · Test gateway HTTP 503", detail: /test gateway rejected/i },
  ])("shows safe diagnostic $title for saved credentials", async ({ failure, title, detail }) => {
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" }));
    fireEvent.change(screen.getByLabelText("Existing Credentials"), { target: { value: c.id } });
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "openrouter/new-model" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    api.POST.mockResolvedValueOnce({ data: { status: "error", duration_ms: 10, failure: { ...failure, message: "PRIVATE-KEY-MARKER" } }, response: response() });
    fireEvent.click(screen.getByRole("button", { name: "Test Connect" }));
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith(title, { description: expect.stringMatching(detail) }));
    expect(screen.getByText(new RegExp(title.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")))).toBeTruthy();
    expect(JSON.stringify(toast.error.mock.calls)).not.toContain("PRIVATE-KEY-MARKER");
    expect((saveModel() as HTMLButtonElement).disabled).toBe(true);
  });
  it("suggests saved Azure credentials before choosing a provider and tests a new model without resending the key or endpoint", async () => {
    const id = "12345678-1234-1234-1234-123456789abc";
    const saved = { ...c, id, name: "azure", provider: "azure_foundry", endpoint_url: "https://resource.services.ai.azure.com/openai", models: [`custom-${id}/gpt-5`] };
    api.GET.mockImplementation((path: string) => Promise.resolve({ data: path.endsWith("/models") ? { items: [], total: 0 } : { ...inventory, public_endpoints_available: true, items: [saved], definitions: [...definitions, { id: "azure_foundry", name: "Azure AI Foundry", credential_label: "Azure API key", model_placeholder: "deployment" }] }, response: response() }));
    render(show()); await screen.findByText("azure"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" }));
    expect(screen.getByRole("option", { name: "azure · Azure AI Foundry · applied" })).toBeTruthy();
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "discard-this-draft" } });
    fireEvent.change(screen.getByLabelText("Existing Credentials"), { target: { value: id } });
    expect((screen.getByRole("combobox", { name: "Provider" }) as HTMLInputElement).value).toBe("Azure AI Foundry");
    expect(screen.queryByLabelText("Upstream API Base")).toBeNull(); expect(screen.queryByLabelText("API key")).toBeNull(); expect(screen.queryByLabelText("Credential name (optional)")).toBeNull();
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "llama-deployment" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    expect((saveModel() as HTMLButtonElement).disabled).toBe(true);
    await passTest();
    expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/test-connection$/), expect.objectContaining({ body: { provider: "azure_foundry", connection_id: id, expected_revision: 3, model: "llama-deployment", mode: "chat" } }));
    expect(toast.success).toHaveBeenCalledWith("Test connection successful · HTTP 200", expect.objectContaining({ description: expect.stringContaining("llama-deployment") }));
    fireEvent.click(saveModel());
    await waitFor(() => expect(api.PUT).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ body: { provider: "azure_foundry", endpoint_url: saved.endpoint_url, name: "azure", models: [...saved.models, "llama-deployment"], model_modes: { [saved.models[0]]: "chat", "llama-deployment": "chat" }, enabled: true, expected_revision: 3 } })));
  });
  it.each([{ status: 200, result: "error" }, { status: 503, result: "success" }])("never toasts success for failed test $status/$result", async ({ status, result }) => {
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" }));
    fireEvent.change(screen.getByLabelText("Existing Credentials"), { target: { value: c.id } });
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "openrouter/new-model" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    api.POST.mockResolvedValueOnce({ data: { status: result, duration_ms: 10 }, response: response(status) });
    fireEvent.click(screen.getByRole("button", { name: "Test Connect" })); await screen.findByText(/Connection test failed/);
    expect(toast.success).not.toHaveBeenCalled(); expect(toast.error).toHaveBeenCalled(); expect((saveModel() as HTMLButtonElement).disabled).toBe(true);
  });
  it("ignores a saved-key test result after switching back to new credentials", async () => {
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" }));
    fireEvent.change(screen.getByLabelText("Existing Credentials"), { target: { value: c.id } });
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "openrouter/new-model" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    let finish!: (value: unknown) => void; api.POST.mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }));
    fireEvent.click(screen.getByRole("button", { name: "Test Connect" }));
    fireEvent.change(screen.getByLabelText("Existing Credentials"), { target: { value: "" } });
    await act(async () => finish({ data: { status: "success", duration_ms: 10 }, response: response() }));
    expect(toast.success).not.toHaveBeenCalled(); expect((screen.getByLabelText("API key") as HTMLInputElement).value).toBe(""); expect((saveModel() as HTMLButtonElement).disabled).toBe(true);
  });
  it("starts without a provider and uses searchable logo options with standard API key caption", async () => {
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" }));
    const picker = screen.getByRole("combobox", { name: "Provider" }) as HTMLInputElement;
    expect(picker.value).toBe(""); expect(screen.getByLabelText("API key")).toBeTruthy();
    expect((screen.getByLabelText("Upstream API Base") as HTMLInputElement).disabled).toBe(true);
    expect(screen.getByText("Select a provider to configure its API endpoint.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Search models" })).toBeNull();
    expect((saveModel() as HTMLButtonElement).disabled).toBe(true);
    fireEvent.focus(picker); expect(within(screen.getByRole("listbox")).getAllByRole("option")).toHaveLength(4);
    expect(screen.getByRole("listbox").querySelectorAll("img")).toHaveLength(4);
    fireEvent.keyDown(picker, { key: "Escape" }); expect(screen.getByRole("tabpanel", { name: "Add Model" })).toBeTruthy();
    selectProvider("Gemini"); expect(picker.value).toBe("Gemini");
    expect((screen.getByLabelText("Exact model name") as HTMLTextAreaElement).placeholder).toBe("gemini/gemini-2.5-flash");
  });
  it("renders approved expanded provider definitions with actual logos and submits their exact provider", async () => {
    const extras = ["groq", "mistral", "cerebras", "xai", "deepseek"].map((id) => ({ id, name: id, credential_label: "API key", model_placeholder: `${id}/model` }));
    api.GET.mockResolvedValue({ data: { ...inventory, definitions: [...definitions, ...extras] }, response: response() });
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" }));
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
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider();
    expect(document.querySelector("textarea")).toBeNull();

    await screen.findByRole("region", { name: "Model suggestions" });
    fireEvent.click(screen.getByLabelText(/GPT-4o mini/));
    expect(screen.getByRole("button", { name: `Remove model ${c.models[0]}` })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Done selecting models" }));
    expect(screen.queryByRole("region", { name: "Model suggestions" })).toBeNull();
    expect(screen.getByRole("tabpanel", { name: "Add Model" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: `Remove model ${c.models[0]}` }));
    expect(screen.queryByRole("button", { name: `Remove model ${c.models[0]}` })).toBeNull();
  });
  it("creates inline, discards secrets and late tests on tab navigation, and cancels a fresh draft", async () => {
    render(show()); await screen.findByText("Engineering");
    fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("tabpanel", { name: "Add Model" })).toBeTruthy();
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "discarded-fixture-key" } });
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: c.models[0] } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    let finish!: (v: unknown) => void;
    api.POST.mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }));
    fireEvent.click(screen.getByRole("button", { name: "Test Connect" }));
    fireEvent.click(screen.getByRole("tab", { name: /LLM Credentials/ }));
    expect(screen.queryByLabelText("API key")).toBeNull();
    fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider();
    expect((screen.getByLabelText("API key") as HTMLInputElement).value).toBe("");
    await act(async () => finish({ data: { status: "success", duration_ms: 20 }, response: response() }));
    expect(screen.queryByText(/Test succeeded/)).toBeNull(); expect((saveModel() as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("tabpanel", { name: "Add Model" })).toBeNull();
    expect(screen.getByRole("tab", { name: /All Models/ }).getAttribute("aria-selected")).toBe("true");
    expect(api.POST).toHaveBeenCalledTimes(1);
  });

  it("creates credentials directly with a tested model scope and returns to LLM Credentials", async () => {
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: /LLM Credentials/ }));
    fireEvent.click(screen.getByRole("button", { name: "Add Credentials" }));
    expect(screen.getByRole("dialog", { name: "Add Credentials" }).getAttribute("data-placement")).toBe("right");
    expect(screen.getByText(/Select at least one model before testing/)).toBeTruthy();
    expect((screen.getByLabelText("Upstream API Base") as HTMLInputElement).disabled).toBe(true);
    expect(screen.queryByLabelText("Existing Credentials")).toBeNull();
    selectProvider("OpenAI");
    fireEvent.change(screen.getByLabelText("Credential name (optional)"), { target: { value: "Production OpenAI" } });
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "new-credential-fixture" } });
    expect((screen.getByRole("button", { name: "Test Connect" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "openai/gpt-4o-mini" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    await passTest();
    expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/test-connection$/), expect.objectContaining({ body: { provider: "openai", model: "openai/gpt-4o-mini", mode: "chat", api_key: "new-credential-fixture" } }));
    fireEvent.click(screen.getByRole("button", { name: "Create credentials" }));
    expect(screen.queryByLabelText("API key")).toBeNull();
    await waitFor(() => expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/providers$/), expect.objectContaining({ body: { provider: "openai", name: "Production OpenAI", models: ["openai/gpt-4o-mini"], model_modes: { "openai/gpt-4o-mini": "chat" }, enabled: true, api_key: "new-credential-fixture" } })));
    expect(screen.getByRole("tab", { name: /LLM Credentials/ }).getAttribute("aria-selected")).toBe("true");
  });
  it("discards direct credential drafts on cancel and tab navigation", async () => {
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: /LLM Credentials/ }));
    fireEvent.click(screen.getByRole("button", { name: "Add Credentials" })); selectProvider();
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "discard-on-cancel" } });
    fireEvent.click(screen.getByRole("button", { name: "Cancel" })); expect(screen.queryByRole("dialog")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Add Credentials" })); selectProvider();
    expect((screen.getByLabelText("API key") as HTMLInputElement).value).toBe("");
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "discard-on-tab" } });
    fireEvent.click(screen.getByRole("tab", { name: /All Models/ })); expect(screen.queryByRole("dialog")).toBeNull();
    fireEvent.click(screen.getByRole("tab", { name: /LLM Credentials/ })); fireEvent.click(screen.getByRole("button", { name: "Add Credentials" }));
    expect((screen.getByLabelText("API key") as HTMLInputElement).value).toBe(""); expect(api.POST).not.toHaveBeenCalled();
  });

  it("requires deployment setup and preserves legacy references", async () => {
    api.GET.mockResolvedValue({ data: { ...inventory, management_available: false }, response: response() }); render(show());
    await screen.findByText("Provider management requires installation setup");
    expect((screen.getByRole("tab", { name: "Add Model" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText("operator-key")).toBeTruthy(); expect(api.POST).not.toHaveBeenCalled();
  });
  it("creates from catalog suggestions and clears the write-only key before response", async () => {
    let finish!: (v: unknown) => void; api.POST.mockImplementation((path: string) => path.endsWith("/test-connection") ? Promise.resolve({ data: { status: "success", duration_ms: 20 }, response: response() }) : new Promise((resolve) => { finish = resolve; }));
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider();
    expect(screen.getByRole("tab", { name: "Add Model" }).getAttribute("aria-selected")).toBe("true");
    expect(screen.queryByLabelText("Connection name")).toBeNull();
    expect((screen.getByLabelText("Upstream API Base") as HTMLInputElement).value).toBe("https://openrouter.ai/api/v1");
    expect((screen.getByLabelText("Upstream API Base") as HTMLInputElement).readOnly).toBe(true);
    expect(within(screen.getByLabelText("Mode")).getAllByRole("option")).toHaveLength(8);
    expect((screen.getByLabelText("Mode") as HTMLSelectElement).value).toBe("chat");
    const key = screen.getByLabelText("API key") as HTMLInputElement; expect(key.type).toBe("password");
    fireEvent.change(key, { target: { value: "fixture-key-not-real" } });
    await screen.findByLabelText(/GPT-4o mini/); fireEvent.click(screen.getByLabelText(/GPT-4o mini/));
    const mapping = within(screen.getByRole("table", { name: "Model mapping preview" }));
    expect(mapping.getByText(c.models[0])).toBeTruthy(); expect(mapping.getByText("openai/gpt-4o-mini")).toBeTruthy();
    await passTest(); fireEvent.click(saveModel());
    expect(screen.queryByLabelText("API key")).toBeNull(); expect(document.body.textContent).not.toContain("fixture-key-not-real");
    expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/providers$/), expect.objectContaining({ body: { provider: "openrouter", name: "OpenRouter · openrouter/openai/gpt-4o-mini", models: c.models, model_modes: { [c.models[0]]: "chat" }, enabled: true, api_key: "fixture-key-not-real" } }));
    await act(async () => finish({ data: c, response: response() }));
    expect(screen.getByRole("tab", { name: /All Models/ }).getAttribute("aria-selected")).toBe("true");
    expect(api.POST.mock.calls.every(([path]) => !path.includes("/chat/completions"))).toBe(true);
  });
  it("automatically bounds new credential names and recomputes them for the chosen provider and model", async () => {
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" }));
    selectProvider("OpenRouter"); selectProvider("OpenAI");
    const model = `openai/${"long-model".repeat(12)}`;
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: model } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    const label = screen.getByLabelText("Credential name (optional)") as HTMLInputElement;
    expect(label.value).toBe(""); expect(label.placeholder).toHaveLength(80); expect(label.placeholder).toMatch(/^OpenAI · openai\//);
    expect((screen.getByLabelText("Upstream API Base") as HTMLInputElement).value).toBe("https://api.openai.com/v1");
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
    fireEvent.click(screen.getByRole("button", { name: "Edit Engineering" })); expect(screen.getByRole("dialog", { name: "Edit credentials" }).getAttribute("data-placement")).toBe("right"); const key = screen.getByLabelText("Replacement API key (optional)") as HTMLInputElement; expect(key.value).toBe("");
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
    const page = render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider(); fireEvent.change(screen.getByLabelText("API key"), { target: { value: "fixture-unsent-key" } });
    page.rerender(show("org-b")); await screen.findByText("Engineering"); expect(screen.queryByLabelText("API key")).toBeNull(); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider();
    expect((screen.getByLabelText("API key") as HTMLInputElement).value).toBe(""); expect(api.POST).not.toHaveBeenCalled();
  });
  it("keeps exact model entry when suggestions fail", async () => {
    api.GET.mockImplementation((path: string) => path.endsWith("/models") ? Promise.reject(Error()) : Promise.resolve({ data: inventory })); render(show()); await screen.findByText("Engineering");
    fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider();  await screen.findByText(/Model suggestions are unavailable/); expect(screen.getByLabelText("Exact model name")).toBeTruthy();
  });
  it("uses backend provider definitions and clears secret/model drafts and stale catalog on provider changes", async () => {
    let finish!: (v: unknown) => void;
    api.GET.mockImplementation((path: string) => path.endsWith("/models") ? new Promise((resolve) => { finish = resolve; }) : Promise.resolve({ data: inventory, response: response() }));
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider();
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "discard-me" } });
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: c.models[0] } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    selectProvider();
    expect((screen.getByLabelText("API key") as HTMLInputElement).value).toBe("discard-me");

    await waitFor(() => expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/models$/), expect.objectContaining({ params: expect.objectContaining({ query: expect.objectContaining({ provider: "openrouter" }) }) })));
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
    fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider();
    expect(screen.queryByRole("option", { name: /Direct OpenAI/ })).toBeNull();
    expect(screen.queryByRole("option", { name: /Pending key|Failed key/ })).toBeNull();
    fireEvent.change(screen.getByLabelText("Existing Credentials"), { target: { value: c.id } });
    expect(screen.queryByLabelText("API key")).toBeNull();
    expect(screen.queryByLabelText("Upstream API Base")).toBeNull();
    expect(screen.queryByRole("button", { name: "Use custom endpoint" })).toBeNull();
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "openrouter/anthropic/claude-sonnet-4" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    await passTest(); fireEvent.click(saveModel());
    await waitFor(() => expect(api.PUT).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ body: { provider: "openrouter", name: c.name, models: [...c.models, "openrouter/anthropic/claude-sonnet-4"], model_modes: { [c.models[0]]: "chat", "openrouter/anthropic/claude-sonnet-4": "chat" }, enabled: true, expected_revision: 3 } })));
    expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/test-connection$/), expect.objectContaining({ body: expect.objectContaining({ connection_id: expect.any(String) }) }));
  });
  it("does not invent new provider options on an older API and keeps connection provider immutable", async () => {
    api.GET.mockResolvedValue({ data: { management_available: true, items: [c], legacy_key_ids: [] }, response: response() });
    render(show()); await screen.findByText("Engineering");
    expect((screen.getByRole("tab", { name: "Add Model" }) as HTMLButtonElement).disabled).toBe(true);
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
    fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider("Custom");
    expect((screen.getByRole("combobox", { name: "Provider" }) as HTMLInputElement).value).toBe("Custom");
    expect(screen.getByText(/Installation setup required: configure secure provider egress/)).toBeTruthy();
    expect(screen.getByLabelText("Upstream API Base")).toBeTruthy(); expect((screen.getByRole("button", { name: "Test Connect" }) as HTMLButtonElement).disabled).toBe(true); expect(api.POST).not.toHaveBeenCalled();
  });
  it("explicitly switches native credentials to Custom and clears keys, models and test proof", async () => {
    api.GET.mockResolvedValue({ data: customInventory }); render(show()); await screen.findByText(custom.name);
    fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider("OpenAI");
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "native-key-must-not-move" } });
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "openai/gpt-4o-mini" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" })); await passTest();
    fireEvent.click(screen.getByRole("button", { name: "Use custom endpoint" }));
    expect((screen.getByRole("combobox", { name: "Provider" }) as HTMLInputElement).value).toBe("Custom");
    expect((screen.getByLabelText("API key") as HTMLInputElement).value).toBe("");
    expect(screen.queryByRole("button", { name: "Remove model openai/gpt-4o-mini" })).toBeNull(); expect(screen.queryByText(/Test succeeded/)).toBeNull();
    expect((saveModel() as HTMLButtonElement).disabled).toBe(true); expect((screen.getByLabelText("Upstream API Base") as HTMLInputElement).readOnly).toBe(false);
    fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: custom.endpoint_url } });
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "custom-key-only" } });
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "model-x" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" })); await passTest(); fireEvent.click(saveModel());
    expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/providers$/), expect.objectContaining({ body: expect.objectContaining({ provider: "custom", endpoint_url: custom.endpoint_url, api_key: "custom-key-only", models: ["model-x"] }) }));
    expect(api.POST.mock.calls.filter(([, options]) => options.body.provider === "custom").every(([, options]) => options.body.api_key !== "native-key-must-not-move")).toBe(true);
  });
  it("creates only an approved custom endpoint using raw names and no precreation catalog request", async () => {
    api.GET.mockResolvedValue({ data: customInventory }); render(show()); await screen.findByText(custom.name);
    fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider("Custom");
    fireEvent.change(screen.getByLabelText("Credential name (optional)"), { target: { value: "New private" } });
    expect(screen.queryByLabelText("Approved upstream endpoint")).toBeNull();
    expect(screen.getByLabelText("Upstream API Base").compareDocumentPosition(screen.getByLabelText("API key")) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: custom.endpoint_url } });
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "synthetic-custom-key" } });
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "custom-00000000-0000-4000-8000-000000000001/model" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    expect((saveModel() as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "custom-model" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    expect(screen.queryByRole("button", { name: "Search models" })).toBeNull();
    const mapping = within(screen.getByRole("table", { name: "Model mapping preview" }));
    expect(mapping.getByText("Assigned when saved")).toBeTruthy(); expect(mapping.getByText("custom-model")).toBeTruthy();
    await passTest(); fireEvent.click(saveModel());
    await waitFor(() => expect(api.POST).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ body: { provider: "custom", endpoint_url: custom.endpoint_url, name: "New private", enabled: true, models: ["custom-model"], model_modes: { "custom-model": "chat" }, api_key: "synthetic-custom-key" } })));
    expect(api.GET.mock.calls.some(([path]) => path.endsWith("/models"))).toBe(false);
  });
  it("tests a typed API base URL, invalidates edits and refuses unapproved destinations", async () => {
    const base = "https://inference.internal";
    api.GET.mockResolvedValue({ data: { ...customInventory, custom_endpoints: [{ name: "Internal inference", url: base }] } });
    render(show()); await screen.findByText(custom.name); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider("Custom");
    fireEvent.change(screen.getByLabelText("Credential name (optional)"), { target: { value: "Typed endpoint" } });
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "model-a" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: base + "/v1/" } });
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "synthetic-custom-key" } });
    expect(screen.getByText(base + "/v1/chat/completions")).toBeTruthy(); await passTest();
    expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/test-connection$/), expect.objectContaining({ body: { provider: "custom", model: "model-a", mode: "chat", api_key: "synthetic-custom-key", endpoint_url: base } }));
    fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: "https://unapproved.internal" } });
    expect(screen.getByText(/This endpoint needs configured network access/)).toBeTruthy(); expect((screen.getByLabelText("API key") as HTMLInputElement).value).toBe("");
    expect(screen.queryByText(/Test succeeded/)).toBeNull(); expect((saveModel() as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "new-secret" } }); fireEvent.click(screen.getByRole("button", { name: "Test Connect" })); expect(api.POST).toHaveBeenCalledTimes(1);
    fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: "https://user:secret@inference.internal" } }); expect(screen.getByText(/without embedded credentials/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: base } }); fireEvent.change(screen.getByLabelText("API key"), { target: { value: "synthetic-custom-key" } }); await passTest();
    fireEvent.click(saveModel()); await waitFor(() => expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/providers$/), expect.objectContaining({ body: expect.objectContaining({ endpoint_url: base }) })));
  });
  it.each(["openrouter", "custom"])("hides saved %s endpoint/key and restores new fields without stale test proof", async (provider) => {
    api.GET.mockResolvedValue({ data: { ...customInventory, items: [c, custom] } });
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" }));
    selectProvider(provider === "custom" ? "Custom" : "OpenRouter");
    if (provider === "custom") fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: custom.endpoint_url } });
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "new-draft-key" } });
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: provider === "custom" ? "model-b" : c.models[0] } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" })); await passTest();
    const saved = provider === "custom" ? custom : c;
    fireEvent.change(screen.getByLabelText("Existing Credentials"), { target: { value: saved.id } });
    expect(screen.queryByLabelText("Upstream API Base")).toBeNull(); expect(screen.queryByLabelText("API key")).toBeNull();
    expect(screen.getByText(`Using ${saved.name}. Its API key stays private and existing models are preserved.`)).toBeTruthy();
    expect(screen.queryByText(/Test succeeded/)).toBeNull();
    fireEvent.change(screen.getByLabelText("Existing Credentials"), { target: { value: "" } });
    expect(screen.getByLabelText("Upstream API Base")).toBeTruthy(); expect((screen.getByLabelText("API key") as HTMLInputElement).value).toBe("");
    expect(screen.queryByText(/Test succeeded/)).toBeNull(); expect((saveModel() as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Cancel" })); fireEvent.click(screen.getByRole("tab", { name: /LLM Credentials/ })); fireEvent.click(screen.getByRole("button", { name: `Edit ${saved.name}` }));
    expect((screen.getByLabelText("Upstream API Base") as HTMLInputElement).readOnly).toBe(true);
    expect((screen.getByLabelText("Upstream API Base") as HTMLInputElement).value).toBe(provider === "custom" ? custom.endpoint_url : "https://openrouter.ai/api/v1");
  });
  it("reuses custom credentials with immutable endpoint and scopes catalog to the connection", async () => {
    api.GET.mockImplementation((path: string) => Promise.resolve({ data: path.endsWith("/models") ? { items: [], total: 0, limit: 50, offset: 0 } : customInventory }));
    render(show()); await screen.findByText(custom.name); fireEvent.click(screen.getByRole("tab", { name: /Models/ })); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider("Custom");
    fireEvent.change(screen.getByLabelText("Existing Credentials"), { target: { value: custom.id } });
    expect(screen.queryByLabelText("Upstream API Base")).toBeNull();
    expect(screen.queryByLabelText("API key")).toBeNull();
    await waitFor(() => expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/models$/), expect.objectContaining({ params: expect.objectContaining({ query: expect.objectContaining({ provider: "custom", connection_id: custom.id }) }) })));
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "model-b" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" })); await passTest(); fireEvent.click(saveModel());
    await waitFor(() => expect(api.PUT).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ body: { provider: "custom", endpoint_url: custom.endpoint_url, name: custom.name, enabled: true, models: [...custom.models, "model-b"], model_modes: { [custom.models[0]]: "chat", "model-b": "chat" }, expected_revision: 4 } })));
  });
});

describe("pre-save inference check", () => {
  const prepare = async () => {
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider();
    fireEvent.change(screen.getByLabelText("Credential name (optional)"), { target: { value: "Tested connection" } });
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "synthetic-key" } });
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: c.models[0] } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
  };
  it("explains a typed but unselected model and a pasted key with whitespace without exposing the key", async () => {
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider();
    const test = screen.getByRole("button", { name: "Test Connect" }) as HTMLButtonElement;
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: c.models[0] } });
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "synthetic-key " } });
    const requirements = screen.getByRole("status", { name: "Test Connect requirements" });
    expect(test.disabled).toBe(true); expect(test.getAttribute("aria-describedby")).toBe(requirements.id);
    expect(within(requirements).getByText(/Click Add exact model/)).toBeTruthy();
    expect(within(requirements).getByText(/API key contains whitespace/)).toBeTruthy();
    expect(requirements.textContent).not.toContain("synthetic-key"); expect(api.POST).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "synthetic-key" } });
    expect(test.disabled).toBe(false); expect(screen.queryByRole("status", { name: "Test Connect requirements" })).toBeNull();
    expect(api.POST).not.toHaveBeenCalled();
  });
  it("requires result success, rejects HTTP200 error and invalidates changed credentials", async () => {
    await prepare(); const save = saveModel() as HTMLButtonElement; expect(save.disabled).toBe(true);
    api.POST.mockResolvedValueOnce({ data: { status: "error", duration_ms: 20 }, response: response() });
    fireEvent.click(screen.getByRole("button", { name: "Test Connect" })); await screen.findByText(/Connection test failed/); expect(save.disabled).toBe(true);
    await passTest(); expect(save.disabled).toBe(false);
    expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/test-connection$/), expect.objectContaining({ body: { provider: "openrouter", model: c.models[0], mode: "chat", api_key: "synthetic-key" } }));
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
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider("AWS SageMaker");
    expect(screen.queryByLabelText("Approved upstream endpoint")).toBeNull();
    fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: "https://aws-bridge.internal" } });
    fireEvent.change(screen.getByLabelText("Credential name (optional)"), { target: { value: "AWS models" } }); fireEvent.change(screen.getByLabelText("Gateway API key"), { target: { value: "synthetic-gateway-key" } });
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "production-model" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    await passTest(); expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/test-connection$/), expect.objectContaining({ body: { provider: "sagemaker", model: "production-model", mode: "chat", api_key: "synthetic-gateway-key", endpoint_url: "https://aws-bridge.internal" } }));
    fireEvent.click(saveModel());
    await waitFor(() => expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/providers$/), expect.objectContaining({ body: expect.objectContaining({ provider: "sagemaker", models: ["production-model"], endpoint_url: "https://aws-bridge.internal" }) })));
    expect(screen.queryByLabelText("AWS Secret Access Key")).toBeNull();
  });
});

describe("Azure AI Foundry OpenAI v1", () => {
  const foundryDefinition = { id: "azure_foundry", name: "Azure AI Foundry", credential_label: "Azure API key", model_placeholder: "my-gpt-deployment" };
  const bases = ["https://sample.services.ai.azure.com/openai", "https://sample.openai.azure.com/openai"];
  const foundryInventory = { ...inventory, definitions: [...definitions, foundryDefinition], foundry_available: true, foundry_endpoints: bases.map((url) => ({ name: "Azure deployment", url })) };
  it("explains deployment and mode conflicts without testing a different target", async () => {
    api.GET.mockResolvedValue({ data: { ...foundryInventory, public_endpoints_available: true, supported_modes: ["chat", "embedding"] } });
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider(foundryDefinition.name);
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "other-deployment" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: `${bases[0]}/deployments/gpt-5/chat/completions?api-version=2025-01-01-preview` } });
    fireEvent.change(screen.getByLabelText("Azure API key"), { target: { value: "synthetic-key" } });
    const test = screen.getByRole("button", { name: "Test Connect" }) as HTMLButtonElement;
    expect(test.disabled).toBe(true); expect(screen.getByText(/The pasted URL targets deployment gpt-5/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Remove model other-deployment" }));
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "gpt-5" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    expect(test.disabled).toBe(false);
    fireEvent.change(screen.getByLabelText("Mode"), { target: { value: "embedding" } });
    expect(test.disabled).toBe(true); expect(screen.getByText(/The pasted URL uses Chat/)).toBeTruthy();
    expect(api.POST).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: bases[0] } });
    fireEvent.change(screen.getByLabelText("Azure API key"), { target: { value: "synthetic-key" } });
    expect(test.disabled).toBe(false); await passTest();
    expect(api.POST).toHaveBeenLastCalledWith(expect.stringMatching(/test-connection$/), expect.objectContaining({ body: expect.objectContaining({ model: "gpt-5", mode: "embedding", endpoint_url: bases[0] }) }));
  });
  it.each(["model", "credentials"])("accepts a pasted Azure portal deployment URL in Add %s and sends the canonical resource", async (form) => {
    api.GET.mockResolvedValue({ data: { ...foundryInventory, public_endpoints_available: true } });
    render(show()); await screen.findByText("Engineering");
    if (form === "model") fireEvent.click(screen.getByRole("tab", { name: "Add Model" }));
    else { fireEvent.click(screen.getByRole("tab", { name: /LLM Credentials/ })); fireEvent.click(screen.getByRole("button", { name: "Add Credentials" })); }
    selectProvider(foundryDefinition.name);
    const base = "https://example.cognitiveservices.azure.com/openai";
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "gpt-5" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: `${base}/deployments/gpt-5/chat/completions?api-version=2025-01-01-preview` } });
    fireEvent.change(screen.getByLabelText("Azure API key"), { target: { value: "synthetic-key" } });
    expect((screen.getByRole("button", { name: "Test Connect" }) as HTMLButtonElement).disabled).toBe(false);
    expect(screen.getByText(`${base}/v1/chat/completions`)).toBeTruthy();
    expect(screen.getByText(/The api-version query is replaced by v1 implicit versioning/)).toBeTruthy();
    await passTest();
    expect(api.POST).toHaveBeenLastCalledWith(expect.stringMatching(/test-connection$/), expect.objectContaining({ body: { provider: "azure_foundry", endpoint_url: base, model: "gpt-5", mode: "chat", api_key: "synthetic-key" } }));
    fireEvent.click(form === "model" ? saveModel() : screen.getByRole("button", { name: "Create credentials" }));
    expect(api.POST).toHaveBeenLastCalledWith(expect.stringMatching(/providers$/), expect.objectContaining({ body: expect.objectContaining({ endpoint_url: base, models: ["gpt-5"] }) }));
  });
  it.each(["model", "credential"])("tests a Foundry Claude portal endpoint in the %s form", async (form) => {
    api.GET.mockResolvedValue({ data: { ...foundryInventory, public_endpoints_available:true, supported_modes:["chat","embedding"] } });
    render(show()); await screen.findByText("Engineering");
    if (form === "model") fireEvent.click(screen.getByRole("tab", {name:"Add Model"}));
    else { fireEvent.click(screen.getByRole("tab", {name:/LLM Credentials/})); fireEvent.click(screen.getByRole("button", {name:"Add Credentials"})); }
    selectProvider(foundryDefinition.name);
    fireEvent.change(screen.getByLabelText("Exact model name"), {target:{value:"claude-opus-5"}}); fireEvent.click(screen.getByRole("button", {name:"Add exact model"}));
    fireEvent.change(screen.getByLabelText("Upstream API Base"), {target:{value:"https://bst-azure-ai-services.services.ai.azure.com/anthropic/v1/messages"}});
    fireEvent.change(screen.getByLabelText("Azure API key"), {target:{value:"synthetic-claude-key"}});
    expect(screen.getByText("https://bst-azure-ai-services.services.ai.azure.com/anthropic/v1/messages")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Mode"), {target:{value:"embedding"}});
    expect((screen.getByRole("button", {name:"Test Connect"}) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Mode"), {target:{value:"chat"}});
    await passTest();
    expect(api.POST).toHaveBeenLastCalledWith(expect.stringMatching(/test-connection$/), expect.objectContaining({body:{provider:"azure_foundry",model:"claude-opus-5",mode:"chat",endpoint_url:"https://bst-azure-ai-services.services.ai.azure.com/anthropic",api_key:"synthetic-claude-key"}}));
    fireEvent.click(form === "model" ? saveModel() : screen.getByRole("button", {name:"Create credentials"}));
    expect(api.POST).toHaveBeenLastCalledWith(expect.stringMatching(/providers$/), expect.objectContaining({body:expect.objectContaining({endpoint_url:"https://bst-azure-ai-services.services.ai.azure.com/anthropic",models:["claude-opus-5"]})}));
  });
  it("keeps a fully filled Azure model testable after mode changes and explains key re-entry after endpoint edits", async () => {
    api.GET.mockResolvedValue({ data: { ...foundryInventory, public_endpoints_available: true, supported_modes: ["chat", "embedding"] } });
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider(foundryDefinition.name);
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "my-deployment" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: "https://sample.cognitiveservices.azure.com/openai/v1/" } });
    fireEvent.change(screen.getByLabelText("Azure API key"), { target: { value: "synthetic-key" } });
    const test = screen.getByRole("button", { name: "Test Connect" }) as HTMLButtonElement;
    expect(test.disabled).toBe(false); fireEvent.change(screen.getByLabelText("Mode"), { target: { value: "embedding" } }); expect(test.disabled).toBe(false);
    fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: "https://next.cognitiveservices.azure.com/openai/v1/" } });
    expect(test.disabled).toBe(true); expect((screen.getByLabelText("Azure API key") as HTMLInputElement).value).toBe("");
    expect(screen.getByText(/If you changed the endpoint, enter the key again/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Azure API key"), { target: { value: "next-synthetic-key" } });
    expect(test.disabled).toBe(false); expect(api.POST).not.toHaveBeenCalled(); await passTest();
    expect(api.POST).toHaveBeenLastCalledWith(expect.stringMatching(/\/test-connection$/), expect.objectContaining({ body: { provider: "azure_foundry", endpoint_url: "https://next.cognitiveservices.azure.com/openai", model: "my-deployment", mode: "embedding", api_key: "next-synthetic-key" } }));
  });
  it.each(bases)("tests and creates the exact deployment through %s with an Azure key", async (base) => {
    api.GET.mockResolvedValue({ data: foundryInventory }); render(show()); await screen.findByText("Engineering");
    fireEvent.click(screen.getByRole("tab", { name: /LLM Credentials/ })); fireEvent.click(screen.getByRole("button", { name: "Add Credentials" }));
    fireEvent.focus(screen.getByRole("combobox", { name: "Provider" }));
    expect(screen.getByRole("listbox").querySelector("svg.ai-provider-logo")).toBeTruthy();
    selectProvider(foundryDefinition.name);
    expect(screen.getByText(/Connect Azure-hosted models, including Claude/)).toBeTruthy(); expect(screen.queryByLabelText("Gateway API key")).toBeNull();
    fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: `${base}/v1` } });
    fireEvent.change(screen.getByLabelText("Azure API key"), { target: { value: "synthetic-azure-api-key" } });
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "my-gpt-deployment" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    const save = screen.getByRole("button", { name: "Create credentials" }) as HTMLButtonElement;
    expect(save.disabled).toBe(true); expect(screen.getByText(`${base}/v1/chat/completions`)).toBeTruthy();
    await passTest(); expect(save.disabled).toBe(false);
    expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/test-connection$/), expect.objectContaining({ body: { provider: "azure_foundry", endpoint_url: base, model: "my-gpt-deployment", mode: "chat", api_key: "synthetic-azure-api-key" } }));
    fireEvent.click(save);
    expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/providers$/), expect.objectContaining({ body: { provider: "azure_foundry", endpoint_url: base, models: ["my-gpt-deployment"], model_modes: { "my-gpt-deployment": "chat" }, api_key: "synthetic-azure-api-key", enabled: true, name: "Azure AI Foundry · my-gpt-deployment" } }));
    expect(screen.queryByLabelText("Azure API key")).toBeNull();
  });
  it("invalidates an Azure endpoint change and refuses unapproved or legacy URLs", async () => {
    api.GET.mockResolvedValue({ data: foundryInventory }); render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider(foundryDefinition.name);
    fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: bases[0] + "/v1" } }); fireEvent.change(screen.getByLabelText("Azure API key"), { target: { value: "old-azure-key" } });
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "deployment" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" })); await passTest();
    fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: bases[1] + "/v1" } });
    expect((screen.getByLabelText("Azure API key") as HTMLInputElement).value).toBe(""); expect(screen.queryByText(/Test succeeded/)).toBeNull(); expect((saveModel() as HTMLButtonElement).disabled).toBe(true);
    for (const url of ["https://other.services.ai.azure.com/openai/v1", "https://sample.services.ai.azure.com/models", "https://sample.openai.azure.com/openai/deployments/deployment?api-version=2024-10-21", "http://sample.openai.azure.com/openai/v1", "https://sample.openai.azure.com.evil.example/openai/v1"]) {
      fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: url } }); fireEvent.change(screen.getByLabelText("Azure API key"), { target: { value: "new-azure-key" } });
      expect((screen.getByRole("button", { name: "Test Connect" }) as HTMLButtonElement).disabled).toBe(true); expect((saveModel() as HTMLButtonElement).disabled).toBe(true);
    }
    expect(api.POST).toHaveBeenCalledTimes(1);
  });
  it("reuses saved Foundry credentials with hidden endpoint/key and preserves the exact namespace", async () => {
    const id = "12345678-1234-1234-1234-123456789abc";
    const saved = { ...c, id, provider: "azure_foundry", name: "Saved Azure", endpoint_url: bases[0], models: [`custom-${id}/deployment-a`] };
    api.GET.mockImplementation((path: string) => Promise.resolve({ data: path.endsWith("/models") ? { items: [], total: 0, limit: 50, offset: 0 } : { ...foundryInventory, items: [saved] } })); render(show()); await screen.findByText("Saved Azure"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider(foundryDefinition.name);
    fireEvent.change(screen.getByLabelText("Existing Credentials"), { target: { value: id } });
    expect(screen.queryByLabelText("Upstream API Base")).toBeNull(); expect(screen.queryByLabelText("Azure API key")).toBeNull(); expect(screen.queryByLabelText("API key")).toBeNull();
     await waitFor(() => expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/models$/), expect.objectContaining({ params: expect.objectContaining({ query: expect.objectContaining({ provider: "azure_foundry", connection_id: id }) }) })));
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "deployment-b" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" })); await passTest(); fireEvent.click(saveModel());
    expect(api.PUT).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ body: { provider: "azure_foundry", endpoint_url: bases[0], models: [...saved.models, "deployment-b"], model_modes: { [saved.models[0]]: "chat", "deployment-b": "chat" }, expected_revision: 3, name: saved.name, enabled: true } })); expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/test-connection$/), expect.objectContaining({ body: expect.objectContaining({ connection_id: expect.any(String) }) }));
  });
  it("keeps Foundry test/save unavailable without installation approval", async () => {
    api.GET.mockResolvedValue({ data: { ...foundryInventory, foundry_available: false, foundry_endpoints: [] } }); render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider(foundryDefinition.name);
    expect(screen.getByText(/Installation setup required: configure secure provider egress/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: bases[0] + "/v1" } }); fireEvent.change(screen.getByLabelText("Azure API key"), { target: { value: "synthetic-key" } });
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "deployment" } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" }));
    expect((screen.getByRole("button", { name: "Test Connect" }) as HTMLButtonElement).disabled).toBe(true); expect((saveModel() as HTMLButtonElement).disabled).toBe(true); expect(api.POST).not.toHaveBeenCalled();
  });
});

describe("self-service endpoints and draft model catalogs", () => {
  const customDef = { id: "custom", name: "Custom", credential_label: "API key", model_placeholder: "model" };
  const azureDef = { id: "azure_foundry", name: "Azure AI Foundry", credential_label: "Azure API key", model_placeholder: "deployment" };
  const sageDef = { id: "sagemaker", name: "AWS SageMaker", credential_label: "Gateway API key", model_placeholder: "alias" };
  const customBase = "https://inference.example.com";
  const azureBase = "https://resource.cognitiveservices.azure.com/openai";
  const sageBase = "http://aws-bridge.internal";
  const saved = { ...c, id: "12345678-1234-1234-1234-123456789abc", provider: "custom", endpoint_url: customBase, models: ["custom-12345678-1234-1234-1234-123456789abc/saved-model"], name: "Saved custom" };
  const publicInventory = { ...inventory, public_endpoints_available: true, custom_available: false, foundry_available: false, custom_endpoints: [], foundry_endpoints: [], sagemaker_available: true, sagemaker_endpoints: [{ name: "Private bridge", url: sageBase }], definitions: [...definitions, customDef, azureDef, sageDef], items: [c, saved] };
  const catalog = { items: [{ id: "deployment-first", name: "Deployment first" }], total: 1, limit: 50, offset: 0 };
  const openDraft = async (name = "Custom") => {
    api.GET.mockResolvedValue({ data: publicInventory }); render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider(name);
  };
  it.each([
    ["custom", "Custom", customBase, "API key"],
    ["sagemaker", "AWS SageMaker", sageBase, "Gateway API key"],
  ])("searches a %s draft using endpoint/key without saving credentials or choosing a model", async (provider, name, base, keyLabel) => {
    await openDraft(name);
    expect(screen.queryByRole("button", { name: "Search models" })).toBeNull();
    fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: base + "/v1" } });
    expect(screen.getByText(/Enter the provider API key to search models/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText(keyLabel), { target: { value: "draft-only-synthetic-key" } });
    expect(screen.queryByRole("button", { name: "Search models" })).toBeNull();
    expect(screen.getByText("Select models to preview their names.")).toBeTruthy();
    api.POST.mockResolvedValueOnce({ data: catalog, response: response() }); fireEvent.change(screen.getByLabelText("Search model catalog"), { target: { value: "deploy" } });
    await screen.findByLabelText(/Deployment first/);
    expect(api.POST).toHaveBeenCalledTimes(1); expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/providers\/model-catalog$/), expect.objectContaining({ body: { provider, endpoint_url: base, api_key: "draft-only-synthetic-key", query: "deploy", mode: "chat", limit: 50, offset: 0 } }));
    expect(api.PUT).not.toHaveBeenCalled(); expect(document.body.textContent).not.toContain("draft-only-synthetic-key");
    fireEvent.click(screen.getByLabelText(/Deployment first/)); expect((saveModel() as HTMLButtonElement).disabled).toBe(true);
    await passTest(); fireEvent.click(saveModel());
    expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/providers$/), expect.objectContaining({ body: expect.objectContaining({ provider, endpoint_url: base, models: ["deployment-first"], api_key: "draft-only-synthetic-key" }) }));
  });
  it.each(["key", "endpoint", "provider", "credential"])("discards a late draft catalog after %s changes", async (field) => {
    await openDraft(); fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: customBase + "/v1" } }); fireEvent.change(screen.getByLabelText("API key"), { target: { value: "old-key" } });
    let finish!: (v: unknown) => void; api.POST.mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }));
    await waitFor(() => expect(api.POST).toHaveBeenCalledTimes(1));
    if (field === "key") fireEvent.change(screen.getByLabelText("API key"), { target: { value: "new-key" } });
    if (field === "endpoint") fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: "https://other.example.com/v1" } });
    if (field === "provider") selectProvider("OpenAI");
    if (field === "credential") fireEvent.change(screen.getByLabelText("Existing Credentials"), { target: { value: saved.id } });
    await act(async () => finish({ data: catalog, response: response() }));
    expect(screen.queryByRole("region", { name: "Model suggestions" })).toBeNull(); expect(screen.queryByLabelText(/Deployment first/)).toBeNull(); expect(api.POST).toHaveBeenCalledTimes(1);
  });
  it("keeps manual deployment entry after a sanitized failed draft catalog", async () => {
    await openDraft(); fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: customBase + "/v1" } }); fireEvent.change(screen.getByLabelText("API key"), { target: { value: "private-key-fixture" } });
    api.POST.mockResolvedValueOnce({ error: { detail: "RAW_UPSTREAM_SECRET" }, response: response(502) });
    await screen.findByText(/Model suggestions are unavailable. Enter the exact model or Azure deployment name manually/);
    expect(screen.getByLabelText("Exact model name")).toBeTruthy(); expect(document.body.textContent).not.toContain("RAW_UPSTREAM_SECRET"); expect(document.body.textContent).not.toContain("private-key-fixture"); expect(api.POST).toHaveBeenCalledTimes(1);
  });
  it("searches Azure LiteLLM reference suggestions without endpoint, key, model or saved connection", async () => {
    const suggestions = { items: [{ id: "gpt-4o-mini", name: "GPT-4o mini" }], total: 51, limit: 50, offset: 0 };
    api.GET.mockImplementation((path: string, options: { params?: { query?: { offset?: number } } }) => Promise.resolve({ data: path.endsWith("/models") ? { ...suggestions, offset: options.params?.query?.offset ?? 0 } : { ...publicInventory, public_endpoints_available: false, foundry_available: false } }));
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider(azureDef.name);
    expect((screen.getByLabelText("Upstream API Base") as HTMLInputElement).value).toBe(""); expect((screen.getByLabelText("Azure API key") as HTMLInputElement).value).toBe("");
    expect(screen.getByText("Select models to preview their names.")).toBeTruthy(); expect(screen.getByText(/Search LiteLLM model suggestions. Use your Azure deployment name if it differs/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Search models" })).toBeNull();
    fireEvent.change(screen.getByLabelText("Search model catalog"), { target: { value: "gpt" } }); await screen.findByLabelText(/GPT-4o mini/);
    expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/ai-gateway\/models$/), { params: { path: { orgId: "org-a" }, query: { provider: "azure_foundry", query: "gpt", mode: "chat", limit: 50, offset: 0 } } });
    fireEvent.click(screen.getByRole("button", { name: "Next models" })); await waitFor(() => expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/models$/), expect.objectContaining({ params: expect.objectContaining({ query: { provider: "azure_foundry", query: "gpt", mode: "chat", limit: 50, offset: 50 } }) })));
    expect(api.POST).not.toHaveBeenCalled(); expect((saveModel() as HTMLButtonElement).disabled).toBe(true);
  });
  it("does not bypass a registered provider kind or public HTTPS port restrictions", async () => {
    api.GET.mockResolvedValue({ data: { ...publicInventory, foundry_endpoints: [{ name: "Azure only", url: azureBase }] } }); render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider("Custom");
    for (const base of [azureBase, "http://inference.example.com", "https://inference.example.com:8443"]) {
      fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: base } }); fireEvent.change(screen.getByLabelText("API key"), { target: { value: "synthetic-key" } });
      expect(screen.queryByRole("button", { name: "Search models" })).toBeNull();
    }
    expect(api.POST).not.toHaveBeenCalled();
  });
});

describe("automatic catalog search", () => {
  const advance = async (ms: number) => { await act(async () => { await vi.advanceTimersByTimeAsync(ms); }); };
  it("debounces rapid typing, ignores late old queries and replaces pending searches on provider switch", async () => {
    render(show()); await screen.findByText("Engineering"); vi.useFakeTimers(); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider();
    const input = screen.getByLabelText("Search model catalog");
    const calls = () => api.GET.mock.calls.filter(([path]) => path.endsWith("/models"));
    fireEvent.change(input, { target: { value: "g" } }); await advance(200);
    fireEvent.change(input, { target: { value: "gp" } }); await advance(200);
    fireEvent.change(input, { target: { value: "gpt" } }); await advance(499); expect(calls()).toHaveLength(0);
    await advance(1); expect(calls()).toHaveLength(1); expect(calls()[0][1].params.query.query).toBe("gpt");
    let finish!: (value: unknown) => void;
    api.GET.mockImplementation((_path: string, options: { params: { query?: { query?: string } } }) => options.params.query?.query === "old" ? new Promise((resolve) => { finish = resolve; }) : Promise.resolve({ data: { items: [{ id: "openrouter/latest", name: "Latest catalog" }], total: 1, offset: 0, limit: 50 } }));
    fireEvent.change(input, { target: { value: "old" } }); await advance(500); expect(screen.getByText("Searching models…")).toBeTruthy();
    fireEvent.change(input, { target: { value: "latest" } });
    await act(async () => finish({ data: { items: [{ id: "openrouter/old", name: "Outdated catalog" }], total: 1, offset: 0, limit: 50 } }));
    expect(screen.queryByText("Outdated catalog")).toBeNull(); await advance(500); expect(screen.getByText("Latest catalog")).toBeTruthy();
    const prior = calls().length; fireEvent.change(input, { target: { value: "discarded" } }); await advance(250); selectProvider("Anthropic"); await advance(499); expect(calls()).toHaveLength(prior);
    await advance(1); expect(calls()).toHaveLength(prior + 1); expect(calls().at(-1)?.[1].params.query).toEqual({ provider: "anthropic", query: "", mode: "chat", limit: 50, offset: 0 });
    expect(calls().some(([, opts]) => opts.params.query.query === "discarded")).toBe(false); expect(api.POST).not.toHaveBeenCalled();
  });
  it("waits for complete draft credentials and never automatically retries a rate-limited catalog", async () => {
    api.GET.mockResolvedValue({ data: { ...inventory, public_endpoints_available: true, definitions: [...definitions, { id: "custom", name: "Custom", credential_label: "API key", model_placeholder: "model" }] } });
    render(show()); await screen.findByText("Engineering"); vi.useFakeTimers(); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider("Custom");
    fireEvent.change(screen.getByLabelText("Search model catalog"), { target: { value: "deployment" } }); await advance(1000); expect(api.POST).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: "https://inference.example.com/v1" } }); await advance(1000); expect(api.POST).not.toHaveBeenCalled();
    api.POST.mockResolvedValueOnce({ error: { code: "rate_limited" }, response: response(429) }); fireEvent.change(screen.getByLabelText("API key"), { target: { value: "synthetic-key" } }); await advance(499); expect(api.POST).not.toHaveBeenCalled();
    await advance(1); expect(api.POST).toHaveBeenCalledTimes(1); expect(screen.getByText(/Model suggestions are unavailable/)).toBeTruthy();
    await advance(60000); expect(api.POST).toHaveBeenCalledTimes(1); expect(api.POST.mock.calls[0][0]).toMatch(/\/model-catalog$/); expect(screen.queryByRole("button", { name: "Search models" })).toBeNull();
  });
});

describe("catalog dismissal", () => {
  it.each(["azure_foundry", "custom"])("keeps the %s catalog dismissed during endpoint/key edits until another search interaction", async (provider) => {
    const name = provider === "custom" ? "Custom" : "Azure AI Foundry";
    const keyLabel = provider === "custom" ? "API key" : "Azure API key";
    const firstBase = provider === "custom" ? "https://first.example.com/v1" : "https://first.openai.azure.com/openai/v1";
    const nextBase = provider === "custom" ? "https://next.example.com/v1" : "https://next.openai.azure.com/openai/v1";
    const catalog = { items: [{ id: "deployment", name: "Deployment" }], total: 1, limit: 50, offset: 0 };
    api.GET.mockImplementation((path: string) => Promise.resolve({ data: path.endsWith("/models") ? catalog : { ...inventory, public_endpoints_available: true, definitions: [...definitions, { id: provider, name, credential_label: keyLabel, model_placeholder: "deployment" }] } }));
    api.POST.mockResolvedValue({ data: catalog, response: response() });
    render(show()); await screen.findByText("Engineering"); vi.useFakeTimers(); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider(name);
    fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: firstBase } }); fireEvent.change(screen.getByLabelText(keyLabel), { target: { value: "first-fixture-key" } });
    await act(async () => { await vi.advanceTimersByTimeAsync(500); }); expect(screen.getByRole("region", { name: "Model suggestions" })).toBeTruthy();
    const requests = () => api.POST.mock.calls.length + api.GET.mock.calls.filter(([path]) => path.endsWith("/models")).length;
    expect(requests()).toBe(1); fireEvent.click(screen.getByRole("button", { name: "Done selecting models" }));
    fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: nextBase } }); fireEvent.change(screen.getByLabelText(keyLabel), { target: { value: "next-fixture-key" } });
    fireEvent.change(screen.getByLabelText("Credential name (optional)"), { target: { value: "Different display name" } });
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); }); expect(screen.queryByRole("region", { name: "Model suggestions" })).toBeNull(); expect(requests()).toBe(1);
    fireEvent.change(screen.getByLabelText("Search model catalog"), { target: { value: "dep" } }); await act(async () => { await vi.advanceTimersByTimeAsync(500); });
    expect(screen.getByRole("region", { name: "Model suggestions" })).toBeTruthy(); expect(requests()).toBe(2);
    fireEvent.click(screen.getByRole("button", { name: "Done selecting models" })); fireEvent.focus(screen.getByLabelText("Search model catalog")); await act(async () => { await vi.advanceTimersByTimeAsync(500); });
    expect(screen.getByRole("region", { name: "Model suggestions" })).toBeTruthy(); expect(requests()).toBe(3);
  });
});

describe("model mode routing", () => {
  const modes = ["chat", "completion", "embedding", "audio_speech", "audio_transcription", "image_generation", "video_generation", "rerank"];
  const addExact = (model: string) => { fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: model } }); fireEvent.click(screen.getByRole("button", { name: "Add exact model" })); };
  beforeEach(() => {
    api.GET.mockImplementation((path: string) => Promise.resolve({ data: path.endsWith("/models") ? { items: [], total: 0, limit: 50, offset: 0 } : { ...inventory, supported_modes: modes } }));
  });
  it.each(modes)("probes and creates %s with an explicit per-model mode", async (mode) => {
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider("OpenAI");
    fireEvent.change(screen.getByLabelText("Mode"), { target: { value: mode } }); addExact("openai/mode-fixture");
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "synthetic-mode-key" } });
    expect((saveModel() as HTMLButtonElement).disabled).toBe(true); await passTest();
    expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/test-connection$/), expect.objectContaining({ body: { provider: "openai", model: "openai/mode-fixture", mode, api_key: "synthetic-mode-key" } }));
    if (mode === "video_generation") expect(screen.getByText(/Video job accepted; generation is not yet complete/)).toBeTruthy();
    fireEvent.click(saveModel());
    expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/providers$/), expect.objectContaining({ body: expect.objectContaining({ models: ["openai/mode-fixture"], model_modes: { "openai/mode-fixture": mode } }) }));
  });
  it("leaves unqualified operation choices disabled on an older installation", async () => {
    api.GET.mockResolvedValue({ data: inventory }); render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" }));
    const options = within(screen.getByLabelText("Mode")).getAllByRole("option") as HTMLOptionElement[];
    expect(options.filter((o) => !o.disabled).map((o) => o.value)).toEqual(["chat"]);
  });
  it("preserves selected models and typed input but invalidates an old probe when the Add Model mode changes", async () => {
    render(show()); await screen.findByText("Engineering"); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider(); addExact(c.models[0]);
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "synthetic-mode-key" } });
    let finish!: (v: unknown) => void; api.POST.mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; })); fireEvent.click(screen.getByRole("button", { name: "Test Connect" }));
    fireEvent.change(screen.getByLabelText("Exact model name"), { target: { value: "openrouter/another-model" } });
    fireEvent.change(screen.getByLabelText("Mode"), { target: { value: "embedding" } });
    expect(screen.getByRole("button", { name: `Remove model ${c.models[0]}` })).toBeTruthy();
    expect((screen.getByLabelText("Exact model name") as HTMLInputElement).value).toBe("openrouter/another-model");
    expect((screen.getByRole("button", { name: "Test Connect" }) as HTMLButtonElement).disabled).toBe(false);
    await act(async () => finish({ data: { status: "success" } })); expect(screen.queryByText(/Test succeeded/)).toBeNull(); expect((saveModel() as HTMLButtonElement).disabled).toBe(true);
    await passTest();
    expect(api.POST).toHaveBeenLastCalledWith(expect.stringMatching(/\/test-connection$/), expect.objectContaining({ body: expect.objectContaining({ model: c.models[0], mode: "embedding" }) }));
    fireEvent.click(saveModel());
    expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/providers$/), expect.objectContaining({ body: expect.objectContaining({ models: c.models, model_modes: { [c.models[0]]: "embedding" } }) }));
  });
  it("filters reference catalogs by mode and refuses late results from the old mode", async () => {
    let finish!: (v: unknown) => void;
    api.GET.mockImplementation((path: string, options: { params?: { query?: { mode?: string } } }) => path.endsWith("/models") && options.params?.query?.mode === "chat" ? new Promise((resolve) => { finish = resolve; }) : Promise.resolve({ data: path.endsWith("/models") ? { items: [{ id: "openai/embed-fixture", name: "Embedding fixture", mode: "embedding" }], total: 1, limit: 50, offset: 0 } : { ...inventory, supported_modes: modes } }));
    render(show()); await screen.findByText("Engineering"); vi.useFakeTimers(); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider("OpenAI");
    await act(async () => { await vi.advanceTimersByTimeAsync(500); }); fireEvent.change(screen.getByLabelText("Mode"), { target: { value: "embedding" } });
    await act(async () => { finish({ data: { items: [{ id: "openai/old", name: "Old chat result" }], total: 1, offset: 0, limit: 50 } }); await vi.advanceTimersByTimeAsync(500); });
    expect(screen.queryByText("Old chat result")).toBeNull(); expect(screen.getByLabelText(/Embedding fixture/)).toBeTruthy();
    expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/models$/), expect.objectContaining({ params: expect.objectContaining({ query: expect.objectContaining({ mode: "embedding" }) }) }));
  });
  it("preserves retained modes when reusing credentials and changing the draft mode", async () => {
    const saved = { ...c, model_modes: { [c.models[0]]: "completion" } };
    api.GET.mockResolvedValue({ data: { ...inventory, items: [saved], supported_modes: modes } }); render(show()); await screen.findByText("Engineering");
    expect(screen.getByText("Completion — /completions")).toBeTruthy(); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider();
    fireEvent.change(screen.getByLabelText("Existing Credentials"), { target: { value: c.id } }); addExact(c.models[0]); addExact("openrouter/draft");
    fireEvent.change(screen.getByLabelText("Mode"), { target: { value: "embedding" } }); addExact("openrouter/embed-fixture"); await passTest(); fireEvent.click(saveModel());
    expect(api.PUT).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ body: expect.objectContaining({ models: [c.models[0], "openrouter/draft", "openrouter/embed-fixture"], model_modes: { [c.models[0]]: "completion", "openrouter/draft": "embedding", "openrouter/embed-fixture": "embedding" }, expected_revision: 3 }) }));
    expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/test-connection$/), expect.objectContaining({ body: expect.objectContaining({ connection_id: expect.any(String) }) }));
  });
  it("sends draft catalog mode and merges canonical Custom modes without duplicating retained names", async () => {
    const id = "12345678-1234-1234-1234-123456789abc", retained = `custom-${id}/embed`;
    const saved = { ...c, id, provider: "custom", endpoint_url: "https://public.example", models: [retained], model_modes: { [retained]: "embedding" } };
    api.GET.mockResolvedValue({ data: { ...inventory, public_endpoints_available: true, items: [saved], supported_modes: modes, definitions: [...definitions, { id: "custom", name: "Custom", credential_label: "API key", model_placeholder: "model" }] } });
    render(show()); await screen.findByText("Engineering"); vi.useFakeTimers(); fireEvent.click(screen.getByRole("tab", { name: "Add Model" })); selectProvider("Custom");
    fireEvent.change(screen.getByLabelText("Mode"), { target: { value: "embedding" } }); fireEvent.change(screen.getByLabelText("Upstream API Base"), { target: { value: "https://public.example/v1" } }); fireEvent.change(screen.getByLabelText("API key"), { target: { value: "draft-fixture" } });
    api.POST.mockResolvedValue({ data: { items: [], total: 0, limit: 50, offset: 0 } }); await act(async () => { await vi.advanceTimersByTimeAsync(500); });
    expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/model-catalog$/), expect.objectContaining({ body: expect.objectContaining({ mode: "embedding", endpoint_url: "https://public.example", api_key: "draft-fixture" }) }));
    fireEvent.change(screen.getByLabelText("Existing Credentials"), { target: { value: id } }); fireEvent.change(screen.getByLabelText("Mode"), { target: { value: "rerank" } }); addExact("embed"); addExact("rank"); vi.useRealTimers(); api.POST.mockResolvedValue({ data: { status: "success", duration_ms: 20 }, response: response() }); await passTest(); fireEvent.click(saveModel());
    expect(api.PUT).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ body: expect.objectContaining({ models: [retained, "rank"], model_modes: { [retained]: "embedding", rank: "rerank" } }) }));
  });
  it("edits mixed modes individually and probes the actual first model mode after rotation", async () => {
    const second = "openrouter/embed-fixture";
    const saved = { ...c, models: [...c.models, second], model_modes: { [c.models[0]]: "completion", [second]: "embedding" } };
    api.GET.mockResolvedValue({ data: { ...inventory, items: [saved], supported_modes: modes } }); render(show()); await screen.findByText("Completion — /completions");
    fireEvent.click(screen.getByRole("tab", { name: /LLM Credentials/ })); fireEvent.click(screen.getByRole("button", { name: "Edit Engineering" }));
    expect((screen.getByLabelText(`Mode for ${second}`) as HTMLSelectElement).value).toBe("embedding");
    fireEvent.change(screen.getByLabelText("Mode"), { target: { value: "rerank" } }); expect((screen.getByLabelText(`Mode for ${c.models[0]}`) as HTMLSelectElement).value).toBe("completion");
    fireEvent.change(screen.getByLabelText("Replacement API key (optional)"), { target: { value: "rotated-mode-key" } }); await passTest();
    expect(api.POST).toHaveBeenLastCalledWith(expect.stringMatching(/\/test-connection$/), expect.objectContaining({ body: expect.objectContaining({ model: c.models[0], mode: "completion" }) }));
    fireEvent.change(screen.getByLabelText(`Mode for ${second}`), { target: { value: "rerank" } }); expect(screen.queryByText(/Test succeeded/)).toBeNull();
    await passTest(); fireEvent.click(screen.getByRole("button", { name: "Save credentials" }));
    expect(api.PUT).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ body: expect.objectContaining({ model_modes: { [c.models[0]]: "completion", [second]: "rerank" } }) }));
  });
});
