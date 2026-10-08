import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AIChatPlayground } from "../src/components/AIChatPlayground";

const api = vi.hoisted(() => ({ POST: vi.fn() }));
vi.mock("../src/lib/api", () => ({ api }));
const path = "/api/v1/organizations/{orgId}/ai-gateway/inference/v1/chat/completions";
const model = "custom-connection/chat-model";
const answer = (text = "Model answer") => ({ data: { choices: [{ message: { content: text } }] }, response: new Response(null, { status: 200 }) });
beforeEach(() => { vi.resetAllMocks(); api.POST.mockResolvedValue(answer()); });
afterEach(cleanup);
const mount = () => render(<AIChatPlayground orgId="org" model={model} />);
const message = () => screen.getByRole("textbox", { name: "Message" });
async function send(text: string) {
  fireEvent.change(message(), { target: { value: text } });
  fireEvent.click(screen.getByRole("button", { name: "Send message" }));
  await waitFor(() => expect(api.POST).toHaveBeenCalled());
}

describe("AI Playground conversation controls", () => {
  it("fills and focuses a starter question without sending it", () => {
    mount();
    fireEvent.click(screen.getByRole("button", { name: "Say hello in one sentence." }));
    expect(message()).toHaveProperty("value", "Say hello in one sentence.");
    expect(document.activeElement).toBe(message());
    expect(api.POST).not.toHaveBeenCalled();
  });
  it("submits trimmed Enter text once while preserving Shift+Enter and IME composition", async () => {
    mount();
    expect(screen.getByRole("button", { name: "Send message" })).toHaveProperty("disabled", true);
    fireEvent.change(message(), { target: { value: "   " } });
    fireEvent.keyDown(message(), { key: "Enter" });
    expect(api.POST).not.toHaveBeenCalled();
    fireEvent.change(message(), { target: { value: "  Hello\nworld  " } });
    fireEvent.keyDown(message(), { key: "Enter", shiftKey: true });
    fireEvent.compositionStart(message());
    fireEvent.keyDown(message(), { key: "Enter", isComposing: true, keyCode: 229 });
    expect(api.POST).not.toHaveBeenCalled();
    fireEvent.compositionEnd(message());
    fireEvent.keyDown(message(), { key: "Enter" });
    await screen.findByText("Model answer");
    expect(api.POST).toHaveBeenCalledExactlyOnceWith(path, expect.objectContaining({
      params: { path: { orgId: "org" } },
      body: { model, messages: [{ role: "user", content: "Hello\nworld" }], max_tokens: 1024, stream: false },
    }));
    expect(message()).toHaveProperty("value", "");
    expect(screen.queryByLabelText(/API key/i)).toBeNull();
  });

  it("stops the pending request and rejects its late answer and raw response", async () => {
    let complete!: (value: unknown) => void;
    api.POST.mockImplementation(() => new Promise((resolve) => { complete = resolve; }));
    mount(); await send("Pending question");
    const signal = api.POST.mock.calls[0][1].signal as AbortSignal;
    expect(signal.aborted).toBe(false);
    expect(screen.getByRole("button", { name: "New chat" })).toHaveProperty("disabled", true);
    fireEvent.change(message(), { target: { value: "Do not send while pending" } });
    fireEvent.keyDown(message(), { key: "Enter" });
    expect(api.POST).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: "Stop" }));
    await waitFor(() => expect(signal.aborted).toBe(true));
    await act(async () => complete(answer("Private late response")));
    expect(screen.queryByText("Private late response")).toBeNull();
    expect(screen.queryByRole("button", { name: "View JSON" })).toBeNull();
    expect(api.POST).toHaveBeenCalledTimes(1);
  });

  it("retries the failed question without duplicating history or displaying upstream errors", async () => {
    api.POST.mockResolvedValueOnce({ error: { detail: "PRIVATE-UPSTREAM-ERROR" }, response: new Response(null, { status: 502 }) }).mockResolvedValue(answer("Retry answer"));
    mount(); await send("Retry this question");
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("HTTP 502");
    expect(document.body.textContent).not.toContain("PRIVATE-UPSTREAM-ERROR");
    fireEvent.click(within(alert).getByRole("button", { name: "Retry" }));
    await screen.findByText("Retry answer");
    expect(api.POST).toHaveBeenCalledTimes(2);
    expect(api.POST.mock.calls[1][1].body.messages).toEqual([{ role: "user", content: "Retry this question" }]);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("clears conversation and raw response before starting a new chat", async () => {
    mount(); await send("Original question");
    await screen.findByText("Model answer");
    expect(screen.getByRole("button", { name: "View JSON" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "New chat" }));
    const log = within(screen.getByRole("log", { name: "Conversation" }));
    expect(log.queryByText("Original question")).toBeNull();
    expect(log.queryByText("Model answer")).toBeNull();
    expect(screen.queryByRole("button", { name: "View JSON" })).toBeNull();
    expect(document.activeElement).toBe(message());
    await send("New question");
    await screen.findByText("Model answer");
    expect(api.POST).toHaveBeenCalledTimes(2);
    expect(api.POST.mock.calls[1][1].body.messages).toEqual([{ role: "user", content: "New question" }]);
  });

  it("aborts an in-flight model request when the conversation is unmounted", async () => {
    let complete!: (value: unknown) => void;
    api.POST.mockImplementation(() => new Promise((resolve) => { complete = resolve; }));
    const page = mount(); await send("Previous model question");
    const signal = api.POST.mock.calls[0][1].signal as AbortSignal;
    page.unmount();
    expect(signal.aborted).toBe(true);
    await act(async () => complete(answer("Previous model answer")));
    expect(screen.queryByText("Previous model answer")).toBeNull();
    expect(api.POST).toHaveBeenCalledTimes(1);
  });
});
