import { useEffect, useMemo, useRef, useState } from "react";
import { useChat } from "@ai-sdk/react";
import type { ChatTransport, UIMessage } from "ai";
import Markdown from "react-markdown";
import { FiArrowUp, FiSquare } from "react-icons/fi";
import { api } from "../lib/api";
import { Button, Modal } from "./ui";
import "./ai-chat-playground.css";

export function AIChatPlayground({ orgId, model }: { orgId: string; model: string }) {
  const [input, setInput] = useState("");
  const [raw, setRaw] = useState("");
  const [inspect, setInspect] = useState(false);
  const bottom = useRef<HTMLDivElement>(null);
  const transport = useMemo<ChatTransport<UIMessage>>(() => ({
    async sendMessages({ messages, abortSignal }) {
      const result = await api.POST("/api/v1/organizations/{orgId}/ai-gateway/inference/v1/chat/completions", {
        params: { path: { orgId } }, signal: abortSignal,
        body: { model, messages: messages.filter(m => m.role === "user" || m.role === "assistant").map(m => ({ role: m.role as "user" | "assistant", content: m.parts.filter(p => p.type === "text").map(p => p.text).join("\n") })), max_tokens: 1024, stream: false },
      });
      if (abortSignal?.aborted) throw new DOMException("Stopped", "AbortError");
      if (result.error || !result.data) throw new Error(`Request failed (HTTP ${result.response.status}). ${result.response.status >= 500 ? "The gateway could not complete the provider request. Please retry." : result.response.status === 429 ? "Too many requests. Wait a moment and retry." : "Check your model access and retry."}`);
      setRaw(JSON.stringify(result.data, null, 2));
      const data = result.data as { choices?: { message?: { content?: string } }[] };
      const text = data.choices?.map(c => typeof c.message?.content === "string" ? c.message.content : "").join("\n\n") || "The model returned no text.";
      return new ReadableStream({ start(controller) {
        controller.enqueue({ type: "start" });
        controller.enqueue({ type: "text-start", id: "answer" });
        controller.enqueue({ type: "text-delta", id: "answer", delta: text });
        controller.enqueue({ type: "text-end", id: "answer" });
        controller.enqueue({ type: "finish" }); controller.close();
      } });
    },
    async reconnectToStream() { return null; },
  }), [orgId, model]);
  const { messages, sendMessage, status, error, stop, regenerate, setMessages, clearError } = useChat({ transport });
  const busy = status === "submitted" || status === "streaming";
  useEffect(() => { bottom.current?.scrollIntoView?.({ block: "nearest" }); }, [messages, status]);
  useEffect(() => () => { void stop(); }, [stop]);
  function submit() {
    if (!input.trim() || busy) return;
    const text = input.trim(); setInput(""); clearError(); void sendMessage({ text });
  }
  return <div className="ai-chat-shell">
    <div className="ai-chat-toolbar ai-chat-actions"><span>Conversation</span><div><Button disabled={busy || !messages.length} onClick={() => { setMessages([]); setRaw(""); clearError(); }}>New chat</Button>{raw && <Button onClick={() => setInspect(true)}>View JSON</Button>}</div></div>
    <div className="ai-chat-history" role="log" aria-label="Conversation">
      {!messages.length && <div className="ai-chat-empty"><h3>What would you like to try?</h3><p>Send a message, then ask follow-up questions.</p><div>{["Say hello in one sentence.", "Explain an API to a beginner.", "Help me draft a project update."].map(text => <Button key={text} onClick={() => setInput(text)}>{text}</Button>)}</div></div>}
      {messages.map(message => <article className={`ai-chat-message ai-chat-${message.role}`} key={message.id}><strong>{message.role === "user" ? "You" : "Assistant"}</strong><div className="ai-chat-markdown">{message.parts.map((part, i) => part.type === "text" ? <Markdown key={i}>{part.text}</Markdown> : null)}</div></article>)}
      {busy && <p role="status">Waiting for the model…</p>}
      <div ref={bottom} />
    </div>
    {error && <div className="ai-chat-error" role="alert">{error.message}<Button disabled={busy} onClick={() => { clearError(); void regenerate(); }}>Retry</Button></div>}
    <form className="ai-chat-composer" onSubmit={e => { e.preventDefault(); submit(); }}>
      <label className="sr-only" htmlFor="chat-message">Message</label><textarea id="chat-message" rows={3} maxLength={8000} value={input} onChange={e => setInput(e.target.value)} placeholder="Ask anything…" onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) { e.preventDefault(); submit(); } }} />
      <div className="ai-chat-toolbar"><small>Enter to send · Shift + Enter for a new line</small>{busy ? <Button type="button" aria-label="Stop" title="Stop response" onClick={() => void stop()}><FiSquare aria-hidden="true" /></Button> : <Button type="submit" aria-label="Send message" title="Send message" disabled={!input.trim()}><FiArrowUp aria-hidden="true" /></Button>}</div>
    </form>
    {inspect && <Modal title="Latest response JSON" size="wide" showClose onDismiss={() => setInspect(false)}><pre className="ai-chat-json">{raw}</pre></Modal>}
  </div>;
}
