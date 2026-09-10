import type { components } from "@tunnex/shared";

type Mode = components["schemas"]["AIModelMode"];
const operations: Record<string, Mode> = {
  "chat/completions": "chat", completions: "completion", embeddings: "embedding",
  "audio/speech": "audio_speech", "audio/transcriptions": "audio_transcription",
  "images/generations": "image_generation", videos: "video_generation", rerank: "rerank",
};

// Onboarding import only. The API and both transports still receive the same
// canonical protocol base; a legacy api-version is never forwarded to v1.
export function parseFoundryEndpoint(input: string): { base: string; deployment?: string; mode?: Mode; legacy: boolean } | null {
  const raw = input.trim();
  if (raw.length > 2048 || /[%\\\s#@]/.test(raw) || /\/(?:\.|\.\.)(?:\/|\?|$)/.test(raw)) return null;
  try {
    const url = new URL(raw);
    if (url.protocol !== "https:" || url.port || url.username || url.password ||
      !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:openai\.azure\.com|services\.ai\.azure\.com|cognitiveservices\.azure\.com)$/.test(url.hostname)) return null;
    const path = url.pathname.replace(/\/$/, "");
    const base = `${url.origin}/openai`;
    const deployment = /^\/openai\/deployments\/([A-Za-z0-9][A-Za-z0-9_.-]{0,254})\/(.+)$/.exec(path);
    if (deployment && Object.prototype.hasOwnProperty.call(operations, deployment[2])) {
      if (raw.includes("?") && !/^\?api-version=\d{4}-\d{2}-\d{2}(?:-preview)?$/.test(url.search)) return null;
      return { base, deployment: deployment[1], mode: operations[deployment[2]], legacy: true };
    }
    if (raw.includes("?")) return null;
    if (["/anthropic", "/anthropic/v1", "/anthropic/v1/messages"].includes(path)) return { base: `${url.origin}/anthropic`, mode: "chat", legacy: false };
    if (["", "/openai", "/openai/v1"].includes(path)) return { base, legacy: false };
    const operationPath = path.startsWith("/openai/v1/") ? path.slice("/openai/v1/".length) : "";
    const operation = Object.prototype.hasOwnProperty.call(operations, operationPath) ? operations[operationPath] : undefined;
    return operation ? { base, mode: operation, legacy: false } : null;
  } catch { return null; }
}
