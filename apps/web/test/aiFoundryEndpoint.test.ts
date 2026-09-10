import { describe, expect, it } from "vitest";
import { parseFoundryEndpoint } from "../src/lib/aiFoundryEndpoint";

describe("Azure portal endpoint import", () => {
  it.each(["openai.azure.com", "services.ai.azure.com", "cognitiveservices.azure.com"])("preserves the resource on %s", (suffix) => {
    const origin = `https://team-resource.${suffix}`;
    for (const path of ["", "/", "/openai", "/openai/", "/openai/v1", "/openai/v1/"]) {
      expect(parseFoundryEndpoint(origin + path)).toEqual({ base: origin + "/openai", legacy: false });
    }
    expect(parseFoundryEndpoint(origin + "/openai/deployments/gpt-5/chat/completions?api-version=2025-01-01-preview"))
      .toEqual({ base: origin + "/openai", deployment: "gpt-5", mode: "chat", legacy: true });
  });
  it.each([
    ["chat/completions", "chat"], ["completions", "completion"], ["embeddings", "embedding"],
    ["audio/speech", "audio_speech"], ["audio/transcriptions", "audio_transcription"],
    ["images/generations", "image_generation"], ["videos", "video_generation"], ["rerank", "rerank"],
  ])("recognizes the operation %s independently of model vendor", (path, mode) => {
    const origin = "https://resource.services.ai.azure.com";
    expect(parseFoundryEndpoint(`${origin}/openai/deployments/Llama-3.3-70B-Instruct/${path}?api-version=2024-10-21`))
      .toEqual({ base: origin + "/openai", deployment: "Llama-3.3-70B-Instruct", mode, legacy: true });
    expect(parseFoundryEndpoint(`${origin}/openai/v1/${path}/`)).toEqual({ base: origin + "/openai", mode, legacy: false });
  });
  it.each([
    "https://evil.example/openai/v1", "https://resource.openai.azure.com.evil.example/openai/v1",
    "https://resource.openai.azure.com:8443/openai/v1", "http://resource.openai.azure.com/openai/v1",
    "https://secret@resource.openai.azure.com/openai/v1", "https://@resource.openai.azure.com/openai/v1", "https://resource.openai.azure.com./openai/v1",
    ...["/models", "/anthropic/v1/messages?api-version=2025-01-01", "/anthropic/v1/embeddings", "/openai/v1?api-version=2024-10-21", "/openai/v1?", "/openai/v1#", "/openai/v1#secret",
      "/openai/v1/../v1", "/openai/%76%31", "/openai//v1", "/openai/v1/__proto__", "/openai/v1/toString",
      "/openai/deployments/a/unknown", "/openai/deployments/a/__proto__", "/openai/deployments/a/chat/completions?",
      "/openai/deployments/a/chat/completions?api-version=2024-10-21&api-key=secret",
      "/openai/deployments/a/chat/completions?api-version=2024-10-21&api-version=2025-01-01-preview",
      "/openai/deployments/a/chat/completions?api-version=secret",
      "/openai/deployments/a/chat/completions?%61pi-version=2024-10-21",
    ].map(path => `https://resource.openai.azure.com${path}`),
  ])("refuses unsafe or unrelated URL %s", (url) => { expect(parseFoundryEndpoint(url)).toBeNull(); });
});

it("imports the Foundry Claude portal URL without changing its protocol", () => {
 for (const path of ["/anthropic", "/anthropic/v1", "/anthropic/v1/messages", "/anthropic/v1/messages/"]) {
  expect(parseFoundryEndpoint("https://bst-azure-ai-services.services.ai.azure.com" + path)).toEqual({base:"https://bst-azure-ai-services.services.ai.azure.com/anthropic", mode:"chat", legacy:false});
 }
});
