import { expect, it } from "vitest";
import { aiLanguageExamples } from "../src/lib/aiLanguageExamples";
const base = "http://100.96.0.1:8083/api/v1/organizations/org/ai-gateway/inference/v1";
it("preserves the published VPN endpoint and exact model in every language without client credentials", () => {
  const examples = aiLanguageExamples(base, "custom-id/model", "chat");
  expect(examples.map(e => e.label)).toEqual(["cURL", "Python", "JavaScript", "TypeScript", "Go", "Java", "C#", "PHP", "Ruby", "HTTP / REST"]);
  for (const e of examples) {
    expect(e.source).toContain("/api/v1/organizations/org/ai-gateway/inference/v1/chat/completions");
    expect(e.source).toContain("100.96.0.1:8083");
    expect(e.source).toContain("custom-id/model");
    expect(e.source).not.toMatch(/Authorization|TUNNEX_API_KEY|YOUR_TUNNEX_CREDENTIAL|api_key/);
  }
});
it.each(["embedding", "audio_speech", "audio_transcription", "video_generation", "completion", "image_generation", "rerank", "unknown"])("has no public fallback for unsupported VPN operation %s", mode => {
  expect(aiLanguageExamples(base, "model", mode)).toEqual([]);
});
