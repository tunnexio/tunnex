import { expect, it } from "vitest";
import { aiOperationExample } from "../src/lib/aiOperationExample";
const base = "http://100.96.0.1:8083/api/v1/organizations/org/ai-gateway/inference/v1";
it("uses VPN identity and quotes shell metacharacters literally", () => {
  const example = aiOperationExample(base, "model'$(whoami)", "chat")!;
  expect(example).toContain(`${base}/chat/completions`);
  expect(example).toContain("model'\\''$(whoami)");
  expect(example).not.toMatch(/Authorization|TUNNEX_API_KEY|api_key/);
});
it.each(["audio_transcription", "video_generation", "audio_speech", "embedding"])("does not generate unsupported VPN operation %s", mode => {
  expect(aiOperationExample(base, "model", mode)).toBeNull();
});
