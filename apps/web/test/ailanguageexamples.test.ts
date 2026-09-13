import { expect, it } from "vitest";
import { aiLanguageExamples } from "../src/lib/aiLanguageExamples";
it("offers languages and preserves exact routing and model in every JSON example", () => {
  const examples = aiLanguageExamples("https://gateway.test/org/inference/v1", "custom-id/model", "embedding");
  expect(examples.map(e => e.label)).toEqual(["cURL", "Python", "JavaScript", "TypeScript", "Go", "Java", "C#", "PHP", "Ruby", "HTTP / REST"]);
  for (const e of examples) {
    expect(e.source).toContain("/org/inference/v1/embeddings");
    expect(e.source).toContain("custom-id/model");
    expect(e.source).toContain("TUNNEX");
  }
});
it("saves binary speech and includes video idempotency in every language", () => {
  for (const e of aiLanguageExamples("https://gateway.test/v1", "model", "audio_speech").filter(e => e.language !== "http")) expect(e.source).toContain("speech.mp3");
  for (const e of aiLanguageExamples("https://gateway.test/v1", "model", "video_generation")) expect(e.source).toContain("Idempotency-Key");
});
it("keeps transcription a multipart file upload", () => {
  const examples = aiLanguageExamples("https://gateway.test/v1", "model", "audio_transcription");
  expect(examples).toHaveLength(1);
  expect(examples[0].source).toContain("file=@audio.wav");
});
