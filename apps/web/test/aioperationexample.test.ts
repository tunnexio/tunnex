import { expect, it } from "vitest";
import { aiOperationExample } from "../src/lib/aiOperationExample";

it("keeps the same video job key when a copied command is retried", () => {
  const example = aiOperationExample("https://gateway.test/v1", "model", "video_generation")!;
  expect(example).toContain('${TUNNEX_VIDEO_IDEMPOTENCY_KEY:=$(uuidgen)}');
  expect(example).toContain('Idempotency-Key: ${TUNNEX_VIDEO_IDEMPOTENCY_KEY}');
  expect(example).not.toContain('Idempotency-Key: $(uuidgen)');
});

it("uses multipart transcription and saves speech bytes to a file", () => {
  expect(aiOperationExample("https://gateway.test/v1", "model", "audio_transcription")).toContain("--form-string 'model=model'");
  expect(aiOperationExample("https://gateway.test/v1", "model", "audio_speech")).toContain("--output speech.mp3");
});

it("requires a Tunnex credential and quotes shell metacharacters literally", () => {
  const example = aiOperationExample("https://gateway.test/v1", "model'$(whoami)", "embedding")!;
  expect(example).toContain("${TUNNEX_API_KEY:?");
  expect(example).toContain("model'\\''$(whoami)");
  expect(example).not.toContain('api_key="unused"');
});
